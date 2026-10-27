package middleend

import (
	"cmp"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

func checkResponsePressureIndex(t *testing.T, budget *ResponseBudget, owners []*ResponseParticipant) {
	t.Helper()
	budget.mu.Lock()
	defer budget.mu.Unlock()
	indexed := make(map[*ResponseParticipant]bool)
	var previous *ResponseParticipant
	for p := budget.pressureCandidates; p != nil; p = p.next {
		if indexed[p] || p.previous != previous {
			t.Fatal("pressure index is cyclic or has inconsistent reverse links")
		}
		indexed[p] = true
		previous = p
	}
	registered, backlogged := 0, 0
	for _, p := range owners {
		if p.registered {
			registered++
		}
		if p.registered && !p.detached && (p.stages[ResponseMemoryQueuePayload] > 0 ||
			p.stages[ResponseMemoryInflight] > 0 || p.stages[ResponseMemoryOutput] > 0) {
			backlogged++
		}
		want := p.registered && !p.detached && !p.pending && p.target != nil &&
			(p.stages[ResponseMemoryQueuePayload] > 0 || p.stages[ResponseMemoryOutput] > 0)
		if indexed[p] != want || p.pressureIndexed != want {
			t.Fatalf("participant %d index membership = %v/%v, want %v", p.id, indexed[p], p.pressureIndexed, want)
		}
		if !want && (p.previous != nil || p.next != nil) {
			t.Fatalf("participant %d retained detached index links", p.id)
		}
		delete(indexed, p)
	}
	if len(indexed) != 0 || registered != budget.participantCount || backlogged != budget.backloggedParticipants {
		t.Fatal("pressure index or owner counters retained an unknown participant")
	}
}

func TestResponsePressureIndexTracksTransfers(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 64 << 10, ProcessingReserveBytes: 16 << 10})
	p := responseParticipantForTest(t, b, 1)
	owners := []*ResponseParticipant{p}
	metadata := responseOwnedForTest(t, p, 64, ResponseMemoryQueueMetadata)
	input := responseOwnedForTest(t, p, 512, ResponseMemoryInflight)
	checkResponsePressureIndex(t, b, owners)
	if victim := selectPolicyVictim(b, time.Now(), 1); victim.Scanned != 0 {
		t.Fatal("metadata or inflight-only owner was scanned")
	}
	if !input.TryMove(ResponseMemoryOrdinary, ResponseMemoryQueuePayload) {
		t.Fatal("queue transfer failed")
	}
	checkResponsePressureIndex(t, b, owners)
	victim := selectPolicyVictim(b, time.Now(), 1)
	if victim.Participant != p || victim.Scanned != 1 {
		t.Fatal("queue owner was omitted from the index")
	}
	checkResponsePressureIndex(t, b, owners)
	victim.Cancel()
	checkResponsePressureIndex(t, b, owners)
	first, second, ok := b.TryReservePair(256, 256, ResponseMemoryProcessing, ResponseMemoryEncode)
	if !ok {
		t.Fatal("processing pair reservation failed")
	}
	t.Cleanup(first.Release)
	t.Cleanup(second.Release)
	if !first.TryMoveReplacing(ResponseMemoryOrdinary, ResponseMemoryOutput, input, second) {
		t.Fatal("output promotion failed")
	}
	checkResponsePressureIndex(t, b, owners)
	if !first.Shrink(64) || !first.TryMove(ResponseMemoryOrdinary, ResponseMemoryInflight) {
		t.Fatal("inflight transfer failed")
	}
	checkResponsePressureIndex(t, b, owners)
	if victim := selectPolicyVictim(b, time.Now(), 1); victim.Scanned != 0 {
		t.Fatal("output-to-inflight transfer retained a candidate")
	}
	if !first.TryMove(ResponseMemoryOrdinary, ResponseMemoryOutput) {
		t.Fatal("output transfer failed")
	}
	p.Detach()
	checkResponsePressureIndex(t, b, owners)
	metadata.Release()
	first.Release()
	checkResponsePressureIndex(t, b, owners)
	if b.Snapshot().UsedBytes != 0 {
		t.Fatal("retired participant retained charged bytes")
	}
}

// This oracle enumerates retained owners independently of the intrusive index
// and sorts by the documented policy. It does not mutate selection state.
func referenceResponsePressureVictim(b *ResponseBudget, owners []*ResponseParticipant, now time.Time, required int) ResponsePressureVictim {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := ResponsePressureVictim{Budget: b.snapshotLocked(), SelectedAt: now, RequiredAdditionalBytes: required}
	available := b.classLimits[ResponseMemoryOrdinary] - b.classes[ResponseMemoryOrdinary]
	if required > b.classLimits[ResponseMemoryOrdinary] || required <= available {
		return result
	}
	result.RequiredReclaimBytes = required - available
	result.FairShareBytes = b.classLimits[ResponseMemoryOrdinary] / max(1, b.backloggedParticipants)
	type candidate struct {
		p      *ResponseParticipant
		s      ResponseParticipantSnapshot
		fit    int
		queued int
		reason ResponsePressureSelectionReason
	}
	var candidates []candidate
	for _, p := range owners {
		if !p.registered || p.detached || p.pending || p.target == nil {
			continue
		}
		snapshot := p.snapshotLocked()
		queued := snapshot.StageBytes[ResponseMemoryQueuePayload] > 0
		if !queued && snapshot.OutputBytes == 0 {
			continue
		}
		result.Scanned++
		if !queued && b.asyncPressureEvictions != 0 {
			continue
		}
		entry := candidate{p: p, s: snapshot}
		if queued {
			entry.queued = 1
			if snapshot.QueuedBytes >= result.RequiredReclaimBytes {
				entry.fit = 1
			}
		}
		if snapshot.OrdinaryBytes > result.FairShareBytes {
			entry.reason = ResponsePressureAboveFairShare
		}
		if snapshot.UnreadBytes > 0 && !snapshot.ObservedAt.IsZero() && !snapshot.ObservedAt.After(now) &&
			now.Sub(snapshot.ObservedAt) <= responsePressureObservationAge && !snapshot.LastProgressAt.IsZero() &&
			now.Sub(snapshot.LastProgressAt) >= responsePressureStallAge {
			entry.reason = ResponsePressureStalled
		}
		candidates = append(candidates, entry)
	}
	slices.SortFunc(candidates, func(a, z candidate) int {
		return cmp.Or(cmp.Compare(z.fit, a.fit), cmp.Compare(z.queued, a.queued),
			cmp.Compare(z.reason, a.reason), cmp.Compare(z.s.OrdinaryBytes, a.s.OrdinaryBytes), cmp.Compare(a.s.ConnectionID, z.s.ConnectionID))
	})
	if len(candidates) != 0 {
		winner := candidates[0]
		result.Participant, result.Snapshot, result.Reason = winner.p, winner.s, winner.reason
		result.Snapshot.PendingEviction = true
	}
	return result
}

func TestResponsePressureIndexMatchesReferencePolicy(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 2 << 20, ProcessingReserveBytes: 256 << 10})
	rng := rand.New(rand.NewPCG(7, 13))
	var owners []*ResponseParticipant
	var allocations []*ResponseAllocation
	var selections []ResponsePressureVictim
	register := func() {
		p, ok := b.registerParticipant(int64(len(owners)+1), &responsePolicyTarget{budget: b, accept: rng.IntN(2) == 0})
		if !ok {
			t.Fatal("owner registration failed")
		}
		owners = append(owners, p)
	}
	for range 32 {
		register()
	}
	t.Cleanup(func() {
		for _, p := range owners {
			p.Detach()
		}
		for _, a := range allocations {
			a.Release()
		}
		if b.Snapshot().UsedBytes != 0 {
			t.Error("randomized lifecycle retained allocations")
		}
	})
	now := time.Unix(100, 0)
	for step := range 1200 {
		p := owners[rng.IntN(len(owners))]
		stage := ResponseMemoryStage(rng.IntN(int(responseMemoryStageCount)))
		class := ResponseMemoryClass(rng.IntN(2))
		var a *ResponseAllocation
		if len(allocations) != 0 {
			a = allocations[rng.IntN(len(allocations))]
		}
		switch rng.IntN(12) {
		case 0:
			register()
		case 1, 2:
			owner := p
			if rng.IntN(3) == 0 {
				owner = nil
			}
			if allocation, ok := b.TryReserveFor(owner, rng.IntN(4096), class, stage); ok {
				allocations = append(allocations, allocation)
			}
		case 3:
			if a != nil {
				a.TryMoveAtLeast(rng.IntN(1024), class, stage)
			}
		case 4:
			if a != nil {
				a.AssignOwner(p)
			}
		case 5:
			if a != nil {
				a.Shrink(rng.IntN(512))
			}
		case 6:
			a.Release()
		case 7:
			p.Detach()
		case 8:
			observed := now.Add(time.Duration(rng.IntN(5000)-2500) * time.Millisecond)
			p.ReportProgress(observed, observed.Add(-time.Duration(rng.IntN(5000))*time.Millisecond), rng.IntN(2)*1024, ResponseOutputClientBuffer)
		case 9:
			if len(selections) != 0 {
				v := selections[rng.IntN(len(selections))]
				if rng.IntN(2) == 0 {
					v.Cancel()
				} else {
					v.TryEvict()
				}
			}
		case 10:
			output, ok := b.TryReserve(256, ResponseMemoryProcessing, ResponseMemoryEncode)
			if ok {
				allocations = append(allocations, output)
				if !output.TryMoveReplacing(ResponseMemoryOrdinary, ResponseMemoryOutput, a) {
					output.Release()
				}
			}
		case 11:
			first, second, ok := b.TryReservePair(64, 64, ResponseMemoryProcessing, ResponseMemoryEncode)
			if ok {
				allocations = append(allocations, first, second)
				first.AssignOwner(p)
				first.TryMoveReplacing(ResponseMemoryOrdinary, stage, second)
			}
		}
		now = now.Add(10 * time.Millisecond)
		checkResponsePressureIndex(t, b, owners)
		snapshot := b.Snapshot()
		required := snapshot.OrdinaryLimitBytes - snapshot.ClassBytes[ResponseMemoryOrdinary] + rng.IntN(8192) - 1
		want := referenceResponsePressureVictim(b, owners, now, required)
		got := b.SelectPressureVictim(now, required)
		if got.Participant != want.Participant || got.Reason != want.Reason || got.Snapshot != want.Snapshot ||
			got.Scanned != want.Scanned || got.FairShareBytes != want.FairShareBytes || got.RequiredReclaimBytes != want.RequiredReclaimBytes || got.Budget != want.Budget {
			t.Fatalf("step %d: indexed selector differs from reference: got %+v, want %+v", step, got, want)
		}
		selections = append(selections, got)
		checkResponsePressureIndex(t, b, owners)
	}
}

func BenchmarkResponsePressureSelection(b *testing.B) {
	for _, scenario := range []struct {
		name     string
		owners   int
		eligible int
	}{
		{"all_100", 100, 100},
		{"all_1000", 1000, 1000},
		{"all_10000", 10000, 10000},
		{"sparse_100_of_10000", 10000, 100},
		{"sparse_1_of_10000", 10000, 1},
	} {
		b.Run(scenario.name, func(b *testing.B) {
			budget, err := NewResponseBudget(ResponseBudgetConfig{LimitBytes: 64 << 20})
			if err != nil {
				b.Fatal(err)
			}
			owners := make([]*ResponseParticipant, 0, scenario.owners)
			allocations := make([]*ResponseAllocation, 0, scenario.owners)
			target := &responsePolicyTarget{budget: budget, accept: true}
			for index := range scenario.owners {
				p, ok := budget.registerParticipant(int64(index+1), target)
				if !ok {
					b.Fatal("register owner")
				}
				owners = append(owners, p)
				stage := ResponseMemoryInflight
				if index < scenario.eligible {
					stage = ResponseMemoryQueuePayload
				}
				a, ok := budget.TryReserveFor(p, 4096, ResponseMemoryOrdinary, stage)
				if !ok {
					b.Fatal("reserve allocation")
				}
				allocations = append(allocations, a)
			}
			b.Cleanup(func() {
				for _, p := range owners {
					p.Detach()
				}
				for _, a := range allocations {
					a.Release()
				}
			})
			snapshot := budget.Snapshot()
			required := snapshot.OrdinaryLimitBytes - snapshot.ClassBytes[ResponseMemoryOrdinary] + 1
			now := time.Unix(100, 0)
			b.ReportAllocs()
			for b.Loop() {
				v := budget.SelectPressureVictim(now, required)
				if v.Participant == nil || v.Scanned != scenario.eligible {
					b.Fatal("selector scanned ineligible owners or missed a victim")
				}
				v.Cancel()
			}
			b.ReportMetric(float64(scenario.eligible), "scanned/op")
		})
	}
}
