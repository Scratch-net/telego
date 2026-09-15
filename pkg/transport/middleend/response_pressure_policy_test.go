package middleend

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type responsePolicyTarget struct {
	budget *ResponseBudget
	accept bool
	calls  atomic.Int32
}

type blockingResponsePolicyTarget struct {
	entered chan struct{}
	resume  chan struct{}
}

func (target *blockingResponsePolicyTarget) evictResponsePressure(responsePressureEvidence) bool {
	close(target.entered)
	<-target.resume
	return false
}

func (target *responsePolicyTarget) evictResponsePressure(responsePressureEvidence) bool {
	// This acquires the pool lock and proves callbacks run outside that lock.
	_ = target.budget.Snapshot()
	target.calls.Add(1)
	return target.accept
}

func responseParticipantForTest(t *testing.T, budget *ResponseBudget, id int64) *ResponseParticipant {
	t.Helper()
	p, ok := budget.registerParticipant(id, &responsePolicyTarget{budget: budget, accept: true})
	if !ok {
		t.Fatal("register participant")
	}
	t.Cleanup(p.Detach)
	return p
}

func responseOwnedForTest(t *testing.T, p *ResponseParticipant, capacity int, stage ResponseMemoryStage) *ResponseAllocation {
	t.Helper()
	a, ok := p.budget.TryReserveFor(p, capacity, ResponseMemoryOrdinary, stage)
	if !ok {
		t.Fatal("reserve participant allocation")
	}
	t.Cleanup(a.Release)
	return a
}

func selectPolicyVictim(b *ResponseBudget, now time.Time, deficit int) ResponsePressureVictim {
	snapshot := b.Snapshot()
	return b.SelectPressureVictim(now, snapshot.OrdinaryLimitBytes-snapshot.ClassBytes[ResponseMemoryOrdinary]+deficit)
}

func TestResponseParticipantTransferSurvivesDetachment(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192, ProcessingReserveBytes: 4096})
	p := responseParticipantForTest(t, b, 1)
	input := responseOwnedForTest(t, p, 128, ResponseMemoryQueuePayload)
	metadata := responseOwnedForTest(t, p, 64, ResponseMemoryQueueMetadata)
	if !input.TryMove(ResponseMemoryOrdinary, ResponseMemoryInflight) {
		t.Fatal("move dequeued allocation")
	}
	if snapshot := p.Snapshot(); snapshot.QueuedBytes != metadata.Bytes() || snapshot.InflightBytes != input.Bytes() {
		t.Fatalf("dequeued payload still reclaimable: %+v", snapshot)
	}
	metadata.Release()
	encoded := reserveResponseForTest(t, b, 128, ResponseMemoryProcessing, ResponseMemoryEncode)
	output := reserveResponseForTest(t, b, 128, ResponseMemoryProcessing, ResponseMemoryEncode)
	p.Detach()
	if p.target != nil || b.Snapshot().Participants != 1 {
		t.Fatal("detached participant retained manager target or lost inflight owner")
	}
	if !output.TryMoveReplacing(ResponseMemoryOrdinary, ResponseMemoryOutput, input, encoded) {
		t.Fatal("promote detached owner's last consumed allocation")
	}
	if output.owner != p || !p.registered || p.Snapshot().OutputBytes != output.Bytes() || p.Snapshot().QueuedBytes != 0 {
		t.Fatal("atomic replacement lost detached participant")
	}
	if !output.Shrink(64) || p.Snapshot().OutputBytes != ResponseAllocationCharge(64) {
		t.Fatal("shrink lost owner accounting")
	}
	output.Release()
	if snapshot := b.Snapshot(); snapshot.UsedBytes != 0 || snapshot.Participants != 0 || snapshot.Allocations != 0 {
		t.Fatalf("last output release retained historical owner: %+v", snapshot)
	}
}

func TestResponseParticipantRejectsConflictingOwnership(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	first := responseParticipantForTest(t, b, 1)
	second := responseParticipantForTest(t, b, 2)
	a := responseOwnedForTest(t, first, 64, ResponseMemoryQueuePayload)
	other := responseOwnedForTest(t, second, 64, ResponseMemoryQueuePayload)
	unowned := reserveResponseForTest(t, b, 64, ResponseMemoryOrdinary, ResponseMemoryOutput)
	defer unowned.Release()
	before := b.Snapshot()
	if unowned.TryMoveReplacing(ResponseMemoryOrdinary, ResponseMemoryOutput, a, other) || a.AssignOwner(second) {
		t.Fatal("transferred allocation between binding identities")
	}
	if before != b.Snapshot() || a.owner != first || other.owner != second {
		t.Fatal("failed transfer changed owner accounting")
	}
	assigned := unowned.AssignOwner(first)
	assignedAgain := unowned.AssignOwner(first)
	if !assigned || !assignedAgain {
		t.Fatal("adopt unowned allocation")
	}
	first.Detach()
	if _, ok := b.TryReserveFor(first, 1, ResponseMemoryOrdinary, ResponseMemoryQueuePayload); ok {
		t.Fatal("detached participant accepted new allocation")
	}
}

func TestResponseParticipantRegistryBoundAndEmptyVictims(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 3 * ResponseParticipantBytes})
	owners := make([]*ResponseParticipant, 0, 3)
	for id := range 3 {
		owners = append(owners, responseParticipantForTest(t, b, int64(id+1)))
	}
	if _, ok := b.registerParticipant(4, &responsePolicyTarget{budget: b}); ok {
		t.Fatal("registry escaped its charged metadata limit")
	}
	if victim := selectPolicyVictim(b, time.Now(), 1); victim.Participant != nil || victim.Scanned != 3 {
		t.Fatal("selected an empty healthy binding")
	}
	if snapshot := b.Snapshot(); snapshot.UsedBytes != 3*ResponseParticipantBytes || snapshot.StageBytes[ResponseMemoryOwnerMetadata] != snapshot.UsedBytes {
		t.Fatalf("registry metadata was not fully charged: %+v", snapshot)
	}
	for _, p := range owners {
		p.Detach()
	}
	if b.Snapshot().UsedBytes != 0 || b.participants != nil {
		t.Fatal("registry retained detached empty bindings")
	}
}

func TestResponsePressurePolicyProgressAndDeficitRanking(t *testing.T) {
	now := time.Unix(100, 0)
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 64 << 10})
	small := responseParticipantForTest(t, b, 1)
	large := responseParticipantForTest(t, b, 2)
	responseOwnedForTest(t, small, 512, ResponseMemoryQueuePayload)
	responseOwnedForTest(t, large, 4096, ResponseMemoryQueuePayload)
	small.ReportProgress(now.Add(-1500*time.Millisecond), time.Time{}, 256, ResponseOutputClientBuffer)
	small.ReportProgress(now, time.Time{}, 256, ResponseOutputClientBuffer)
	victim := selectPolicyVictim(b, now, 128)
	if victim.Participant != small || victim.Reason != ResponsePressureStalled {
		t.Fatalf("fresh stalled backlog not preferred: %+v", victim)
	}
	victim.Cancel()
	victim = selectPolicyVictim(b, now, 1024)
	if victim.Participant != large {
		t.Fatal("tiny stalled queue displaced a queue that covers the deficit")
	}
	victim.Cancel()
	victim = selectPolicyVictim(b, now.Add(3*time.Second), 128)
	if victim.Participant != large || victim.Reason == ResponsePressureStalled {
		t.Fatal("stale progress was treated as a stalled client")
	}
	victim.Cancel()
	small.ReportProgress(now.Add(time.Millisecond), time.Time{}, 128, ResponseOutputClientBuffer)
	victim = selectPolicyVictim(b, now.Add(2*time.Millisecond), 128)
	if victim.Participant != large {
		t.Fatal("partial output drain did not reset progress age")
	}
	victim.Cancel()
	small.ReportProgress(now.Add(3*time.Millisecond), time.Time{}, 0, ResponseOutputSharedBudget)
	small.ReportProgress(now.Add(4*time.Millisecond), now.Add(-time.Hour), 256, ResponseOutputClientBuffer)
	if last := small.Snapshot().LastProgressAt; !last.Equal(now.Add(4 * time.Millisecond)) {
		t.Fatalf("new backlog inherited old stalled timestamp: %v", last)
	}
	if victim := selectPolicyVictim(b, now.Add(5*time.Millisecond), 128); victim.Participant != large {
		t.Fatal("new output backlog was treated as an old stall")
	} else {
		victim.Cancel()
	}
}

func TestResponsePressurePolicyFairShareAndStableIdentity(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	first := responseParticipantForTest(t, b, 1)
	second := responseParticipantForTest(t, b, 2)
	responseOwnedForTest(t, first, 512, ResponseMemoryQueuePayload)
	responseOwnedForTest(t, second, 5000, ResponseMemoryQueuePayload)
	v := selectPolicyVictim(b, time.Now(), 64)
	if v.Participant != second || v.Reason != ResponsePressureAboveFairShare || v.FairShareBytes != 4096 {
		t.Fatalf("largest above fair share was not selected: %+v", v)
	}
	v.Cancel()
	other := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	lower := responseParticipantForTest(t, other, 1)
	higher := responseParticipantForTest(t, other, 2)
	responseOwnedForTest(t, lower, 512, ResponseMemoryQueuePayload)
	responseOwnedForTest(t, higher, 512, ResponseMemoryQueuePayload)
	if v := selectPolicyVictim(other, time.Now(), 1); v.Participant != lower {
		t.Fatal("equal victims were not ordered by stable connection identity")
	} else {
		v.Cancel()
	}
}

func TestResponsePressurePolicyOutputOnlyWaitsForActualRelease(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	first := responseParticipantForTest(t, b, 1)
	second := responseParticipantForTest(t, b, 2)
	output := responseOwnedForTest(t, first, 2048, ResponseMemoryOutput)
	responseOwnedForTest(t, second, 1024, ResponseMemoryOutput)
	before := b.Snapshot().UsedBytes
	v := selectPolicyVictim(b, time.Now(), 128)
	if v.Participant != first || !v.TryEvict() || v.TryEvict() {
		t.Fatal("output victim lifecycle callback was not invoked exactly once")
	}
	if b.Snapshot().UsedBytes != before {
		t.Fatal("asynchronous output closure was counted as free memory")
	}
	if another := selectPolicyVictim(b, time.Now(), 128); another.Participant != nil {
		t.Fatal("selected another output-only victim before actual reclamation")
	}
	output.Release()
	if first.Snapshot().PendingEviction || first.Snapshot().Detached {
		t.Fatal("drained output kept an active metadata-only victim pending")
	}
	if another := selectPolicyVictim(b, time.Now(), 128); another.Participant != second {
		t.Fatal("actual output release did not permit further pressure decisions")
	} else {
		another.Cancel()
	}
}

func TestResponsePressurePolicyStaleSelectionCannotCancelSuccessor(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	p := responseParticipantForTest(t, b, 1)
	responseOwnedForTest(t, p, 1024, ResponseMemoryQueuePayload)
	first := selectPolicyVictim(b, time.Now(), 1)
	first.Cancel()
	second := selectPolicyVictim(b, time.Now(), 1)
	first.Cancel()
	if first.TryEvict() || !second.TryEvict() || second.TryEvict() {
		t.Fatal("stale selection interfered with a later pressure decision")
	}
}

func TestResponsePressurePolicyCancelCannotReselectInvokedTarget(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	target := &blockingResponsePolicyTarget{entered: make(chan struct{}), resume: make(chan struct{})}
	unblock := sync.OnceFunc(func() { close(target.resume) })
	defer unblock()
	p, ok := b.registerParticipant(1, target)
	if !ok {
		t.Fatal("register blocking target")
	}
	defer p.Detach()
	responseOwnedForTest(t, p, 1024, ResponseMemoryQueuePayload)
	victim := selectPolicyVictim(b, time.Now(), 1)
	done := make(chan bool, 1)
	go func() { done <- victim.TryEvict() }()
	<-target.entered
	victim.Cancel()
	if again := selectPolicyVictim(b, time.Now(), 1); again.Participant != nil {
		t.Fatal("concurrent cancellation permitted a second lifecycle callback")
	}
	unblock()
	if <-done {
		t.Fatal("blocking target accepted eviction unexpectedly")
	}
	if p.Snapshot().PendingEviction {
		t.Fatal("failed callback did not clear its pending selection")
	}
	if again := selectPolicyVictim(b, time.Now(), 1); again.Participant != p {
		t.Fatal("failed lifecycle callback prevented a later selection")
	} else {
		again.Cancel()
	}
}

func TestResponsePressurePolicyRechecksAdmissionAfterRelease(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	p := responseParticipantForTest(t, b, 1)
	responseOwnedForTest(t, p, 1024, ResponseMemoryQueuePayload)
	ordinary := reserveResponseForTest(t, b, 4096, ResponseMemoryOrdinary, ResponseMemoryOutput)
	before := b.Snapshot()
	required := before.OrdinaryLimitBytes - before.ClassBytes[ResponseMemoryOrdinary] + 512
	ordinary.Release()
	if victim := b.SelectPressureVictim(time.Now(), required); victim.Participant != nil || victim.Scanned != 0 {
		t.Fatal("selected a victim after concurrent release made admission fit")
	}
	if victim := b.SelectPressureVictim(time.Now(), 0); victim.Participant != nil {
		t.Fatal("selected a victim for admission that needed no new capacity")
	}
	if victim := b.SelectPressureVictim(time.Now(), before.OrdinaryLimitBytes+1); victim.Participant != nil || victim.Scanned != 0 {
		t.Fatal("selected a victim for admission that can never fit the ordinary pool")
	}
}

func TestResponsePressurePolicyExcludesMetadataOnlyAndDetachedOwners(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	metadataOnly := responseParticipantForTest(t, b, 1)
	responseOwnedForTest(t, metadataOnly, 2048, ResponseMemoryQueueMetadata)
	active := responseParticipantForTest(t, b, 2)
	responseOwnedForTest(t, active, 1024, ResponseMemoryQueuePayload)
	detached := responseParticipantForTest(t, b, 3)
	responseOwnedForTest(t, detached, 2048, ResponseMemoryOutput)
	detached.Detach()
	if victim := selectPolicyVictim(b, time.Now(), 1); victim.Participant != active {
		t.Fatal("selected an empty metadata-only owner or detached output owner")
	} else {
		victim.Cancel()
	}
}

func TestResponsePressurePolicyExcludesInflightProcessingWait(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	p := responseParticipantForTest(t, b, 1)
	responseOwnedForTest(t, p, 4096, ResponseMemoryInflight)
	now := time.Unix(100, 0)
	p.ReportProgress(now.Add(-1500*time.Millisecond), time.Time{}, 0, ResponseOutputSharedBudget)
	p.ReportProgress(now, time.Time{}, 0, ResponseOutputSharedBudget)
	if victim := selectPolicyVictim(b, now, 1); victim.Participant != nil {
		t.Fatal("selected an owner with no queued or output allocation while processing its response")
	}
}

func TestResponseBudgetAtomicPairContention(t *testing.T) {
	const capacity = 1024
	charge := 2 * ResponseAllocationCharge(capacity)
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: charge + 1, ProcessingReserveBytes: charge})
	type result struct {
		first, second *ResponseAllocation
		ok            bool
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	for range 2 {
		group.Go(func() {
			<-start
			first, second, ok := b.TryReservePair(capacity, capacity, ResponseMemoryProcessing, ResponseMemoryEncode)
			results <- result{first, second, ok}
		})
	}
	close(start)
	group.Wait()
	close(results)
	winners := 0
	for result := range results {
		if result.ok {
			winners++
			if result.first == nil || result.second == nil {
				t.Fatal("admitted only part of an encoding operation")
			}
		} else if result.first != nil || result.second != nil {
			t.Fatal("rejected pair retained a partial reservation")
		}
		t.Cleanup(result.first.Release)
		t.Cleanup(result.second.Release)
	}
	if snapshot := b.Snapshot(); winners != 1 || snapshot.UsedBytes != charge || snapshot.Allocations != 2 {
		t.Fatalf("complete processing operation did not win: winners=%d snapshot=%+v", winners, snapshot)
	}
	before := b.Snapshot()
	if _, _, ok := b.TryReservePair(math.MaxInt, 1, ResponseMemoryProcessing, ResponseMemoryEncode); ok || before != b.Snapshot() {
		t.Fatal("invalid pair changed processing ownership")
	}
}

func TestResponseParticipantOrdinaryAdmissionCredit(t *testing.T) {
	b := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192, ProcessingReserveBytes: 4096})
	a := reserveResponseForTest(t, b, 256, ResponseMemoryProcessing, ResponseMemoryDecode)
	if a.OrdinaryBytes() != 0 {
		t.Fatal("processing allocation supplied ordinary admission credit")
	}
	if !a.TryMove(ResponseMemoryOrdinary, ResponseMemoryQueuePayload) || a.OrdinaryBytes() != a.Bytes() {
		t.Fatal("ordinary allocation did not supply its existing charge")
	}
	a.Release()
	if a.OrdinaryBytes() != 0 {
		t.Fatal("released allocation supplied ordinary credit")
	}
}

func BenchmarkResponsePressureRegistryScan(b *testing.B) {
	for _, size := range []struct {
		name  string
		count int
	}{{"20000", 20000}, {"ordinary_limit_detached", math.MaxInt}} {
		b.Run(size.name, func(b *testing.B) {
			budget, err := NewResponseBudget(ResponseBudgetConfig{LimitBytes: 64 << 20})
			if err != nil {
				b.Fatal(err)
			}
			target := &responsePolicyTarget{budget: budget, accept: true}
			var allocations []*ResponseAllocation
			for id := 1; id <= size.count; id++ {
				p, ok := budget.registerParticipant(int64(id), target)
				if !ok {
					break
				}
				a, ok := budget.TryReserveFor(p, 1, ResponseMemoryOrdinary, ResponseMemoryOutput)
				if !ok {
					p.Detach()
					break
				}
				allocations = append(allocations, a)
				if size.count == math.MaxInt {
					p.Detach()
				}
			}
			count := budget.Snapshot().Participants
			scanCount := count
			if size.count == math.MaxInt {
				scanCount = 0
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				victim := budget.SelectPressureVictim(time.Unix(100, 0), 64<<20)
				if victim.Scanned != scanCount {
					b.Fatal("registry scan retained historical owners or omitted active owners")
				}
				victim.Cancel()
			}
			b.StopTimer()
			b.ReportMetric(float64(count), "participants")
			for _, a := range allocations {
				p := a.owner
				p.Detach()
				a.Release()
			}
			if budget.Snapshot().UsedBytes != 0 {
				b.Fatal("benchmark retained owner metadata")
			}
		})
	}
}
