package middleend

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func newSlotRefreshTestManager(t *testing.T, slots []FixedBindingSlot, factory fixedBindingSlotRepair) *FixedBindingManager {
	t.Helper()
	manager, err := newFixedBindingManager(slots, fixedBindingTestLimits(), factory)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	return manager
}

func dueSlotRefreshes(manager *FixedBindingManager) {
	manager.state.mu.Lock()
	for _, slot := range manager.state.order {
		slot.unusedSince = time.Now().Add(-time.Minute)
		slot.refreshAfter = time.Now()
	}
	manager.state.mu.Unlock()
}

func refreshCandidateFactory(link ClientLink) fixedBindingSlotRepair {
	return func(_ context.Context, dcID DCID) (FixedBindingSlot, error) {
		return FixedBindingSlot{DCID: dcID, SourceIP: netip.MustParseAddr("8.8.8.8"), Link: link}, nil
	}
}

func candidatePing(t *testing.T, candidate *fixedBindingFakeLink) Ping {
	t.Helper()
	_, _, _, submissions, _ := candidate.stats()
	if len(submissions) != 1 {
		t.Fatalf("candidate submissions = %d, want one real ping", len(submissions))
	}
	return fixedBindingProbePing(t, submissions[0])
}

func TestSlotRefreshRequiresMatchingPongAndKeepsIncumbentReady(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, candidate := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(candidate))
		oldSlot := manager.state.slots[2]
		dueSlotRefreshes(manager)
		manager.state.refreshUnusedSlots(t.Context(), time.Now())
		synctest.Wait()
		ping := candidatePing(t, candidate)
		candidate.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID + 1})
		synctest.Wait()
		pending := manager.Snapshot()
		if pending.RefreshingSlots != 1 || !pending.Slots[0].Refreshing || pending.Slots[0].Repairing || pending.DCs[0].ReadySlots != 1 {
			t.Fatalf("candidate hid incumbent: %+v", pending)
		}
		if manager.state.slots[2] != oldSlot || channelClosed(old.Done()) {
			t.Fatal("unmatched pong retired incumbent")
		}
		candidate.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
		synctest.Wait()
		current := manager.state.slots[2]
		if current == oldSlot || current.link != candidate || !channelClosed(old.Done()) {
			t.Fatal("matching pong did not publish new physical slot identity")
		}
		if err := manager.state.probeSlot(t.Context(), 2, oldSlot); err != nil {
			t.Fatalf("captured retired probe: %v", err)
		}
		manager.state.failSlot(oldSlot, context.DeadlineExceeded, FixedBindingSlotFailureProbeTimeout)
		packet := []byte{1, 2, 3, 4}
		if err := manager.state.routeEvent(oldSlot, LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: 999, Packet: packet}); err != nil {
			t.Fatal(err)
		}
		if packet[0] != 0 {
			t.Fatal("retired packet was not cleared")
		}
		snapshot := manager.Snapshot()
		if snapshot.SlotFailures != 0 || snapshot.DCs[0].SlotRefreshSuccesses != 1 || snapshot.RefreshingSlots != 0 || snapshot.DCs[0].ZeroReadyTransitions != 0 {
			t.Fatalf("retired callback changed replacement: %+v", snapshot)
		}
		_, _, closes, _, _ := old.stats()
		if closes != 1 {
			t.Fatalf("old closes = %d, want 1", closes)
		}
	})
}

func TestSlotRefreshBindEpochRejectsCandidateAfterClientAlreadyClosed(t *testing.T) {
	for _, phase := range []string{"factory", "start", "pong"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				old, candidate := newFixedBindingFakeLink(), newFixedBindingFakeLink()
				gate := make(chan struct{})
				factory := refreshCandidateFactory(candidate)
				if phase == "start" {
					candidate.startGate = gate
				}
				if phase == "factory" {
					factory = func(ctx context.Context, dcID DCID) (FixedBindingSlot, error) {
						select {
						case <-gate:
							return refreshCandidateFactory(candidate)(ctx, dcID)
						case <-ctx.Done():
							return FixedBindingSlot{}, context.Cause(ctx)
						}
					}
				}
				manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, factory)
				dueSlotRefreshes(manager)
				manager.state.refreshUnusedSlots(t.Context(), time.Now())
				synctest.Wait()
				binding, err := manager.Bind(2)
				if err != nil || binding.state.slot.link != old {
					t.Fatalf("incumbent bind = %v", err)
				}
				if err := binding.Close(); err != nil {
					t.Fatal(err)
				}
				close(gate)
				synctest.Wait()
				candidate.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: candidatePing(t, candidate).ID})
				synctest.Wait()
				if manager.state.slots[2].link != old || channelClosed(old.Done()) || !channelClosed(candidate.Done()) {
					t.Fatal("bind-and-close was not detected at publication")
				}
				if snapshot := manager.Snapshot(); snapshot.DCs[0].SlotRefreshCanceled != 1 || snapshot.RefreshingSlots != 0 {
					t.Fatalf("canceled refresh snapshot = %+v", snapshot)
				}
			})
		})
	}
}

func TestSlotRefreshPreparationFailuresKeepIncumbentAndBackOff(t *testing.T) {
	for _, mode := range []string{"factory", "factory_owned_error", "start", "wrong_pong", "timeout", "peer_eof", "wrong_dc", "private_source", "nil_events"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				old, candidate := newFixedBindingFakeLink(), newFixedBindingFakeLink()
				failure := errors.New("candidate failed")
				if mode == "start" {
					candidate.startErr = failure
				}
				if mode == "nil_events" {
					candidate.events = nil
					// Keep a valid close implementation for this malformed link.
					candidate.onClose = func() { candidate.events = make(chan LinkEvent) }
				}
				calls := 0
				factory := func(_ context.Context, dcID DCID) (FixedBindingSlot, error) {
					calls++
					result := FixedBindingSlot{DCID: dcID, SourceIP: netip.MustParseAddr("8.8.8.8"), Link: candidate}
					switch mode {
					case "factory":
						return FixedBindingSlot{}, failure
					case "factory_owned_error":
						return result, failure
					case "wrong_dc":
						result.DCID = -dcID
					case "private_source":
						result.SourceIP = netip.MustParseAddr("127.0.0.1")
					}
					return result, nil
				}
				manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, factory)
				dueSlotRefreshes(manager)
				manager.state.refreshUnusedSlots(t.Context(), time.Now())
				synctest.Wait()
				if mode == "wrong_pong" {
					candidate.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: candidatePing(t, candidate).ID + 1})
				}
				if mode == "peer_eof" {
					candidate.peerClose(io.EOF)
				}
				if mode == "wrong_pong" || mode == "timeout" {
					time.Sleep(slotRefreshPreparationTimeout)
				}
				synctest.Wait()
				if channelClosed(old.Done()) || manager.state.slots[2].link != old {
					t.Fatal("failed candidate replaced incumbent")
				}
				if mode != "factory" {
					_, _, closes, _, _ := candidate.stats()
					if closes != 1 {
						t.Fatalf("candidate closes = %d, want 1", closes)
					}
				}
				manager.state.refreshUnusedSlots(t.Context(), time.Now())
				synctest.Wait()
				if calls != 1 {
					t.Fatalf("retry ignored positive backoff: %d calls", calls)
				}
				snapshot := manager.Snapshot()
				if snapshot.DCs[0].SlotRefreshFailures != 1 || snapshot.SlotFailures != 0 || snapshot.RefreshingSlots != 0 {
					t.Fatalf("candidate failure counters = %+v", snapshot)
				}
			})
		})
	}
}

func TestSlotRefreshBoundsAndFairnessAcrossTwelveDCs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var slots []FixedBindingSlot
		for dcID := DCID(1); dcID <= 12; dcID++ {
			for range 4 {
				slots = append(slots, FixedBindingSlot{DCID: dcID, Link: newFixedBindingFakeLink()})
			}
		}
		gate := make(chan struct{})
		var mu sync.Mutex
		calls := make(map[DCID]int)
		factory := &generationSlotRepairTestFactory{}
		manager := newSlotRefreshTestManager(t, slots, func(ctx context.Context, dcID DCID) (FixedBindingSlot, error) {
			mu.Lock()
			calls[dcID]++
			mu.Unlock()
			select {
			case <-gate:
				return factory.build(ctx, dcID)
			case <-ctx.Done():
				return FixedBindingSlot{}, context.Cause(ctx)
			}
		})
		dueSlotRefreshes(manager)
		var schedulers sync.WaitGroup
		for range 32 {
			schedulers.Go(func() { manager.state.refreshUnusedSlots(t.Context(), time.Now()) })
		}
		schedulers.Wait()
		synctest.Wait()
		if snapshot := manager.Snapshot(); snapshot.RefreshingSlots != 8 {
			t.Fatalf("blocked reservations = %d, want 8", snapshot.RefreshingSlots)
		}
		mu.Lock()
		if len(calls) != 8 {
			t.Errorf("reserved DCs = %d, want 8", len(calls))
		}
		for dcID, count := range calls {
			if count != 1 {
				t.Errorf("DC %d has %d simultaneous candidates", dcID, count)
			}
		}
		mu.Unlock()
		close(gate)
		synctest.Wait()
		manager.state.refreshUnusedSlots(t.Context(), time.Now())
		synctest.Wait()
		mu.Lock()
		if len(calls) != 12 {
			t.Errorf("round-robin scheduler reached %d DCs, want all 12", len(calls))
		}
		mu.Unlock()
		if snapshot := manager.Snapshot(); snapshot.RefreshingSlots != 0 || snapshot.SlotFailures != 0 || len(snapshot.Slots) != 48 {
			t.Fatalf("settled bounded refresh = %+v", snapshot)
		}
	})
}

func TestSlotRefreshQuiesceAndCloseJoinCandidate(t *testing.T) {
	for _, phase := range []string{"factory", "start", "pong", "close_factory", "close_start", "close_pong"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				old, candidate := newFixedBindingFakeLink(), newFixedBindingFakeLink()
				if phase == "start" || phase == "close_start" {
					candidate.startGate = make(chan struct{})
				}
				factory := refreshCandidateFactory(candidate)
				if phase == "factory" || phase == "close_factory" {
					factory = func(ctx context.Context, _ DCID) (FixedBindingSlot, error) {
						<-ctx.Done()
						return FixedBindingSlot{}, context.Cause(ctx)
					}
				}
				manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, factory)
				dueSlotRefreshes(manager)
				manager.state.refreshUnusedSlots(t.Context(), time.Now())
				synctest.Wait()
				if phase == "close_factory" || phase == "close_start" || phase == "close_pong" {
					if err := manager.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					drained := manager.Quiesce()
					synctest.Wait()
					if !channelClosed(drained) || channelClosed(old.Done()) {
						t.Fatal("quiescence did not join candidates while preserving incumbent")
					}
				}
				if phase != "factory" && phase != "close_factory" {
					_, _, closes, _, _ := candidate.stats()
					if closes != 1 {
						t.Fatalf("candidate closes = %d, want 1", closes)
					}
				}
				if snapshot := manager.Snapshot(); snapshot.RefreshingSlots != 0 || snapshot.DCs[0].SlotRefreshCanceled != 1 {
					t.Fatalf("quiesced snapshot = %+v", snapshot)
				}
				if err := manager.Close(); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestSlotRefreshRejectsOwnedFactoryAliasesBeforeStartOrClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newFixedBindingFakeLink()
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(nonComparableClientLink{old}))
		dueSlotRefreshes(manager)
		manager.state.refreshUnusedSlots(t.Context(), time.Now())
		synctest.Wait()
		starts, _, closes, _, _ := old.stats()
		if starts != 1 || closes != 0 || manager.Snapshot().DCs[0].SlotRefreshFailures != 1 {
			t.Fatalf("owned incumbent was touched: starts=%d closes=%d", starts, closes)
		}
	})
}

func TestSlotRefreshAndFailedRepairShareCandidateOwnership(t *testing.T) {
	for _, first := range []string{"refresh", "repair"} {
		t.Run(first, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				old, failed, candidate := newFixedBindingFakeLink(), newFixedBindingFakeLink(), newFixedBindingFakeLink()
				gate := make(chan struct{})
				if first == "repair" {
					candidate.startGate = gate
				}
				manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}, {DCID: 3, Link: failed}}, refreshCandidateFactory(candidate))
				failed.peerClose(io.EOF)
				synctest.Wait()
				dueSlotRefreshes(manager)
				repairDone := make(chan error, 1)
				if first == "refresh" {
					manager.state.refreshUnusedSlots(t.Context(), time.Now())
					synctest.Wait()
					if err := manager.state.repairFailedSlots(t.Context()); err == nil {
						t.Fatal("repair adopted an unpublished refresh candidate")
					}
				} else {
					go func() { repairDone <- manager.state.repairFailedSlots(t.Context()) }()
					synctest.Wait()
					manager.state.refreshUnusedSlots(t.Context(), time.Now())
					synctest.Wait()
				}
				starts, _, closes, _, _ := candidate.stats()
				if starts != 1 || closes != 0 {
					t.Fatalf("alias changed candidate ownership: starts=%d closes=%d", starts, closes)
				}
				if first == "refresh" {
					candidate.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: candidatePing(t, candidate).ID})
				} else {
					close(gate)
					if err := <-repairDone; err != nil {
						t.Fatal(err)
					}
				}
				synctest.Wait()
				if channelClosed(candidate.Done()) {
					t.Fatal("rejected alias closed the true owner's candidate")
				}
			})
		})
	}
}

func TestSlotRefreshLosesToFailedIncumbentRepair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, candidate, repaired := newFixedBindingFakeLink(), newFixedBindingFakeLink(), newFixedBindingFakeLink()
		var repair atomic.Bool
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, func(ctx context.Context, dcID DCID) (FixedBindingSlot, error) {
			if repair.Load() {
				return refreshCandidateFactory(repaired)(ctx, dcID)
			}
			return refreshCandidateFactory(candidate)(ctx, dcID)
		})
		dueSlotRefreshes(manager)
		manager.state.refreshUnusedSlots(t.Context(), time.Now())
		synctest.Wait()
		ping := candidatePing(t, candidate)
		old.peerClose(io.EOF)
		synctest.Wait()
		repair.Store(true)
		if err := manager.state.repairFailedSlots(t.Context()); err != nil {
			t.Fatal(err)
		}
		candidate.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
		synctest.Wait()
		snapshot := manager.Snapshot()
		if manager.state.slots[2].link != repaired || snapshot.Slots[0].Refreshing || snapshot.RefreshingSlots != 0 ||
			snapshot.SlotFailures != 1 || snapshot.DCs[0].SlotRefreshCanceled != 1 || !channelClosed(candidate.Done()) {
			t.Fatalf("refresh damaged independently repaired incumbent: %+v", snapshot)
		}
	})
}

func TestSlotRefreshRetirementPreservesEarlierPeerFailureOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newFixedBindingFakeLink()
		old.onClose = func() { old.peerClose(io.EOF) }
		factory := &generationSlotRepairTestFactory{}
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, factory.build)
		dueSlotRefreshes(manager)
		manager.state.refreshUnusedSlots(t.Context(), time.Now())
		synctest.Wait()
		snapshot := manager.Snapshot()
		if snapshot.SlotFailures != 1 || !snapshot.LastSlotFailure.PeerEOF || snapshot.LastSlotFailure.AffectedBindings != 0 ||
			snapshot.DCs[0].ZeroReadyTransitions != 0 || snapshot.DCs[0].SlotRefreshSuccesses != 1 || snapshot.Slots[0].Failed {
			t.Fatalf("peer terminal lost or applied to replacement: %+v", snapshot)
		}
		_, _, closes, _, _ := old.stats()
		if closes != 1 {
			t.Fatalf("retired peer failure caused %d closes, want 1", closes)
		}
	})
}

type refreshPendingSnapshotLink struct {
	*fixedBindingFakeLink
	pending atomic.Bool
}

func (l *refreshPendingSnapshotLink) Snapshot() LinkSnapshot {
	snapshot := l.fixedBindingFakeLink.Snapshot()
	if l.pending.Load() {
		snapshot.PendingSubmissions = 1
		snapshot.PendingSubmissionBytes = 32
	}
	return snapshot
}

func TestSlotRefreshRejectsPendingLinkWorkAtPublication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := &refreshPendingSnapshotLink{fixedBindingFakeLink: newFixedBindingFakeLink()}
		candidate := newFixedBindingFakeLink()
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(candidate))
		dueSlotRefreshes(manager)
		manager.state.refreshUnusedSlots(t.Context(), time.Now())
		synctest.Wait()
		old.pending.Store(true)
		candidate.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: candidatePing(t, candidate).ID})
		synctest.Wait()
		if channelClosed(old.Done()) || manager.state.slots[2].link != old || !channelClosed(candidate.Done()) {
			t.Fatal("retired link-owned work after manager queues drained")
		}
	})
}

func TestSlotRefreshRejectsEveryPendingManagerQueue(t *testing.T) {
	for _, queue := range []string{"resident", "request", "control", "response", "waiter", "outbound", "probe"} {
		t.Run(queue, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				old := newFixedBindingFakeLink()
				factory := &generationSlotRepairTestFactory{}
				manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, factory.build)
				dueSlotRefreshes(manager)
				manager.state.mu.Lock()
				slot := manager.state.slots[2]
				switch queue {
				case "resident":
					slot.resident = 1
				case "request":
					slot.requestItems, slot.requestBytes = 1, 1
				case "control":
					slot.controlItems, slot.controlBytes = 1, 1
				case "response":
					slot.pending, slot.bytes = 1, 1
				case "waiter":
					slot.waitHead = new(preparedRequest)
				case "outbound":
					slot.outHead = new(outboundItem)
				case "probe":
					slot.probe = new(fixedBindingProbe)
				}
				manager.state.mu.Unlock()
				manager.state.refreshUnusedSlots(t.Context(), time.Now())
				synctest.Wait()
				if len(factory.snapshotLinks()) != 0 {
					t.Errorf("refresh prepared over pending %s", queue)
				}
				manager.state.mu.Lock()
				slot.resident, slot.requestItems, slot.requestBytes, slot.controlItems, slot.controlBytes, slot.pending, slot.bytes = 0, 0, 0, 0, 0, 0, 0
				slot.waitHead, slot.outHead, slot.probe = nil, nil, nil
				manager.state.mu.Unlock()
			})
		})
	}
}

func TestGenerationSupervisorRefreshDoesNotWaitForStalledLivenessRound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pooled := newPooledGenerationTestManager(t, 2, true, true, true, true)
		replacements := &generationSlotRepairTestFactory{}
		pooled.manager.state.repairLink = replacements.build
		config := generationTestConfig()
		config.ProbeInterval, config.ProbeFailureTimeout = 5*time.Second, 100*time.Second
		supervisor := newGenerationTestSupervisor(t, config)
		if err := supervisor.Start(t.Context(), func(context.Context) (*FixedBindingManager, error) { return pooled.manager, nil }); err != nil {
			t.Fatal(err)
		}
		pooled.responds[0].Store(false)
		time.Sleep(75 * time.Second)
		synctest.Wait()
		if got := len(replacements.snapshotLinks()); got != 3 {
			t.Fatalf("refreshes during stalled 100s round = %d, want 3 healthy siblings", got)
		}
		pooled.manager.state.mu.Lock()
		pending := pooled.manager.state.order[0].probe != nil
		pooled.manager.state.mu.Unlock()
		if !pending || supervisor.Snapshot().SlotFailures != 0 {
			t.Fatal("liveness did not remain in its original bounded probe")
		}
	})
}

func TestSlotRefreshCompletedProbeDeadlineDoesNotFailLink(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 2, Link: link})
	probe := &fixedBindingProbe{slot: manager.state.slots[2], done: make(chan struct{})}
	manager.state.mu.Lock()
	manager.state.completeProbeLocked(probe, nil)
	manager.state.mu.Unlock()
	// This is the cancellation arm after both channels become ready. Calling
	// that arm directly fixes the select order without a probabilistic race.
	if err := manager.state.cancelProbe(probe, context.DeadlineExceeded); err != nil {
		t.Fatalf("completed probe cancellation = %v", err)
	}
	if snapshot := manager.Snapshot(); snapshot.SlotFailures != 0 || snapshot.Slots[0].Failed || channelClosed(link.Done()) {
		t.Fatalf("completed pong became a false timeout: %+v", snapshot)
	}
}

func TestSlotRefreshFailureCleanupCannotCloseConcurrentRepair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, repaired := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(repaired))
		observerEntered, observerRelease := make(chan struct{}), make(chan struct{})
		var observeOnce sync.Once
		manager.state.slotFailureObserver = func(FixedBindingSlotFailureSnapshot) {
			observeOnce.Do(func() {
				close(observerEntered)
				<-observerRelease
			})
		}
		failureDone := make(chan struct{})
		go func() {
			manager.state.failSlot(manager.state.slots[2], io.EOF, FixedBindingSlotFailureLinkTerminal)
			close(failureDone)
		}()
		<-observerEntered
		old.peerClose(io.EOF)
		synctest.Wait()
		if err := manager.state.repairFailedSlots(t.Context()); err != nil {
			t.Fatal(err)
		}
		close(observerRelease)
		<-failureDone
		synctest.Wait()
		if channelClosed(repaired.Done()) || manager.Snapshot().Slots[0].Failed {
			t.Fatal("old failure cleanup closed the repaired physical incarnation")
		}
	})
}

func TestSlotRefreshOldFailedProbeDeadlineCannotFailRepair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, repaired := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(repaired))
		probeResult := make(chan error, 1)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() { probeResult <- manager.Probe(ctx, 2) }()
		synctest.Wait()
		manager.state.mu.Lock()
		probe := manager.state.slots[2].probe
		manager.state.mu.Unlock()
		if probe == nil {
			t.Fatal("probe did not begin")
		}
		old.peerClose(io.EOF)
		synctest.Wait()
		if err := <-probeResult; !errors.Is(err, io.EOF) {
			t.Fatalf("old probe failure = %v", err)
		}
		if err := manager.state.repairFailedSlots(t.Context()); err != nil {
			t.Fatal(err)
		}
		// Reproduce the delayed cancellation arm with the exact completed probe.
		_ = manager.state.cancelProbe(probe, context.DeadlineExceeded)
		synctest.Wait()
		if channelClosed(repaired.Done()) || manager.Snapshot().SlotFailures != 1 {
			t.Fatal("old failed probe deadline failed the repaired incarnation")
		}
	})
}

type refreshSnapshotWindowLink struct {
	*fixedBindingFakeLink
	manager *fixedBindingManager
	exposed atomic.Bool
}

func (l *refreshSnapshotWindowLink) Snapshot() LinkSnapshot {
	snapshot := l.fixedBindingFakeLink.Snapshot()
	if l.manager != nil && l.manager.mu.TryLock() {
		// A close control can be accepted after this snapshot but before a
		// later manager queue check unless the publication lock excludes it.
		l.exposed.Store(true)
		l.manager.mu.Unlock()
	}
	return snapshot
}

func TestSlotRefreshLinkSnapshotAndManagerQueuesSharePublicationLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := &refreshSnapshotWindowLink{fixedBindingFakeLink: newFixedBindingFakeLink()}
		factory := &generationSlotRepairTestFactory{}
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, factory.build)
		old.manager = manager.state
		dueSlotRefreshes(manager)
		manager.state.refreshUnusedSlots(t.Context(), time.Now())
		synctest.Wait()
		if old.exposed.Load() || !channelClosed(old.Done()) || manager.Snapshot().DCs[0].SlotRefreshSuccesses != 1 {
			t.Fatal("link and manager queue checks allowed an intervening submission")
		}
	})
}

func TestSlotRefreshInitialAdmissionFailureIsNotZeroReadyLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		candidate := newGenerationTestManager(t, []DCID{2}, false)
		config := generationTestConfig()
		config.PreparationTimeout = time.Second
		supervisor := newGenerationTestSupervisor(t, config)
		_, err := supervisor.state.prepareGeneration(t.Context(), func(context.Context) (*FixedBindingManager, error) {
			return candidate.manager, nil
		})
		if err == nil {
			t.Fatal("initial admission unexpectedly succeeded")
		}
		for _, dc := range supervisor.Snapshot().DCs {
			if dc.ZeroReadyTransitions != 0 {
				t.Fatalf("unpublished startup candidate reported %d zero-ready transitions", dc.ZeroReadyTransitions)
			}
		}
		if supervisor.Snapshot().SlotFailures != 1 {
			t.Fatal("startup exclusion erased the actual physical-link failure")
		}
	})
}

func TestSlotRefreshCoverageActivationSharesPublicationBoundary(t *testing.T) {
	for _, failBeforePublication := range []bool{false, true} {
		name := "failure after publication counts"
		if failBeforePublication {
			name = "failed unpublished candidate is rejected"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				prepared := newGenerationTestManager(t, []DCID{2}, true)
				supervisor := newGenerationTestSupervisor(t, generationTestConfig())
				candidate, err := supervisor.state.prepareGeneration(t.Context(), func(context.Context) (*FixedBindingManager, error) { return prepared.manager, nil })
				if err != nil {
					t.Fatal(err)
				}
				if failBeforePublication {
					prepared.links[2].peerClose(io.EOF)
					synctest.Wait()
				}
				supervisor.state.mu.Lock()
				published := supervisor.state.publishGenerationLocked(candidate, nil)
				supervisor.state.mu.Unlock()
				if failBeforePublication {
					if published {
						t.Fatal("published an already zero-ready pool")
					}
					supervisor.state.closeGeneration(candidate)
				} else {
					if !published {
						t.Fatal("healthy prepared candidate was not published")
					}
					prepared.links[2].peerClose(io.EOF)
					synctest.Wait()
				}
				var transitions uint64
				for _, dc := range supervisor.Snapshot().DCs {
					transitions += dc.ZeroReadyTransitions
				}
				want := uint64(1)
				if failBeforePublication {
					want = 0
				}
				if transitions != want {
					t.Fatalf("publication transitions = %d, want %d", transitions, want)
				}
			})
		})
	}
}

func TestGenerationSupervisorRefreshesUnusedSlotsBeforePeerExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pooled := newPooledGenerationTestManager(t, 2, true, true, true, true)
		replacements := &generationSlotRepairTestFactory{}
		pooled.manager.state.repairLink = replacements.build
		config := generationTestConfig()
		config.ProbeInterval = 5 * time.Second
		config.ProbeFailureTimeout = 100 * time.Second
		supervisor := newGenerationTestSupervisor(t, config)
		if err := supervisor.Start(t.Context(), func(context.Context) (*FixedBindingManager, error) {
			return pooled.manager, nil
		}); err != nil {
			t.Fatal(err)
		}

		// All four incumbent links answer liveness probes. No client request is
		// necessary to prove proactive replacement before the observed 90s EOF.
		time.Sleep(75 * time.Second)
		synctest.Wait()
		if got := len(replacements.snapshotLinks()); got < 4 {
			t.Fatalf("unused slots refreshed = %d, want at least 4 before 90s peer expiry", got)
		}
		snapshot := supervisor.Snapshot()
		if !snapshot.Admitting || snapshot.SlotFailures != 0 || len(snapshot.Active.Slots) != 4 {
			t.Fatalf("refresh changed admitted coverage: %+v", snapshot)
		}
		for _, slot := range snapshot.Active.Slots {
			if slot.Failed || slot.Repairing || slot.Link.State != LinkStateReady {
				t.Fatalf("refreshed slot is unavailable: %+v", slot)
			}
		}
	})
}
