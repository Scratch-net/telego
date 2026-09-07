package middleend

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func retirementTestConfig() GenerationSupervisorConfig {
	config := generationTestConfig()
	config.ProbeInterval = time.Second
	config.ProbeFailureTimeout = 5 * time.Second
	return config
}

func generationManagerFactory(manager *FixedBindingManager) FixedBindingGenerationFactory {
	return func(context.Context) (*FixedBindingManager, error) { return manager, nil }
}

func TestRetirementClosesEmptyOrdinalWithoutFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newPooledGenerationTestManager(t, 1, true, true)
		next := newGenerationTestManager(t, []DCID{1}, true)
		repairs := &generationSlotRepairTestFactory{}
		old.manager.state.repairLink = repairs.build
		supervisor := newGenerationTestSupervisor(t, retirementTestConfig())
		if err := supervisor.Start(t.Context(), generationManagerFactory(old.manager)); err != nil {
			t.Fatal(err)
		}
		binding, err := supervisor.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := supervisor.Rotate(t.Context(), generationManagerFactory(next.manager)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if !channelClosed(old.links[1].Done()) || channelClosed(old.links[0].Done()) {
			t.Fatal("empty ordinal did not close independently of the bound ordinal")
		}
		if snapshot := supervisor.Snapshot(); snapshot.SlotFailures != 0 || snapshot.LastForcedRetirement.Sequence != 0 || len(repairs.snapshotLinks()) != 0 {
			t.Fatalf("intentional cleanup counted failure or started replacement: %+v", snapshot)
		}
		if len(old.links[0].attemptedSubmissions()) < 3 {
			t.Fatal("bound retiring ordinal stopped probing")
		}
		if err := binding.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRetirementProbeRetriesAfterControlBackpressure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newGenerationTestManager(t, []DCID{1}, true)
		next := newGenerationTestManager(t, []DCID{1}, true)
		supervisor := newGenerationTestSupervisor(t, retirementTestConfig())
		if err := supervisor.Start(t.Context(), generationManagerFactory(old.manager)); err != nil {
			t.Fatal(err)
		}
		binding, err := supervisor.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := supervisor.Rotate(t.Context(), generationManagerFactory(next.manager)); err != nil {
			t.Fatal(err)
		}
		// Hold the sole control item with a stale-connection close. The bound
		// client's next periodic PING receives manager admission pressure.
		old.links[1].setTryError(ErrLinkBackpressure)
		old.links[1].emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 999999})
		synctest.Wait()
		old.manager.state.mu.Lock()
		old.manager.state.limits.MaxPendingControlItemsPerSlot = 1
		old.manager.state.mu.Unlock()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if snapshot := supervisor.Snapshot(); snapshot.SlotFailures != 0 || !errors.Is(snapshot.LastError, ErrFixedBindingControlBackpressure) {
			t.Fatalf("retiring probe pressure = %+v", snapshot)
		}
		before := len(old.links[1].attemptedSubmissions())
		old.links[1].setTryError(nil)
		old.links[1].ready <- struct{}{}
		synctest.Wait()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if after := len(old.links[1].attemptedSubmissions()); after < before+3 {
			t.Fatalf("retiring PINGs did not resume after control release: %d -> %d", before, after)
		}
		if err := binding.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRetirementStalledProbeDoesNotStopHealthySiblingOrRepair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newPooledGenerationTestManager(t, 1, true, true)
		next := newGenerationTestManager(t, []DCID{1}, true)
		repairs := &generationSlotRepairTestFactory{}
		old.manager.state.repairLink = repairs.build
		supervisor := newGenerationTestSupervisor(t, retirementTestConfig())
		if err := supervisor.Start(t.Context(), generationManagerFactory(old.manager)); err != nil {
			t.Fatal(err)
		}
		failed, err := supervisor.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		healthy, err := supervisor.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := supervisor.Rotate(t.Context(), generationManagerFactory(next.manager)); err != nil {
			t.Fatal(err)
		}
		old.responds[0].Store(false)
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if len(old.links[1].attemptedSubmissions()) < 3 || old.manager.Snapshot().Slots[0].Failed {
			t.Fatal("healthy sibling lost PINGs while retired probe remained pending")
		}
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if snapshot := supervisor.Snapshot(); snapshot.SlotFailures != 1 || len(repairs.snapshotLinks()) != 0 || snapshot.SlotRepairFailures != 0 {
			t.Fatalf("retiring failed ordinal started repair: %+v", snapshot)
		}
		if _, err := failed.NextEvent(t.Context()); !errors.Is(err, ErrFixedBindingSlotFailed) {
			t.Fatalf("failed retired binding = %v", err)
		}
		if err := healthy.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRetirementFailedActiveKeepsHealthyRemainderWithoutDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newPooledGenerationTestManager(t, 1, true, true)
		next := newGenerationTestManager(t, []DCID{1}, true)
		factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: old.manager}, {manager: next.manager}}}
		supervisor := newGenerationTestSupervisor(t, retirementTestConfig())
		if err := supervisor.Start(t.Context(), factory.build); err != nil {
			t.Fatal(err)
		}
		failed, err := supervisor.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		healthy, err := supervisor.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		old.links[0].peerClose(io.EOF)
		synctest.Wait()
		if _, err := failed.NextEvent(t.Context()); !errors.Is(err, ErrFixedBindingSlotFailed) {
			t.Fatalf("failed binding = %v", err)
		}
		time.Sleep(3 * time.Minute)
		synctest.Wait()
		if snapshot := supervisor.Snapshot(); !snapshot.Admitting || snapshot.Retiring == nil || snapshot.LastForcedRetirement.Sequence != 0 {
			t.Fatalf("failed active's healthy remainder did not survive natural retirement: %+v", snapshot)
		}
		if len(old.links[1].attemptedSubmissions()) < 90 {
			t.Fatal("failed active's healthy remainder stopped originating PINGs")
		}
		old.links[1].emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: healthy.ConnectionID(), ConfirmKey: 19})
		if event, err := healthy.NextEvent(t.Context()); err != nil || event.ConfirmKey != 19 {
			t.Fatalf("healthy old response: %+v, %v", event, err)
		}
		if err := healthy.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRetirementQuiesceCancelsAndJoinsRepairCandidate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, candidate := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 1, Link: old}}, refreshCandidateFactory(candidate))
		old.peerClose(io.EOF)
		synctest.Wait()
		closeEntered, releaseClose := make(chan struct{}), make(chan struct{})
		candidate.onClose = func() { close(closeEntered); <-releaseClose }
		result := make(chan error, 1)
		go func() { result <- manager.state.repairFailedSlots(t.Context()) }()
		synctest.Wait()
		candidatePing(t, candidate)
		manager.Quiesce()
		<-closeEntered
		closed := make(chan error, 1)
		go func() { closed <- manager.Close() }()
		synctest.Wait()
		if channelClosed(manager.Done()) {
			t.Fatal("manager completed before canceled repair ownership was released")
		}
		if attempted, err := manager.state.repairFailedSlot(t.Context(), manager.state.slots[1]); attempted || err != nil {
			t.Fatalf("retired repair was claimed: %t, %v", attempted, err)
		}
		close(releaseClose)
		if err := <-result; !errors.Is(err, ErrFixedBindingManagerQuiesced) {
			t.Fatalf("canceled candidate result = %v", err)
		}
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if snapshot := manager.Snapshot(); snapshot.SlotRepairSuccesses != 0 || snapshot.SlotRepairFailures != 0 || snapshot.RepairingSlots != 0 {
			t.Fatalf("intentional cancellation counted repair failure: %+v", snapshot)
		}
	})
}

func TestRetirementCapacityFailurePreservesActiveAndTerminalToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newGenerationTestManager(t, []DCID{1}, true)
		current := newGenerationTestManager(t, []DCID{1}, true)
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		if err := supervisor.Start(t.Context(), generationManagerFactory(old.manager)); err != nil {
			t.Fatal(err)
		}
		binding, err := supervisor.BindReady(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := supervisor.Rotate(t.Context(), generationManagerFactory(current.manager)); err != nil {
			t.Fatal(err)
		}
		failure := errors.New("third candidate rejected")
		if err := supervisor.Rotate(t.Context(), func(context.Context) (*FixedBindingManager, error) {
			if !channelClosed(old.manager.Done()) {
				t.Error("oldest manager not joined before third construction")
			}
			return nil, failure
		}); !errors.Is(err, failure) {
			t.Fatalf("candidate result = %v", err)
		}
		synctest.Wait()
		if supervisor.state.active.manager != current.manager || !supervisor.Snapshot().Admitting {
			t.Fatal("candidate failure changed healthy active generation")
		}
		token := supervisor.TryNextReady()
		if token == nil || token.ConnectionID() != binding.ConnectionID() {
			t.Fatal("capacity retirement lost terminal readiness token")
		}
		if _, terminal, err := token.TryTerminal(); err != nil || !terminal {
			t.Fatalf("capacity token did not deliver terminal notification: %t, %v", terminal, err)
		}
		if err := token.Ack(); err != nil {
			t.Fatal(err)
		}
		if snapshot := supervisor.Snapshot(); snapshot.SlotFailures != 0 || snapshot.LastForcedRetirement.AffectedBindings != 1 || snapshot.LastForcedRetirement.Sequence != 1 {
			t.Fatalf("capacity counters = %+v", snapshot)
		}
	})
}

func TestRetirementCanceledRotationCannotEvict(t *testing.T) {
	old := newGenerationTestManager(t, []DCID{1}, true)
	current := newGenerationTestManager(t, []DCID{1}, true)
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), generationManagerFactory(old.manager)); err != nil {
		t.Fatal(err)
	}
	binding, err := supervisor.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Rotate(t.Context(), generationManagerFactory(current.manager)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var builds atomic.Int32
	supervisor.state.transitions.Lock()
	entered, result := make(chan struct{}), make(chan error, 1)
	go func() {
		close(entered)
		result <- supervisor.Rotate(ctx, func(context.Context) (*FixedBindingManager, error) {
			builds.Add(1)
			return nil, errGenerationTestFactoryExhausted
		})
	}()
	<-entered
	cancel()
	supervisor.state.transitions.Unlock()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled rotation = %v", err)
	}
	if builds.Load() != 0 || channelClosed(old.manager.Done()) || supervisor.Snapshot().LastForcedRetirement.Sequence != 0 {
		t.Fatal("canceled rotation evicted or constructed a candidate")
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRetirementTerminalClaimCountsOnlyNewInterruptionOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		live, err := manager.BindReady(1)
		if err != nil {
			t.Fatal(err)
		}
		closing, err := manager.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		terminal, err := manager.BindReady(1)
		if err != nil {
			t.Fatal(err)
		}
		manager.state.terminalizeBinding(terminal.state, io.EOF)
		link.setTryError(ErrLinkBackpressure)
		closing.BeginClose()
		synctest.Wait()
		var winners atomic.Int32
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(func() {
				if record, won := manager.state.beginForcedRetirement(GenerationRetirementArtifactCapacity); won {
					winners.Add(1)
					if record.AffectedBindings != 1 {
						t.Errorf("newly interrupted bindings = %d, want only %d", record.AffectedBindings, live.ConnectionID())
					}
				}
			})
		}
		workers.Wait()
		if winners.Load() != 1 {
			t.Fatalf("winning capacity claims = %d", winners.Load())
		}
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRetirementIdleOrdinalWaitsForOwnedWork(t *testing.T) {
	for _, pending := range []string{"request", "control", "response", "probe", "engine_submission", "refresh"} {
		t.Run(pending, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				link := &refreshPendingSnapshotLink{fixedBindingFakeLink: newFixedBindingFakeLink()}
				manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
				manager.Quiesce()
				m := manager.state
				m.mu.Lock()
				slot := m.slots[1]
				switch pending {
				case "request":
					slot.requestItems, slot.requestBytes = 1, 32
				case "control":
					slot.controlItems, slot.controlBytes = 1, KeepalivePayloadSize
				case "response":
					slot.pending, slot.bytes = 1, 32
				case "probe":
					slot.probe = &fixedBindingProbe{}
				case "engine_submission":
					link.pending.Store(true)
				case "refresh":
					slot.refreshing = true
				}
				m.mu.Unlock()
				if m.retireUnusedSlot(slot) || channelClosed(link.Done()) {
					t.Fatal("idle cleanup abandoned owned work")
				}
				m.mu.Lock()
				slot.requestItems, slot.requestBytes, slot.controlItems, slot.controlBytes, slot.pending, slot.bytes = 0, 0, 0, 0, 0, 0
				slot.probe = nil
				slot.refreshing = false
				link.pending.Store(false)
				m.mu.Unlock()
				if !m.retireUnusedSlot(slot) || !channelClosed(link.Done()) {
					t.Fatal("empty ordinal did not retire after ownership cleared")
				}
				if snapshot := manager.Snapshot(); snapshot.SlotFailures != 0 {
					t.Fatalf("orderly cleanup counted physical failure: %+v", snapshot)
				}
			})
		})
	}
}

func TestRetirementIdleOrdinalCleanupJoinsBeforeManagerDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		manager.Quiesce()
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		link.onClose = func() { once.Do(func() { close(entered); <-release }) }
		retired := make(chan bool, 1)
		go func() { retired <- manager.state.retireUnusedSlot(manager.state.slots[1]) }()
		<-entered
		closed := make(chan error, 1)
		go func() { closed <- manager.Close() }()
		synctest.Wait()
		if channelClosed(manager.Done()) {
			t.Fatal("manager completed before idle-link cleanup joined")
		}
		close(release)
		if !<-retired {
			t.Fatal("empty ordinal cleanup was not claimed")
		}
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	})
}

func TestRetirementIdleOrdinalRetainsPeerFailureThatWinsClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		manager.Quiesce()
		link.onClose = func() { link.peerClose(io.EOF) }
		if !manager.state.retireUnusedSlot(manager.state.slots[1]) {
			t.Fatal("empty ordinal did not enter cleanup")
		}
		if snapshot := manager.Snapshot(); snapshot.SlotFailures != 1 || !errors.Is(snapshot.LastSlotFailure.Error, io.EOF) || snapshot.SlotFailureAffectedBindings != 0 {
			t.Fatalf("peer failure winning orderly cleanup = %+v", snapshot)
		}
	})
}

func TestRetirementNaturalCloseWinsCapacityClaim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newGenerationTestManager(t, []DCID{1}, true)
		current := newGenerationTestManager(t, []DCID{1}, true)
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		if err := supervisor.Start(t.Context(), generationManagerFactory(old.manager)); err != nil {
			t.Fatal(err)
		}
		binding, err := supervisor.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := supervisor.Rotate(t.Context(), generationManagerFactory(current.manager)); err != nil {
			t.Fatal(err)
		}
		retiring := supervisor.state.retiring
		entered, release := make(chan struct{}), make(chan struct{})
		old.links[1].onClose = func() { close(entered); <-release }
		if err := binding.Close(); err != nil {
			t.Fatal(err)
		}
		<-entered
		forced := make(chan struct{})
		go func() {
			supervisor.state.forceRetireGeneration(retiring, GenerationRetirementArtifactCapacity)
			close(forced)
		}()
		synctest.Wait()
		if snapshot := supervisor.Snapshot(); snapshot.LastForcedRetirement.Sequence != 0 {
			t.Fatalf("natural terminal claim was recounted as capacity retirement: %+v", snapshot.LastForcedRetirement)
		}
		close(release)
		<-forced
	})
}

func TestRetirementShutdownWinsCapacityClaim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newGenerationTestManager(t, []DCID{1}, true)
		current := newGenerationTestManager(t, []DCID{1}, true)
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		if err := supervisor.Start(t.Context(), generationManagerFactory(old.manager)); err != nil {
			t.Fatal(err)
		}
		if _, err := supervisor.Bind(1); err != nil {
			t.Fatal(err)
		}
		if err := supervisor.Rotate(t.Context(), generationManagerFactory(current.manager)); err != nil {
			t.Fatal(err)
		}
		retiring := supervisor.state.retiring
		entered, release := make(chan struct{}), make(chan struct{})
		old.links[1].onClose = func() { close(entered); <-release }
		closed := make(chan error, 1)
		go func() { closed <- supervisor.Close() }()
		<-entered
		forced := make(chan struct{})
		go func() {
			supervisor.state.forceRetireGeneration(retiring, GenerationRetirementArtifactCapacity)
			close(forced)
		}()
		synctest.Wait()
		if snapshot := supervisor.Snapshot(); snapshot.LastForcedRetirement.Sequence != 0 {
			t.Fatalf("shutdown was counted as capacity retirement: %+v", snapshot.LastForcedRetirement)
		}
		close(release)
		<-forced
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	})
}

func TestRetirementApplyDoesNotAcknowledgeTerminalManagerBeforeWatcher(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newGenerationTestManager(t, []DCID{1}, true)
		next := newGenerationTestManager(t, []DCID{1}, true)
		factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: old.manager}, {manager: next.manager}}}
		plan := &generationFactoryPlan{build: factory.build}
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		if published, err := supervisor.applyFactory(t.Context(), plan); err != nil || !published {
			t.Fatalf("initial application = %t, %v", published, err)
		}
		generation := supervisor.state.active
		entered, release := make(chan struct{}), make(chan struct{})
		old.links[1].onClose = func() { close(entered); <-release }
		old.manager.state.beginTerminal(nil)
		<-entered
		if generation.failed.Load() || channelClosed(old.manager.Done()) {
			t.Fatal("test did not hold the terminal manager before its failure watcher")
		}
		published, err := supervisor.applyFactory(t.Context(), plan)
		close(release)
		if err != nil || !published || supervisor.state.active.manager != next.manager {
			t.Fatalf("terminal manager was acknowledged instead of recovered: %t, %v", published, err)
		}
	})
}

func TestRetirementConcurrentCapacityCallsCountOneTransition(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newGenerationTestManager(t, []DCID{1}, true)
		current := newGenerationTestManager(t, []DCID{1}, true)
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		if err := supervisor.Start(t.Context(), generationManagerFactory(old.manager)); err != nil {
			t.Fatal(err)
		}
		if _, err := supervisor.Bind(1); err != nil {
			t.Fatal(err)
		}
		if err := supervisor.Rotate(t.Context(), generationManagerFactory(current.manager)); err != nil {
			t.Fatal(err)
		}
		retiring := supervisor.state.retiring
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(func() { supervisor.state.forceRetireGeneration(retiring, GenerationRetirementArtifactCapacity) })
		}
		workers.Wait()
		snapshot := supervisor.Snapshot()
		if snapshot.LastForcedRetirement.Sequence != 1 || snapshot.LastForcedRetirement.AffectedBindings != 1 || snapshot.ForcedRetirements[0].Retirements != 1 || snapshot.ForcedRetirements[0].AffectedBindings != 1 || snapshot.SlotFailures != 0 {
			t.Fatalf("duplicate capacity accounting = %+v", snapshot)
		}
	})
}

func TestRetirementPublicationQuiescesBeforeRoleVisible(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newPooledGenerationTestManager(t, 1, true, true)
		next := newGenerationTestManager(t, []DCID{1}, true)
		replacement := newFixedBindingFakeLink()
		respondToFixedBindingPings(replacement)
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		defer releaseOnce.Do(func() { close(release) })
		old.manager.state.repairLink = func(ctx context.Context, dcID DCID) (FixedBindingSlot, error) {
			close(entered)
			// Return ownership even after cancellation to exercise the manager's
			// cleanup and publication checks at the retirement boundary.
			<-release
			return refreshCandidateFactory(replacement)(ctx, dcID)
		}
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		if err := supervisor.Start(t.Context(), generationManagerFactory(old.manager)); err != nil {
			t.Fatal(err)
		}
		oldGeneration := supervisor.state.active
		old.links[0].peerClose(io.EOF)
		<-entered
		candidate, err := supervisor.state.prepareGeneration(t.Context(), generationManagerFactory(next.manager))
		if err != nil {
			t.Fatal(err)
		}
		candidate.plan = &generationFactoryPlan{build: generationManagerFactory(next.manager)}
		supervisor.state.transitions.Lock()
		supervisor.state.mu.Lock()
		published := supervisor.state.publishGenerationLocked(candidate, oldGeneration)
		supervisor.state.mu.Unlock()
		supervisor.state.transitions.Unlock()
		// Deliberately do not call retireRoutine: the publication boundary
		// itself must stop replacements before exposing the retiring role.
		accepting := old.manager.Snapshot().Accepting
		releaseOnce.Do(func() { close(release) })
		synctest.Wait()
		if !published || accepting {
			t.Fatalf("publication exposed an accepting retiree: published=%t accepting=%t", published, accepting)
		}
		if snapshot := old.manager.Snapshot(); snapshot.SlotRepairSuccesses != 0 || snapshot.SlotRepairFailures != 0 || snapshot.RepairingSlots != 0 || !channelClosed(replacement.Done()) {
			t.Fatalf("repair crossed publication cutoff or escaped cleanup: %+v", snapshot)
		}
		if attempted, err := old.manager.state.repairFailedSlot(t.Context(), old.manager.state.order[0]); attempted || err != nil {
			t.Fatalf("new repair claim after retiring role: %t, %v", attempted, err)
		}
	})
}
