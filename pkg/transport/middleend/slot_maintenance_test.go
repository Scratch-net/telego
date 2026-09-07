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

func respondToFixedBindingPings(link *fixedBindingFakeLink) {
	link.afterTry = func(accepted bool) {
		if !accepted {
			return
		}
		attempts := link.attemptedSubmissions()
		if len(attempts) == 0 {
			return
		}
		ping, err := ParsePing(attempts[len(attempts)-1].Payload)
		if err == nil {
			link.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
		}
	}
}

func TestFixedBindingRepairRequiresMatchingPong(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, replacement := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(replacement))
		old.peerClose(io.EOF)
		synctest.Wait()
		result := make(chan error, 1)
		go func() { result <- manager.state.repairFailedSlots(t.Context()) }()
		synctest.Wait()
		ping := candidatePing(t, replacement)
		replacement.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID + 1})
		synctest.Wait()
		if snapshot := manager.Snapshot(); !snapshot.Slots[0].Failed || !snapshot.Slots[0].Repairing || snapshot.SlotRepairSuccesses != 0 {
			t.Fatalf("unverified candidate became ready: %+v", snapshot)
		}
		if _, err := manager.Bind(2); !errors.Is(err, ErrFixedBindingSlotFailed) {
			t.Fatalf("unverified candidate admitted binding: %v", err)
		}
		replacement.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		if snapshot := manager.Snapshot(); snapshot.Slots[0].Failed || snapshot.SlotRepairSuccesses != 1 {
			t.Fatalf("verified candidate not published: %+v", snapshot)
		}
	})
}

func TestFixedBindingRepairSilentCandidateTimesOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, replacement := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(replacement))
		old.peerClose(io.EOF)
		synctest.Wait()
		if err := manager.state.repairFailedSlots(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("silent replacement result = %v", err)
		}
		if snapshot := manager.Snapshot(); !snapshot.Slots[0].Failed || snapshot.SlotRepairSuccesses != 0 || snapshot.SlotRepairFailures != 1 || snapshot.RepairingSlots != 0 {
			t.Fatalf("silent candidate accounting = %+v", snapshot)
		}
		if !channelClosed(replacement.Done()) {
			t.Fatal("timed-out candidate not closed")
		}
	})
}

func TestFixedBindingRepairCleansCandidateReturnedWithError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, replacement := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		failure := errors.New("candidate construction failed")
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, func(ctx context.Context, dcID DCID) (FixedBindingSlot, error) {
			slot, _ := refreshCandidateFactory(replacement)(ctx, dcID)
			return slot, failure
		})
		old.peerClose(io.EOF)
		synctest.Wait()
		if err := manager.state.repairFailedSlots(t.Context()); !errors.Is(err, failure) {
			t.Fatalf("failed candidate result = %v", err)
		}
		starts, _, closes, _, _ := replacement.stats()
		if starts != 0 || closes != 1 {
			t.Fatalf("failed candidate starts=%d closes=%d, want 0 and 1", starts, closes)
		}
	})
}

func TestFixedBindingRepairRejectsCandidateClosedAfterPong(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, replacement := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		respondToFixedBindingPings(replacement)
		respond := replacement.afterTry
		replacement.afterTry = func(accepted bool) {
			respond(accepted)
			replacement.peerClose(io.EOF)
		}
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(replacement))
		old.peerClose(io.EOF)
		synctest.Wait()
		if err := manager.state.repairFailedSlots(t.Context()); err == nil {
			t.Fatal("closed candidate published after matching PONG")
		}
		if snapshot := manager.Snapshot(); !snapshot.Slots[0].Failed || snapshot.SlotRepairSuccesses != 0 || snapshot.SlotRepairFailures != 1 {
			t.Fatalf("closed candidate accounting = %+v", snapshot)
		}
	})
}

func TestFixedBindingRepairClaimsOneWorkerPerSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, replacement := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		respondToFixedBindingPings(replacement)
		gate := make(chan struct{})
		var attempts atomic.Int32
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, func(ctx context.Context, dcID DCID) (FixedBindingSlot, error) {
			attempts.Add(1)
			select {
			case <-gate:
			case <-ctx.Done():
				return FixedBindingSlot{}, context.Cause(ctx)
			}
			return refreshCandidateFactory(replacement)(ctx, dcID)
		})
		old.peerClose(io.EOF)
		synctest.Wait()
		slot := manager.state.slots[2]
		var claimed atomic.Int32
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(func() {
				if attempted, err := manager.state.repairFailedSlot(t.Context(), slot); attempted {
					claimed.Add(1)
					if err != nil {
						t.Errorf("claimed repair: %v", err)
					}
				}
			})
		}
		synctest.Wait()
		if got := attempts.Load(); got != 1 {
			t.Fatalf("concurrent factory calls = %d, want 1", got)
		}
		close(gate)
		workers.Wait()
		if got := claimed.Load(); got != 1 {
			t.Fatalf("claimed repairs = %d, want 1", got)
		}
	})
}

func TestGenerationSupervisorSlotMaintenanceIsIndependent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := generationTestConfig()
		config.ProbeInterval = 10 * time.Millisecond
		config.ProbeFailureTimeout = 200 * time.Millisecond
		active := newPooledGenerationTestManager(t, 1, true, true, true)
		repairs := &generationSlotRepairTestFactory{}
		active.manager.state.repairLink = repairs.build
		factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
		supervisor := newGenerationTestSupervisor(t, config)
		if err := supervisor.Start(t.Context(), factory.build); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Millisecond)
		synctest.Wait()
		active.responds[0].Store(false)
		time.Sleep(20 * time.Millisecond)
		synctest.Wait()
		healthyBefore := len(active.links[2].attemptedSubmissions())
		active.links[1].peerClose(io.EOF)
		time.Sleep(80 * time.Millisecond)
		synctest.Wait()
		if snapshot := supervisor.Snapshot(); snapshot.SlotRepairSuccesses != 1 {
			t.Errorf("repair waits for another slot's probe: %+v", snapshot)
		}
		if after := len(active.links[2].attemptedSubmissions()); after <= healthyBefore {
			t.Errorf("healthy slot PINGs stopped at %d while another probe waits", after)
		}
		if attempts := len(active.links[0].attemptedSubmissions()); attempts != 5 {
			t.Errorf("silent slot submitted %d PINGs, want 5 with one pending probe", attempts)
		}
	})
}

func TestGenerationSupervisorRepairDoesNotWaitForOtherRepair(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := generationTestConfig()
		config.ProbeInterval = 10 * time.Millisecond
		config.ProbeFailureTimeout = 200 * time.Millisecond
		active := newPooledGenerationTestManager(t, 1, true, true, true)
		repairs := &generationSlotRepairTestFactory{}
		var attempts atomic.Int32
		active.manager.state.repairLink = func(ctx context.Context, dcID DCID) (FixedBindingSlot, error) {
			if attempts.Add(1) == 1 {
				<-ctx.Done()
				return FixedBindingSlot{}, context.Cause(ctx)
			}
			return repairs.build(ctx, dcID)
		}
		factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
		supervisor := newGenerationTestSupervisor(t, config)
		if err := supervisor.Start(t.Context(), factory.build); err != nil {
			t.Fatal(err)
		}
		active.links[0].peerClose(io.EOF)
		time.Sleep(20 * time.Millisecond)
		synctest.Wait()
		if got := attempts.Load(); got != 1 {
			t.Fatalf("initial repair attempts = %d, want 1", got)
		}
		active.links[1].peerClose(io.EOF)
		time.Sleep(80 * time.Millisecond)
		synctest.Wait()
		if got := attempts.Load(); got != 2 {
			t.Errorf("repair attempts = %d, want 2 independent repairs", got)
		}
		snapshot := supervisor.Snapshot()
		if snapshot.SlotRepairSuccesses != 1 || snapshot.Active.RepairingSlots != 1 {
			t.Errorf("second repair blocked by first: %+v", snapshot)
		}
		if got := len(active.links[2].attemptedSubmissions()); got < 5 {
			t.Errorf("healthy PINGs during stalled repair = %d, want at least 5", got)
		}
	})
}

func TestGenerationSupervisorSlotMaintenanceFollowsRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := generationTestConfig()
		config.ProbeInterval = 10 * time.Millisecond
		config.ProbeFailureTimeout = 200 * time.Millisecond
		active := newPooledGenerationTestManager(t, 1, true)
		repairs := &generationSlotRepairTestFactory{}
		active.manager.state.repairLink = repairs.build
		factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
		supervisor := newGenerationTestSupervisor(t, config)
		if err := supervisor.Start(t.Context(), factory.build); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		dueSlotRefreshes(active.manager)
		active.manager.state.refreshUnusedSlots(t.Context(), time.Now())
		synctest.Wait()
		links := repairs.snapshotLinks()
		if len(links) != 1 || !channelClosed(active.links[0].Done()) {
			t.Fatal("refresh did not replace the incumbent")
		}
		before := len(links[0].attemptedSubmissions())
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		if got := len(links[0].attemptedSubmissions()); got <= before {
			t.Fatalf("maintenance did not follow refreshed ordinal: PINGs %d -> %d", before, got)
		}
		if snapshot := supervisor.Snapshot(); snapshot.SlotFailures != 0 || snapshot.SlotRepairSuccesses != 0 {
			t.Fatalf("intentional refresh caused failure or repair: %+v", snapshot)
		}
	})
}

func TestGenerationSupervisorCloseJoinsIndependentSlotMaintenance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := generationTestConfig()
		config.ProbeInterval = 10 * time.Millisecond
		config.ProbeFailureTimeout = 200 * time.Millisecond
		active := newPooledGenerationTestManager(t, 1, true, true)
		canceled, release := make(chan struct{}), make(chan struct{})
		active.manager.state.repairLink = func(ctx context.Context, _ DCID) (FixedBindingSlot, error) {
			<-ctx.Done()
			close(canceled)
			<-release
			return FixedBindingSlot{}, context.Cause(ctx)
		}
		factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
		supervisor := newGenerationTestSupervisor(t, config)
		if err := supervisor.Start(t.Context(), factory.build); err != nil {
			t.Fatal(err)
		}
		active.responds[0].Store(false)
		active.links[1].peerClose(io.EOF)
		time.Sleep(20 * time.Millisecond)
		synctest.Wait()
		result := make(chan error, 1)
		go func() { result <- supervisor.Close() }()
		synctest.Wait()
		if !channelClosed(canceled) {
			t.Error("shutdown did not cancel the stalled repair")
		}
		select {
		case err := <-result:
			t.Errorf("shutdown returned before candidate cleanup: %v", err)
		default:
		}
		close(release)
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		for _, link := range active.links {
			if !channelClosed(link.Done()) {
				t.Error("shutdown retained a physical link")
			}
		}
	})
}
