package middleend

import (
	"context"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type socketDiagnosticFakeLink struct {
	*fixedBindingFakeLink
	transportMu sync.Mutex
	transport   LinkTransportSnapshot
	afterClose  func()
}

func newSocketDiagnosticFakeLink() *socketDiagnosticFakeLink {
	return &socketDiagnosticFakeLink{
		fixedBindingFakeLink: newFixedBindingFakeLink(),
		transport:            LinkTransportSnapshot{IO: LinkIOSnapshot{Available: true, ReadBytes: 123}, Socket: LinkSocketSnapshot{Status: LinkSocketNotCaptured}},
	}
}

func (l *socketDiagnosticFakeLink) Snapshot() LinkSnapshot {
	snapshot := l.fixedBindingFakeLink.Snapshot()
	l.transportMu.Lock()
	snapshot.Transport = l.transport
	l.transportMu.Unlock()
	return snapshot
}

func (l *socketDiagnosticFakeLink) captureSocket() {
	l.transportMu.Lock()
	if l.transport.Socket.At.IsZero() {
		l.transport.Socket = LinkSocketSnapshot{Status: LinkSocketAvailable, At: time.Now(), State: 8, TotalRetrans: 2}
	}
	l.transportMu.Unlock()
}

func (l *socketDiagnosticFakeLink) Close() error {
	l.captureSocket()
	err := l.fixedBindingFakeLink.Close()
	if l.afterClose != nil {
		l.afterClose()
	}
	return err
}

func socketDiagnosticTestObserver(manager *FixedBindingManager, supervisor *FixedBindingGenerationSupervisor) {
	repairDiagnosticTestObserver(manager, supervisor)
	manager.state.mu.Lock()
	manager.state.slotSocketObserver = supervisor.state.recordSlotSocket
	manager.state.mu.Unlock()
}

func TestGenerationSocketDiagnosticsProbeTimeoutFollowup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link := newSocketDiagnosticFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: -2, Link: link})
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		socketDiagnosticTestObserver(manager, supervisor)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := manager.state.probeSlot(ctx, -2, manager.state.order[0]); err == nil {
			t.Fatal("silent probe succeeded")
		}
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 2 {
			t.Fatalf("records = %+v", records)
		}
		initial, socket := records[0], records[1]
		if initial.Kind != GenerationDiagnosticSlotFailure || initial.Reason != FixedBindingSlotFailureProbeTimeout || initial.Transport.IO.ReadBytes != 123 ||
			!initial.Transport.Socket.At.IsZero() || socket.Kind != GenerationDiagnosticSlotSocket || socket.Transport.Socket.Status != LinkSocketAvailable ||
			socket.FailureObservedAt != initial.At || socket.FailureSequence != 0 || socket.AffectedBindings != 0 || socket.GenerationID != initial.GenerationID ||
			socket.Slot != initial.Slot || socket.Incarnation != initial.Incarnation || socket.Role != initial.Role || socket.DCID != initial.DCID {
			t.Fatalf("uncorrelated local failure evidence: %+v", records)
		}
		if snapshot := supervisor.Snapshot(); snapshot.SlotFailures != 1 || snapshot.SlotFailureAffectedBindings != 0 || snapshot.SlotRepairFailures != 0 {
			t.Fatalf("socket record changed counters: %+v", snapshot)
		}
	})
}

func TestGenerationSocketDiagnosticsEOFAvoidsDuplicate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link := newSocketDiagnosticFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 2, Link: link})
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		socketDiagnosticTestObserver(manager, supervisor)
		link.captureSocket()
		link.peerClose(io.EOF)
		synctest.Wait()
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 1 || records[0].Kind != GenerationDiagnosticSlotFailure || records[0].Transport.Socket.Status != LinkSocketAvailable {
			t.Fatalf("EOF missing or duplicated close evidence: %+v", records)
		}
	})
}

func TestGenerationSocketDiagnosticsFollowupKeepsOldIncarnation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, replacement := newSocketDiagnosticFakeLink(), newFixedBindingFakeLink()
		respondToFixedBindingPings(replacement)
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		old.afterClose = func() { once.Do(func() { close(entered); <-release }) }
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(replacement))
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		socketDiagnosticTestObserver(manager, supervisor)
		slot := manager.state.order[0]
		done := make(chan struct{})
		go func() {
			manager.state.failSlot(slot, context.DeadlineExceeded, FixedBindingSlotFailureProbeTimeout)
			close(done)
		}()
		<-entered
		synctest.Wait()
		if err := manager.state.repairFailedSlots(t.Context()); err != nil {
			t.Fatal(err)
		}
		if slot.incarnation != 2 {
			t.Fatal("replacement did not advance incarnation")
		}
		close(release)
		<-done
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 2 || records[1].Incarnation != 1 || records[1].Transport.Socket.TotalRetrans != 2 ||
			records[1].FailureObservedAt != records[0].At || records[1].FailureSequence != 0 || channelClosed(replacement.Done()) {
			t.Fatalf("followup captured replacement identity or closed it: %+v", records)
		}
	})
}

func TestGenerationSocketDiagnosticsOverflowDoesNotCountFailures(t *testing.T) {
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	for range generationDiagnosticCapacity + 3 {
		supervisor.state.recordSlotSocket(GenerationDiagnosticRecord{Kind: GenerationDiagnosticSlotSocket})
	}
	journal, snapshot := supervisor.DiagnosticSnapshot(), supervisor.Snapshot()
	if len(journal.Records) != generationDiagnosticCapacity || journal.DroppedRecords != 3 || snapshot.SlotFailures != 0 ||
		snapshot.SlotFailureAffectedBindings != 0 || snapshot.SlotRepairFailures != 0 || snapshot.SlotRepairSuccesses != 0 {
		t.Fatalf("socket overflow changed failure accounting: dropped=%d snapshot=%+v", journal.DroppedRecords, snapshot)
	}
}

func TestGenerationSocketDiagnosticsRejectedCandidateIsSeparate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, replacement := newFixedBindingFakeLink(), newSocketDiagnosticFakeLink()
		replacement.startErr = ErrInvalidHandshake
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(replacement))
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		socketDiagnosticTestObserver(manager, supervisor)
		old.peerClose(io.EOF)
		synctest.Wait()
		if err := manager.state.repairFailedSlots(t.Context()); err == nil {
			t.Fatal("invalid candidate succeeded")
		}
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 2 || records[0].Transport.IO.Available || records[1].Kind != GenerationDiagnosticSlotRepairFailure ||
			records[1].Transport.IO.ReadBytes != 123 || records[1].Transport.Socket.Status != LinkSocketAvailable || records[1].ErrorCode != "invalid_handshake" {
			t.Fatalf("candidate evidence leaked into incumbent failure: %+v", records)
		}
	})
}
