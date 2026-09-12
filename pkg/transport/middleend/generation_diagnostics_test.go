package middleend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func TestGenerationDiagnosticJournalRetainsFirstUnseen(t *testing.T) {
	var journal generationDiagnosticJournal
	for index := range 257 {
		journal.append(GenerationDiagnosticRecord{FailureSequence: uint64(index + 1)})
	}
	snapshot := journal.snapshot()
	if len(snapshot.Records) != 256 || snapshot.ThroughSequence != 257 || snapshot.DroppedRecords != 1 {
		t.Fatalf("journal bounds = %d, %d, %d", len(snapshot.Records), snapshot.ThroughSequence, snapshot.DroppedRecords)
	}
	for index, record := range snapshot.Records {
		if record.Sequence != uint64(index+1) || record.FailureSequence != uint64(index+1) {
			t.Fatalf("retained record %d = %+v", index, record)
		}
	}
	snapshot.Records[0].ErrorText = "mutated copy"
	if journal.snapshot().Records[0].ErrorText != "" {
		t.Fatal("snapshot aliases journal storage")
	}
	journal.acknowledge(256)
	if next := journal.snapshot(); len(next.Records) != 0 || next.AcknowledgedThrough != 256 || next.DroppedRecords != 1 {
		t.Fatalf("acknowledged retained boundary = %+v", next)
	}
	journal.acknowledge(257) // The boundary can contain only dropped records.
	journal.append(GenerationDiagnosticRecord{FailureSequence: 258})
	journal.acknowledge(256)
	journal.acknowledge(257)
	if next := journal.snapshot(); len(next.Records) != 1 || next.Records[0].Sequence != 258 || next.AcknowledgedThrough != 257 {
		t.Fatalf("stale acknowledgement = %+v", next)
	}
	journal.acknowledge(^uint64(0))
	if next := journal.snapshot(); len(next.Records) != 0 || next.AcknowledgedThrough != 258 || next.DroppedRecords != 1 {
		t.Fatalf("future acknowledgement = %+v", next)
	}
}

func TestGenerationDiagnosticJournalKeepsArrivalsDuringEmission(t *testing.T) {
	var journal generationDiagnosticJournal
	journal.append(GenerationDiagnosticRecord{ErrorCode: "eof"})
	journal.append(GenerationDiagnosticRecord{ErrorCode: "deadline_exceeded"})
	snapshot := journal.snapshot()
	if len(snapshot.Records) != 2 || snapshot.Records[0].ErrorCode != "eof" {
		t.Fatalf("first causes = %+v", snapshot)
	}
	journal.append(GenerationDiagnosticRecord{ErrorCode: "errno"})
	journal.acknowledge(snapshot.ThroughSequence)
	if next := journal.snapshot(); len(next.Records) != 1 || next.Records[0].Sequence != 3 || next.Records[0].ErrorCode != "errno" {
		t.Fatalf("new arrival was acknowledged = %+v", next)
	}
}

type diagnosticSecretError struct{}

func (diagnosticSecretError) Error() string { panic("diagnostics called an arbitrary Error method") }

func TestGenerationDiagnosticErrorClassificationRedacts(t *testing.T) {
	secret := "private-credential-ABC123"
	private := &net.TCPAddr{IP: net.ParseIP("192.0.2.15"), Port: 4443}
	cases := []struct {
		name      string
		cause     error
		code      string
		operation string
		errno     uint64
	}{
		{"unknown", diagnosticSecretError{}, "unknown", "unknown", 0},
		{"custom text", errors.New(secret), "unknown", "unknown", 0},
		{"eof before wrapper", errors.Join(ErrFixedBindingSlotFailed, io.EOF), "eof", "unknown", 0},
		{"short write before wrapper", errors.Join(ErrFixedBindingSlotFailed, io.ErrShortWrite), "short_write", "unknown", 0},
		{"no progress before wrapper", errors.Join(ErrFixedBindingSlotFailed, io.ErrNoProgress), "no_progress", "unknown", 0},
		{"deadline before wrapper", errors.Join(ErrFixedBindingSlotFailed, context.DeadlineExceeded), "deadline_exceeded", "unknown", 0},
		{"protocol before wrapper", errors.Join(ErrFixedBindingSlotFailed, ErrChecksumMismatch), "checksum_mismatch", "unknown", 0},
		{"errno before wrapper", errors.Join(ErrFixedBindingSlotFailed, &net.OpError{Op: "write", Net: secret, Source: private, Addr: private, Err: syscall.ECONNRESET}), "errno", "write", uint64(syscall.ECONNRESET)},
		{"unsafe operation", &net.OpError{Op: secret, Addr: private, Err: errors.New(secret)}, "unknown", "unknown", 0},
		{"nil operation", (*net.OpError)(nil), "unknown", "unknown", 0},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := classifyGenerationDiagnosticError(test.cause)
			if got.code != test.code || got.operation != test.operation || got.errno != test.errno {
				t.Fatalf("classification = %+v", got)
			}
			for _, forbidden := range []string{secret, private.IP.String(), "4443"} {
				if strings.Contains(fmt.Sprintf("%+v", got), forbidden) {
					t.Fatalf("classification contains forbidden marker %q", forbidden)
				}
			}
		})
	}
}

func diagnosticTestObserver(manager *FixedBindingManager, supervisor *FixedBindingGenerationSupervisor) {
	manager.state.mu.Lock()
	manager.state.generationID = 7
	manager.state.generationRole = GenerationRoleActive
	manager.state.slotFailureObserver = supervisor.state.recordSlotFailure
	manager.state.mu.Unlock()
}

func TestGenerationDiagnosticsConcurrentReadersAndLifetimeCounters(t *testing.T) {
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	service := &Service{state: &serviceState{supervisor: supervisor}}
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 300 {
				snapshot := service.DiagnosticSnapshot()
				if len(snapshot.Records) != 0 {
					snapshot.Records[0].ErrorText = "reader mutation"
				}
			}
		})
	}
	for range 257 {
		supervisor.state.recordSlotFailure(FixedBindingSlotFailureSnapshot{
			AffectedBindings: 1, diagnostic: GenerationDiagnosticRecord{GenerationID: 7, ErrorCode: "eof"},
		})
	}
	readers.Wait()
	snapshot := service.DiagnosticSnapshot()
	operational := supervisor.Snapshot()
	if len(snapshot.Records) != 256 || snapshot.DroppedRecords != 1 || operational.DiagnosticRecordsDropped != 1 ||
		operational.SlotFailures != 257 || operational.LastSlotFailure.Sequence != 257 || operational.SlotFailureAffectedBindings != 257 ||
		snapshot.Records[0].ErrorText != "" {
		t.Fatalf("readers or overflow changed lifetime state: journal=%+v snapshot=%+v", snapshot, operational)
	}
	service.AcknowledgeDiagnostics(snapshot.ThroughSequence)
	if after := service.DiagnosticSnapshot(); len(after.Records) != 0 || after.DroppedRecords != 1 || after.AcknowledgedThrough != 257 {
		t.Fatalf("service acknowledgement = %+v", after)
	}
}

func TestGenerationDiagnosticsRoleCapturedBeforeDelayedCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: -2, Link: link})
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		diagnosticTestObserver(manager, supervisor)
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		manager.state.mu.Lock()
		manager.state.slotFailureObserver = func(failure FixedBindingSlotFailureSnapshot) {
			close(entered)
			<-release
			supervisor.state.recordSlotFailure(failure)
		}
		manager.state.mu.Unlock()
		go func() {
			manager.state.failSlot(manager.state.order[0], errors.New("private-secret-ABC"), FixedBindingSlotFailureSubmission)
			close(done)
		}()
		<-entered
		manager.quiesceWithRole(GenerationRoleRetiring)
		close(release)
		<-done
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 1 || records[0].Role != GenerationRoleActive || records[0].GenerationID != 7 ||
			records[0].Slot != 0 || records[0].Incarnation != 1 || records[0].ErrorCode != "unknown" || records[0].At.IsZero() ||
			strings.Contains(fmt.Sprintf("%+v", records), "private-secret-ABC") {
			t.Fatalf("claim metadata = %+v", records)
		}
	})
}

func TestGenerationDiagnosticsProbeTimelineBeforeTimeoutCleanup(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(fmt.Sprintf("accepted=%t", accepted), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				link := newFixedBindingFakeLink()
				if !accepted {
					link.setTryError(ErrLinkBackpressure)
				}
				manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 2, Link: link})
				supervisor := newGenerationTestSupervisor(t, generationTestConfig())
				diagnosticTestObserver(manager, supervisor)
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				result := make(chan error, 1)
				go func() { result <- manager.Probe(ctx, 2) }()
				synctest.Wait()
				manager.state.mu.Lock()
				queued := manager.state.order[0].controlItems
				manager.state.mu.Unlock()
				time.Sleep(time.Second)
				if err := <-result; !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("timeout result = %v", err)
				}
				synctest.Wait()
				records := supervisor.DiagnosticSnapshot().Records
				if len(records) != 1 {
					t.Fatalf("timeout records = %+v", records)
				}
				record := records[0]
				deadline, _ := ctx.Deadline()
				if record.Reason != FixedBindingSlotFailureProbeTimeout || record.ErrorCode != "deadline_exceeded" ||
					record.ProbeID == 0 || !record.ProbePending || record.ProbeQueuedAt.IsZero() ||
					record.ProbeAcceptedAt.IsZero() == accepted || record.ProbeDeadline != deadline ||
					record.ControlItems != queued || record.ControlBytes != queued*KeepalivePayloadSize ||
					!record.LastPongAt.IsZero() {
					t.Fatalf("timeout lost pre-cleanup timeline = %+v, queued=%d", record, queued)
				}
				if slot := manager.Snapshot().Slots[0]; slot.ControlItems != 0 || slot.ControlBytes != 0 {
					t.Fatalf("failure did not clean the probe queue = %+v", slot)
				}
			})
		})
	}
}

func TestGenerationDiagnosticsMatchingPongOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 2, Link: link})
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		diagnosticTestObserver(manager, supervisor)
		result := make(chan error, 1)
		go func() { result <- manager.Probe(t.Context(), 2) }()
		synctest.Wait()
		slot := manager.state.order[0]
		probe := slot.probe
		link.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: probe.id + 1})
		synctest.Wait()
		if !slot.lastProbe.lastPongAt.IsZero() {
			t.Fatal("unmatched PONG changed timestamp")
		}
		link.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: probe.id})
		if err := <-result; err != nil {
			t.Fatal(err)
		}
		matched := time.Now()
		time.Sleep(time.Second)
		link.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: probe.id})
		synctest.Wait()
		if err := manager.state.cancelProbe(probe, context.DeadlineExceeded); err != nil {
			t.Fatal("matching PONG lost to late deadline", err)
		}
		manager.state.failSlot(slot, io.EOF, FixedBindingSlotFailureLinkTerminal)
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 1 || records[0].LastPongAt != matched || records[0].ProbePending || records[0].ProbeID != probe.id {
			t.Fatalf("matching PONG timeline = %+v", records)
		}
	})
}

func TestGenerationDiagnosticsQueueCountsBeforeFailureCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link := newFixedBindingFakeLink()
		link.setTryError(ErrLinkBackpressure)
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 2, Link: link})
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		diagnosticTestObserver(manager, supervisor)
		binding, err := manager.Bind(2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := binding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil {
			t.Fatal(err)
		}
		link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID(), ConfirmKey: 17})
		result := make(chan error, 1)
		go func() { result <- manager.Probe(t.Context(), 2) }()
		synctest.Wait()
		before := manager.Snapshot().Slots[0]
		if before.RequestItems != 1 || before.ControlItems != 1 || before.ResponseItems != 1 {
			t.Fatalf("test did not fill queues = %+v", before)
		}
		manager.state.failSlot(manager.state.order[0], io.EOF, FixedBindingSlotFailureLinkTerminal)
		if err := <-result; !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		record := supervisor.DiagnosticSnapshot().Records[0]
		if record.RequestItems != before.RequestItems || record.RequestBytes != before.RequestBytes ||
			record.ControlItems != before.ControlItems || record.ControlBytes != before.ControlBytes ||
			record.ResponseItems != before.ResponseItems || record.ResponseBytes != before.ResponseBytes {
			t.Fatalf("pre-cleanup queues = %+v; before=%+v", record, before)
		}
	})
}

func TestGenerationDiagnosticsRepairPreservesClaimedIncarnation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, replacement := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		respondToFixedBindingPings(replacement)
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: -2, Link: old}}, refreshCandidateFactory(replacement))
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		repairDiagnosticTestObserver(manager, supervisor)
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var once sync.Once
		manager.state.mu.Lock()
		manager.state.slotFailureObserver = func(failure FixedBindingSlotFailureSnapshot) {
			once.Do(func() { close(entered); <-release })
			supervisor.state.recordSlotFailure(failure)
		}
		manager.state.mu.Unlock()
		slot := manager.state.order[0]
		go func() {
			manager.state.failSlot(slot, io.EOF, FixedBindingSlotFailureLinkTerminal)
			close(done)
		}()
		<-entered
		old.peerClose(io.EOF)
		synctest.Wait()
		if err := manager.state.repairFailedSlots(t.Context()); err != nil {
			t.Fatal(err)
		}
		close(release)
		<-done
		if snapshot := supervisor.Snapshot(); snapshot.SlotRepairSuccesses != 1 || snapshot.SlotRepairFailures != 0 || len(supervisor.DiagnosticSnapshot().Records) != 1 {
			t.Fatal("successful repair emitted a repair failure")
		}
		if slot.ordinal != 0 || slot.incarnation != 2 || slot.lastProbe.id != 0 || !slot.lastProbe.lastPongAt.IsZero() {
			t.Fatalf("repair identity/summary = ordinal %d incarnation %d probe %+v", slot.ordinal, slot.incarnation, slot.lastProbe)
		}
		manager.state.failSlot(slot, context.DeadlineExceeded, FixedBindingSlotFailureProbeTimeout)
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 2 || records[0].Slot != 0 || records[0].Incarnation != 1 || records[1].Slot != 0 || records[1].Incarnation != 2 {
			t.Fatalf("delayed repair failure identity = %+v", records)
		}
	})
}

func TestGenerationDiagnosticsRefreshRetainsOldIdentity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, replacement := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		old.onClose = func() { old.peerClose(io.EOF) }
		respondToFixedBindingPings(replacement)
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: -2, Link: old}}, refreshCandidateFactory(replacement))
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		diagnosticTestObserver(manager, supervisor)
		oldSlot := manager.state.order[0]
		dueSlotRefreshes(manager)
		manager.state.refreshUnusedSlots(t.Context(), time.Now())
		synctest.Wait()
		current := manager.state.order[0]
		if current == oldSlot || current.ordinal != oldSlot.ordinal || current.incarnation != 2 || oldSlot.incarnation != 1 ||
			current.lastProbe.id != 0 || !current.lastProbe.lastPongAt.IsZero() {
			t.Fatalf("refresh identity/summary changed incorrectly: old=%d/%d new=%d/%d", oldSlot.ordinal, oldSlot.incarnation, current.ordinal, current.incarnation)
		}
		manager.state.failSlot(current, context.DeadlineExceeded, FixedBindingSlotFailureProbeTimeout)
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 2 || records[0].Incarnation != 1 || records[1].Incarnation != 2 || records[0].Slot != records[1].Slot {
			t.Fatalf("old refresh failure identity = %+v", records)
		}
	})
}

func TestGenerationDiagnosticsPublicationAndCapacityLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newPooledGenerationTestManager(t, 2, true, true)
		// This test isolates generation lifetime events. Any repair started
		// before rotation waits for retirement instead of racing an extra failure.
		old.manager.state.repairLink = func(ctx context.Context, _ DCID) (FixedBindingSlot, error) {
			<-ctx.Done()
			return FixedBindingSlot{}, context.Cause(ctx)
		}
		current := newGenerationTestManager(t, []DCID{2}, true)
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		if err := supervisor.Start(t.Context(), generationManagerFactory(old.manager)); err != nil {
			t.Fatal(err)
		}
		if old.manager.state.generationID != 1 || old.manager.state.generationRole != GenerationRoleActive {
			t.Fatal("initial manager did not receive active generation metadata")
		}
		if _, err := supervisor.BindReady(2); err != nil {
			t.Fatal(err)
		}
		// A spare link failure does not remove the bound active slot.
		old.manager.state.failSlot(old.manager.state.order[1], io.EOF, FixedBindingSlotFailureLinkTerminal)
		if err := supervisor.Rotate(t.Context(), generationManagerFactory(current.manager)); err != nil {
			t.Fatal(err)
		}
		if old.manager.state.generationRole != GenerationRoleRetiring || current.manager.state.generationRole != GenerationRoleActive ||
			current.manager.state.generationID != 2 {
			t.Fatal("publication did not update generation metadata")
		}
		candidate := newGenerationTestManager(t, []DCID{2}, false)
		if err := supervisor.Rotate(t.Context(), generationManagerFactory(candidate.manager)); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("silent candidate result = %v", err)
		}
		synctest.Wait()
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 3 || records[0].Kind != GenerationDiagnosticSlotFailure || records[0].Role != GenerationRoleActive || records[0].Incarnation != 1 ||
			records[1].Kind != GenerationDiagnosticForcedRetirement || records[1].GenerationID != 1 || records[1].Role != GenerationRoleRetiring ||
			records[1].RetirementReason != GenerationRetirementArtifactCapacity || records[1].AffectedBindings != 1 || records[1].FailureSequence != 0 ||
			records[2].Kind != GenerationDiagnosticSlotFailure || records[2].GenerationID != 3 || records[2].Role != GenerationRoleCandidate ||
			records[2].FailureSequence != 2 {
			t.Fatalf("generation lifecycle journal = %+v", records)
		}
		if err := supervisor.Close(); err != nil {
			t.Fatal(err)
		}
		if after := supervisor.DiagnosticSnapshot(); len(after.Records) != 3 || after.ThroughSequence != 3 {
			t.Fatalf("shutdown changed lifetime journal = %+v", after)
		}
	})
}
