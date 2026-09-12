package middleend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func repairDiagnosticTestObserver(manager *FixedBindingManager, supervisor *FixedBindingGenerationSupervisor) {
	diagnosticTestObserver(manager, supervisor)
	manager.state.mu.Lock()
	manager.state.slotRepairObserver = supervisor.state.recordSlotRepair
	manager.state.mu.Unlock()
}

type repairDiagnosticBusyLink struct{ *fixedBindingFakeLink }

func (link repairDiagnosticBusyLink) Snapshot() LinkSnapshot {
	snapshot := link.fixedBindingFakeLink.Snapshot()
	snapshot.PendingEvents = 1
	return snapshot
}

func TestGenerationRepairDiagnosticsStagesAndRedaction(t *testing.T) {
	for _, test := range []struct {
		name  string
		stage GenerationSlotRepairStage
		code  string
	}{
		{"wait", GenerationSlotRepairWaitConsumer, "deadline_exceeded"},
		{"construct", GenerationSlotRepairConstruct, "errno"},
		{"construct with link", GenerationSlotRepairConstruct, "eof"},
		{"validate", GenerationSlotRepairValidate, "slot_repair"},
		{"start", GenerationSlotRepairStart, "invalid_handshake"},
		{"probe", GenerationSlotRepairProbe, "deadline_exceeded"},
		{"publish", GenerationSlotRepairPublish, "slot_repair"},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				old, replacement := newFixedBindingFakeLink(), newFixedBindingFakeLink()
				factory := refreshCandidateFactory(replacement)
				switch test.name {
				case "construct":
					factory = func(context.Context, DCID) (FixedBindingSlot, error) {
						return FixedBindingSlot{}, &net.OpError{Op: "dial", Net: "private-secret-ABC", Addr: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 77), Port: 4443}, Err: syscall.ECONNREFUSED}
					}
				case "construct with link":
					factory = func(ctx context.Context, dc DCID) (FixedBindingSlot, error) {
						slot, _ := refreshCandidateFactory(replacement)(ctx, dc)
						return slot, fmt.Errorf("private-secret-ABC: %w", io.EOF)
					}
				case "validate":
					factory = func(ctx context.Context, dc DCID) (FixedBindingSlot, error) {
						slot, _ := refreshCandidateFactory(replacement)(ctx, dc)
						slot.SourceIP = netip.MustParseAddr("127.0.0.1")
						return slot, nil
					}
				case "start":
					replacement.startErr = fmt.Errorf("private-secret-ABC: %w", ErrInvalidHandshake)
				case "publish":
					respondToFixedBindingPings(replacement)
					factory = refreshCandidateFactory(repairDiagnosticBusyLink{replacement})
				}
				manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: -2, Link: old}}, factory)
				supervisor := newGenerationTestSupervisor(t, generationTestConfig())
				repairDiagnosticTestObserver(manager, supervisor)
				old.peerClose(io.EOF)
				synctest.Wait()
				if test.name == "wait" {
					manager.state.order[0].consumerDone = make(chan struct{})
				}
				started := time.Now()
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				if err := manager.state.repairFailedSlots(ctx); err == nil {
					t.Fatal("replacement unexpectedly succeeded")
				}
				records := supervisor.DiagnosticSnapshot().Records
				if len(records) != 2 {
					t.Fatalf("retained records = %d, want original failure and repair failure", len(records))
				}
				record := records[1]
				if record.Kind != GenerationDiagnosticSlotRepairFailure || record.RepairStage != test.stage || record.ErrorCode != test.code ||
					record.GenerationID != 7 || record.Role != GenerationRoleActive || record.DCID != -2 || record.Slot != 0 || record.Incarnation != 1 ||
					record.At.Before(started) || record.RepairDuration != record.At.Sub(started) || record.FailureSequence != 0 || record.AffectedBindings != 0 {
					t.Fatalf("repair diagnostic = %+v", record)
				}
				if test.name == "construct" && (record.NetworkOperation != "dial" || record.Errno != uint64(syscall.ECONNREFUSED)) {
					t.Fatalf("dial evidence = %+v", record)
				}
				for _, forbidden := range []string{"private-secret-ABC", "203.0.113.77", "4443", "127.0.0.1"} {
					if strings.Contains(fmt.Sprintf("%+v", record), forbidden) {
						t.Fatalf("diagnostic contains forbidden marker %q", forbidden)
					}
				}
				if snapshot := supervisor.Snapshot(); snapshot.SlotFailures != 1 || snapshot.SlotFailureAffectedBindings != 0 || snapshot.SlotRepairFailures != 1 {
					t.Fatalf("repair changed physical failure counters: %+v", snapshot)
				}
			})
		})
	}
}

func TestGenerationRepairDiagnosticsCancellationDoesNotCount(t *testing.T) {
	for _, mode := range []string{"caller", "retirement", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				old, replacement := newFixedBindingFakeLink(), newFixedBindingFakeLink()
				replacement.startGate = make(chan struct{})
				manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(replacement))
				supervisor := newGenerationTestSupervisor(t, generationTestConfig())
				repairDiagnosticTestObserver(manager, supervisor)
				old.peerClose(io.EOF)
				synctest.Wait()
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				result := make(chan error, 1)
				go func() { result <- manager.state.repairFailedSlots(ctx) }()
				synctest.Wait()
				switch mode {
				case "caller":
					cancel(errors.New("private intentional stop"))
				case "retirement":
					manager.Quiesce()
				case "shutdown":
					if err := manager.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if err := <-result; err == nil {
					t.Fatal("canceled attempt succeeded")
				}
				if snapshot := manager.Snapshot(); snapshot.SlotRepairFailures != 0 || snapshot.RepairingSlots != 0 {
					t.Fatalf("cancellation counted as failure: %+v", snapshot)
				}
				if snapshot := supervisor.Snapshot(); snapshot.SlotRepairFailures != 0 || len(supervisor.DiagnosticSnapshot().Records) != 1 {
					t.Fatal("cancellation emitted a repair failure")
				}
			})
		})
	}
}

func TestGenerationRepairDiagnosticsCaptureBeforeCandidateCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old, replacement := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		replacement.startErr = io.EOF
		cleanupEntered, release := make(chan struct{}), make(chan struct{})
		replacement.onClose = func() { close(cleanupEntered); <-release }
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(replacement))
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		repairDiagnosticTestObserver(manager, supervisor)
		old.peerClose(io.EOF)
		synctest.Wait()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		started := time.Now()
		result := make(chan error, 1)
		go func() { result <- manager.state.repairFailedSlots(ctx) }()
		<-cleanupEntered
		time.Sleep(2 * time.Second)
		manager.quiesceWithRole(GenerationRoleRetiring)
		if !manager.Snapshot().Slots[0].Repairing {
			t.Fatal("cleanup released the repair claim early")
		}
		close(release)
		if err := <-result; !errors.Is(err, io.EOF) {
			t.Fatalf("return cause changed: %v", err)
		}
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 2 || records[1].ErrorCode != "eof" || records[1].At != started || records[1].RepairDuration != 0 ||
			records[1].Role != GenerationRoleActive || records[1].RepairStage != GenerationSlotRepairStart {
			t.Fatalf("cleanup rewrote failure evidence: %+v", records)
		}
		if manager.Snapshot().SlotRepairFailures != 1 || supervisor.Snapshot().SlotRepairFailures != 1 {
			t.Fatal("cleanup cancellation discarded an already failed attempt")
		}
	})
}

func TestGenerationRepairDiagnosticsConcurrentAttemptsAndOverflow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first, second := newFixedBindingFakeLink(), newFixedBindingFakeLink()
		entered, release := make(chan DCID, 2), make(chan struct{})
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: -2, Link: first}, {DCID: 2, Link: second}}, func(_ context.Context, dc DCID) (FixedBindingSlot, error) {
			entered <- dc
			<-release
			if dc < 0 {
				return FixedBindingSlot{}, io.EOF
			}
			return FixedBindingSlot{}, ErrInvalidNonce
		})
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		repairDiagnosticTestObserver(manager, supervisor)
		first.peerClose(io.EOF)
		second.peerClose(io.EOF)
		synctest.Wait()
		result := make(chan error, 1)
		go func() { result <- manager.state.repairFailedSlots(t.Context()) }()
		<-entered
		<-entered
		close(release)
		<-result
		records := supervisor.DiagnosticSnapshot().Records
		if len(records) != 4 {
			t.Fatalf("concurrent failures retained %d records, want 4", len(records))
		}
		causes := make(map[DCID]string)
		for _, record := range records[2:] {
			causes[record.DCID] = record.ErrorCode
		}
		if causes[-2] != "eof" || causes[2] != "invalid_nonce" {
			t.Fatalf("concurrent attempt overwrote another cause: %v", causes)
		}
		var writers sync.WaitGroup
		for range generationDiagnosticCapacity {
			writers.Go(func() { supervisor.state.recordSlotRepair(false, records[2]) })
		}
		writers.Wait()
		journal, snapshot := supervisor.DiagnosticSnapshot(), supervisor.Snapshot()
		if len(journal.Records) != generationDiagnosticCapacity || journal.DroppedRecords != 4 || snapshot.DiagnosticRecordsDropped != 4 ||
			snapshot.SlotRepairFailures != generationDiagnosticCapacity+2 || snapshot.SlotFailures != 2 || snapshot.SlotFailureAffectedBindings != 0 {
			t.Fatalf("repair overflow accounting changed: retained=%d dropped=%d snapshot=%+v", len(journal.Records), journal.DroppedRecords, snapshot)
		}
	})
}
