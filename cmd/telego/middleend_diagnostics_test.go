package main

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

type diagnosticMonitorSource struct {
	mu               sync.Mutex
	snapshot         middleend.GenerationDiagnosticSnapshot
	acknowledgements []uint64
}

func (source *diagnosticMonitorSource) DiagnosticSnapshot() middleend.GenerationDiagnosticSnapshot {
	source.mu.Lock()
	defer source.mu.Unlock()
	snapshot := source.snapshot
	snapshot.Records = slices.Clone(snapshot.Records)
	return snapshot
}

func (source *diagnosticMonitorSource) AcknowledgeDiagnostics(through uint64) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.acknowledgements = append(source.acknowledgements, through)
	source.snapshot.AcknowledgedThrough = through
	source.snapshot.Records = slices.DeleteFunc(source.snapshot.Records, func(record middleend.GenerationDiagnosticRecord) bool {
		return record.Sequence <= through
	})
}

func diagnosticMonitorRecords() []middleend.GenerationDiagnosticRecord {
	at := time.Date(2026, time.September, 7, 14, 15, 16, 123456789, time.UTC)
	return []middleend.GenerationDiagnosticRecord{
		{
			Sequence: 1, FailureSequence: 1, Kind: middleend.GenerationDiagnosticSlotFailure,
			At: at, GenerationID: 1, Role: middleend.GenerationRoleActive,
			DCID: -2, Slot: 3, Incarnation: 5, Reason: middleend.FixedBindingSlotFailureLinkTerminal,
			ErrorCode: "eof", ErrorText: "peer closed the stream", NetworkOperation: "unknown",
			Age: 49 * time.Second, PeerEOF: true,
		},
		{
			Sequence: 2, FailureSequence: 2, Kind: middleend.GenerationDiagnosticSlotFailure,
			At: at.Add(time.Millisecond), GenerationID: 1, Role: middleend.GenerationRoleRetiring,
			DCID: 2, Slot: 1, Incarnation: 2, Reason: middleend.FixedBindingSlotFailureProbeTimeout,
			AffectedBindings: 2, ErrorCode: "deadline_exceeded", ErrorText: "operation deadline expired", NetworkOperation: "unknown",
			Age: 150 * time.Second, Used: true,
			ProbeID: 17, ProbeQueuedAt: at.Add(-5 * time.Second), ProbeAcceptedAt: at.Add(-4 * time.Second),
			ProbeDeadline: at.Add(time.Millisecond), LastPongAt: at.Add(-10 * time.Second), ProbePending: true,
			RequestItems: 2, RequestBytes: 128, ControlItems: 1, ControlBytes: 16, ResponseItems: 3, ResponseBytes: 256,
		},
		{
			Sequence: 3, Kind: middleend.GenerationDiagnosticForcedRetirement,
			At: at.Add(2 * time.Millisecond), GenerationID: 1, Role: middleend.GenerationRoleRetiring,
			RetirementReason: middleend.GenerationRetirementArtifactCapacity, AffectedBindings: 1,
		},
	}
}

func readDiagnosticJSON(t *testing.T, output string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode diagnostic: %v", err)
		}
		records = append(records, record)
	}
	return records
}

func TestMiddleEndDiagnosticsEmitEveryFailureAndSeparateRetirement(t *testing.T) {
	source := &diagnosticMonitorSource{snapshot: middleend.GenerationDiagnosticSnapshot{
		Records: diagnosticMonitorRecords(), ThroughSequence: 3,
	}}
	var output bytes.Buffer
	logger := zerolog.New(&output).Level(zerolog.InfoLevel)
	if dropped := observeMiddleEndDiagnostics(source, &logger, 0); dropped != 0 {
		t.Fatalf("dropped = %d", dropped)
	}
	records := readDiagnosticJSON(t, output.String())
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3", len(records))
	}
	for index, level := range []string{"info", "warn", "warn"} {
		if records[index]["level"] != level || records[index]["diagnostic_sequence"] != float64(index+1) {
			t.Errorf("record %d level/sequence = %v", index, records[index])
		}
	}
	if records[0]["error_code"] != "eof" || records[1]["error_code"] != "deadline_exceeded" {
		t.Fatal("burst lost the first cause")
	}
	if records[0]["message"] != middleEndSlotFailureMessage || records[2]["message"] != middleEndForcedRetirementMessage {
		t.Fatal("diagnostic messages changed")
	}
	if records[2]["diagnostic_kind"] != "forced_retirement" || records[2]["retirement_reason"] != "artifact_capacity" {
		t.Fatal("forced retirement was not separate")
	}
	for _, field := range []string{"failure_sequence", "reason", "error_code", "probe_id", "dc", "slot"} {
		if _, exists := records[2][field]; exists {
			t.Errorf("forced retirement included physical field %s", field)
		}
	}
	if records[1]["probe_accepted_at"] != "2026-09-07T14:15:12.123456789Z" ||
		records[1]["control_bytes"] != float64(16) || records[1]["probe_pending"] != true {
		t.Fatal("probe or pre-cleanup queue fields changed")
	}
	if len(source.snapshot.Records) != 0 || !slices.Equal(source.acknowledgements, []uint64{3}) {
		t.Fatal("monitor did not acknowledge the copied boundary")
	}
}

type diagnosticCallbackWriter struct {
	output   bytes.Buffer
	callback func()
}

func (writer *diagnosticCallbackWriter) Write(data []byte) (int, error) {
	if writer.callback != nil {
		callback := writer.callback
		writer.callback = nil
		callback()
	}
	return writer.output.Write(data)
}

func TestMiddleEndDiagnosticsAcknowledgeOnlyEmittedBoundary(t *testing.T) {
	records := diagnosticMonitorRecords()
	source := &diagnosticMonitorSource{snapshot: middleend.GenerationDiagnosticSnapshot{
		Records: records[:1], ThroughSequence: 1,
	}}
	writer := &diagnosticCallbackWriter{callback: func() {
		// An event arrives during logging. The logger does not hold source locks.
		source.mu.Lock()
		defer source.mu.Unlock()
		source.snapshot.Records = append(source.snapshot.Records, records[1])
		source.snapshot.ThroughSequence = 2
	}}
	logger := zerolog.New(writer).Level(zerolog.InfoLevel)
	observeMiddleEndDiagnostics(source, &logger, 0)
	snapshot := source.DiagnosticSnapshot()
	if len(snapshot.Records) != 1 || snapshot.Records[0].Sequence != 2 || snapshot.AcknowledgedThrough != 1 {
		t.Fatalf("acknowledgement lost a later event: %+v", snapshot)
	}
	observeMiddleEndDiagnostics(source, &logger, 0)
	if len(readDiagnosticJSON(t, writer.output.String())) != 2 || len(source.DiagnosticSnapshot().Records) != 0 {
		t.Fatal("later event was not emitted once on the next observation")
	}
}

func TestMiddleEndDiagnosticsWarnOnceForDroppedBoundary(t *testing.T) {
	source := &diagnosticMonitorSource{snapshot: middleend.GenerationDiagnosticSnapshot{
		ThroughSequence: 261, AcknowledgedThrough: 0, DroppedRecords: 5,
	}}
	var output bytes.Buffer
	logger := zerolog.New(&output).Level(zerolog.InfoLevel)
	previous := observeMiddleEndDiagnostics(source, &logger, 2)
	observeMiddleEndDiagnostics(source, &logger, previous)
	records := readDiagnosticJSON(t, output.String())
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	record := records[0]
	if record["level"] != "warn" || record["diagnostic_kind"] != "records_dropped" ||
		record["message"] != middleEndDiagnosticsDroppedMessage || record["new_dropped_records"] != float64(3) ||
		record["dropped_records_total"] != float64(5) || record["through_sequence"] != float64(261) {
		t.Fatalf("drop warning = %v", record)
	}
	if _, exists := record["diagnostic_sequence"]; exists {
		t.Fatal("drop warning invented a retained event sequence")
	}
	if !slices.Equal(source.acknowledgements, []uint64{261, 261}) {
		t.Fatal("drop-only boundary was not acknowledged")
	}
}

func TestMiddleEndDiagnosticsEmitFullRetainedBatch(t *testing.T) {
	source := &diagnosticMonitorSource{snapshot: middleend.GenerationDiagnosticSnapshot{
		Records: make([]middleend.GenerationDiagnosticRecord, 256), ThroughSequence: 257, DroppedRecords: 1,
	}}
	for index := range source.snapshot.Records {
		record := diagnosticMonitorRecords()[0]
		record.Sequence, record.FailureSequence = uint64(index+1), uint64(index+1)
		source.snapshot.Records[index] = record
	}
	var output bytes.Buffer
	logger := zerolog.New(&output).Level(zerolog.InfoLevel)
	observeMiddleEndDiagnostics(source, &logger, 0)
	records := readDiagnosticJSON(t, output.String())
	if len(records) != 257 {
		t.Fatalf("emissions = %d, want 256 events plus one drop warning", len(records))
	}
	if records[0]["diagnostic_sequence"] != float64(1) || records[255]["diagnostic_sequence"] != float64(256) {
		t.Fatal("bounded batch lost its retained sequence")
	}
	if !slices.Equal(source.acknowledgements, []uint64{257}) {
		t.Fatal("acknowledgement omitted the rejected event boundary")
	}
}

func writeMiddleEndDiagnosticConsoleFixture(output io.Writer) {
	// This is the application console configuration from pkg/log/log.go.
	logger := zerolog.New(zerolog.ConsoleWriter{Out: output, TimeFormat: time.RFC3339}).
		With().Timestamp().Logger().Level(zerolog.InfoLevel)
	source := &diagnosticMonitorSource{snapshot: middleend.GenerationDiagnosticSnapshot{
		Records: diagnosticMonitorRecords(), ThroughSequence: 4, DroppedRecords: 1,
	}}
	observeMiddleEndDiagnostics(source, &logger, 0)
}

func TestMiddleEndDiagnosticsProductionConsoleFormatter(t *testing.T) {
	var output bytes.Buffer
	writeMiddleEndDiagnosticConsoleFixture(&output)
	content := output.String()
	if strings.Count(content, "\n") != 4 {
		t.Fatal("console formatter did not emit four records")
	}
	for _, expected := range []string{
		middleEndSlotFailureMessage, middleEndForcedRetirementMessage, middleEndDiagnosticsDroppedMessage,
		"diagnostic_kind=", "slot_failure", "forced_retirement", "records_dropped",
		"diagnostic_sequence=", "through_sequence=", "probe_accepted_at=", "2026-09-07T14:15:12.123456789Z",
		`"peer closed the stream"`,
	} {
		if !strings.Contains(content, expected) {
			t.Errorf("console fixture lacks %q", expected)
		}
	}
	for _, forbidden := range []string{"client_id=", "connection_id=", "endpoint=", "probe_sent_at=", "error="} {
		if strings.Contains(content, forbidden) {
			t.Errorf("console fixture includes %q", forbidden)
		}
	}
}

func TestMiddleEndDiagnosticsUnknownSafeCause(t *testing.T) {
	record := diagnosticMonitorRecords()[0]
	record.ErrorCode, record.ErrorText = "unknown", "redacted unclassified error"
	var output bytes.Buffer
	logger := zerolog.New(&output)
	emitMiddleEndDiagnostic(&logger, record)
	decoded := readDiagnosticJSON(t, output.String())[0]
	if decoded["error_code"] != "unknown" || decoded["error_text"] != "redacted unclassified error" {
		t.Fatal("monitor did not preserve the source's safe error classification")
	}
}

func TestMiddleEndDiagnosticsSeparateRepairAttempt(t *testing.T) {
	record := middleend.GenerationDiagnosticRecord{
		Kind: middleend.GenerationDiagnosticSlotRepairFailure, Sequence: 4,
		At:           time.Date(2026, time.September, 12, 12, 0, 0, 0, time.UTC),
		GenerationID: 7, Role: middleend.GenerationRoleActive, DCID: -2, Slot: 3, Incarnation: 5,
		RepairStage: middleend.GenerationSlotRepairStart, RepairDuration: 25 * time.Millisecond,
		ErrorCode: "eof", ErrorText: "peer closed the stream", NetworkOperation: "read",
	}
	var output bytes.Buffer
	logger := zerolog.New(&output).Level(zerolog.InfoLevel)
	emitMiddleEndDiagnostic(&logger, record)
	decoded := readDiagnosticJSON(t, output.String())[0]
	if decoded["message"] != middleEndSlotRepairFailureMessage || decoded["diagnostic_kind"] != "slot_repair_failure" ||
		decoded["repair_stage"] != "start" || decoded["repair_duration_ms"] != float64(25) || decoded["error_code"] != "eof" ||
		decoded["level"] != "info" || decoded["dc"] != float64(-2) || decoded["incarnation"] != float64(5) {
		t.Fatalf("repair record = %v", decoded)
	}
	for _, field := range []string{"failure_sequence", "reason", "retirement_reason", "probe_id", "age_ms", "error"} {
		if _, exists := decoded[field]; exists {
			t.Errorf("repair record included unrelated field %s", field)
		}
	}
}

func TestMiddleEndDiagnosticsZeroImpactCapacityRetirementUsesInfo(t *testing.T) {
	record := diagnosticMonitorRecords()[2]
	record.RetirementReason = middleend.GenerationRetirementRecoveryCapacity
	record.AffectedBindings = 0
	var output bytes.Buffer
	logger := zerolog.New(&output).Level(zerolog.InfoLevel)
	emitMiddleEndDiagnostic(&logger, record)
	decoded := readDiagnosticJSON(t, output.String())[0]
	if decoded["level"] != "info" || decoded["affected_bindings"] != float64(0) || decoded["retirement_reason"] != "recovery_capacity" {
		t.Fatal("zero-impact capacity retirement did not remain an INFO lifecycle record")
	}
}
