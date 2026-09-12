package main

import (
	"time"

	"github.com/rs/zerolog"

	"github.com/scratch-net/telego/pkg/log"
	"github.com/scratch-net/telego/pkg/transport/middleend"
)

const (
	middleEndSlotFailureMessage        = "Middle-End physical link failed"
	middleEndSlotRepairFailureMessage  = "Middle-End physical-link replacement attempt failed"
	middleEndSlotSocketMessage         = "Middle-End physical-link close evidence"
	middleEndForcedRetirementMessage   = "Middle-End capacity retirement closed a generation"
	middleEndDiagnosticsDroppedMessage = "Middle-End diagnostic journal dropped records"
)

type middleEndDiagnosticSource interface {
	DiagnosticSnapshot() middleend.GenerationDiagnosticSnapshot
	AcknowledgeDiagnostics(uint64)
}

type middleEndDiagnosticLogger interface {
	Info() *zerolog.Event
	Warn() *zerolog.Event
}

type middleEndApplicationLogger struct{}

func (middleEndApplicationLogger) Info() *zerolog.Event { return log.Info() }
func (middleEndApplicationLogger) Warn() *zerolog.Event { return log.Warn() }

// observeMiddleEndDiagnostics emits a copied journal without holding source locks.
// Acknowledgement marks logger emission, not durable storage. Later events remain.
func observeMiddleEndDiagnostics(source middleEndDiagnosticSource, logger middleEndDiagnosticLogger, previousDropped uint64) uint64 {
	snapshot := source.DiagnosticSnapshot()
	for _, record := range snapshot.Records {
		emitMiddleEndDiagnostic(logger, record)
	}
	if dropped := middleEndCounterIncrease(snapshot.DroppedRecords, previousDropped); dropped > 0 {
		logger.Warn().
			Str("diagnostic_kind", "records_dropped").
			Uint64("through_sequence", snapshot.ThroughSequence).
			Uint64("acknowledged_through", snapshot.AcknowledgedThrough).
			Uint64("new_dropped_records", dropped).
			Uint64("dropped_records_total", snapshot.DroppedRecords).
			Msg(middleEndDiagnosticsDroppedMessage)
	}
	source.AcknowledgeDiagnostics(snapshot.ThroughSequence)
	return max(previousDropped, snapshot.DroppedRecords)
}

func emitMiddleEndDiagnostic(logger middleEndDiagnosticLogger, record middleend.GenerationDiagnosticRecord) {
	var event *zerolog.Event
	if middleEndSlotFailureHasClientImpact(uint64(max(0, record.AffectedBindings))) {
		event = logger.Warn()
	} else {
		event = logger.Info()
	}
	event = event.
		Str("diagnostic_kind", string(record.Kind)).
		Uint64("diagnostic_sequence", record.Sequence).
		Str("observed_at", record.At.UTC().Format(time.RFC3339Nano)).
		Uint64("generation_id", record.GenerationID).
		Str("role", string(record.Role))
	if record.Kind == middleend.GenerationDiagnosticSlotSocket {
		emitMiddleEndTransport(event, record.Transport)
		event.
			Int("dc", int(record.DCID)).
			Int("slot", record.Slot).
			Uint64("incarnation", record.Incarnation).
			Str("failure_observed_at", record.FailureObservedAt.UTC().Format(time.RFC3339Nano)).
			Msg(middleEndSlotSocketMessage)
		return
	}
	event.Int("affected_bindings", record.AffectedBindings)
	if record.Kind == middleend.GenerationDiagnosticForcedRetirement {
		event.
			Str("retirement_reason", string(record.RetirementReason)).
			Msg(middleEndForcedRetirementMessage)
		return
	}
	if record.Kind == middleend.GenerationDiagnosticSlotRepairFailure {
		emitMiddleEndTransport(event, record.Transport)
		event.
			Str("transport_subject", "replacement_candidate").
			Int("dc", int(record.DCID)).
			Int("slot", record.Slot).
			Uint64("incarnation", record.Incarnation).
			Str("repair_stage", string(record.RepairStage)).
			Int64("repair_duration_ms", max(0, record.RepairDuration.Milliseconds())).
			Str("error_code", record.ErrorCode).
			Str("error_text", record.ErrorText).
			Str("network_operation", record.NetworkOperation).
			Uint64("errno", record.Errno).
			Msg(middleEndSlotRepairFailureMessage)
		return
	}
	// The source classifies errors before journal retention. No raw error or
	// operational snapshot enters this path. Accepted means local queue acceptance.
	emitMiddleEndTransport(event, record.Transport)
	event.
		Uint64("failure_sequence", record.FailureSequence).
		Int("dc", int(record.DCID)).
		Int("slot", record.Slot).
		Uint64("incarnation", record.Incarnation).
		Str("reason", string(record.Reason)).
		Str("error_code", record.ErrorCode).
		Str("error_text", record.ErrorText).
		Str("network_operation", record.NetworkOperation).
		Uint64("errno", record.Errno).
		Int64("age_ms", max(0, record.Age.Milliseconds())).
		Bool("used", record.Used).
		Bool("peer_eof", record.PeerEOF).
		Uint64("probe_id", record.ProbeID).
		Str("probe_queued_at", record.ProbeQueuedAt.UTC().Format(time.RFC3339Nano)).
		Str("probe_accepted_at", record.ProbeAcceptedAt.UTC().Format(time.RFC3339Nano)).
		Str("probe_deadline", record.ProbeDeadline.UTC().Format(time.RFC3339Nano)).
		Str("last_pong_at", record.LastPongAt.UTC().Format(time.RFC3339Nano)).
		Bool("probe_pending", record.ProbePending).
		Int("request_items", record.RequestItems).
		Int("request_bytes", record.RequestBytes).
		Int("control_items", record.ControlItems).
		Int("control_bytes", record.ControlBytes).
		Int("response_items", record.ResponseItems).
		Int("response_bytes", record.ResponseBytes).
		Msg(middleEndSlotFailureMessage)
}
