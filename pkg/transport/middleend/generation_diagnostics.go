package middleend

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

// GenerationRole is the manager role at the diagnostic claim, not delivery.
type GenerationRole string

const (
	GenerationRoleCandidate GenerationRole = "candidate"
	GenerationRoleActive    GenerationRole = "active"
	GenerationRoleRetiring  GenerationRole = "retiring"
)

// GenerationDiagnosticKind identifies one bounded diagnostic event class.
type GenerationDiagnosticKind string

const (
	GenerationDiagnosticSlotFailure       GenerationDiagnosticKind = "slot_failure"
	GenerationDiagnosticSlotRepairFailure GenerationDiagnosticKind = "slot_repair_failure"
	GenerationDiagnosticSlotSocket        GenerationDiagnosticKind = "slot_socket"
	GenerationDiagnosticForcedRetirement  GenerationDiagnosticKind = "forced_retirement"
)

// GenerationSlotRepairStage identifies the operation which rejected a replacement.
type GenerationSlotRepairStage string

const (
	GenerationSlotRepairWaitConsumer GenerationSlotRepairStage = "wait_consumer"
	GenerationSlotRepairConstruct    GenerationSlotRepairStage = "construct"
	GenerationSlotRepairValidate     GenerationSlotRepairStage = "validate"
	GenerationSlotRepairStart        GenerationSlotRepairStage = "start"
	GenerationSlotRepairProbe        GenerationSlotRepairStage = "probe"
	GenerationSlotRepairPublish      GenerationSlotRepairStage = "publish"
)

// GenerationDiagnosticRecord contains values only: no raw errors, endpoints,
// client identities, packets, or callbacks. Slot is a zero-based logical ordinal.
// At records local observation time; Sequence records supervisor arrival order.
type GenerationDiagnosticRecord struct {
	Sequence        uint64
	FailureSequence uint64
	Kind            GenerationDiagnosticKind
	At              time.Time
	GenerationID    uint64
	Role            GenerationRole
	DCID            DCID
	Slot            int
	Incarnation     uint64
	// Socket follow-ups correlate by the original physical identity and claim
	// time, not FailureSequence, which only the supervisor can assign globally.
	FailureObservedAt time.Time
	// Repair records describe the rejected candidate's transport. Other records
	// describe the failed incumbent. Socket.At can follow the failure claim.
	Transport LinkTransportSnapshot
	// Repair failures identify the failed incumbent, not an unpublished candidate.
	RepairStage      GenerationSlotRepairStage
	RepairDuration   time.Duration
	Reason           FixedBindingSlotFailureReason
	RetirementReason GenerationRetirementReason
	AffectedBindings int
	ErrorCode        string
	ErrorText        string
	NetworkOperation string
	Errno            uint64
	Age              time.Duration
	Used             bool
	PeerEOF          bool
	ProbeID          uint64
	ProbeQueuedAt    time.Time
	// ProbeAcceptedAt records successful local TrySubmit, not transmission.
	ProbeAcceptedAt time.Time
	ProbeDeadline   time.Time
	LastPongAt      time.Time
	ProbePending    bool
	RequestItems    int
	RequestBytes    int
	ControlItems    int
	ControlBytes    int
	ResponseItems   int
	ResponseBytes   int
}

// GenerationDiagnosticSnapshot is a non-destructive copy of unacknowledged
// records. ThroughSequence includes events rejected by the full journal.
type GenerationDiagnosticSnapshot struct {
	Records             []GenerationDiagnosticRecord
	ThroughSequence     uint64
	AcknowledgedThrough uint64
	DroppedRecords      uint64
}

const generationDiagnosticCapacity = 256

// The supervisor lock protects the journal. A full journal keeps the earliest
// unseen records and rejects new ones until the monitor acknowledges a boundary.
type generationDiagnosticJournal struct {
	records      [generationDiagnosticCapacity]GenerationDiagnosticRecord
	head         int
	count        int
	sequence     uint64
	acknowledged uint64
	dropped      uint64
}

func (j *generationDiagnosticJournal) append(record GenerationDiagnosticRecord) {
	j.sequence++
	if j.count == len(j.records) {
		j.dropped++
		return
	}
	record.Sequence = j.sequence
	j.records[(j.head+j.count)%len(j.records)] = record
	j.count++
}

func (j *generationDiagnosticJournal) snapshot() GenerationDiagnosticSnapshot {
	snapshot := GenerationDiagnosticSnapshot{
		Records:             make([]GenerationDiagnosticRecord, j.count),
		ThroughSequence:     j.sequence,
		AcknowledgedThrough: j.acknowledged,
		DroppedRecords:      j.dropped,
	}
	for index := range j.count {
		snapshot.Records[index] = j.records[(j.head+index)%len(j.records)]
	}
	return snapshot
}

func (j *generationDiagnosticJournal) acknowledge(through uint64) {
	through = min(through, j.sequence)
	if through <= j.acknowledged {
		return
	}
	for j.count != 0 && j.records[j.head].Sequence <= through {
		j.records[j.head] = GenerationDiagnosticRecord{}
		j.head = (j.head + 1) % len(j.records)
		j.count--
	}
	j.acknowledged = through
}

type generationDiagnosticError struct {
	code      string
	text      string
	operation string
	errno     uint64
}

// Specific causes precede generic manager wrappers. Text is deliberately fixed:
// arbitrary Error methods and network addresses never enter diagnostics.
var generationDiagnosticErrors = [...]struct {
	cause error
	code  string
	text  string
}{
	{io.EOF, "eof", "peer closed the stream"},
	{io.ErrUnexpectedEOF, "unexpected_eof", "stream ended before the expected data"},
	{io.ErrShortWrite, "short_write", "write accepted fewer bytes than requested"},
	{io.ErrNoProgress, "no_progress", "read returned no data or terminal result"},
	{context.DeadlineExceeded, "deadline_exceeded", "operation deadline expired"},
	{context.Canceled, "canceled", "operation was canceled"},
	{net.ErrClosed, "network_closed", "network connection is closed"},
	{ErrInvalidFrameSize, "invalid_frame_size", "invalid frame size"},
	{ErrFrameTooLarge, "frame_too_large", "frame exceeds the size limit"},
	{ErrChecksumMismatch, "checksum_mismatch", "frame checksum mismatch"},
	{ErrSequenceMismatch, "sequence_mismatch", "frame sequence mismatch"},
	{ErrSequenceExhausted, "sequence_exhausted", "frame sequence is exhausted"},
	{ErrIncompleteFrame, "incomplete_frame", "incomplete frame"},
	{ErrIncompleteBlock, "incomplete_block", "incomplete encrypted block"},
	{ErrInvalidPlaintext, "invalid_plaintext", "invalid encrypted block plaintext"},
	{ErrInvalidNonce, "invalid_nonce", "invalid nonce packet"},
	{ErrKeySelector, "key_selector", "key selector mismatch"},
	{ErrTimestampSkew, "timestamp_skew", "nonce timestamp exceeds allowed skew"},
	{ErrInvalidHandshake, "invalid_handshake", "invalid handshake packet"},
	{ErrProcessIDMismatch, "process_id_mismatch", "handshake process identity mismatch"},
	{ErrInvalidRPCPayload, "invalid_rpc_payload", "invalid RPC payload"},
	{ErrUnsupportedRPC, "unsupported_rpc", "unsupported RPC operation"},
	{ErrInvalidRPCFlags, "invalid_rpc_flags", "invalid RPC flags"},
	{ErrInvalidTLString, "invalid_tl_string", "invalid TL string"},
	{ErrChecksumTransition, "checksum_transition", "invalid checksum transition"},
	{ErrUnexpectedPong, "unexpected_pong", "unexpected probe response"},
	{ErrBootstrapIncomplete, "bootstrap_incomplete", "bootstrap did not complete"},
	{ErrBootstrapState, "bootstrap_state", "invalid bootstrap state"},
	{ErrLinkEventBackpressure, "link_event_backpressure", "link event queue is full"},
	{ErrLinkSubmissionTooLarge, "link_submission_too_large", "link submission exceeds the byte limit"},
	{ErrLinkBackpressure, "link_backpressure", "link submission queue is full"},
	{ErrInvalidLinkSubmission, "invalid_link_submission", "invalid link submission"},
	{ErrUnexpectedLinkRPC, "unexpected_link_rpc", "unexpected link RPC"},
	{ErrGnetOutboundBackpressure, "gnet_outbound_backpressure", "gnet outbound buffer is full"},
	{ErrGnetControlItemBackpressure, "gnet_control_item_backpressure", "gnet control item queue is full"},
	{ErrGnetControlByteBackpressure, "gnet_control_byte_backpressure", "gnet control byte queue is full"},
	{ErrGnetRuntimeStopped, "gnet_runtime_stopped", "gnet runtime is stopped"},
	{ErrFixedBindingResponseBackpressure, "response_backpressure", "manager response queue is full"},
	{ErrFixedBindingControlBackpressure, "control_backpressure", "manager control queue is full"},
	{ErrFixedBindingProtocol, "routing_protocol", "manager routing protocol failure"},
	{ErrFixedBindingConnectionIDExhausted, "connection_id_exhausted", "connection identities are exhausted"},
	{ErrFixedBindingSubmissionIDExhausted, "submission_id_exhausted", "submission identities are exhausted"},
	{ErrFixedBindingWaitTicketExhausted, "wait_ticket_exhausted", "wait tickets are exhausted"},
	{ErrFixedBindingEpochExhausted, "epoch_exhausted", "binding epochs are exhausted"},
	{ErrFixedBindingProbeIDExhausted, "probe_id_exhausted", "probe identities are exhausted"},
}

func classifyGenerationDiagnosticError(cause error) generationDiagnosticError {
	result := generationDiagnosticError{code: "unknown", text: "redacted unclassified error", operation: "unknown"}
	if operation, ok := errors.AsType[*net.OpError](cause); ok {
		if operation == nil {
			return result
		}
		switch operation.Op {
		case "read", "write", "dial", "accept":
			result.operation = operation.Op
		}
	}
	if errno, ok := errors.AsType[syscall.Errno](cause); ok {
		result.errno = uint64(errno)
	}
	for _, entry := range generationDiagnosticErrors {
		if errors.Is(cause, entry.cause) {
			result.code, result.text = entry.code, entry.text
			return result
		}
	}
	if result.errno != 0 {
		result.code, result.text = "errno", syscall.Errno(result.errno).Error()
		return result
	}
	for _, entry := range [...]struct {
		cause error
		code  string
		text  string
	}{
		{ErrLinkClosed, "link_closed", "link is closed"},
		{ErrLinkNotReady, "link_not_ready", "link is not ready"},
		{ErrFixedBindingManagerClosed, "manager_closed", "manager is closed"},
		{ErrFixedBindingManagerQuiesced, "manager_quiesced", "manager is not admitting bindings"},
		{ErrFixedBindingSlotFailed, "slot_failed", "physical link failed"},
		{ErrFixedBindingSlotRepair, "slot_repair", "physical link replacement failed"},
	} {
		if errors.Is(cause, entry.cause) {
			result.code, result.text = entry.code, entry.text
			return result
		}
	}
	return result
}

// DiagnosticSnapshot copies the journal without acknowledging records. This is
// separate from Snapshot to keep routine metrics reads independent of journal size.
func (s *FixedBindingGenerationSupervisor) DiagnosticSnapshot() GenerationDiagnosticSnapshot {
	if s == nil || s.state == nil {
		return GenerationDiagnosticSnapshot{}
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	return s.state.diagnostics.snapshot()
}

// AcknowledgeDiagnostics releases records through a copied boundary. Only the
// primary monitor calls this after logger emission; it does not prove durability.
func (s *FixedBindingGenerationSupervisor) AcknowledgeDiagnostics(through uint64) {
	if s == nil || s.state == nil {
		return
	}
	s.state.mu.Lock()
	s.state.diagnostics.acknowledge(through)
	s.state.mu.Unlock()
}
