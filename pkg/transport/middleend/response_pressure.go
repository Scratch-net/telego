package middleend

import "time"

// ResponsePressureLimit identifies the first rejected response-queue check.
type ResponsePressureLimit uint8

const (
	ResponsePressureBindingItems ResponsePressureLimit = iota
	ResponsePressureBindingBytes
	ResponsePressureSlotItems
	ResponsePressureSlotBytes
	ResponsePressureManagerItems
	ResponsePressureManagerBytes
	ResponsePressureUnknown
	ResponsePressureLimitCount
)

func (limit ResponsePressureLimit) String() string {
	switch limit {
	case ResponsePressureBindingItems:
		return "binding_items"
	case ResponsePressureBindingBytes:
		return "binding_bytes"
	case ResponsePressureSlotItems:
		return "slot_items"
	case ResponsePressureSlotBytes:
		return "slot_bytes"
	case ResponsePressureManagerItems:
		return "manager_items"
	case ResponsePressureManagerBytes:
		return "manager_bytes"
	default:
		return "unknown"
	}
}

// ResponseQueueDiagnostic describes occupancy before eviction and cleanup.
type ResponseQueueDiagnostic struct {
	Items, Bytes         int
	ItemLimit, ByteLimit int
}

// ResponsePressureDiagnostic contains no binding identity or packet data.
// EvictionSequence is local to a generation and identifies an event, not a client.
type ResponsePressureDiagnostic struct {
	EvictionSequence    uint64
	ObservedAt          time.Time
	Limit               ResponsePressureLimit
	IncomingBytes       int
	IncomingDCID        DCID
	IncomingSlot        int
	IncomingIncarnation uint64
	VictimIsIncoming    bool
	Incoming            ResponseQueueDiagnostic
	Victim              ResponseQueueDiagnostic
	Slot                ResponseQueueDiagnostic // incoming physical slot
	Manager             ResponseQueueDiagnostic
	QueueNonemptySince  time.Time // victim's current nonempty interval
	LastDequeueAt       time.Time
	DequeuedItems       uint64
	DequeuedBytes       uint64
	ReadyQueued         bool
	ReadyLeased         bool
}

// ResponsePressureOutput is sampled by the client owner after eviction. It is
// deliberately separate from the manager's earlier queue snapshot. Accounted
// bytes and write calls do not establish kernel acceptance or peer delivery.
type ResponsePressureOutput struct {
	At                   time.Time
	Closing              bool
	Web                  bool
	BufferedAvailable    bool
	BufferedBytes        int
	AccountedBytes       int64
	BufferLimit          int
	SharedAccountedBytes int64
	SharedLimit          int64
	LastWriteAt          time.Time
	LastBufferDecreaseAt time.Time
	WriteBytes           uint64
	WriteEvents          uint64
	Wait                 ResponseOutputWait
	WaitSince            time.Time
	RetryPending         bool
	StallDeadline        time.Time
}

// ResponseOutputWait describes the last owner-observed reason for deferral.
type ResponseOutputWait uint8

const (
	ResponseOutputNotWaiting ResponseOutputWait = iota
	ResponseOutputClientBuffer
	ResponseOutputSharedBudget
	ResponseOutputCarrierBudget
)

func (wait ResponseOutputWait) String() string {
	switch wait {
	case ResponseOutputNotWaiting:
		return "none"
	case ResponseOutputClientBuffer:
		return "client_buffer"
	case ResponseOutputSharedBudget:
		return "shared_budget"
	case ResponseOutputCarrierBudget:
		return "carrier_budget"
	default:
		return "unknown"
	}
}

func (m *fixedBindingManager) responsePressureDiagnosticLocked(incoming, victim *clientBinding, size int) GenerationDiagnosticRecord {
	now := time.Now()
	limit := ResponsePressureUnknown
	// Match enqueueEventLocked's order, including item checks before byte checks.
	switch {
	case incoming.items >= m.limits.MaxPendingResponseItemsPerBinding:
		limit = ResponsePressureBindingItems
	case size > m.limits.MaxPendingResponseBytesPerBinding-incoming.bytes:
		limit = ResponsePressureBindingBytes
	case incoming.slot.pending >= m.limits.MaxPendingResponseItemsPerSlot:
		limit = ResponsePressureSlotItems
	case size > m.limits.MaxPendingResponseBytesPerSlot-incoming.slot.bytes:
		limit = ResponsePressureSlotBytes
	case m.pending >= m.limits.MaxPendingResponseItems:
		limit = ResponsePressureManagerItems
	case size > m.limits.MaxPendingResponseBytes-m.pendingBytes:
		limit = ResponsePressureManagerBytes
	}
	m.responseEvictionSequence++
	record := GenerationDiagnosticRecord{
		Kind: GenerationDiagnosticResponsePressure, At: now,
		GenerationID: m.generationID, Role: m.generationRole,
		DCID: victim.slot.dcID, Slot: victim.slot.ordinal, Incarnation: victim.slot.incarnation,
		AffectedBindings: 1,
		Pressure: ResponsePressureDiagnostic{
			EvictionSequence: m.responseEvictionSequence, ObservedAt: now, Limit: limit,
			IncomingBytes: size, IncomingDCID: incoming.slot.dcID,
			IncomingSlot: incoming.slot.ordinal, IncomingIncarnation: incoming.slot.incarnation,
			VictimIsIncoming:   incoming == victim,
			Incoming:           ResponseQueueDiagnostic{incoming.items, incoming.bytes, m.limits.MaxPendingResponseItemsPerBinding, m.limits.MaxPendingResponseBytesPerBinding},
			Victim:             ResponseQueueDiagnostic{victim.items, victim.bytes, m.limits.MaxPendingResponseItemsPerBinding, m.limits.MaxPendingResponseBytesPerBinding},
			Slot:               ResponseQueueDiagnostic{incoming.slot.pending, incoming.slot.bytes, m.limits.MaxPendingResponseItemsPerSlot, m.limits.MaxPendingResponseBytesPerSlot},
			Manager:            ResponseQueueDiagnostic{m.pending, m.pendingBytes, m.limits.MaxPendingResponseItems, m.limits.MaxPendingResponseBytes},
			QueueNonemptySince: victim.responseNonemptySince, LastDequeueAt: victim.responseLastDequeueAt,
			DequeuedItems: victim.responseDequeuedItems, DequeuedBytes: victim.responseDequeuedBytes,
			ReadyQueued: victim.readyQueued, ReadyLeased: victim.readyLeased,
		},
	}
	if m.responsePressureObserver != nil {
		victim.responsePressure = new(record)
	}
	return record
}

// ReportResponsePressureOutput appends at most one owner observation for this
// binding's eviction. It remains usable after terminal cleanup. The observer
// runs outside the manager lock, as do physical-link diagnostic observers.
func (b *ClientBinding) ReportResponsePressureOutput(output ResponsePressureOutput) {
	if b == nil || b.state == nil {
		return
	}
	m := b.state.manager
	m.mu.Lock()
	record := b.state.responsePressure
	b.state.responsePressure = nil
	observer := m.responsePressureObserver
	m.mu.Unlock()
	if record == nil || observer == nil {
		return
	}
	followup := *record
	followup.Kind = GenerationDiagnosticResponsePressureOutput
	followup.At = output.At
	followup.AffectedBindings = 0
	followup.PressureOutput = output
	observer(followup)
}

func (s *generationSupervisorState) recordResponsePressure(record GenerationDiagnosticRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record.Kind == GenerationDiagnosticResponsePressure {
		limit := min(record.Pressure.Limit, ResponsePressureUnknown)
		s.responsePressureEvictions[limit]++
		s.responsePressureDiscardedBytes[limit] += uint64(max(0, record.Pressure.Victim.Bytes))
	}
	s.diagnostics.append(record)
}
