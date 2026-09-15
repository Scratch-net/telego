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
	ResponsePressureSharedBudget
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
	case ResponsePressureSharedBudget:
		return "shared_budget"
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
	// Shared values are immutable selection evidence. ReclaimedBytes counts
	// only the synchronous cleanup performed by this eviction.
	Budget                     ResponseBudgetSnapshot
	SelectionAt                time.Time
	SelectionReason            ResponsePressureSelectionReason
	RequiredAdditionalBytes    int
	RequiredReclaimBytes       int
	FairShareBytes             int
	ScannedParticipants        int
	VictimRetainedBytes        int
	VictimQueuedBytes          int
	VictimInflightBytes        int
	VictimOutputBytes          int
	VictimUnreadBytes          int
	VictimWait                 ResponseOutputWait
	VictimObservationAvailable bool
	VictimObservationAge       time.Duration
	VictimProgressAvailable    bool
	VictimProgressAge          time.Duration
	ReclaimedBytes             int
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
	SharedResponseBudget bool
	ResponseBudget       ResponseBudgetSnapshot
}

// These values cross manager locks without retaining another manager or client.
type responsePressureIncoming struct {
	connectionID                   int64
	bytes                          int
	dcID                           DCID
	slot                           int
	incarnation                    uint64
	queue, slotQueue, managerQueue ResponseQueueDiagnostic
}

type responsePressureEvidence struct {
	incoming                                                responsePressureIncoming
	budget                                                  ResponseBudgetSnapshot
	selectedAt                                              time.Time
	reason                                                  ResponsePressureSelectionReason
	requiredAdditional, requiredReclaim, fairShare, scanned int
	victim                                                  ResponseParticipantSnapshot
}

func (e responsePressureEvidence) apply(p *ResponsePressureDiagnostic, victimID int64) {
	p.IncomingBytes, p.IncomingDCID = e.incoming.bytes, e.incoming.dcID
	p.IncomingSlot, p.IncomingIncarnation = e.incoming.slot, e.incoming.incarnation
	p.VictimIsIncoming = e.incoming.connectionID == victimID
	p.Incoming, p.Slot, p.Manager = e.incoming.queue, e.incoming.slotQueue, e.incoming.managerQueue
	p.Budget, p.SelectionAt, p.SelectionReason = e.budget, e.selectedAt, e.reason
	p.RequiredAdditionalBytes, p.RequiredReclaimBytes = e.requiredAdditional, e.requiredReclaim
	p.FairShareBytes, p.ScannedParticipants = e.fairShare, e.scanned
	p.VictimRetainedBytes, p.VictimQueuedBytes = e.victim.RetainedBytes, e.victim.QueuedBytes
	p.VictimInflightBytes, p.VictimOutputBytes = e.victim.InflightBytes, e.victim.OutputBytes
	p.VictimUnreadBytes, p.VictimWait = e.victim.UnreadBytes, e.victim.Wait
	p.VictimObservationAvailable = !e.victim.ObservedAt.IsZero() && !e.victim.ObservedAt.After(e.selectedAt)
	if p.VictimObservationAvailable {
		p.VictimObservationAge = e.selectedAt.Sub(e.victim.ObservedAt)
	}
	p.VictimProgressAvailable = !e.victim.LastProgressAt.IsZero() && !e.victim.LastProgressAt.After(e.selectedAt)
	if p.VictimProgressAvailable {
		p.VictimProgressAge = e.selectedAt.Sub(e.victim.LastProgressAt)
	}
}

// ResponseOutputWait describes the last owner-observed reason for deferral.
type ResponseOutputWait uint8

const (
	ResponseOutputNotWaiting ResponseOutputWait = iota
	ResponseOutputClientBuffer
	ResponseOutputSharedBudget
	ResponseOutputCarrierBudget
	ResponseOutputProcessingReserve
	ResponseOutputWaitCount
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
	case ResponseOutputProcessingReserve:
		return "processing_reserve"
	default:
		return "unknown"
	}
}

func (m *fixedBindingManager) responsePressureDiagnosticLocked(incoming, victim *clientBinding, size int) GenerationDiagnosticRecord {
	now := time.Now()
	limit := ResponsePressureUnknown
	// Match enqueueEventLocked's order, including item checks before byte checks.
	switch {
	case m.responseBudget != nil:
		limit = ResponsePressureSharedBudget
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
	if m.responseBudget != nil {
		for _, queue := range []*ResponseQueueDiagnostic{&record.Pressure.Incoming, &record.Pressure.Victim, &record.Pressure.Slot, &record.Pressure.Manager} {
			queue.ItemLimit, queue.ByteLimit = 0, 0
		}
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
		s.responsePressureReclaimedBytes[limit] += uint64(max(0, record.Pressure.ReclaimedBytes))
		if limit == ResponsePressureSharedBudget && record.Pressure.SelectionReason < ResponsePressureSelectionReasonCount {
			s.responsePressureSelections[record.Pressure.SelectionReason]++
		}
	}
	s.diagnostics.append(record)
}
