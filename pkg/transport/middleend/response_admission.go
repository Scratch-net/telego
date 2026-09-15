package middleend

import (
	"errors"
	"fmt"
	"time"
)

const responsePressureAdmissionAttempts = 4

// MinimumResponseOrdinaryBytes admits one maximum response and its first queue
// chunk and owner record. Processing capacity is a separate protected reserve.
func MinimumResponseOrdinaryBytes() int {
	maximum, _ := ClientResponseOutputBound(LinkEventProxyAnswer, MaxClientPacketSize)
	return ResponseParticipantBytes + ResponseAllocationCharge(maximum+ResponseOutputMetadataBytes) +
		ResponseAllocationCharge(responseQueueChunkBytes)
}

// ReportResponseProgress publishes owner observations without exposing the
// frontend endpoint. Accepted writes do not establish output drain progress.
func (b *ClientBinding) ReportResponseProgress(observedAt, lastProgress time.Time, unreadBytes int, wait ResponseOutputWait) {
	if b == nil || b.state == nil {
		return
	}
	m := b.state.manager
	m.mu.Lock()
	participant := b.state.responseParticipant
	m.mu.Unlock()
	participant.ReportProgress(observedAt, lastProgress, unreadBytes, wait)
}

// The binding must stop retaining the record when its lifecycle target ends.
// Outstanding allocation handles retain and charge the detached record.
func (binding *clientBinding) detachResponseParticipantLocked() int {
	participant := binding.responseParticipant
	binding.responseParticipant = nil
	return participant.detachBytes()
}

// The caller holds m.mu and has already failed admission. Each attempt selects
// under the pool lock, evicts outside every manager lock, and retries against
// actual released capacity. The borrowed incoming event never leaves this call.
func (m *fixedBindingManager) retrySharedResponseLocked(slot *fixedBindingSlot, events <-chan LinkEvent, binding *clientBinding, event LinkEvent) error {
	for range responsePressureAdmissionAttempts {
		required := m.responseAdmissionAdditionalLocked(binding, event)
		incoming := m.responsePressureIncomingLocked(binding, event)
		m.mu.Unlock()
		victim := m.responseBudget.SelectPressureVictim(time.Now(), required)
		_ = victim.tryEvict(incoming)
		m.mu.Lock()
		if !m.responseIncomingValidLocked(slot, events, binding) {
			m.mu.Unlock()
			event.Release()
			return nil
		}
		if err := m.enqueueEventLocked(binding, event); err == nil {
			m.mu.Unlock()
			return nil
		} else if !errors.Is(err, ErrFixedBindingResponseBackpressure) {
			m.mu.Unlock()
			event.Release()
			return err
		}
		if victim.Participant == nil && victim.RequiredReclaimBytes > 0 {
			break
		}
	}
	// No asynchronous close or detached cleanup counts as reclaimed credit.
	// If bounded attempts cannot admit this response, close its own binding.
	budget := m.responseBudget.Snapshot()
	required := m.responseAdmissionAdditionalLocked(binding, event)
	evidence := responsePressureEvidence{
		incoming: m.responsePressureIncomingLocked(binding, event), budget: budget,
		selectedAt: time.Now(), reason: ResponsePressureIncomingFallback,
		requiredAdditional: required, requiredReclaim: max(0, required-(budget.OrdinaryLimitBytes-budget.ClassBytes[ResponseMemoryOrdinary])),
		victim: binding.responseParticipant.Snapshot(),
	}
	m.mu.Unlock()
	_ = binding.closeResponsePressure(true, evidence)
	event.Release()
	return nil
}

func (m *fixedBindingManager) responsePressureIncomingLocked(binding *clientBinding, event LinkEvent) responsePressureIncoming {
	return responsePressureIncoming{
		connectionID: binding.connectionID, bytes: event.ByteSize(), dcID: binding.slot.dcID,
		slot: binding.slot.ordinal, incarnation: binding.slot.incarnation,
		queue:        ResponseQueueDiagnostic{Items: binding.items, Bytes: binding.bytes},
		slotQueue:    ResponseQueueDiagnostic{Items: binding.slot.pending, Bytes: binding.slot.bytes},
		managerQueue: ResponseQueueDiagnostic{Items: m.pending, Bytes: m.pendingBytes},
	}
}

func (m *fixedBindingManager) responseIncomingValidLocked(slot *fixedBindingSlot, events <-chan LinkEvent, binding *clientBinding) bool {
	return m.state != fixedBindingManagerClosing && m.state != fixedBindingManagerClosed &&
		!slot.failed && !slot.retired && (events == nil || slot.events == events) &&
		m.byID[binding.connectionID] == binding && binding.slot == slot &&
		!binding.terminal && !binding.localClosing
}

func (m *fixedBindingManager) responseAdmissionAdditionalLocked(binding *clientBinding, event LinkEvent) int {
	descriptor := event
	adopt := event.ResponseAllocation != nil && event.ResponseAllocation.budget == m.responseBudget
	if !adopt {
		descriptor.Packet = descriptor.Packet[:len(descriptor.Packet):len(descriptor.Packet)]
	}
	capacity, err := responseEventAllocationCapacity(descriptor)
	if err != nil {
		return 0
	}
	required := ResponseAllocationCharge(capacity)
	if adopt {
		required = max(0, required-event.ResponseAllocation.OrdinaryBytes())
	}
	if binding.responseParticipant == nil {
		required += ResponseParticipantBytes
	}
	if tail := binding.responseQueueTail; tail == nil || tail.tail == len(tail.events) {
		required += ResponseAllocationCharge(responseQueueChunkBytes)
	}
	return required
}

// Selection never owns the client endpoint. Publishing terminal readiness makes
// its owner close output asynchronously; only cleared queue allocations release
// immediately. No lifecycle or socket completion is awaited here.
func (binding *clientBinding) evictResponsePressure(evidence responsePressureEvidence) bool {
	return binding.closeResponsePressure(false, evidence)
}

func (binding *clientBinding) closeResponsePressure(incoming bool, evidence responsePressureEvidence) bool {
	m := binding.manager
	m.mu.Lock()
	// A terminal event can win after the incoming manager releases its lock.
	// Preserve its accepted responses and ordered close marker in that case.
	if incoming && (!m.responseIncomingValidLocked(binding.slot, nil, binding) || binding.slot.incarnation != evidence.incoming.incarnation) {
		m.mu.Unlock()
		return false
	}
	if !binding.resident || binding.localClosing || binding.closeSet ||
		binding.terminal && !binding.hasResponseLocked() {
		if binding.terminal && !binding.hasResponseLocked() {
			binding.detachResponseParticipantLocked()
		}
		m.mu.Unlock()
		return false
	}
	if !incoming {
		// The selected owner may have drained while the caller released locks.
		// Queue metadata and old progress observations do not prove backlog.
		snapshot := binding.responseParticipant.Snapshot()
		if binding.items == 0 && snapshot.OutputBytes == 0 {
			m.mu.Unlock()
			return false
		}
	}
	record := m.responsePressureDiagnosticLocked(binding, binding, 0)
	evidence.apply(&record.Pressure, binding.connectionID)
	// Detach before release lets the last synchronous queue release account
	// for its owner record. Later worker/output releases are not credited here.
	reclaimed := binding.detachResponseParticipantLocked()
	reclaimed += m.evictBackpressuredBindingLocked(binding, fmt.Errorf("%w: shared retained allocation budget", ErrFixedBindingResponseBackpressure))
	record.Pressure.ReclaimedBytes = reclaimed
	if binding.responsePressure != nil {
		*binding.responsePressure = record
	}
	var controlErr error
	if !binding.remoteClosed && !binding.slot.failed && !binding.slot.retired &&
		m.state != fixedBindingManagerClosing && m.state != fixedBindingManagerClosed {
		controlErr = m.queueControlLocked(binding.slot, nil, binding.connectionID)
	}
	observer := m.responsePressureObserver
	m.mu.Unlock()
	if observer != nil {
		observer(record)
	}
	if errors.Is(controlErr, ErrFixedBindingSubmissionIDExhausted) {
		m.exhaustSubmissionIDs()
	}
	return true
}
