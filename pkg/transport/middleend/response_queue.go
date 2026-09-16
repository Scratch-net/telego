package middleend

import (
	"fmt"
	"unsafe"
)

const responseQueueChunkItems = 16
const responseQueueChunkBytes = int(unsafe.Sizeof(responseQueueChunk{}))

// Fixed chunks bound allocation and copying on the physical ME owner. The
// detached job link lives in already charged storage, so scheduling cleanup
// cannot allocate or fail while the response pool is full.
type responseQueueChunk struct {
	events     [responseQueueChunkItems]LinkEvent
	next       *responseQueueChunk
	jobNext    *responseQueueChunk
	head, tail int
	allocation *ResponseAllocation
}

func (m *fixedBindingManager) growSharedResponseQueueLocked(binding *clientBinding) error {
	if tail := binding.responseQueueTail; tail != nil && tail.tail < len(tail.events) {
		return nil
	}
	allocation, ok := m.responseBudget.TryReserveFor(binding.responseParticipant, responseQueueChunkBytes, ResponseMemoryOrdinary, ResponseMemoryQueueMetadata)
	if !ok {
		m.responseBackpressureEvents++
		return fmt.Errorf("%w: response chunk metadata", ErrFixedBindingResponseBackpressure)
	}
	chunk := &responseQueueChunk{allocation: allocation}
	if binding.responseQueueTail == nil {
		binding.responseQueueHead = chunk
	} else {
		binding.responseQueueTail.next = chunk
	}
	binding.responseQueueTail = chunk
	return nil
}

func (binding *clientBinding) popSharedResponseLocked() {
	chunk := binding.responseQueueHead
	chunk.events[chunk.head] = LinkEvent{}
	chunk.head++
	if chunk.head != chunk.tail {
		return
	}
	binding.responseQueueHead = chunk.next
	if binding.responseQueueHead == nil {
		binding.responseQueueTail = nil
	}
	chunk.next = nil
	allocation := chunk.allocation
	chunk.allocation = nil
	allocation.Release()
}

// Release enough actual ownership for one maximum admission, with a fixed
// entry bound. Remaining chunks stay charged until the cleanup worker clears
// them. Other owners may consume released capacity before admission retries.
func (m *fixedBindingManager) clearSharedResponseQueueLocked(binding *clientBinding) int {
	head := binding.responseQueueHead
	binding.responseQueueHead, binding.responseQueueTail = nil, nil
	if head == nil {
		return 0
	}
	byteBudget := MinimumResponseOrdinaryBytes()
	// ACKs have the smallest queued envelope; close markers live inline.
	// Ignore chunk reclamation when deriving the finite entry bound so it
	// still covers byteBudget on architectures with smaller allocation charges.
	minimumOutput, _ := ClientResponseOutputBound(LinkEventSimpleAck, 0)
	minimumCharge := ResponseAllocationCharge(minimumOutput + ResponseOutputMetadataBytes)
	itemBudget := 1 + (byteBudget-1)/minimumCharge
	remaining, freed := releaseResponseChunks(head, byteBudget, itemBudget)
	if remaining == nil {
		return freed
	}
	if m.reclaimTail == nil {
		m.reclaimHead = remaining
	} else {
		m.reclaimTail.jobNext = remaining
	}
	m.reclaimTail = remaining
	m.signalReclaimLocked()
	return freed
}

// No manager or pool lock is required: the caller owns this detached chain.
func releaseResponseChunks(head *responseQueueChunk, byteBudget, itemBudget int) (*responseQueueChunk, int) {
	freed := 0
	for head != nil && freed < byteBudget && itemBudget > 0 {
		for head.head < head.tail && freed < byteBudget && itemBudget > 0 {
			event := &head.events[head.head]
			allocation := event.ResponseAllocation
			clear(event.Packet)
			*event = LinkEvent{}
			freed += allocation.releaseBytes()
			head.head++
			itemBudget--
		}
		if head.head != head.tail {
			break
		}
		next := head.next
		head.next = nil
		allocation := head.allocation
		head.allocation = nil
		freed += allocation.releaseBytes()
		head = next
	}
	return head, freed
}

func (m *fixedBindingManager) signalReclaimLocked() {
	select {
	case m.reclaimReady <- struct{}{}:
	default:
	}
}

// At most one cleanup worker exists per manager, and the service owns at most
// two managers. Close joins the worker after links and response consumers stop.
func (m *fixedBindingManager) reclaimResponses() {
	defer close(m.reclaimDone)
	for {
		m.mu.Lock()
		job := m.reclaimHead
		if job != nil {
			m.reclaimHead = job.jobNext
			if m.reclaimHead == nil {
				m.reclaimTail = nil
			}
			job.jobNext = nil
		}
		closing := m.reclaimClosing
		m.mu.Unlock()
		if job == nil {
			if closing {
				return
			}
			<-m.reclaimReady
			continue
		}
		for job != nil {
			job, _ = releaseResponseChunks(job, int(^uint(0)>>1), responseQueueChunkItems)
		}
	}
}
