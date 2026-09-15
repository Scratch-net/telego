package middleend

import (
	"errors"
	"testing"
	"time"
)

func TestSharedResponseQueueMaximumTinyEventsHasBoundedReclamation(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 64 << 20})
	manager, binding := responseBudgetBindingForTest(t, budget)
	event := LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID()}
	m := manager.state
	m.mu.Lock()
	count := 0
	start := time.Now()
	for {
		err := m.enqueueEventLocked(binding.state, event)
		if err != nil {
			if !errors.Is(err, ErrFixedBindingResponseBackpressure) {
				m.mu.Unlock()
				t.Fatal(err)
			}
			break
		}
		count++
	}
	fillDuration := time.Since(start)
	before := budget.Snapshot()
	start = time.Now()
	m.clearBindingQueueLocked(binding.state)
	clearDuration := time.Since(start)
	after := budget.Snapshot()
	pending := m.reclaimHead != nil
	if !pending || binding.state.responseQueueHead != nil || binding.state.items != 0 || after.UsedBytes <= ResponseParticipantBytes {
		m.mu.Unlock()
		t.Fatal("large queue did not detach with retained cleanup ownership")
	}
	// The worker cannot acquire this lock yet. Only the bounded synchronous
	// turn can have released allocations. One final ACK/chunk may overshoot.
	freed := before.UsedBytes - after.UsedBytes
	if freed < MinimumResponseOrdinaryBytes() || freed > MinimumResponseOrdinaryBytes()+responseAckEnvelopeCharge()+ResponseAllocationCharge(responseQueueChunkBytes) {
		m.mu.Unlock()
		t.Fatalf("synchronous reclamation not bounded: %d", freed)
	}
	m.mu.Unlock()
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.reclaimDone:
	default:
		t.Fatal("manager shutdown did not join cleanup worker")
	}
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.Allocations != 0 || snapshot.HighWaterBytes > snapshot.LimitBytes {
		t.Fatalf("cleanup leaked ownership: %+v", snapshot)
	}
	t.Logf("64 MiB admits %d ACKs; fill=%s bounded clear=%s released=%d B chunk=%d B participant=%d B", count, fillDuration, clearDuration, freed, ResponseAllocationCharge(responseQueueChunkBytes), ResponseParticipantBytes)
}

func TestSharedResponseQueueThousandBindingMetadata(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8 << 20})
	limits := fixedBindingTestLimits()
	limits.MaxResidentBindings, limits.MaxResidentBindingsPerSlot = 1000, 1000
	manager, err := NewFixedBindingManagerWithResponseBudget([]FixedBindingSlot{{DCID: 2, Link: newFixedBindingFakeLink()}}, limits, budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	for range 1000 {
		binding, err := manager.Bind(2)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.state.routeEvent(binding.state.slot, LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID()}); err != nil {
			t.Fatal(err)
		}
	}
	want := 1000 * (ResponseParticipantBytes + ResponseAllocationCharge(responseQueueChunkBytes) + responseAckEnvelopeCharge())
	snapshot := budget.Snapshot()
	if snapshot.UsedBytes != want || snapshot.HighWaterBytes != want || manager.Snapshot().ResponseItems != 1000 || manager.Snapshot().ResponseBackpressureEvents != 0 {
		t.Fatalf("1000 one-ACK bindings used unexpected storage: %+v", snapshot)
	}
	t.Logf("1000 one-ACK bindings: total=%d B queue metadata=%d B participant metadata=%d B", snapshot.UsedBytes, snapshot.StageBytes[ResponseMemoryQueueMetadata], snapshot.StageBytes[ResponseMemoryOwnerMetadata])
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.Participants != 0 {
		t.Fatalf("thousand-binding shutdown leaked: %+v", snapshot)
	}
}
