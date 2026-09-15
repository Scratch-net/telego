package middleend

import (
	"errors"
	"testing"
	"time"
)

func queueResponseForTest(t *testing.T, manager *FixedBindingManager, binding *ClientBinding, size int) {
	t.Helper()
	if err := manager.state.routeEvent(binding.state.slot, LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: make([]byte, size)}); err != nil {
		t.Fatal(err)
	}
}

func TestSharedResponseBorrowingExceedsLegacyLimitsAndRecovers(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8 << 20})
	manager, binding := responseBudgetBindingForTest(t, budget)
	const count = 2000
	for turn := range 2 {
		for index := range count {
			if err := manager.state.routeEvent(binding.state.slot, LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID(), ConfirmKey: uint32(index)}); err != nil {
				t.Fatal(err)
			}
		}
		for range 5 {
			queueResponseForTest(t, manager, binding, 512<<10)
		}
		if snapshot := manager.Snapshot(); snapshot.ResponseItems != count+5 || snapshot.ResponseBytes <= 2<<20 || snapshot.ResponseBackpressureEvents != 0 {
			t.Fatalf("turn %d did not borrow beyond legacy limits: %+v", turn, snapshot)
		}
		for index := range count + 5 {
			event := nextFixedBindingEvent(t, binding)
			if index < count && (event.Kind != LinkEventSimpleAck || event.ConfirmKey != uint32(index)) {
				t.Fatalf("event %d lost ACK order", index)
			}
			if index >= count && (event.Kind != LinkEventProxyAnswer || len(event.Packet) != 512<<10) {
				t.Fatalf("event %d lost packet order", index)
			}
			event.Release()
		}
		if snapshot := budget.Snapshot(); snapshot.UsedBytes != ResponseParticipantBytes || snapshot.HighWaterBytes > snapshot.LimitBytes {
			t.Fatalf("turn %d retained drained storage: %+v", turn, snapshot)
		}
	}
}

func TestSharedResponsePressureAcrossGenerationsPreservesHealthyBinding(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 2 << 20})
	old, slow := responseBudgetBindingForTest(t, budget)
	current, healthy := responseBudgetBindingForTest(t, budget)
	queueResponseForTest(t, current, healthy, 64)
	for range 3 {
		queueResponseForTest(t, old, slow, 512<<10)
	}
	queueResponseForTest(t, current, healthy, 512<<10)
	old.state.mu.Lock()
	terminal := slow.state.terminal && errors.Is(slow.state.terminalErr, ErrFixedBindingResponseBackpressure)
	old.state.mu.Unlock()
	if !terminal || current.Snapshot().ResponseItems != 2 || current.Snapshot().SlotFailures != 0 {
		t.Fatalf("global victim isolation failed: old=%+v current=%+v", old.Snapshot(), current.Snapshot())
	}
	for _, size := range []int{64, 512 << 10} {
		event := nextFixedBindingEvent(t, healthy)
		if len(event.Packet) != size {
			t.Fatal("existing healthy response displaced")
		}
		event.Release()
	}
}

func TestSharedResponseSelectionRechecksFreedCapacity(t *testing.T) {
	charge := ResponseParticipantBytes + responsePacketEnvelopeCharge(128) + ResponseAllocationCharge(responseQueueChunkBytes)
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: charge + ResponseParticipantBytes})
	first, firstBinding := responseBudgetBindingForTest(t, budget)
	second, incoming := responseBudgetBindingForTest(t, budget)
	queueResponseForTest(t, first, firstBinding, 128)
	event := LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: incoming.ConnectionID(), Packet: make([]byte, 128)}
	second.state.mu.Lock()
	err := second.state.enqueueEventLocked(incoming.state, event)
	required := second.state.responseAdmissionAdditionalLocked(incoming.state, event)
	second.state.mu.Unlock()
	if !errors.Is(err, ErrFixedBindingResponseBackpressure) {
		t.Fatal(err)
	}
	// Capacity changes after the failed admission and its required-charge
	// calculation, before selection takes the budget lock.
	retained := nextFixedBindingEvent(t, firstBinding)
	retained.Release()
	if victim := budget.SelectPressureVictim(time.Now(), required); victim.Participant != nil || victim.RequiredReclaimBytes != 0 {
		t.Fatalf("free capacity still selected a victim: %+v", victim)
	}
	second.state.mu.Lock()
	err = second.state.enqueueEventLocked(incoming.state, event)
	second.state.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSharedResponseSelectedVictimDrainsBeforeClose(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	manager, binding := responseBudgetBindingForTest(t, budget)
	queueResponseForTest(t, manager, binding, 128)
	victim := budget.SelectPressureVictim(time.Now(), budget.Snapshot().OrdinaryLimitBytes)
	if victim.Participant != binding.state.responseParticipant {
		t.Fatal("queued owner was not selected")
	}
	event := nextFixedBindingEvent(t, binding)
	event.Release()
	if victim.TryEvict() {
		t.Fatal("selected owner was closed after its backlog drained")
	}
	queueResponseForTest(t, manager, binding, 128)
	if manager.Snapshot().ResponseItems != 1 {
		t.Fatal("drained healthy binding did not remain usable")
	}
}

func TestSharedResponseInvalidOwnershipNeverSelectsVictims(t *testing.T) {
	for _, kind := range []string{"foreign_participant", "released", "undersized"} {
		for _, full := range []bool{false, true} {
			name := kind + "/free"
			if full {
				name = kind + "/full"
			}
			t.Run(name, func(t *testing.T) {
				budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
				manager, healthy := responseBudgetBindingForTest(t, budget)
				incoming, err := manager.Bind(2)
				if err != nil {
					t.Fatal(err)
				}
				queueResponseForTest(t, manager, healthy, 128)
				capacity := 128
				if kind == "undersized" {
					capacity = 1
				}
				allocation := reserveResponseForTest(t, budget, capacity, ResponseMemoryOrdinary, ResponseMemoryDecode)
				if kind == "foreign_participant" && !allocation.AssignOwner(healthy.state.responseParticipant) {
					t.Fatal("could not establish foreign owner")
				}
				if kind == "released" {
					allocation.Release()
				}
				if full {
					snapshot := budget.Snapshot()
					filler := reserveResponseForTest(t, budget, snapshot.OrdinaryLimitBytes-snapshot.UsedBytes-ResponseAllocationCharge(0), ResponseMemoryOrdinary, ResponseMemoryOutput)
					defer filler.Release()
				}
				err = manager.state.routeEvent(incoming.state.slot, LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: incoming.ConnectionID(), Packet: make([]byte, 128), ResponseAllocation: allocation})
				if !errors.Is(err, ErrFixedBindingProtocol) || manager.Snapshot().ResponseBackpressureEvents != 0 || manager.Snapshot().ResponseItems != 1 {
					t.Fatalf("malformed ownership caused global collateral: %v, %+v", err, manager.Snapshot())
				}
			})
		}
	}
}

type responsePressureCallback func() bool

func (f responsePressureCallback) evictResponsePressure(responsePressureEvidence) bool { return f() }

func TestSharedResponseIncomingCancellationDuringGlobalEviction(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 2 << 20})
	old, slow := responseBudgetBindingForTest(t, budget)
	current, incoming := responseBudgetBindingForTest(t, budget)
	for range 3 {
		queueResponseForTest(t, old, slow, 512<<10)
	}
	participant := slow.state.responseParticipant
	budget.mu.Lock()
	participant.target = responsePressureCallback(func() bool {
		// These calls would deadlock if either manager or budget lock leaked
		// across the callback. Cancellation invalidates incoming publication.
		incoming.BeginClose()
		return slow.state.evictResponsePressure(responsePressureEvidence{})
	})
	budget.mu.Unlock()
	queueResponseForTest(t, current, incoming, 512<<10)
	if current.Snapshot().ResponseItems != 0 {
		t.Fatal("canceled incoming binding accepted a borrowed response")
	}
}

func TestSharedResponseOutputOnlyPressureDoesNotAssumeCloseCredit(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	manager, first := responseBudgetBindingForTest(t, budget)
	second, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	incoming, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	var output [2]LinkEvent
	for index, binding := range []*ClientBinding{first, second} {
		queueResponseForTest(t, manager, binding, 1024)
		output[index] = nextFixedBindingEvent(t, binding)
		if !output[index].ResponseAllocation.TryMove(ResponseMemoryOrdinary, ResponseMemoryOutput) {
			t.Fatal("could not establish retained client output")
		}
		defer output[index].Release()
	}
	snapshot := budget.Snapshot()
	filler := reserveResponseForTest(t, budget, snapshot.OrdinaryLimitBytes-snapshot.UsedBytes-ResponseAllocationCharge(0), ResponseMemoryOrdinary, ResponseMemoryOutput)
	defer filler.Release()
	before := budget.Snapshot().UsedBytes
	queueResponseForTest(t, manager, incoming, 128)
	manager.state.mu.Lock()
	firstClosed, secondClosed, incomingClosed := first.state.terminal, second.state.terminal, incoming.state.terminal
	manager.state.mu.Unlock()
	if !firstClosed || secondClosed || !incomingClosed || budget.Snapshot().UsedBytes != before {
		t.Fatalf("asynchronous output closure assumed credit or cascaded: first=%v second=%v incoming=%v budget=%+v", firstClosed, secondClosed, incomingClosed, budget.Snapshot())
	}
	output[0].Release()
	filler.Release()
	queueResponseForTest(t, manager, second, 128)
	if manager.Snapshot().ResponseItems != 1 {
		t.Fatal("existing output-only neighbor did not survive actual credit recovery")
	}
}

func TestSharedResponseClosingOwnersDoNotConsumeVictimAttempts(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 32 << 20})
	manager, victim := responseBudgetBindingForTest(t, budget)
	for range responsePressureAdmissionAttempts + 1 {
		closing, err := manager.Bind(2)
		if err != nil {
			t.Fatal(err)
		}
		queueResponseForTest(t, manager, closing, 512<<10)
		output := nextFixedBindingEvent(t, closing)
		if !output.ResponseAllocation.TryMove(ResponseMemoryOrdinary, ResponseMemoryOutput) {
			t.Fatal("could not establish retained output")
		}
		defer output.Release()
		participant := closing.state.responseParticipant
		closing.BeginClose()
		if snapshot := participant.Snapshot(); !snapshot.Detached || snapshot.OutputBytes == 0 {
			t.Fatalf("local close left retained owner eligible: %+v", snapshot)
		}
	}
	queueResponseForTest(t, manager, victim, 512<<10)
	incoming, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := budget.Snapshot()
	filler := reserveResponseForTest(t, budget, snapshot.OrdinaryLimitBytes-snapshot.UsedBytes-ResponseAllocationCharge(0), ResponseMemoryOrdinary, ResponseMemoryOutput)
	defer filler.Release()
	queueResponseForTest(t, manager, incoming, 128)
	manager.state.mu.Lock()
	victimClosed, incomingClosed := victim.state.terminal, incoming.state.terminal
	manager.state.mu.Unlock()
	if !victimClosed || incomingClosed || manager.Snapshot().ResponseItems != 1 {
		t.Fatal("closing owners exhausted bounded attempts before an eligible victim")
	}
}

func TestSharedResponseTerminalEmptyEndsParticipantTarget(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	manager, binding := responseBudgetBindingForTest(t, budget)
	queueResponseForTest(t, manager, binding, 128)
	event := nextFixedBindingEvent(t, binding)
	defer event.Release()
	if !event.ResponseAllocation.TryMove(ResponseMemoryOrdinary, ResponseMemoryOutput) {
		t.Fatal("could not establish retained output")
	}
	participant := binding.state.responseParticipant
	manager.state.mu.Lock()
	manager.state.publishBindingTerminalLocked(binding.state, errors.New("terminal while output remains"))
	retained := binding.state.responseParticipant
	manager.state.mu.Unlock()
	if snapshot := participant.Snapshot(); !snapshot.Detached || snapshot.OutputBytes == 0 || retained != nil {
		t.Fatalf("terminal-empty binding retained its lifecycle target or lost output charge: %+v", snapshot)
	}
	event.Release()
	if budget.Snapshot().UsedBytes != 0 {
		t.Fatal("detached owner did not retire after actual output release")
	}
}
