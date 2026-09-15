package middleend

import (
	"testing"
	"time"
)

func TestResponseReleaseBytesIncludesOnlyActualOwnedRefund(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	participant := responseParticipantForTest(t, budget, 1)
	first, ok := budget.TryReserveFor(participant, 128, ResponseMemoryOrdinary, ResponseMemoryOutput)
	if !ok {
		t.Fatal("first reservation failed")
	}
	second, ok := budget.TryReserveFor(participant, 64, ResponseMemoryOrdinary, ResponseMemoryQueuePayload)
	if !ok {
		t.Fatal("second reservation failed")
	}
	unrelated := reserveResponseForTest(t, budget, 512, ResponseMemoryOrdinary, ResponseMemoryOutput)
	if got := participant.detachBytes(); got != 0 {
		t.Fatalf("retained allocations refunded owner: %d", got)
	}
	if got := second.releaseBytes(); got != ResponseAllocationCharge(64) {
		t.Fatalf("queue release = %d", got)
	}
	if got := first.releaseBytes(); got != ResponseAllocationCharge(128)+ResponseParticipantBytes {
		t.Fatalf("last owned release = %d", got)
	}
	if first.releaseBytes() != 0 || participant.detachBytes() != 0 || budget.Snapshot().UsedBytes != unrelated.Bytes() {
		t.Fatal("duplicate release or unrelated credit counted")
	}
}

func TestSharedPressureTelemetryCarriesCrossManagerSelection(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 2 << 20})
	old, slow := responseBudgetBindingForTest(t, budget)
	current, healthy := responseBudgetBindingForTest(t, budget)
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	old.state.responsePressureObserver = supervisor.state.recordResponsePressure
	current.state.responsePressureObserver = supervisor.state.recordResponsePressure
	queueResponseForTest(t, current, healthy, 64)
	for range 3 {
		queueResponseForTest(t, old, slow, 512<<10)
	}
	before := budget.Snapshot()
	owner := slow.state.responseParticipant.Snapshot()
	now := time.Now()
	slow.ReportResponseProgress(now.Add(-1500*time.Millisecond), time.Time{}, 1000, ResponseOutputClientBuffer)
	slow.ReportResponseProgress(now, time.Time{}, 1000, ResponseOutputClientBuffer)
	queueResponseForTest(t, current, healthy, 512<<10)
	records := supervisor.DiagnosticSnapshot().Records
	if len(records) != 1 {
		t.Fatalf("records = %d", len(records))
	}
	p := records[0].Pressure
	if p.Limit != ResponsePressureSharedBudget || p.SelectionReason != ResponsePressureStalled || p.VictimIsIncoming ||
		p.IncomingBytes != 512<<10+ProxyAnswerHeaderSize || p.Incoming.Bytes != 64+ProxyAnswerHeaderSize ||
		p.Victim.Bytes != 3*(512<<10+ProxyAnswerHeaderSize) || p.Budget != before ||
		p.VictimRetainedBytes != owner.RetainedBytes || p.VictimUnreadBytes != 1000 ||
		!p.VictimObservationAvailable || !p.VictimProgressAvailable || p.VictimProgressAge < time.Second ||
		p.RequiredAdditionalBytes <= p.RequiredReclaimBytes || p.RequiredReclaimBytes <= 0 || p.ReclaimedBytes <= 0 ||
		p.ReclaimedBytes >= p.VictimRetainedBytes || p.Incoming.ItemLimit != 0 || p.Victim.ByteLimit != 0 {
		t.Fatalf("selection/reclamation evidence: %+v", p)
	}
	// Queue cleanup is bounded: remaining worker release is reflected only by
	// current occupancy. It does not increase immediate reclaimed counters.
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot := supervisor.Snapshot()
	if snapshot.ResponsePressureEvictions[ResponsePressureSharedBudget] != 1 ||
		snapshot.ResponsePressureSelections[ResponsePressureStalled] != 1 ||
		snapshot.ResponsePressureReclaimedBytes[ResponsePressureSharedBudget] != uint64(p.ReclaimedBytes) ||
		snapshot.ResponsePressureDiscardedBytes[ResponsePressureSharedBudget] != uint64(p.Victim.Bytes) {
		t.Fatalf("lifetime shared pressure counters: %+v", snapshot)
	}
	slow.ReportResponsePressureOutput(ResponsePressureOutput{At: time.Now(), SharedResponseBudget: true, ResponseBudget: budget.Snapshot()})
	records = supervisor.DiagnosticSnapshot().Records
	if len(records) != 2 || records[1].Pressure != p {
		t.Fatal("owner followup lost selection or final immediate reclamation")
	}
	supervisor.AcknowledgeDiagnostics(^uint64(0))
	if supervisor.Snapshot().ResponsePressureSelections != snapshot.ResponsePressureSelections {
		t.Fatal("journal acknowledgement reset lifetime selection counters")
	}
}

func TestSharedPressureImmediateReclamationIncludesFinalOwnerRecord(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	old, slow := responseBudgetBindingForTest(t, budget)
	current, incoming := responseBudgetBindingForTest(t, budget)
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	old.state.responsePressureObserver = supervisor.state.recordResponsePressure
	queueResponseForTest(t, old, slow, 128)
	owner := slow.state.responseParticipant.Snapshot()
	snapshot := budget.Snapshot()
	filler := reserveResponseForTest(t, budget, snapshot.OrdinaryLimitBytes-snapshot.UsedBytes-ResponseAllocationCharge(0), ResponseMemoryOrdinary, ResponseMemoryOutput)
	queueResponseForTest(t, current, incoming, 128)
	records := supervisor.DiagnosticSnapshot().Records
	if len(records) != 1 || records[0].Pressure.ReclaimedBytes != owner.RetainedBytes ||
		records[0].Pressure.Victim.Bytes != 128+ProxyAnswerHeaderSize || current.Snapshot().ResponseItems != 1 ||
		filler.Bytes() == 0 {
		t.Fatalf("final owner refund missing or unrelated credit included: %+v", records)
	}
}

func TestSharedPressureFallbackPreservesConcurrentTerminalResponses(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
	manager, binding := responseBudgetBindingForTest(t, budget)
	queueResponseForTest(t, manager, binding, 128)
	manager.state.mu.Lock()
	evidence := responsePressureEvidence{
		incoming: manager.state.responsePressureIncomingLocked(binding.state, LinkEvent{Kind: LinkEventSimpleAck}),
	}
	manager.state.mu.Unlock()
	if err := manager.state.routeEvent(binding.state.slot, LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: binding.ConnectionID()}); err != nil {
		t.Fatal(err)
	}
	before := budget.Snapshot()
	if binding.state.closeResponsePressure(true, evidence) || budget.Snapshot() != before {
		t.Fatal("forced incoming fallback cleared a response accepted before terminal")
	}
	first := nextFixedBindingEvent(t, binding)
	if first.Kind != LinkEventProxyAnswer || len(first.Packet) != 128 {
		t.Fatal("accepted payload order changed")
	}
	first.Release()
	last := nextFixedBindingEvent(t, binding)
	if last.Kind != LinkEventCloseExternal {
		t.Fatal("terminal close marker was lost")
	}
	last.Release()
}
