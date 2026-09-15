package middleend

import (
	"io"
	"testing"
)

func TestResponseCloseMarkerSurvivesFullPoolInOrder(t *testing.T) {
	for _, tokenMode := range []bool{false, true} {
		name := "blocking"
		if tokenMode {
			name = "token"
		}
		t.Run(name, func(t *testing.T) {
			budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192})
			manager, binding := responseBudgetBindingForTest(t, budget)
			if err := manager.state.routeEvent(binding.state.slot, LinkEvent{
				Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: []byte{1, 2, 3, 4},
			}); err != nil {
				t.Fatal(err)
			}
			free := budget.Snapshot().OrdinaryLimitBytes - budget.Snapshot().UsedBytes
			filler := reserveResponseForTest(t, budget, free-ResponseAllocationCharge(0), ResponseMemoryOrdinary, ResponseMemoryOutput)
			defer filler.Release()
			before := budget.Snapshot()
			if err := manager.state.routeEvent(binding.state.slot, LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: binding.ConnectionID()}); err != nil {
				t.Fatal(err)
			}
			if budget.Snapshot() != before || manager.Snapshot().ResponseItems != 2 {
				t.Fatal("ordered close allocated or displaced queued payload")
			}
			if tokenMode {
				token := manager.TryNextReady()
				if token == nil {
					t.Fatal("missing payload/close readiness")
				}
				for _, kind := range []LinkEventKind{LinkEventProxyAnswer, LinkEventCloseExternal} {
					if _, terminal, err := token.TryTerminal(); terminal || err != nil {
						t.Fatalf("terminal outran ordered event: %v, %v", terminal, err)
					}
					head, ok, err := token.TryPeekResponse()
					if err != nil || !ok || head.Kind != kind {
						t.Fatalf("ordered head: %v, %v, %v", head.Kind, ok, err)
					}
					event, ok, err := token.TryTakeResponse(head)
					if err != nil || !ok || event.Kind != kind {
						t.Fatalf("ordered take: %v, %v, %v", event.Kind, ok, err)
					}
					event.Release()
					if _, ok, err := token.TryTakeResponse(head); ok || err != nil {
						t.Fatalf("stale head substituted close: %v, %v", ok, err)
					}
				}
				if result, terminal, err := token.TryTerminal(); result != nil || !terminal || err != nil {
					t.Fatalf("ordered terminal: %v, %v, %v", result, terminal, err)
				}
				if err := token.Ack(); err != nil {
					t.Fatal(err)
				}
			} else {
				for _, kind := range []LinkEventKind{LinkEventProxyAnswer, LinkEventCloseExternal} {
					event, err := binding.NextEvent(t.Context())
					if err != nil || event.Kind != kind {
						t.Fatalf("ordered blocking event: %v, %v", event.Kind, err)
					}
					event.Release()
				}
				if _, err := binding.NextEvent(t.Context()); err != io.EOF {
					t.Fatalf("ordered blocking terminal: %v", err)
				}
			}
			if manager.Snapshot().ResponseItems != 0 || manager.Snapshot().ResponseBytes != 0 {
				t.Fatal("inline marker did not release queue counters")
			}
		})
	}
}
