package middleend

import (
	"context"
	"sync/atomic"
	"testing"
)

// BenchmarkFixedBindingRouteResponse measures one routed response and its
// consumption. Each parallel worker owns one slot and one binding, as one
// link consumer and one client event loop do in production.
func BenchmarkFixedBindingRouteResponse(b *testing.B) {
	for _, shared := range []bool{false, true} {
		name := "legacy"
		if shared {
			name = "shared_budget"
		}
		b.Run(name, func(b *testing.B) {
			const workers = 16
			slots := make([]FixedBindingSlot, 0, workers)
			for index := range workers {
				slots = append(slots, FixedBindingSlot{DCID: DCID(index + 1), Link: newFixedBindingFakeLink()})
			}
			var manager *FixedBindingManager
			var err error
			if shared {
				budget, budgetErr := NewResponseBudget(ResponseBudgetConfig{LimitBytes: 64 << 20})
				if budgetErr != nil {
					b.Fatal(budgetErr)
				}
				manager, err = NewFixedBindingManagerWithResponseBudget(slots, fixedBindingTestLimits(), budget)
			} else {
				manager, err = NewFixedBindingManager(slots, fixedBindingTestLimits())
			}
			if err != nil {
				b.Fatal(err)
			}
			if err := manager.Start(context.Background()); err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = manager.Close() })
			bindings := make([]*ClientBinding, workers)
			for index := range workers {
				bindings[index], err = manager.Bind(DCID(index + 1))
				if err != nil {
					b.Fatal(err)
				}
			}
			packet := make([]byte, 256)
			var next atomic.Int32
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				index := int(next.Add(1)-1) % workers
				slot := manager.state.order[index]
				binding := bindings[index]
				ctx := context.Background()
				for pb.Next() {
					event := LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet}
					if err := manager.state.routeEvent(slot, event); err != nil {
						b.Error(err)
						return
					}
					received, err := binding.NextEvent(ctx)
					if err != nil {
						b.Error(err)
						return
					}
					received.Release()
				}
			})
		})
	}
}
