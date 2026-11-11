package middleend

import (
	"context"
	"fmt"
	"testing"
)

// BenchmarkFixedBindingWaiterScan measures the per-request waiter checks with
// no waiting request, the common case, for production slot counts.
func BenchmarkFixedBindingWaiterScan(b *testing.B) {
	for _, slots := range []int{48, 112} {
		b.Run(fmt.Sprintf("slots_%d", slots), func(b *testing.B) {
			configured := make([]FixedBindingSlot, 0, slots)
			for index := range slots {
				configured = append(configured, FixedBindingSlot{DCID: DCID(index%16 + 1), Link: newFixedBindingFakeLink()})
			}
			limits := fixedBindingTestLimits()
			limits.MaxPendingControlItems = 4 * slots
			limits.MaxPendingControlBytes = limits.MaxPendingControlItems * ClosePayloadSize
			limits.MaxPendingControlItemsPerSlot = 2
			limits.MaxPendingControlBytesPerSlot = 2 * ClosePayloadSize
			manager, err := NewFixedBindingManager(configured, limits)
			if err != nil {
				b.Fatal(err)
			}
			if err := manager.Start(context.Background()); err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = manager.Close() })
			m := manager.state
			b.ReportAllocs()
			for b.Loop() {
				m.mu.Lock()
				waiters := m.hasWaitersLocked()
				m.promoteRequestsLocked()
				m.mu.Unlock()
				if waiters {
					b.Fatal("unexpected waiter")
				}
			}
		})
	}
}
