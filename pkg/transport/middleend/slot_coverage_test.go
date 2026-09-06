package middleend

import (
	"io"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

func TestFixedBindingZeroReadyCountsOneTransitionAfterConcurrentPhysicalCloses(t *testing.T) {
	for _, quiesced := range []bool{false, true} {
		name := "admitting"
		if quiesced {
			name = "quiesced"
		}
		t.Run(name, func(t *testing.T) {
			links := []*fixedBindingFakeLink{
				newFixedBindingFakeLink(), newFixedBindingFakeLink(),
				newFixedBindingFakeLink(), newFixedBindingFakeLink(),
			}
			slots := make([]FixedBindingSlot, len(links))
			for index, link := range links {
				slots[index] = FixedBindingSlot{DCID: -2, Link: link}
			}
			manager := newStartedFixedBindingManager(t, slots...)
			var observed atomic.Uint64
			manager.state.mu.Lock()
			manager.state.dcObserver = func(delta FixedBindingDCSnapshot) {
				observed.Add(delta.ZeroReadyTransitions)
			}
			manager.state.mu.Unlock()
			if quiesced {
				manager.Quiesce()
			}

			// Publish every physical close before the manager can process any
			// failure. Reading Link.Done or Link.State now sees zero live links.
			manager.state.mu.Lock()
			incumbents := slices.Clone(manager.state.order)
			for _, link := range links {
				link.peerClose(io.EOF)
			}
			for _, link := range links {
				if link.Snapshot().State != LinkStateClosed {
					manager.state.mu.Unlock()
					t.Fatal("physical closure was not visible before manager callbacks")
				}
			}
			manager.state.mu.Unlock()
			for _, slot := range incumbents {
				select {
				case <-slot.consumerDone:
				case <-time.After(time.Second):
					t.Fatal("manager did not finish a closed-link consumer")
				}
			}
			want := uint64(1)
			if quiesced {
				want = 0
			}
			assertCoverage := func() {
				t.Helper()
				snapshot := manager.Snapshot()
				if len(snapshot.DCs) != 1 || snapshot.DCs[0].ReadySlots != 0 || snapshot.DCs[0].ZeroReadyTransitions != want {
					t.Fatalf("DC coverage after physical closes = %+v, want one DC with 0 ready and %d transitions", snapshot.DCs, want)
				}
				if observed.Load() != want {
					t.Fatalf("service-observer delta = %d, want %d", observed.Load(), want)
				}
			}
			assertCoverage()
			// Late terminal notifications after the pool is already empty do
			// not create another availability transition.
			for _, slot := range incumbents {
				manager.state.failSlot(slot, io.EOF, FixedBindingSlotFailureLinkTerminal)
			}
			assertCoverage()
		})
	}
}
