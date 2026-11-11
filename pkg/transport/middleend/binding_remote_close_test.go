package middleend

import (
	"testing"
)

func controlIsolationTestManager(t *testing.T) (*FixedBindingManager, *fixedBindingFakeLink, *fixedBindingFakeLink) {
	t.Helper()
	limits := fixedBindingTestLimits()
	limits.MaxPendingControlItemsPerSlot = limits.MaxPendingControlItems
	limits.MaxPendingControlBytesPerSlot = limits.MaxPendingControlBytes
	stalled := newFixedBindingFakeLink()
	stalled.setTryError(ErrLinkBackpressure)
	healthy := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: stalled}, {DCID: 2, Link: healthy}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager, stalled, healthy
}

func TestFixedBindingStalledSlotCannotExhaustControlCapacity(t *testing.T) {
	manager, stalled, healthy := controlIsolationTestManager(t)
	const staleReplies = 100
	for index := range staleReplies {
		stalled.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: int64(1_000_000 + index)})
	}
	stalledSlot := manager.state.order[0]
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return stalledSlot.controlItems+int(manager.state.controlBackpressureEvents) == staleReplies
	})
	binding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	connectionID := binding.ConnectionID()
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	waitFixedBindingCondition(t, func() bool {
		healthy.mu.Lock()
		defer healthy.mu.Unlock()
		for _, submission := range healthy.attempted {
			if submission.ConnectionID == connectionID {
				return true
			}
		}
		return false
	})
}

func TestFixedBindingStaleRepliesQueueOneCloseForConnection(t *testing.T) {
	manager, stalled, _ := controlIsolationTestManager(t)
	const replies = 10
	for range replies {
		stalled.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 1_000_000})
	}
	// A later reply for another ID proves that every earlier event was routed.
	stalled.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 2_000_000})
	stalledSlot := manager.state.order[0]
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		for item := stalledSlot.outHead; item != nil; item = item.next {
			if item.kind == outboundControl && item.submission.ConnectionID == 2_000_000 {
				return true
			}
		}
		return false
	})
	manager.state.mu.Lock()
	queued := stalledSlot.controlItems
	manager.state.mu.Unlock()
	if queued != 2 {
		t.Fatalf("queued closes = %d, want 2", queued)
	}
}

func TestFixedBindingRemoteCloseCancelsPendingRequest(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "legacy"
		if shared {
			name = "shared_budget"
		}
		t.Run(name, func(t *testing.T) {
			link := newFixedBindingFakeLink()
			link.setTryError(ErrLinkBackpressure)
			slots := []FixedBindingSlot{{DCID: 1, Link: link}}
			// One request item forces the target request to wait.
			limits := fixedBindingTestLimits()
			limits.MaxPendingRequestItemsPerSlot = 1
			limits.MaxPendingRequestItems = 1
			var manager *FixedBindingManager
			var err error
			if shared {
				budget, budgetErr := NewResponseBudget(ResponseBudgetConfig{LimitBytes: 64 << 20})
				if budgetErr != nil {
					t.Fatal(budgetErr)
				}
				manager, err = NewFixedBindingManagerWithResponseBudget(slots, limits, budget)
			} else {
				manager, err = NewFixedBindingManager(slots, limits)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = manager.Close() })
			blocker, err := manager.Bind(1)
			if err != nil {
				t.Fatal(err)
			}
			target, err := manager.Bind(1)
			if err != nil {
				t.Fatal(err)
			}
			request := fixedBindingProxyRequest()
			if status, err := blocker.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestQueued {
				t.Fatalf("blocker prepare = %d, %v", status, err)
			}
			waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
			if status, err := target.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestWaiting {
				t.Fatalf("target prepare = %d, %v", status, err)
			}
			link.emit(LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: target.ConnectionID()})
			waitFixedBindingCondition(t, func() bool {
				manager.state.mu.Lock()
				defer manager.state.mu.Unlock()
				return target.state.remoteClosed
			})
			manager.state.mu.Lock()
			pending := target.state.request
			waiting := target.state.slot.waitHead
			waitingSlots := manager.state.waitingSlots
			manager.state.mu.Unlock()
			if waitingSlots != 0 {
				t.Fatalf("waiting slot count = %d after the only waiter left", waitingSlots)
			}
			if pending != nil || waiting != nil {
				t.Fatal("remote close kept the pending request of the closed connection")
			}
			link.setTryError(nil)
			link.ready <- struct{}{}
			waitFixedBindingCondition(t, func() bool {
				manager.state.mu.Lock()
				defer manager.state.mu.Unlock()
				return blocker.state.result != nil
			})
			for _, submission := range link.attemptedSubmissions() {
				if submission.ConnectionID == target.ConnectionID() {
					t.Fatal("request for the remotely closed connection reached the link")
				}
			}
		})
	}
}

// A client that already took its prepare reservation keeps it when Middle-End
// closes the connection. The reserved request completes as a clean close: no
// PROXY_REQ is sent and responses queued before the close are delivered.
func TestFixedBindingRemoteCloseKeepsHandedReservation(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "legacy"
		if shared {
			name = "shared_budget"
		}
		t.Run(name, func(t *testing.T) {
			link := newFixedBindingFakeLink()
			link.setTryError(ErrLinkBackpressure)
			slots := []FixedBindingSlot{{DCID: 1, Link: link}}
			limits := fixedBindingTestLimits()
			limits.MaxPendingRequestItemsPerSlot = 1
			limits.MaxPendingRequestItems = 1
			var manager *FixedBindingManager
			var err error
			if shared {
				budget, budgetErr := NewResponseBudget(ResponseBudgetConfig{LimitBytes: 64 << 20})
				if budgetErr != nil {
					t.Fatal(budgetErr)
				}
				manager, err = NewFixedBindingManagerWithResponseBudget(slots, limits, budget)
			} else {
				manager, err = NewFixedBindingManager(slots, limits)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = manager.Close() })
			blocker, err := manager.BindReady(1)
			if err != nil {
				t.Fatal(err)
			}
			waiter, err := manager.BindReady(1)
			if err != nil {
				t.Fatal(err)
			}
			request := fixedBindingProxyRequest()
			if _, err := blocker.PrepareProxyRequest(request); err != nil {
				t.Fatal(err)
			}
			if status, err := waiter.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestWaiting {
				t.Fatalf("waiter prepare = %d, %v", status, err)
			}
			link.setTryError(nil)
			link.ready <- struct{}{}

			var token *ClientReadyToken
			var reservation *ClientPrepareReservation
			waitFixedBindingCondition(t, func() bool {
				next := manager.TryNextReady()
				if next == nil {
					return false
				}
				if next.ConnectionID() != waiter.ConnectionID() {
					_, _, _ = next.TryTakeRequestResult()
					_ = next.Ack()
					return false
				}
				taken, ok, err := next.TryTakePrepareReservation()
				if err != nil {
					t.Fatal(err)
				}
				if !ok {
					_ = next.Ack()
					return false
				}
				token, reservation = next, taken
				return true
			})
			// The frontend holds the token while it materializes the request.
			link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: waiter.ConnectionID(), Packet: []byte{1, 2, 3, 4}})
			link.emit(LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: waiter.ConnectionID()})
			waitFixedBindingCondition(t, func() bool {
				manager.state.mu.Lock()
				defer manager.state.mu.Unlock()
				return waiter.state.remoteClosed
			})
			if err := waiter.PrepareReservedProxyRequest(reservation, request); err != nil {
				t.Fatalf("remote close turned a clean close into a rejection: %v", err)
			}
			for _, submission := range link.attemptedSubmissions() {
				if submission.ConnectionID == waiter.ConnectionID() {
					t.Fatal("PROXY_REQ was sent for a remotely closed connection")
				}
			}
			if _, terminal, err := token.TryTerminal(); err != nil || terminal {
				t.Fatalf("terminal before queued responses = %v, %v", terminal, err)
			}
			answer, ok, err := token.TryNextEvent()
			if err != nil || !ok || answer.Kind != LinkEventProxyAnswer {
				t.Fatalf("first response = %v, %v, %v", answer.Kind, ok, err)
			}
			answer.Release()
			closeEvent, ok, err := token.TryNextEvent()
			if err != nil || !ok || closeEvent.Kind != LinkEventCloseExternal {
				t.Fatalf("second response = %v, %v, %v", closeEvent.Kind, ok, err)
			}
			closeEvent.Release()
			terminalErr, terminal, err := token.TryTerminal()
			if err != nil || !terminal || terminalErr != nil {
				t.Fatalf("terminal = %v, %v, %v", terminalErr, terminal, err)
			}
		})
	}
}
