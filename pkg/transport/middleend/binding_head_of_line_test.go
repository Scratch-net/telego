package middleend

import (
	"testing"
	"time"
)

// TestFixedBindingSlowClientLoopDoesNotDelayLaterRequests measures
// head-of-line delay on one link. Two clients prepare requests while the link
// is backpressured. The first client's event loop then stalls. The second
// client's request must not wait for that loop.
func TestFixedBindingSlowClientLoopDoesNotDelayLaterRequests(t *testing.T) {
	const slowLoop = 100 * time.Millisecond
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	blocker, _ := manager.BindReady(1)
	slow, _ := manager.BindReady(1)
	later, _ := manager.BindReady(1)
	request := fixedBindingProxyRequest()
	if _, err := blocker.PrepareProxyRequest(request); err != nil {
		t.Fatal(err)
	}
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	if _, err := slow.PrepareProxyRequest(request); err != nil {
		t.Fatal(err)
	}
	if _, err := later.PrepareProxyRequest(request); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	link.setTryError(nil)
	link.ready <- struct{}{}

	// One consumer serves readiness. The slow client's token waits for its
	// stalled loop; every other client loop responds at once.
	var slowToken *ClientReadyToken
	arrived := func() bool {
		for _, submission := range link.attemptedSubmissions() {
			if submission.ConnectionID == later.ConnectionID() {
				return true
			}
		}
		return false
	}
	deadline := time.Now().Add(5 * time.Second)
	for !arrived() {
		if time.Now().After(deadline) {
			t.Fatal("later request did not reach the link")
		}
		if slowToken != nil && time.Since(started) >= slowLoop {
			if reservation, ok, err := slowToken.TryTakePrepareReservation(); err != nil {
				t.Fatal(err)
			} else if ok {
				if err := slow.PrepareReservedProxyRequest(reservation, request); err != nil {
					t.Fatal(err)
				}
			}
			_ = slowToken.Ack()
			slowToken = nil
		}
		token := manager.TryNextReady()
		if token == nil {
			time.Sleep(50 * time.Microsecond)
			continue
		}
		switch token.ConnectionID() {
		case slow.ConnectionID():
			slowToken = token
			continue
		case later.ConnectionID():
			if reservation, ok, err := token.TryTakePrepareReservation(); err != nil {
				t.Fatal(err)
			} else if ok {
				if err := later.PrepareReservedProxyRequest(reservation, request); err != nil {
					t.Fatal(err)
				}
			}
		}
		_, _, _ = token.TryTakeRequestResult()
		if err := token.Ack(); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(started)
	t.Logf("later request reached the link after %v with a %v slow client loop", elapsed, slowLoop)
	if elapsed >= slowLoop {
		t.Fatalf("later request waited for another client's event loop: %v", elapsed)
	}
}
