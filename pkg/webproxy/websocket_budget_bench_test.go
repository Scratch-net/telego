package webproxy

import (
	"math"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

func BenchmarkWebSocketTouchLiveness(b *testing.B) {
	_, session := benchmarkSession(b, func(config *ManagerConfig) { config.Carrier = CarrierWebSocket })
	transport, err := newWebSocketConnection(session, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	transport.phase = webSocketOpen
	connection := &heartbeatTestConn{owner: &budgetTestOwner{queue: make(chan gnet.Runnable, 1)}}
	b.Cleanup(func() { transport.phase = webSocketClosing; transport.close() })
	b.ReportAllocs()
	for b.Loop() {
		transport.touchLiveness(connection)
	}
}

type timerReuseTestOwner struct {
	budgetTestOwner
	closes int
}

func (o *timerReuseTestOwner) Close(gnet.Conn) error {
	o.closes++
	return nil
}

type timerReuseTestConn struct {
	gnet.Conn
	owner *timerReuseTestOwner
}

func (c *timerReuseTestConn) EventLoop() gnet.EventLoop { return c.owner }

// A reused timer can run its callback for an older expiry after a refresh.
// That callback must not close the refreshed connection.
func TestReusedTimersIgnoreStaleExpiry(t *testing.T) {
	newConnection := func() *timerReuseTestConn {
		return &timerReuseTestConn{owner: &timerReuseTestOwner{budgetTestOwner: budgetTestOwner{queue: make(chan gnet.Runnable, 4)}}}
	}
	expire := func(t *testing.T, connection *timerReuseTestConn, refresh func()) {
		t.Helper()
		var stale gnet.Runnable
		select {
		case stale = <-connection.owner.queue:
		case <-time.After(time.Second):
			t.Fatal("timer did not expire")
		}
		refresh()
		if err := stale.Run(t.Context()); err != nil || connection.owner.closes != 0 {
			t.Fatalf("stale expiry closed the refreshed connection: %v", err)
		}
		select {
		case current := <-connection.owner.queue:
			if err := current.Run(t.Context()); err != nil || connection.owner.closes != 1 {
				t.Fatalf("current expiry closes = %d, %v", connection.owner.closes, err)
			}
		case <-time.After(time.Second):
			t.Fatal("refreshed timer did not expire")
		}
	}

	t.Run("WebSocket liveness", func(t *testing.T) {
		profiles := testProfiles(t)
		manager := testManager(t, profiles, func(config *ManagerConfig) {
			config.Carrier = CarrierWebSocket
			config.Timeouts.LongPoll = 10 * time.Millisecond
		}, nil)
		transport, err := newWebSocketConnection(createTestSession(t, manager, profiles[0]).Session, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(transport.close)
		transport.phase = webSocketOpen
		connection := newConnection()
		transport.touchLiveness(connection)
		expire(t, connection, func() { transport.touchLiveness(connection) })
	})

	t.Run("HTTP deadline", func(t *testing.T) {
		state := &httpConnectionState{}
		t.Cleanup(state.close)
		connection := newConnection()
		state.armDeadline(connection, 10*time.Millisecond)
		expire(t, connection, func() { state.armDeadline(connection, 20*time.Millisecond) })
	})
}

func BenchmarkHTTPConnectionArmDeadline(b *testing.B) {
	state := &httpConnectionState{}
	connection := &heartbeatTestConn{owner: &budgetTestOwner{queue: make(chan gnet.Runnable, 1)}}
	b.Cleanup(state.close)
	b.ReportAllocs()
	for b.Loop() {
		state.armDeadline(connection, time.Hour)
	}
}

func BenchmarkWebSocketInboundBudgetChurn(b *testing.B) {
	budget := &webSocketInboundBudget{maxBytes: math.MaxInt, maxItems: maxWebSocketInboundItemsPerSocket}
	for size := range maxWebSocketInboundItemsPerSocket - 1 {
		if !budget.reserve(&webSocketOwnedInput{}, 1, 1024+size) {
			b.Fatal("cannot prefill budget")
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		owner := &webSocketOwnedInput{}
		if !budget.reserve(owner, 100, 100) || !budget.resize(owner, 100, 200, 200) {
			b.Fatal("cannot reserve")
		}
		budget.release(owner, 200)
	}
}

func TestWebSocketInboundBudgetCopyLimitTracksLiveMaximum(t *testing.T) {
	budget := &webSocketInboundBudget{maxBytes: 1 << 20, maxItems: 8}
	small, large, equal := &webSocketOwnedInput{}, &webSocketOwnedInput{}, &webSocketOwnedInput{}
	check := func(step string, want int) {
		t.Helper()
		if bytes, _ := budget.snapshot(); bytes != budget.rawBytes+want {
			t.Fatalf("%s: charged %d, want raw %d plus copy %d", step, bytes, budget.rawBytes, want)
		}
	}
	if !budget.reserve(small, 10, 100) || !budget.reserve(large, 10, 500) || !budget.reserve(equal, 10, 500) {
		t.Fatal("cannot reserve")
	}
	check("two equal maxima", 500)
	budget.release(large, 10)
	check("one maximum left", 500)
	if !budget.resize(equal, 10, 10, 50) {
		t.Fatal("cannot shrink")
	}
	check("unique maximum shrank", 100)
	if !budget.resize(small, 10, 10, 900) {
		t.Fatal("cannot grow")
	}
	check("growth", 900)
	budget.release(small, 10)
	check("unique maximum released", 50)
	budget.release(equal, 10)
	check("empty", 0)
}
