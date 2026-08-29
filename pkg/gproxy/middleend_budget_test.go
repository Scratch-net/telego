package gproxy

import (
	"testing"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestMiddleEndByteBudgetReservationIsHardBound(t *testing.T) {
	budget := newMiddleEndByteBudget(100)
	if !budget.tryReserve(60) {
		t.Fatal("first reservation was rejected")
	}
	if budget.tryReserve(41) {
		t.Fatal("over-limit reservation was accepted")
	}
	current, highWater, limit, backpressure := budget.snapshot()
	if current != 60 || highWater != 60 || limit != 100 || backpressure != 1 {
		t.Fatalf("budget snapshot = current %d high-water %d limit %d backpressure %d", current, highWater, limit, backpressure)
	}
	budget.release(60)
	if current, _, _, _ := budget.snapshot(); current != 0 {
		t.Fatalf("released budget current = %d, want 0", current)
	}
}

func TestMiddleEndInputBudgetAccountsObservedOverflowUntilClose(t *testing.T) {
	frontend := &middleEndFrontend{inputBudget: newMiddleEndByteBudget(8)}
	client := &middleEndClient{frontend: frontend}
	conn := newMiddleEndOwnerConn()
	conn.SetReadData(make([]byte, 9))
	var accepted bool
	runMiddleEndOwner(conn, func() gnet.Action {
		accepted = client.reconcileInput(conn)
		return gnet.None
	})
	if accepted {
		t.Fatal("observed input over the aggregate limit was accepted")
	}
	stats := frontend.stats()
	if stats.InputBytes != 9 || stats.InputBytesHighWater != 9 || stats.InputBackpressureEvents != 1 {
		t.Fatalf("input stats = %+v", stats)
	}
	client.releaseBudgets()
	if current := frontend.stats().InputBytes; current != 0 {
		t.Fatalf("input bytes after close = %d, want 0", current)
	}
}

func TestMiddleEndOutputReservationTransfersToObservedGnetBytes(t *testing.T) {
	frontend := &middleEndFrontend{outputBudget: newMiddleEndByteBudget(middleEndMaxEncodedResponse + 100)}
	client := &middleEndClient{frontend: frontend}
	conn := newMiddleEndOwnerConn()
	if !frontend.reserveOutput() {
		t.Fatal("output reservation was rejected")
	}
	conn.SetOutboundBuffered(100)
	runMiddleEndOwner(conn, func() gnet.Action {
		client.reconcileOutput(conn, int64(middleEndMaxEncodedResponse))
		return gnet.None
	})
	if stats := frontend.stats(); stats.OutputBytes != 100 || stats.OutputBytesHighWater != int64(middleEndMaxEncodedResponse) {
		t.Fatalf("output stats after transfer = %+v", stats)
	}
	client.releaseBudgets()
	if current := frontend.stats().OutputBytes; current != 0 {
		t.Fatalf("output bytes after close = %d, want 0", current)
	}
}

func TestMiddleEndOutputPressureEvictsLargestBufferedClient(t *testing.T) {
	frontend := &middleEndFrontend{
		outputBudget: newMiddleEndByteBudget(middleEndMaxEncodedResponse),
		routes:       make(map[int64]*middleEndRoute),
	}
	firstConn := newMiddleEndOwnerConn()
	secondConn := newMiddleEndOwnerConn()
	first := &middleEndClient{frontend: frontend, binding: &middleend.ClientBinding{}}
	second := &middleEndClient{frontend: frontend, binding: &middleend.ClientBinding{}}
	first.outputAccounted.Store(80)
	second.outputAccounted.Store(40)
	frontend.outputBudget.observe(120)
	frontend.routes[1] = &middleEndRoute{conn: firstConn, client: first}
	frontend.routes[2] = &middleEndRoute{conn: secondConn, client: second}

	if current := frontend.evictOutputPressureVictim(second); current {
		t.Fatal("pressure selected the current smaller client")
	}
	if !firstConn.IsClosed() || secondConn.IsClosed() {
		t.Fatalf("largest closed = %t, smaller closed = %t", firstConn.IsClosed(), secondConn.IsClosed())
	}
	if stats := frontend.stats(); stats.OutputEvictions != 1 {
		t.Fatalf("output evictions = %d, want 1", stats.OutputEvictions)
	}
}
