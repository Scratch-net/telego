package gproxy

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/panjf2000/gnet/v2"
	"github.com/panjf2000/gnet/v2/pkg/buffer/elastic"
)

type relayCapacityOwner struct {
	testMockEventLoop
	tasks  []gnet.Runnable
	reject error
}

func (o *relayCapacityOwner) ExecuteHighPriority(_ context.Context, task gnet.Runnable) error {
	if o.reject != nil {
		return o.reject
	}
	o.tasks = append(o.tasks, task)
	return nil
}

type relayCapacityConn struct {
	*testMockGnetConn
	owner  relayCapacityOwner
	output elastic.Buffer
	writes int
}

func (c *relayCapacityConn) EventLoop() gnet.EventLoop { return &c.owner }
func (c *relayCapacityConn) OutboundBuffered() int     { return c.output.Buffered() }
func (c *relayCapacityConn) WriteOwned(data []byte, release func(error)) (int, error) {
	c.writes++
	c.output.AppendOwned(data, release)
	return len(data), nil
}

func TestRelayOutputPartialDrainRetainsCapacityCharge(t *testing.T) {
	const size = 65537
	conn := &relayCapacityConn{testMockGnetConn: newTestMockGnetConn()}
	stream, _, budget, _ := newQueuedLogicalOutput(t)
	output := newRelayOutput(conn, stream, stream.ctx, 2*size)
	t.Cleanup(output.close)
	if n := output.reserve(size, 1); n != size {
		t.Fatalf("reservation = %d", n)
	}
	released := 0
	if err := output.write(make([]byte, size), func() { released++ }); err != nil {
		t.Fatal(err)
	}
	if len(conn.owner.tasks) != 1 || budget.bytes != size {
		t.Fatal("submission did not retain its allocation")
	}
	if err := conn.owner.tasks[0].Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.output.Discard(size - 1)
	output.refresh(0)
	if budget.bytes != size || released != 0 || output.queued != size {
		t.Fatalf("partial drain released allocation: budget=%d release=%d queued=%d", budget.bytes, released, output.queued)
	}
	_, _ = conn.output.Discard(1)
	if released != 1 || stream.work.Load() != 0 {
		t.Fatal("final disposal did not complete once")
	}
	budget.assertEmpty(t)
	conn.output.Release()
	if released != 1 {
		t.Fatal("close repeated release")
	}
}

func TestRelayOutputOwnerRetirementClearsQueuedAllocation(t *testing.T) {
	conn := &relayCapacityConn{testMockGnetConn: newTestMockGnetConn()}
	stream, owner, budget, closed := newQueuedLogicalOutput(t)
	output := newRelayOutput(conn, stream, stream.ctx, 4096)
	if output.reserve(33, 1) != 33 {
		t.Fatal("reservation failed")
	}
	released := 0
	if err := output.write(make([]byte, 33), func() { released++ }); err != nil {
		t.Fatal(err)
	}
	var pending *relayPendingWrite
	for item := range output.pendingWrites {
		pending = item
	}
	if pending == nil || cap(pending.data) != 33 {
		t.Fatal("pending task did not own exact allocation")
	}
	output.destinationClosed()
	if pending.data != nil || released != 1 {
		t.Fatal("retired task retained its data")
	}
	// An abandoned queue can still retain its task. A stale replay must not
	// submit the released allocation or invoke its release callback again.
	if err := conn.owner.tasks[0].Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending.complete(net.ErrClosed)
	if conn.writes != 0 || released != 1 {
		t.Fatal("stale task reused retired allocation")
	}
	runQueuedLogicalOutput(t, owner)
	if stream.work.Load() != 0 {
		t.Fatal("retirement retained logical work")
	}
	select {
	case <-closed:
	default:
		t.Fatal("retirement retained logical close")
	}
	budget.assertEmpty(t)
}

func TestRelayOutputTimerPreservesOrdinaryPrefix(t *testing.T) {
	conn := &relayCapacityConn{testMockGnetConn: newTestMockGnetConn()}
	conn.output.Reset(4096)
	_, _ = conn.output.Write(make([]byte, 100))
	output := newRelayOutput(conn, newTestMockGnetConn(), NewConnContext(), 200)
	output.buffered = conn.OutboundBuffered()
	t.Cleanup(output.close)
	if output.reserve(50, 1) != 50 {
		t.Fatal("reservation failed")
	}
	if err := output.write(make([]byte, 50), nil); err != nil {
		t.Fatal(err)
	}
	if err := conn.owner.tasks[0].Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	output.refresh(0)
	if output.buffered != 100 || output.queued != 50 {
		t.Fatal("timer forgot ordinary prefix")
	}
	_, _ = conn.output.Discard(149)
	output.refresh(0)
	if output.queued != 50 || output.buffered != 1 {
		t.Fatal("partial prefix accounting not conservative")
	}
	_, _ = conn.output.Discard(1)
	if output.queued != 0 || output.buffered != 0 {
		t.Fatal("completed owned write retained drained prefix")
	}
	conn.output.Release()
}

func TestProxyHeadersHaveExactRetainedCapacity(t *testing.T) {
	for _, address := range []string{"192.0.2.1", "2001:db8::1"} {
		for _, version := range []int{1, 2} {
			header := buildProxyProtocolHeader(version, &net.TCPAddr{IP: net.ParseIP(address), Port: 12345}, &net.TCPAddr{IP: net.ParseIP(address), Port: 443})
			if cap(header) != len(header) {
				t.Fatalf("v%d %s retained=%d, wire=%d", version, address, cap(header), len(header))
			}
		}
	}
}

// Windows supports OwnedWriter but has no Unix high-priority task queue.
// Its original AsyncWrite writes synchronously once its owner runs the task.
type relayCompatConn struct {
	*testMockGnetConn
	owner                     *queuedIdleOwner
	nativeWrites, ownedWrites int
}

func (c *relayCompatConn) EventLoop() gnet.EventLoop { return c.owner }
func (c *relayCompatConn) OutboundBuffered() int     { return 0 }
func (c *relayCompatConn) WriteOwned(_ []byte, release func(error)) (int, error) {
	c.ownedWrites++
	release(net.ErrClosed)
	return 0, net.ErrClosed
}
func (c *relayCompatConn) AsyncWrite(data []byte, callback gnet.AsyncCallback) error {
	c.nativeWrites++
	return c.owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		_, err := c.Write(data)
		if callback != nil {
			_ = callback(c, err)
		}
		return err
	}))
}

func TestRelayOutputOwnedWriterWithoutPriorityUsesNativeAsyncWrite(t *testing.T) {
	stream, owner, budget, _ := newQueuedLogicalOutput(t)
	conn := &relayCompatConn{testMockGnetConn: newTestMockGnetConn(), owner: owner}
	output := newRelayOutput(conn, stream, stream.ctx, 4096)
	t.Cleanup(output.close)
	if output.ownedNative {
		t.Fatal("owner without high-priority support selected owned accounting")
	}
	if output.reserve(33, 1) != 33 {
		t.Fatal("reservation failed")
	}
	released := 0
	if err := output.write(make([]byte, 33), func() { released++ }); err != nil {
		t.Fatalf("native compatibility write: %v", err)
	}
	if conn.nativeWrites != 1 || conn.ownedWrites != 0 || released != 0 || budget.bytes != 33 || output.inflight != 1 {
		t.Fatal("native submission lost its callback or pending allocation")
	}
	runQueuedLogicalOutput(t, owner)
	if len(conn.GetWrittenData()) != 33 || released != 1 || output.queued != 0 || output.inflight != 0 || stream.work.Load() != 0 {
		t.Fatal("native completion did not release exactly once")
	}
	budget.assertEmpty(t)
}

func TestRelayOutputHighPriorityRejectionDoesNotRetryNative(t *testing.T) {
	stream, owner, budget, _ := newQueuedLogicalOutput(t)
	conn := &relayCapacityConn{testMockGnetConn: newTestMockGnetConn()}
	conn.owner.reject = net.ErrClosed
	output := newRelayOutput(conn, stream, stream.ctx, 4096)
	if !output.ownedNative || output.reserve(33, 1) != 33 {
		t.Fatal("supported high-priority owner did not select owned output")
	}
	released := 0
	if err := output.write(make([]byte, 33), func() { released++ }); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("submission rejection = %v", err)
	}
	if len(conn.GetAsyncWrites()) != 0 || conn.writes != 0 || released != 1 || output.inflight != 0 {
		t.Fatal("rejected high-priority write retried or retained its allocation")
	}
	runQueuedLogicalOutput(t, owner)
	budget.assertEmpty(t)
}
