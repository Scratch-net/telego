package gproxy

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/panjf2000/gnet/v2"
	errorx "github.com/panjf2000/gnet/v2/pkg/errors"
	"github.com/panjf2000/gnet/v2/pkg/netpoll"
	"github.com/panjf2000/gnet/v2/pkg/queue"
)

// This adapter uses eventloop.Execute's exact scheduling policy. The actual
// epoll/eventfd poller executes both queues without opening network sockets.
type logicalOutputPollerOwner struct {
	gnet.EventLoop
	poller *netpoll.Poller
}

func (owner logicalOutputPollerOwner) Execute(ctx context.Context, task gnet.Runnable) error {
	return owner.poller.Trigger(queue.LowPriority, func(any) error { return task.Run(ctx) }, nil)
}

func TestLogicalOutputFIFOAcrossPollerPriorityQueues(t *testing.T) {
	poller, err := netpoll.OpenPoller()
	if err != nil {
		t.Fatal(err)
	}
	defer poller.Close()
	owner := logicalOutputPollerOwner{poller: poller}
	budget := &logicalTestBudget{}
	stream := &LogicalStream{ctx: NewConnContext(), options: LogicalStreamOptions{
		Owner: owner, MaxOutputBytes: 1024, MaxOutputItems: 16,
		OutputBudget: budget.callbacks(), Notify: func() {},
	}}
	for range 2 {
		if stream.reserveOutput(1, 1) != 1 {
			t.Fatal("reserve two output blocks")
		}
	}
	// A enters the overflow queue before polling starts. As the urgent queue
	// drains, B's later submission may enter that queue and overtake A unless
	// the stream preserves its own output order.
	for index := range netpoll.MaxPollEventsCap {
		if err := owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
			if index == 0 {
				return asyncWriteClient(stream, []byte("B"), func(err error) error { return err })
			}
			return nil
		})); err != nil {
			t.Fatal(err)
		}
	}
	if err := asyncWriteClient(stream, []byte("A"), func(err error) error {
		if err != nil {
			return err
		}
		return errorx.ErrEngineShutdown
	}); err != nil {
		t.Fatal(err)
	}
	if optimized, ok := any(poller).(interface{ Polling() error }); ok {
		err = optimized.Polling()
	} else {
		err = any(poller).(interface {
			Polling(netpoll.PollEventHandler) error
		}).Polling(nil)
	}
	if !errors.Is(err, errorx.ErrEngineShutdown) {
		t.Fatalf("poller exit: %v", err)
	}
	if got := bytes.Join(stream.output, nil); string(got) != "AB" {
		t.Fatalf("logical downlink delivered %q, want submission order AB", got)
	}
}

func TestLogicalOutputEOFBarrierAcrossPollerPriorityQueues(t *testing.T) {
	poller, err := netpoll.OpenPoller()
	if err != nil {
		t.Fatal(err)
	}
	defer poller.Close()
	owner := logicalOutputPollerOwner{poller: poller}
	budget := &logicalTestBudget{}
	stream := &LogicalStream{ctx: NewConnContext(), options: LogicalStreamOptions{
		Owner: owner, MaxOutputBytes: 1024, MaxOutputItems: 16,
		OutputBudget: budget.callbacks(), Notify: func() {},
	}}
	if stream.reserveOutput(1, 1) != 1 {
		t.Fatal("output reservation failed")
	}
	var beforeEOF string
	for index := range netpoll.MaxPollEventsCap {
		if err := owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
			if index == 0 {
				return executeAfterClientOutput(stream, gnet.RunnableFunc(func(context.Context) error {
					beforeEOF = string(bytes.Join(stream.output, nil))
					return errorx.ErrEngineShutdown
				}))
			}
			return nil
		})); err != nil {
			t.Fatal(err)
		}
	}
	if err := asyncWriteClient(stream, []byte("A"), func(err error) error { return err }); err != nil {
		t.Fatal(err)
	}
	if optimized, ok := any(poller).(interface{ Polling() error }); ok {
		err = optimized.Polling()
	} else {
		err = any(poller).(interface {
			Polling(netpoll.PollEventHandler) error
		}).Polling(nil)
	}
	if !errors.Is(err, errorx.ErrEngineShutdown) {
		t.Fatalf("poller exit: %v", err)
	}
	if beforeEOF != "A" {
		t.Fatalf("EOF barrier observed %q, want prior output A", beforeEOF)
	}
}
