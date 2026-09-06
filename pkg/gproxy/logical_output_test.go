package gproxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

func newQueuedLogicalOutput(t *testing.T) (*LogicalStream, *queuedIdleOwner, *logicalTestBudget, <-chan error) {
	t.Helper()
	owner := &queuedIdleOwner{testMockEventLoop: &testMockEventLoop{}, queue: make(chan gnet.Runnable, 8)}
	budget := &logicalTestBudget{}
	closed := make(chan error, 1)
	stream := &LogicalStream{ctx: NewConnContext(), options: LogicalStreamOptions{
		Owner: owner, MaxOutputBytes: 4096, MaxOutputItems: 512,
		InputBudget: budget.callbacks(), OutputBudget: budget.callbacks(), Notify: func() {},
		OnOpened: func(error) {}, OnClosed: func(err error) { closed <- err },
	}}
	return stream, owner, budget, closed
}

func runQueuedLogicalOutput(t *testing.T, owner *queuedIdleOwner) {
	t.Helper()
	for {
		select {
		case task := <-owner.queue:
			if err := task.Run(t.Context()); err != nil {
				t.Fatal(err)
			}
		default:
			return
		}
	}
}

func TestLogicalOutputFIFOCoalescesConcurrentProducers(t *testing.T) {
	stream, owner, budget, closed := newQueuedLogicalOutput(t)
	const producers, blocks = 8, 32
	var workers sync.WaitGroup
	var callbacks atomic.Int32
	for producer := range producers {
		workers.Go(func() {
			for sequence := range blocks {
				if stream.reserveOutput(2, 2) != 2 {
					t.Error("output reservation failed within configured limit")
					return
				}
				if err := asyncWriteClient(stream, []byte{byte(producer), byte(sequence)}, func(err error) error {
					callbacks.Add(1)
					return err
				}); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	workers.Wait()
	if queued := len(owner.queue); queued != 1 {
		t.Fatalf("owner has %d dispatchers for %d writes", queued, producers*blocks)
	}
	runQueuedLogicalOutput(t, owner)
	wantSequence := make([]byte, producers)
	for _, block := range stream.output {
		if len(block) != 2 || block[1] != wantSequence[block[0]] {
			t.Fatalf("producer order changed: block %v, next sequences %v", block, wantSequence)
		}
		wantSequence[block[0]]++
	}
	for producer, count := range wantSequence {
		if count != blocks {
			t.Errorf("producer %d delivered %d blocks, want %d", producer, count, blocks)
		}
	}
	if callbacks.Load() != producers*blocks || stream.work.Load() != 0 {
		t.Fatalf("callbacks %d, retained work %d", callbacks.Load(), stream.work.Load())
	}
	_ = stream.Close()
	runQueuedLogicalOutput(t, owner)
	select {
	case <-closed:
	default:
		t.Fatal("drained output retained close")
	}
	budget.assertEmpty(t)
}

func TestLogicalOutputReentrantEnqueueFollowsCurrentBatch(t *testing.T) {
	stream, owner, budget, _ := newQueuedLogicalOutput(t)
	for range 3 {
		if stream.reserveOutput(1, 1) != 1 {
			t.Fatal("output reservation failed")
		}
	}
	if err := asyncWriteClient(stream, []byte("A"), func(err error) error {
		if err != nil {
			return err
		}
		return asyncWriteClient(stream, []byte("C"), func(err error) error { return err })
	}); err != nil {
		t.Fatal(err)
	}
	if err := asyncWriteClient(stream, []byte("B"), func(err error) error { return err }); err != nil {
		t.Fatal(err)
	}
	runQueuedLogicalOutput(t, owner)
	if got := bytes.Join(stream.output, nil); string(got) != "ABC" {
		t.Fatalf("reentrant output = %q, want ABC", got)
	}
	_ = stream.Close()
	runQueuedLogicalOutput(t, owner)
	budget.assertEmpty(t)
}

func TestLogicalOutputRejectedDispatcherReleasesAcceptedWrite(t *testing.T) {
	stream, owner, budget, closed := newQueuedLogicalOutput(t)
	rejecting := &rejectingLogicalOwner{EventLoop: owner}
	rejecting.reject.Store(true)
	stream.options.Owner = rejecting
	if stream.reserveOutput(32, 32) != 32 {
		t.Fatal("output reservation failed")
	}
	var callbacks atomic.Int32
	if err := asyncWriteClient(stream, make([]byte, 32), func(err error) error {
		callbacks.Add(1)
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("rejected dispatcher callback = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("accepted write returned synchronous error: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("dispatcher rejection retained accepted output")
	}
	if callbacks.Load() != 1 || stream.work.Load() != 0 {
		t.Fatalf("callbacks %d, retained work %d", callbacks.Load(), stream.work.Load())
	}
	budget.assertEmpty(t)
}

type gatedRejectLogicalOutputOwner struct {
	gnet.EventLoop
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (owner *gatedRejectLogicalOutputOwner) Execute(context.Context, gnet.Runnable) error {
	owner.once.Do(func() {
		close(owner.started)
		<-owner.release
	})
	return net.ErrClosed
}

func TestLogicalOutputSchedulingRejectionRetiresConcurrentFollower(t *testing.T) {
	stream, _, budget, closed := newQueuedLogicalOutput(t)
	owner := &gatedRejectLogicalOutputOwner{started: make(chan struct{}), release: make(chan struct{})}
	stream.options.Owner = owner
	unblock := sync.OnceFunc(func() { close(owner.release) })
	t.Cleanup(unblock)
	for range 2 {
		if stream.reserveOutput(32, 32) != 32 {
			t.Fatal("output reservation failed")
		}
	}
	var callbacks atomic.Int32
	callback := func(err error) error {
		callbacks.Add(1)
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("rejected concurrent submission callback = %v", err)
		}
		return nil
	}
	first := make(chan error, 1)
	go func() { first <- asyncWriteClient(stream, make([]byte, 32), callback) }()
	select {
	case <-owner.started:
	case <-time.After(3 * time.Second):
		t.Fatal("first dispatcher did not enter scheduling")
	}
	if err := asyncWriteClient(stream, make([]byte, 32), callback); err != nil {
		t.Fatal(err)
	}
	unblock()
	if err := <-first; err != nil {
		t.Fatalf("accepted first submission returned error: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("scheduling rejection retained concurrently accepted output")
	}
	if callbacks.Load() != 2 || stream.work.Load() != 0 {
		t.Fatalf("rejected callbacks %d, retained work %d", callbacks.Load(), stream.work.Load())
	}
	budget.assertEmpty(t)
}

func TestLogicalOutputOwnerStoppedRetiresFIFOAndEOFExactlyOnce(t *testing.T) {
	stream, owner, budget, closed := newQueuedLogicalOutput(t)
	var callbacks, barriers atomic.Int32
	for range 3 {
		if stream.reserveOutput(32, 32) != 32 {
			t.Fatal("output reservation failed")
		}
		if err := asyncWriteClient(stream, make([]byte, 32), func(err error) error {
			callbacks.Add(1)
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("retired output callback = %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := executeAfterClientOutput(stream, gnet.RunnableFunc(func(context.Context) error {
		barriers.Add(1)
		if callbacks.Load() != 3 {
			t.Errorf("EOF barrier ran before %d pending write callbacks", 3-callbacks.Load())
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	stream.OwnerStopped()
	stream.OwnerStopped()
	// A poller may retain a stale dispatcher reference after Stop. Replaying
	// that wrapper must not invoke any write callback or EOF release twice.
	runQueuedLogicalOutput(t, owner)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("owner retirement retained ordered output")
	}
	if callbacks.Load() != 3 || barriers.Load() != 1 || stream.work.Load() != 0 {
		t.Fatalf("callbacks %d, EOF barriers %d, work %d", callbacks.Load(), barriers.Load(), stream.work.Load())
	}
	budget.assertEmpty(t)
}

func TestLogicalOutputOwnerStoppedRacesFirstSubmission(t *testing.T) {
	for range 100 {
		stream, owner, budget, closed := newQueuedLogicalOutput(t)
		if stream.reserveOutput(32, 32) != 32 {
			t.Fatal("output reservation failed")
		}
		var callbacks atomic.Int32
		var workers sync.WaitGroup
		workers.Go(func() {
			if err := asyncWriteClient(stream, make([]byte, 32), func(err error) error {
				callbacks.Add(1)
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("retired first submission callback = %v", err)
				}
				return nil
			}); err != nil {
				t.Errorf("first accepted output: %v", err)
			}
		})
		workers.Go(stream.OwnerStopped)
		workers.Wait()
		runQueuedLogicalOutput(t, owner)
		select {
		case <-closed:
		case <-time.After(3 * time.Second):
			t.Fatal("owner retirement raced past first output dispatcher")
		}
		if callbacks.Load() != 1 || stream.work.Load() != 0 {
			t.Fatalf("first submission callbacks %d, work %d", callbacks.Load(), stream.work.Load())
		}
		budget.assertEmpty(t)
	}
}

func TestLogicalOutputRescheduleRejectionRetiresNextBatch(t *testing.T) {
	stream, owner, budget, closed := newQueuedLogicalOutput(t)
	rejecting := &rejectingLogicalOwner{EventLoop: owner}
	stream.options.Owner = rejecting
	for range 2 {
		if stream.reserveOutput(32, 32) != 32 {
			t.Fatal("output reservation failed")
		}
	}
	var callbacks atomic.Int32
	if err := asyncWriteClient(stream, make([]byte, 32), func(err error) error {
		callbacks.Add(1)
		if err != nil {
			return err
		}
		rejecting.reject.Store(true)
		return asyncWriteClient(stream, make([]byte, 32), func(err error) error {
			callbacks.Add(1)
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("rejected next batch callback = %v", err)
			}
			if stream.reserveOutput(1, 1) != 0 {
				t.Error("terminal callback accepted another output reservation")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	runQueuedLogicalOutput(t, owner)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("reschedule rejection abandoned the next output batch")
	}
	if callbacks.Load() != 2 || stream.work.Load() != 0 {
		t.Fatalf("batch callbacks %d, work %d", callbacks.Load(), stream.work.Load())
	}
	budget.assertEmpty(t)
}
