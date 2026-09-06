package gproxy

import (
	"context"
	"errors"

	"github.com/panjf2000/gnet/v2"
)

// Each queued write already owns an output byte/item reservation. The only
// uncharged entry is the one-shot splice EOF barrier. No payload is copied
// into this queue, and one tracked owner task dispatches the whole batch.
type logicalOutputTask struct {
	run  gnet.Runnable
	done func()
	next *logicalOutputTask
}

// executeOrderedOutput preserves submission order independently of gnet's
// two priority queues. Once accepted, a task owns its callback cleanup even
// if scheduling fails; the caller must not release its reservation again.
func (s *LogicalStream) executeOrderedOutput(run gnet.Runnable) error {
	s.outputOrderMu.Lock()
	if s.outputError != nil {
		err := s.outputError
		s.outputOrderMu.Unlock()
		return err
	}
	task := &logicalOutputTask{run: run, done: retainLogicalWork(s)}
	if s.outputTail == nil {
		s.outputHead = task
	} else {
		s.outputTail.next = task
	}
	s.outputTail = task
	start := !s.outputRunning
	s.outputRunning = true
	s.outputOrderMu.Unlock()
	if start {
		s.dispatchOrderedOutput()
	}
	return nil
}

func (s *LogicalStream) dispatchOrderedOutput() {
	if err := s.execute(gnet.RunnableFunc(s.drainOrderedOutput)); err != nil {
		s.outputOrderMu.Lock()
		s.outputError = err
		s.outputOrderMu.Unlock()
		s.requestedClose.Store(true)
		// Rejection can occur from an owner callback. Wait outside that callback
		// before running terminal branches that release captured reservations.
		go func() {
			s.ownerMu.Lock()
			defer s.ownerMu.Unlock()
			s.finish(err)
			_ = s.drainOrderedOutput(context.Background())
			s.notifyClosed()
		}()
	}
}

// drainOrderedOutput runs under ownerMu. Detaching one bounded batch lets
// later submissions wait without extending the current owner turn forever.
// Terminal cleanup drains all remaining entries without scheduling new work.
func (s *LogicalStream) drainOrderedOutput(ctx context.Context) (result error) {
	for {
		s.outputOrderMu.Lock()
		batch := s.outputHead
		s.outputHead, s.outputTail = nil, nil
		s.outputOrderMu.Unlock()
		for task := batch; task != nil; {
			next := task.next
			result = errors.Join(result, task.run.Run(ctx))
			task.run = nil
			task.next = nil
			task.done()
			task.done = nil
			task = next
		}
		s.outputOrderMu.Lock()
		pending := s.outputHead != nil
		if !pending {
			s.outputRunning = false
		}
		s.outputOrderMu.Unlock()
		if !pending {
			return result
		}
		if s.requestedClose.Load() {
			continue
		}
		s.dispatchOrderedOutput()
		return result
	}
}
