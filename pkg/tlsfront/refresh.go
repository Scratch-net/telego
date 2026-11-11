package tlsfront

import (
	"context"
	"sync"
	"time"
)

const (
	// refreshRetryInitial is the first retry delay after a failed fetch.
	refreshRetryInitial = 5 * time.Second
	// refreshRetryMaximum bounds the retry delay. The bound is also at most
	// half of the refresh period, so a failure never waits a full period.
	refreshRetryMaximum = 5 * time.Minute
)

// refreshWorker owns one periodic worker and joins its current network fetch.
// Once stopped, it cannot be restarted by a concurrent or repeated Start.
type refreshWorker struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	stopped bool
}

// A failed refresh is retried after refreshRetryInitial, doubling up to
// min(period/2, refreshRetryMaximum). A success restores the normal period.
func (w *refreshWorker) start(period time.Duration, refresh func(context.Context) error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped || w.done != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		if ctx.Err() != nil {
			return
		}
		retryMaximum := min(period/2, refreshRetryMaximum)
		var retry time.Duration
		timer := time.NewTimer(period)
		defer timer.Stop()
		for {
			delay := period
			if err := refresh(ctx); err != nil {
				retry = min(max(2*retry, refreshRetryInitial), retryMaximum)
				delay = retry
			} else {
				retry = 0
			}
			timer.Reset(delay)
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if ctx.Err() != nil {
					return
				}
			}
		}
	}()
}

func (w *refreshWorker) stop() {
	w.mu.Lock()
	w.stopped = true
	cancel, done := w.cancel, w.done
	w.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
