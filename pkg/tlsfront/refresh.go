package tlsfront

import (
	"context"
	"sync"
	"time"
)

// refreshWorker owns one periodic worker and joins its current network fetch.
// Once stopped, it cannot be restarted by a concurrent or repeated Start.
type refreshWorker struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
	stopped bool
}

func (w *refreshWorker) start(period time.Duration, refresh func(context.Context)) {
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
		refresh(ctx)
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ctx.Err() != nil {
					return
				}
				refresh(ctx)
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
