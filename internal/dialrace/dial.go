// Package dialrace bounds staggered connection attempts and owns loser cleanup.
package dialrace

import (
	"context"
	"errors"
	"time"
)

// Delay preserves the first candidate's head start before another is tried.
const Delay = 250 * time.Millisecond

// First tries candidates in order with at most two attempts in flight. A failed
// attempt advances immediately. dial must honor context cancellation; First
// cancels and joins every loser before returning the winning value and index.
// dispose must accept the zero value and release any partially returned value.
func First[T any](ctx context.Context, count int, dial func(context.Context, int) (T, error), dispose func(T)) (T, int, error) {
	var zero T
	if cause := context.Cause(ctx); cause != nil {
		return zero, -1, cause
	}
	if count == 0 {
		return zero, -1, errors.New("no dial candidates")
	}
	if count == 1 {
		value, err := dial(ctx, 0)
		if cause := context.Cause(ctx); cause != nil {
			err = cause
		}
		if err != nil {
			dispose(value)
			return zero, -1, err
		}
		return value, 0, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	type result struct {
		value T
		index int
		err   error
	}
	results := make(chan result, 2)
	next, active := 0, 0
	start := func() {
		index := next
		next++
		active++
		go func() {
			value, err := dial(ctx, index)
			results <- result{value, index, err}
		}()
	}
	defer func() {
		cancel()
		for range active {
			dispose((<-results).value)
		}
	}()
	start()
	timer := time.NewTimer(Delay)
	defer timer.Stop()
	tick := timer.C
	var lastErr error
	for active > 0 {
		select {
		case <-ctx.Done():
			return zero, -1, context.Cause(ctx)
		case <-tick:
			start()
			tick = nil
		case r := <-results:
			active--
			if cause := context.Cause(ctx); cause != nil {
				dispose(r.value)
				return zero, -1, cause
			}
			if r.err == nil {
				return r.value, r.index, nil
			}
			dispose(r.value)
			lastErr = r.err
			if next < count {
				start()
			}
			timer.Stop()
			tick = nil
			if active == 1 && next < count {
				timer.Reset(Delay)
				tick = timer.C
			}
		}
	}
	return zero, -1, lastErr
}
