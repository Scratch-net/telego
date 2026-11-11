package tlsfront

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// A failed refresh is retried with bounded exponential backoff instead of
// waiting a full period. A success returns to the normal period.
func TestRefreshWorkerRetriesFailureWithBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const period = 5 * time.Minute
		start := time.Now()
		var mu sync.Mutex
		var calls []time.Duration
		failures := 6
		var worker refreshWorker
		worker.start(period, func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, time.Since(start))
			if len(calls) <= failures {
				return errors.New("mask host unavailable")
			}
			return nil
		})
		time.Sleep(20 * time.Minute)
		synctest.Wait()
		worker.stop()

		// Failures at 0, 5s, 15s, 35s, 75s, 155s; the cap is period/2 = 150s,
		// so the next retry is at 305s and succeeds. Then the normal period.
		want := []time.Duration{0, 5, 15, 35, 75, 155, 305, 605, 905}
		mu.Lock()
		defer mu.Unlock()
		if len(calls) != len(want) {
			t.Fatalf("calls at %v, want %v seconds", calls, want)
		}
		for i := range want {
			if calls[i] != want[i]*time.Second {
				t.Fatalf("call %d at %v, want %v (all: %v)", i, calls[i], want[i]*time.Second, calls)
			}
		}
	})
}
