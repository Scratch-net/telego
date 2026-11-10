package dialrace

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type testConnection struct{ closes atomic.Int32 }

func disposeTestConnection(c *testConnection) {
	if c != nil {
		c.closes.Add(1)
	}
}

func TestFirstStaggersAndJoinsLateSuccessfulLoser(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	loser, winner := new(testConnection), new(testConnection)
	var active, calls atomic.Int32
	started := time.Now()
	value, index, err := First(ctx, 4, func(ctx context.Context, index int) (*testConnection, error) {
		calls.Add(1)
		active.Add(1)
		defer active.Add(-1)
		if index == 0 {
			<-ctx.Done()
			// A dial can complete just as cancellation arrives. Its returned
			// connection still belongs to First and must be closed.
			return loser, nil
		}
		if elapsed := time.Since(started); elapsed < Delay {
			t.Errorf("fallback started before its head start: %v", elapsed)
		}
		return winner, nil
	}, disposeTestConnection)
	if err != nil || value != winner || index != 1 {
		t.Fatalf("winner/index/error = %p/%d/%v", value, index, err)
	}
	if loser.closes.Load() != 1 || winner.closes.Load() != 0 || active.Load() != 0 || calls.Load() != 2 {
		t.Fatalf("loser/winner closes, active, calls = %d/%d/%d/%d", loser.closes.Load(), winner.closes.Load(), active.Load(), calls.Load())
	}
}

func TestFirstCancellationBoundsAndJoinsAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var calls, active atomic.Int32
	_, _, err := First(ctx, 100, func(ctx context.Context, _ int) (*testConnection, error) {
		active.Add(1)
		defer active.Add(-1)
		if calls.Add(1) == 2 {
			cancel()
		}
		<-ctx.Done()
		return new(testConnection), context.Cause(ctx)
	}, disposeTestConnection)
	if !errors.Is(err, context.Canceled) || calls.Load() != 2 || active.Load() != 0 {
		t.Fatalf("error/calls/active = %v/%d/%d", err, calls.Load(), active.Load())
	}
}

func TestFirstImmediateFailureAdvancesAndDisposesPartialValue(t *testing.T) {
	partial, winner := new(testConnection), new(testConnection)
	var calls int
	value, index, err := First(t.Context(), 2, func(_ context.Context, index int) (*testConnection, error) {
		calls++
		if index == 0 {
			return partial, errors.New("refused")
		}
		return winner, nil
	}, disposeTestConnection)
	if err != nil || value != winner || index != 1 || calls != 2 || partial.closes.Load() != 1 {
		t.Fatalf("result/index/error/calls/partial closes = %p/%d/%v/%d/%d", value, index, err, calls, partial.closes.Load())
	}
}

func TestFirstHealthyPrimaryDoesNotDialFallback(t *testing.T) {
	for _, count := range []int{1, 10} {
		var calls atomic.Int32
		value, index, err := First(t.Context(), count, func(context.Context, int) (int, error) {
			calls.Add(1)
			return 123, nil
		}, func(int) { t.Error("disposed winner") })
		if err != nil || value != 123 || index != 0 || calls.Load() != 1 {
			t.Fatalf("count %d: value/index/error/calls = %d/%d/%v/%d", count, value, index, err, calls.Load())
		}
	}
}

func TestFirstAllFailuresPreserveError(t *testing.T) {
	want := errors.New("unavailable")
	for _, count := range []int{1, 4} {
		_, _, err := First(t.Context(), count, func(context.Context, int) (int, error) {
			return 0, want
		}, func(int) {})
		if !errors.Is(err, want) {
			t.Fatalf("error = %v, want %v", err, want)
		}
	}
}
