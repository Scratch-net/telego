package gproxy

import (
	"math"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestResponseWaitDurationBeyondNanosecondCounterHorizon(t *testing.T) {
	frontend := &middleEndFrontend{}
	const reason = middleend.ResponseOutputClientBuffer
	initial := uint64(math.MaxUint64 / 1000)
	frontend.responseWaits[reason].duration.Store(initial)
	client := &middleEndClient{frontend: frontend}
	now := time.Now()
	client.observeResponseOutputWaitAt(reason, now)
	client.observeResponseOutputWaitAt(middleend.ResponseOutputNotWaiting, now.Add(100*time.Second))
	if got := frontend.stats().ResponseWaitDurationMicroseconds[reason]; got != initial+100_000_000 || got <= initial {
		t.Fatalf("duration wrapped at old nanosecond horizon: %d", got)
	}
}

func TestResponseWaitMetricsTransitionsAndCleanup(t *testing.T) {
	frontend := &middleEndFrontend{}
	client := &middleEndClient{frontend: frontend}
	now := time.Now().Add(-time.Second)
	client.observeResponseOutputWaitAt(middleend.ResponseOutputClientBuffer, now)
	client.observeResponseOutputWaitAt(middleend.ResponseOutputClientBuffer, now.Add(time.Millisecond))
	client.observeResponseOutputWaitAt(middleend.ResponseOutputProcessingReserve, now.Add(10*time.Millisecond))
	stats := frontend.stats()
	if stats.ResponseWaitsTotal[middleend.ResponseOutputClientBuffer] != 1 ||
		stats.ResponseWaitsCompletedTotal[middleend.ResponseOutputClientBuffer] != 1 ||
		stats.ResponseWaitDurationMicroseconds[middleend.ResponseOutputClientBuffer] != uint64((10*time.Millisecond).Microseconds()) ||
		stats.ResponseWaitsActive[middleend.ResponseOutputClientBuffer] != 0 ||
		stats.ResponseWaitsTotal[middleend.ResponseOutputProcessingReserve] != 1 ||
		stats.ResponseWaitsActive[middleend.ResponseOutputProcessingReserve] != 1 ||
		stats.ResponseWaitsCompletedTotal[middleend.ResponseOutputProcessingReserve] != 0 ||
		stats.ResponseWaitsTotal[middleend.ResponseOutputSharedBudget] != 0 {
		t.Fatalf("reason transition accounting: %+v", stats)
	}
	// A write timestamp is not actual drain and cannot complete a wait.
	client.responseLastWriteAt = now.Add(20 * time.Millisecond)
	client.releaseBudgets()
	client.releaseBudgets()
	stats = frontend.stats()
	if stats.ResponseWaitsActive[middleend.ResponseOutputProcessingReserve] != 0 ||
		stats.ResponseWaitsCompletedTotal[middleend.ResponseOutputProcessingReserve] != 1 ||
		stats.ResponseWaitDurationMicroseconds[middleend.ResponseOutputProcessingReserve] < uint64((900*time.Millisecond).Microseconds()) ||
		stats.ResponseWaitsTotal[middleend.ResponseOutputNotWaiting] != 0 {
		t.Fatalf("cleanup lost or double completed a wait: %+v", stats)
	}
}

func TestResponseWaitMetricsSurviveClientsAndCountStallOnce(t *testing.T) {
	budget, err := middleend.NewResponseBudget(middleend.ResponseBudgetConfig{LimitBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	frontend := &middleEndFrontend{responseBudget: budget}
	for range 2 {
		client := &middleEndClient{frontend: frontend}
		client.observeResponseOutputWait(middleend.ResponseOutputCarrierBudget)
		client.outputStallDeadline = time.Now().Add(-time.Second)
		first := client.waitForOutput(nil)
		again := client.waitForOutput(nil)
		if first || again {
			t.Fatal("expired output deadline did not close")
		}
		client.releaseBudgets()
	}
	stats := frontend.stats()
	if !stats.SharedResponseBudget || stats.ResponseStallClosures != 2 ||
		stats.ResponseWaitsTotal[middleend.ResponseOutputCarrierBudget] != 2 ||
		stats.ResponseWaitsCompletedTotal[middleend.ResponseOutputCarrierBudget] != 2 ||
		stats.ResponseWaitsActive[middleend.ResponseOutputCarrierBudget] != 0 {
		t.Fatalf("lifetime wait/stall accounting: %+v", stats)
	}
}
