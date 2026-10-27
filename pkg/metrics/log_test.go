package metrics

import (
	"context"
	"math"
	"sync/atomic"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestDroppedLogMetricIsCumulativeUnlabeledAndFresh(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown metrics: %v", err)
		}
	})
	var dropped atomic.Uint64
	registerLogMetrics(provider.Meter("telego-log-test"), dropped.Load)
	for _, count := range []uint64{0, 3, math.MaxUint64} {
		dropped.Store(count)
		var collected metricdata.ResourceMetrics
		if err := reader.Collect(t.Context(), &collected); err != nil {
			t.Fatal(err)
		}
		if len(collected.ScopeMetrics) != 1 || len(collected.ScopeMetrics[0].Metrics) != 1 {
			t.Fatalf("unexpected metric collection: %+v", collected)
		}
		instrument := collected.ScopeMetrics[0].Metrics[0]
		if instrument.Name != "telego_log_dropped_messages_total" {
			t.Fatalf("metric name = %q", instrument.Name)
		}
		sum, ok := instrument.Data.(metricdata.Sum[int64])
		if !ok || !sum.IsMonotonic || sum.Temporality != metricdata.CumulativeTemporality || len(sum.DataPoints) != 1 {
			t.Fatalf("expected one cumulative counter sample: %+v", instrument.Data)
		}
		point := sum.DataPoints[0]
		if point.Attributes.Len() != 0 || point.Value != int64(min(count, math.MaxInt64)) {
			t.Errorf("dropped=%d, exported value=%d attributes=%v", count, point.Value, point.Attributes)
		}
	}
}
