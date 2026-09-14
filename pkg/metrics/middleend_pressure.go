package metrics

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func registerMiddleEndResponsePressureMetrics(meter metric.Meter, provider MiddleEndStatsProvider) {
	for _, counter := range []struct {
		name, description string
		discarded         bool
	}{
		{"telego_middleend_response_pressure_evictions_total", "ME client bindings evicted by response queue limits during the service lifetime", false},
		{"telego_middleend_response_pressure_discarded_bytes_total", "Queued ME response bytes discarded from evicted bindings during the service lifetime; excludes the rejected incoming response", true},
	} {
		meter.Int64ObservableCounter(counter.name,
			metric.WithDescription(counter.description),
			metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
				snapshot := provider.Snapshot().Supervisor
				counts := snapshot.ResponsePressureEvictions
				if counter.discarded {
					counts = snapshot.ResponsePressureDiscardedBytes
				}
				for limit := middleend.ResponsePressureBindingItems; limit < middleend.ResponsePressureLimitCount; limit++ {
					observer.Observe(metricValue(counts[limit]), metric.WithAttributes(attribute.String("limit", limit.String())))
				}
				return nil
			}),
		)
	}
}
