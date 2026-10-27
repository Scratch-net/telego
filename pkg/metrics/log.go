package metrics

import (
	"context"

	"go.opentelemetry.io/otel/metric"
)

func registerLogMetrics(meter metric.Meter, droppedMessages func() uint64) {
	meter.Int64ObservableCounter("telego_log_dropped_messages_total",
		metric.WithDescription("Log messages dropped when the asynchronous log queue is full or shutdown has started during the process lifetime"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(metricValue(droppedMessages()))
			return nil
		}),
	)
}
