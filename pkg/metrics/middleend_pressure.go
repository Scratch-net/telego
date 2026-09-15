package metrics

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func registerMiddleEndResponsePressureMetrics(meter metric.Meter, provider MiddleEndStatsProvider) {
	evictions, _ := meter.Int64ObservableCounter("telego_middleend_response_pressure_evictions_total",
		metric.WithDescription("ME client bindings evicted by response pressure during the service lifetime"))
	discarded, _ := meter.Int64ObservableCounter("telego_middleend_response_pressure_discarded_bytes_total",
		metric.WithDescription("Logical queued ME response bytes discarded during the service lifetime; excludes incoming rejection, output, reserved headroom, and metadata"))
	reclaimed, _ := meter.Int64ObservableCounter("telego_middleend_response_pressure_reclaimed_bytes_total",
		metric.WithDescription("Response budget charges synchronously released by pressure closure, including reserved headroom and metadata; excludes later deferred/output releases and does not measure heap or RSS reduction"))
	selections, _ := meter.Int64ObservableCounter("telego_middleend_response_pressure_selections_total",
		metric.WithDescription("Shared ME response-pressure closures by selection rule during the service lifetime; excludes failed or canceled selections"))

	meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		snapshot := provider.Snapshot().Supervisor
		for limit := middleend.ResponsePressureBindingItems; limit < middleend.ResponsePressureLimitCount; limit++ {
			attributes := metric.WithAttributes(attribute.String("limit", limit.String()))
			observer.ObserveInt64(evictions, metricValue(snapshot.ResponsePressureEvictions[limit]), attributes)
			observer.ObserveInt64(discarded, metricValue(snapshot.ResponsePressureDiscardedBytes[limit]), attributes)
			observer.ObserveInt64(reclaimed, metricValue(snapshot.ResponsePressureReclaimedBytes[limit]), attributes)
		}
		for rule := middleend.ResponsePressureLargestBacklog; rule < middleend.ResponsePressureSelectionReasonCount; rule++ {
			observer.ObserveInt64(selections, metricValue(snapshot.ResponsePressureSelections[rule]), metric.WithAttributes(attribute.String("rule", rule.String())))
		}
		return nil
	}, evictions, discarded, reclaimed, selections)
}
