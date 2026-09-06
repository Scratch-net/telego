package metrics

import (
	"context"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func registerMiddleEndRefreshMetrics(meter metric.Meter, provider MiddleEndStatsProvider) {
	meter.Int64ObservableGauge("telego_middleend_slot_refreshes_active",
		metric.WithDescription("ME refresh candidate reservations by generation role and signed DC, including cleanup"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			forEachMiddleEndRole(provider.Snapshot().Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
				for _, dc := range manager.DCs {
					observer.Observe(int64(dc.RefreshingSlots), metric.WithAttributes(
						attribute.String("role", role),
						attribute.String("dc", strconv.Itoa(int(dc.DCID))),
					))
				}
			})
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_middleend_slot_refresh_total",
		metric.WithDescription("ME unused-link refresh outcomes by signed DC for the service lifetime"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			for _, dc := range provider.Snapshot().Supervisor.DCs {
				for _, result := range []struct {
					name  string
					count uint64
				}{
					{name: "success", count: dc.SlotRefreshSuccesses},
					{name: "failure", count: dc.SlotRefreshFailures},
					{name: "canceled", count: dc.SlotRefreshCanceled},
				} {
					observer.Observe(metricValue(result.count), metric.WithAttributes(
						attribute.String("dc", strconv.Itoa(int(dc.DCID))),
						attribute.String("result", result.name),
					))
				}
			}
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_middleend_zero_ready_transitions_total",
		metric.WithDescription("Manager-observed losses of all ready ME slots by signed DC for the service lifetime"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			for _, dc := range provider.Snapshot().Supervisor.DCs {
				observer.Observe(metricValue(dc.ZeroReadyTransitions), metric.WithAttributes(
					attribute.String("dc", strconv.Itoa(int(dc.DCID))),
				))
			}
			return nil
		}),
	)
}
