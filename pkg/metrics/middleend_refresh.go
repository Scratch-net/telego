package metrics

import (
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func registerMiddleEndRefreshMetrics(group *snapshotMetricGroup[middleend.ServiceSnapshot]) {
	meter := group.meter

	refreshesActive, _ := meter.Int64ObservableGauge("telego_middleend_slot_refreshes_active",
		metric.WithDescription("ME refresh candidate reservations by generation role and signed DC, including cleanup"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		forEachMiddleEndRole(collected.Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
			for _, dc := range manager.DCs {
				observer.ObserveInt64(refreshesActive, int64(dc.RefreshingSlots), metric.WithAttributes(
					attribute.String("role", role),
					attribute.String("dc", strconv.Itoa(int(dc.DCID))),
				))
			}
		})
	}, refreshesActive)
	refreshTotal, _ := meter.Int64ObservableCounter("telego_middleend_slot_refresh_total",
		metric.WithDescription("ME unused-link refresh outcomes by signed DC for the service lifetime"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		for _, dc := range collected.Supervisor.DCs {
			for _, result := range []struct {
				name  string
				count uint64
			}{
				{name: "success", count: dc.SlotRefreshSuccesses},
				{name: "failure", count: dc.SlotRefreshFailures},
				{name: "canceled", count: dc.SlotRefreshCanceled},
			} {
				observer.ObserveInt64(refreshTotal, metricValue(result.count), metric.WithAttributes(
					attribute.String("dc", strconv.Itoa(int(dc.DCID))),
					attribute.String("result", result.name),
				))
			}
		}
	}, refreshTotal)
	zeroReadyTransitions, _ := meter.Int64ObservableCounter("telego_middleend_zero_ready_transitions_total",
		metric.WithDescription("Manager-observed losses of all ready ME slots by signed DC for the service lifetime"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		for _, dc := range collected.Supervisor.DCs {
			observer.ObserveInt64(zeroReadyTransitions, metricValue(dc.ZeroReadyTransitions), metric.WithAttributes(
				attribute.String("dc", strconv.Itoa(int(dc.DCID))),
			))
		}
	}, zeroReadyTransitions)
}
