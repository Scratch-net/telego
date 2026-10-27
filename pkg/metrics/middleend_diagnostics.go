package metrics

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func registerMiddleEndDiagnosticMetrics(group *snapshotMetricGroup[middleend.ServiceSnapshot]) {
	meter := group.meter

	registerMiddleEndResponsePressureMetrics(group)
	recordsDropped, _ := meter.Int64ObservableCounter("telego_middleend_diagnostic_records_dropped_total",
		metric.WithDescription("ME diagnostic records rejected by the full journal during the service lifetime"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		observer.ObserveInt64(recordsDropped, metricValue(collected.Supervisor.DiagnosticRecordsDropped))
	}, recordsDropped)
	for _, counter := range []struct {
		name        string
		description string
		value       func(middleend.GenerationForcedRetirementCounter) uint64
	}{
		{
			name:        "telego_middleend_forced_retirement_total",
			description: "ME generations closed to free capacity during the service lifetime",
			value:       func(count middleend.GenerationForcedRetirementCounter) uint64 { return count.Retirements },
		},
		{
			name:        "telego_middleend_forced_retirement_affected_bindings_total",
			description: "ME bindings interrupted by capacity retirement during the service lifetime",
			value:       func(count middleend.GenerationForcedRetirementCounter) uint64 { return count.AffectedBindings },
		},
	} {
		forcedRetirement, _ := meter.Int64ObservableCounter(counter.name,
			metric.WithDescription(counter.description),
		)
		group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
			snapshot := collected.Supervisor
			for _, reason := range [...]middleend.GenerationRetirementReason{
				middleend.GenerationRetirementArtifactCapacity,
				middleend.GenerationRetirementRecoveryCapacity,
			} {
				var value uint64
				for _, count := range snapshot.ForcedRetirements {
					if count.Reason == reason {
						value = counter.value(count)
						break
					}
				}
				observer.ObserveInt64(forcedRetirement, metricValue(value), metric.WithAttributes(attribute.String("reason", string(reason))))
			}
		}, forcedRetirement)
	}
}
