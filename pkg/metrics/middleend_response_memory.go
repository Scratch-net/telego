package metrics

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func registerMiddleEndResponseMemoryMetrics(meter metric.Meter, provider MiddleEndStatsProvider) {
	used, _ := meter.Int64ObservableGauge("telego_middleend_response_memory_used_bytes",
		metric.WithDescription("Shared ME response charge, including reserved output headroom, allocation handles, and owner metadata; not process RSS"), metric.WithUnit("By"))
	limit, _ := meter.Int64ObservableGauge("telego_middleend_response_memory_limit_bytes",
		metric.WithDescription("Service-wide ME response allocation limit shared across generations; excludes separately bounded decoder storage, WEB carrier storage, and runtime/kernel memory"), metric.WithUnit("By"))
	highWater, _ := meter.Int64ObservableGauge("telego_middleend_response_memory_high_water_bytes",
		metric.WithDescription("Service-lifetime high-water shared ME response charge, including reserved headroom and metadata"), metric.WithUnit("By"))
	classUsed, _ := meter.Int64ObservableGauge("telego_middleend_response_memory_class_bytes",
		metric.WithDescription("Shared ME response charge by protected memory class, including headroom and metadata"), metric.WithUnit("By"))
	classLimit, _ := meter.Int64ObservableGauge("telego_middleend_response_memory_class_limit_bytes",
		metric.WithDescription("Protected capacity of each shared ME response memory class"), metric.WithUnit("By"))
	stageUsed, _ := meter.Int64ObservableGauge("telego_middleend_response_memory_stage_bytes",
		metric.WithDescription("Shared ME response charge by ownership stage, including reserved headroom, allocation handles, and owner metadata"), metric.WithUnit("By"))

	// One snapshot keeps totals, classes, and stages consistent during a scrape.
	meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		snapshot := provider.Snapshot().ResponseBudget
		if snapshot.LimitBytes == 0 {
			return nil
		}
		observer.ObserveInt64(used, int64(snapshot.UsedBytes))
		observer.ObserveInt64(limit, int64(snapshot.LimitBytes))
		observer.ObserveInt64(highWater, int64(snapshot.HighWaterBytes))
		for _, class := range []struct {
			name  string
			class middleend.ResponseMemoryClass
			limit int
		}{
			{"ordinary", middleend.ResponseMemoryOrdinary, snapshot.OrdinaryLimitBytes},
			{"processing", middleend.ResponseMemoryProcessing, snapshot.ProcessingReserveBytes},
			{"control", middleend.ResponseMemoryControl, snapshot.ControlReserveBytes},
		} {
			attributes := metric.WithAttributes(attribute.String("class", class.name))
			observer.ObserveInt64(classUsed, int64(snapshot.ClassBytes[class.class]), attributes)
			observer.ObserveInt64(classLimit, int64(class.limit), attributes)
		}
		for _, stage := range []struct {
			name  string
			stage middleend.ResponseMemoryStage
		}{
			{"queue_payload", middleend.ResponseMemoryQueuePayload},
			{"queue_metadata", middleend.ResponseMemoryQueueMetadata},
			{"decode", middleend.ResponseMemoryDecode},
			{"encode", middleend.ResponseMemoryEncode},
			{"output", middleend.ResponseMemoryOutput},
			{"inflight", middleend.ResponseMemoryInflight},
			{"owner_metadata", middleend.ResponseMemoryOwnerMetadata},
		} {
			observer.ObserveInt64(stageUsed, int64(snapshot.StageBytes[stage.stage]), metric.WithAttributes(attribute.String("stage", stage.name)))
		}
		return nil
	}, used, limit, highWater, classUsed, classLimit, stageUsed)
}

func registerMiddleEndResponseWaitMetrics(meter metric.Meter, provider middleEndFrontendStatsProvider) {
	entered, _ := meter.Int64ObservableCounter("telego_middleend_response_admission_waits_total",
		metric.WithDescription("ME frontend response admission wait intervals entered during the frontend lifetime"))
	completed, _ := meter.Int64ObservableCounter("telego_middleend_response_admission_waits_completed_total",
		metric.WithDescription("ME frontend response admission wait intervals completed, including intervals ended by client closure"))
	duration, _ := meter.Float64ObservableCounter("telego_middleend_response_admission_wait_seconds_total",
		metric.WithDescription("Total duration of completed ME frontend admission wait intervals; excludes time in currently active waits"), metric.WithUnit("s"))
	active, _ := meter.Int64ObservableGauge("telego_middleend_response_admission_waits_active",
		metric.WithDescription("Current unfinished ME frontend admission wait intervals"))
	stalls, _ := meter.Int64ObservableCounter("telego_middleend_response_output_stall_closures_total",
		metric.WithDescription("ME frontend clients closed after the independent output no-progress deadline expired"))

	meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		stats := provider.MiddleEndFrontendStats()
		for reason := middleend.ResponseOutputClientBuffer; reason < middleend.ResponseOutputWaitCount; reason++ {
			attributes := metric.WithAttributes(attribute.String("reason", reason.String()))
			observer.ObserveInt64(entered, metricValue(stats.ResponseWaitsTotal[reason]), attributes)
			observer.ObserveInt64(completed, metricValue(stats.ResponseWaitsCompletedTotal[reason]), attributes)
			observer.ObserveFloat64(duration, float64(stats.ResponseWaitDurationMicroseconds[reason])/1e6, attributes)
			observer.ObserveInt64(active, stats.ResponseWaitsActive[reason], attributes)
		}
		observer.ObserveInt64(stalls, metricValue(stats.ResponseStallClosures))
		return nil
	}, entered, completed, duration, active, stalls)
}
