// Package metrics provides Prometheus metrics via OpenTelemetry.
package metrics

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/webproxy"
)

// Server wraps the metrics HTTP server.
type Server struct {
	httpServer *http.Server
	provider   *sdkmetric.MeterProvider
}

// StatsProvider provides user statistics for metrics.
type StatsProvider interface {
	Stats() []gproxy.UserIPStats
}

// ProxyStatsProvider supplies cumulative MTProxy handshake diagnostics.
type ProxyStatsProvider interface {
	HandshakeFailureStats() []gproxy.HandshakeFailureStat
}

type middleEndFrontendStatsProvider interface {
	MiddleEndFrontendStats() gproxy.MiddleEndFrontendStats
}

// WebStatsProvider supplies WEB lifecycle and capacity diagnostics.
type WebStatsProvider interface {
	RuntimeStats() webproxy.RuntimeStats
}

// MiddleEndStatsProvider supplies redacted ME lifecycle, pool, and queue state.
type MiddleEndStatsProvider interface {
	Snapshot() middleend.ServiceSnapshot
}

// Config configures the metrics server.
type Config struct {
	BindAddr   string
	Path       string
	ProxyStats ProxyStatsProvider
	WebStats   WebStatsProvider
	MiddleEnd  MiddleEndStatsProvider
}

// NewServer creates a new metrics server.
func NewServer(cfg Config, limiter StatsProvider) (*Server, error) {
	// Create Prometheus exporter
	exporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}

	// Create meter provider
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	otel.SetMeterProvider(provider)

	meter := provider.Meter("telego")

	// Register observable instruments
	if limiter != nil {
		registerMetrics(meter, limiter)
	}
	if cfg.ProxyStats != nil {
		registerProxyMetrics(meter, cfg.ProxyStats)
	}
	if cfg.WebStats != nil {
		registerWebMetrics(meter, cfg.WebStats)
	}
	if cfg.MiddleEnd != nil {
		registerMiddleEndMetrics(meter, cfg.MiddleEnd)
	}

	// Create HTTP server
	mux := http.NewServeMux()
	path := cfg.Path
	if path == "" {
		path = "/metrics"
	}
	mux.Handle(path, promhttp.Handler())

	httpServer := &http.Server{
		Addr:    cfg.BindAddr,
		Handler: mux,
	}

	return &Server{
		httpServer: httpServer,
		provider:   provider,
	}, nil
}

func registerMiddleEndMetrics(meter metric.Meter, provider MiddleEndStatsProvider) {
	meter.Int64ObservableGauge("telego_middleend_capacity",
		metric.WithDescription("Configured Middle-End topology and bounded-queue capacities"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			capacity := provider.Snapshot().Capacity
			for resource, value := range map[string]int{
				"event_loops":            capacity.EventLoops,
				"links_per_dc":           capacity.LinksPerDC,
				"resident_bindings":      capacity.MaxResidentBindings,
				"link_submission_items":  capacity.LinkSubmissionItems,
				"link_submission_bytes":  capacity.LinkSubmissionBytes,
				"link_event_items":       capacity.LinkEventItems,
				"link_event_bytes":       capacity.LinkEventBytes,
				"manager_request_items":  capacity.ManagerRequestItems,
				"manager_request_bytes":  capacity.ManagerRequestBytes,
				"manager_control_items":  capacity.ManagerControlItems,
				"manager_control_bytes":  capacity.ManagerControlBytes,
				"manager_response_items": capacity.ManagerResponseItems,
				"manager_response_bytes": capacity.ManagerResponseBytes,
				"binding_response_items": capacity.BindingResponseItems,
				"binding_response_bytes": capacity.BindingResponseBytes,
			} {
				observer.Observe(int64(value), metric.WithAttributes(attribute.String("resource", resource)))
			}
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_middleend_admitting",
		metric.WithDescription("Whether a healthy active ME generation admits new bindings"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(boolMetric(provider.Snapshot().Supervisor.Admitting))
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_middleend_repairing",
		metric.WithDescription("Whether the ME generation supervisor is repairing protection"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(boolMetric(provider.Snapshot().Supervisor.Repairing))
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_middleend_slot_repairs_active",
		metric.WithDescription("ME physical-link slots currently being replaced by generation role"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			forEachMiddleEndRole(provider.Snapshot().Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
				observer.Observe(int64(manager.RepairingSlots), metric.WithAttributes(attribute.String("role", role)))
			})
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_middleend_slot_repair_total",
		metric.WithDescription("ME physical-link replacement outcomes for the service lifetime"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			snapshot := provider.Snapshot().Supervisor
			observer.Observe(metricValue(snapshot.SlotRepairSuccesses), metric.WithAttributes(attribute.String("result", "success")))
			observer.Observe(metricValue(snapshot.SlotRepairFailures), metric.WithAttributes(attribute.String("result", "failure")))
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_middleend_slot_failure_total",
		metric.WithDescription("ME physical-link failures for the service lifetime"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(metricValue(provider.Snapshot().Supervisor.SlotFailures))
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_middleend_slot_failure_affected_bindings_total",
		metric.WithDescription("ME bindings terminated by physical-link failures for the service lifetime"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(metricValue(provider.Snapshot().Supervisor.SlotFailureAffectedBindings))
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_middleend_artifact_state",
		metric.WithDescription("Current Telegram ME artifact application state"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			snapshot := provider.Snapshot().Coordinator
			observer.Observe(boolMetric(snapshot.Applied), metric.WithAttributes(attribute.String("state", "applied")))
			observer.Observe(boolMetric(snapshot.Pending), metric.WithAttributes(attribute.String("state", "pending")))
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_middleend_artifact_refresh_total",
		metric.WithDescription("Telegram ME artifact refresh outcomes"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			snapshot := provider.Snapshot().Coordinator
			observer.Observe(metricValue(snapshot.RefreshSuccesses), metric.WithAttributes(attribute.String("result", "success")))
			observer.Observe(metricValue(snapshot.RefreshFailures), metric.WithAttributes(attribute.String("result", "failure")))
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_middleend_generation_apply_total",
		metric.WithDescription("Telegram ME generation application outcomes"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			snapshot := provider.Snapshot().Coordinator
			observer.Observe(metricValue(snapshot.GenerationSuccesses), metric.WithAttributes(attribute.String("result", "success")))
			observer.Observe(metricValue(snapshot.GenerationFailures), metric.WithAttributes(attribute.String("result", "failure")))
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_middleend_links",
		metric.WithDescription("ME physical links by generation role, signed DC, and state"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			forEachMiddleEndRole(provider.Snapshot().Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
				counts := make(map[middleEndLinkMetricKey]int64)
				for _, slot := range manager.Slots {
					key := middleEndLinkMetricKey{dc: slot.DCID, state: middleEndLinkState(slot)}
					counts[key]++
				}
				for key, count := range counts {
					observer.Observe(count, metric.WithAttributes(
						attribute.String("role", role),
						attribute.String("dc", strconv.Itoa(int(key.dc))),
						attribute.String("state", key.state),
					))
				}
			})
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_middleend_bindings_active",
		metric.WithDescription("ME client bindings by generation role and signed DC"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			forEachMiddleEndRole(provider.Snapshot().Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
				byDC := make(map[middleend.DCID]int64)
				for _, slot := range manager.Slots {
					byDC[slot.DCID] += int64(slot.ResidentBindings)
				}
				for dcID, bindings := range byDC {
					observer.Observe(bindings, metric.WithAttributes(
						attribute.String("role", role),
						attribute.String("dc", strconv.Itoa(int(dcID))),
					))
				}
			})
			return nil
		}),
	)
	registerMiddleEndManagerQueueMetrics(meter, provider)
	registerMiddleEndLinkQueueMetrics(meter, provider)
}

type middleEndLinkMetricKey struct {
	dc    middleend.DCID
	state string
}

func middleEndLinkState(slot middleend.FixedBindingSlotSnapshot) string {
	if slot.Repairing {
		return "repairing"
	}
	if slot.Failed {
		return "failed"
	}
	switch slot.Link.State {
	case middleend.LinkStateCreated:
		return "created"
	case middleend.LinkStateBootstrapping:
		return "bootstrapping"
	case middleend.LinkStateReady:
		return "ready"
	case middleend.LinkStateClosing:
		return "closing"
	case middleend.LinkStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

func forEachMiddleEndRole(snapshot middleend.GenerationSupervisorSnapshot, visit func(string, *middleend.FixedBindingManagerSnapshot)) {
	for _, item := range []struct {
		role    string
		manager *middleend.FixedBindingManagerSnapshot
	}{
		{role: "active", manager: snapshot.Active},
		{role: "retiring", manager: snapshot.Retiring},
	} {
		if item.manager != nil {
			visit(item.role, item.manager)
		}
	}
}

func registerMiddleEndManagerQueueMetrics(meter metric.Meter, provider MiddleEndStatsProvider) {
	registerMiddleEndManagerQueueMetric(meter, provider, "telego_middleend_manager_queue_items", "Items retained by ME generation-manager queues", false, false)
	registerMiddleEndManagerQueueMetric(meter, provider, "telego_middleend_manager_queue_bytes", "Bytes retained by ME generation-manager queues", true, false)
	registerMiddleEndManagerQueueMetric(meter, provider, "telego_middleend_manager_queue_high_water_items", "Lifetime high-water items retained by ME generation-manager queues", false, true)
	registerMiddleEndManagerQueueMetric(meter, provider, "telego_middleend_manager_queue_high_water_bytes", "Lifetime high-water bytes retained by ME generation-manager queues", true, true)
	meter.Int64ObservableGauge("telego_middleend_manager_backpressure_events",
		metric.WithDescription("Lifetime bounded-queue rejections in the current ME generation manager"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			forEachMiddleEndRole(provider.Snapshot().Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
				observer.Observe(metricValue(manager.ResponseBackpressureEvents), metric.WithAttributes(
					attribute.String("role", role),
					attribute.String("kind", "response"),
				))
				observer.Observe(metricValue(manager.ControlBackpressureEvents), metric.WithAttributes(
					attribute.String("role", role),
					attribute.String("kind", "control"),
				))
			})
			return nil
		}),
	)
}

func registerMiddleEndManagerQueueMetric(
	meter metric.Meter,
	provider MiddleEndStatsProvider,
	name string,
	description string,
	bytes bool,
	highWater bool,
) {
	options := []metric.Int64ObservableGaugeOption{metric.WithDescription(description)}
	if bytes {
		options = append(options, metric.WithUnit("By"))
	}
	options = append(options, metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
		forEachMiddleEndRole(provider.Snapshot().Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
			request, control, response := middleEndManagerQueueValues(manager, bytes, highWater)
			for queue, value := range map[string]int{
				"request":  request,
				"control":  control,
				"response": response,
			} {
				observer.Observe(int64(value), metric.WithAttributes(attribute.String("role", role), attribute.String("queue", queue)))
			}
		})
		return nil
	}))
	meter.Int64ObservableGauge(name, options...)
}

func middleEndManagerQueueValues(snapshot *middleend.FixedBindingManagerSnapshot, bytes, highWater bool) (request, control, response int) {
	switch {
	case bytes && highWater:
		return snapshot.RequestBytesHighWater, snapshot.ControlBytesHighWater, snapshot.ResponseBytesHighWater
	case bytes:
		return snapshot.RequestBytes, snapshot.ControlBytes, snapshot.ResponseBytes
	case highWater:
		return snapshot.RequestItemsHighWater, snapshot.ControlItemsHighWater, snapshot.ResponseItemsHighWater
	default:
		return snapshot.RequestItems, snapshot.ControlItems, snapshot.ResponseItems
	}
}

func registerMiddleEndLinkQueueMetrics(meter metric.Meter, provider MiddleEndStatsProvider) {
	registerMiddleEndLinkQueueMetric(meter, provider, "telego_middleend_link_queue_items", "Items pending in ME gnet link queues", false, false)
	registerMiddleEndLinkQueueMetric(meter, provider, "telego_middleend_link_queue_bytes", "Bytes pending in ME gnet link queues", true, false)
	registerMiddleEndLinkQueueMetric(meter, provider, "telego_middleend_link_queue_high_water_items", "Lifetime high-water items in ME gnet link queues", false, true)
	registerMiddleEndLinkQueueMetric(meter, provider, "telego_middleend_link_queue_high_water_bytes", "Lifetime high-water bytes in ME gnet link queues", true, true)
	registerMiddleEndLinkQueueCapacityMetric(meter, provider, "telego_middleend_link_queue_capacity_items", "Configured item capacity of each ME gnet link queue", false)
	registerMiddleEndLinkQueueCapacityMetric(meter, provider, "telego_middleend_link_queue_capacity_bytes", "Configured byte capacity of each ME gnet link queue", true)
}

func registerMiddleEndLinkQueueCapacityMetric(
	meter metric.Meter,
	provider MiddleEndStatsProvider,
	name string,
	description string,
	bytes bool,
) {
	options := []metric.Int64ObservableGaugeOption{metric.WithDescription(description)}
	if bytes {
		options = append(options, metric.WithUnit("By"))
	}
	options = append(options, metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
		snapshot := provider.Snapshot()
		forEachMiddleEndRole(snapshot.Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
			linksByDC := make(map[middleend.DCID]int)
			for _, slot := range manager.Slots {
				linksByDC[slot.DCID]++
				link := linksByDC[slot.DCID]
				var submission, event int
				if bytes {
					submission = snapshot.Capacity.LinkSubmissionBytes
					event = snapshot.Capacity.LinkEventBytes
				} else {
					submission = snapshot.Capacity.LinkSubmissionItems
					event = snapshot.Capacity.LinkEventItems
				}
				for queue, value := range map[string]int{"submission": submission, "event": event} {
					observer.Observe(int64(value), metric.WithAttributes(
						attribute.String("role", role),
						attribute.String("dc", strconv.Itoa(int(slot.DCID))),
						attribute.Int("link", link),
						attribute.String("queue", queue),
					))
				}
			}
		})
		return nil
	}))
	meter.Int64ObservableGauge(name, options...)
}

func registerMiddleEndLinkQueueMetric(
	meter metric.Meter,
	provider MiddleEndStatsProvider,
	name string,
	description string,
	bytes bool,
	highWater bool,
) {
	options := []metric.Int64ObservableGaugeOption{metric.WithDescription(description)}
	if bytes {
		options = append(options, metric.WithUnit("By"))
	}
	options = append(options, metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
		forEachMiddleEndRole(provider.Snapshot().Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
			values := make(map[middleEndLinkQueueMetricKey]int64)
			linksByDC := make(map[middleend.DCID]int)
			for _, slot := range manager.Slots {
				linksByDC[slot.DCID]++
				link := linksByDC[slot.DCID]
				submission, event := middleEndLinkQueueValues(slot.Link, bytes, highWater)
				values[middleEndLinkQueueMetricKey{dc: slot.DCID, link: link, queue: "submission"}] = int64(submission)
				values[middleEndLinkQueueMetricKey{dc: slot.DCID, link: link, queue: "event"}] = int64(event)
			}
			for key, value := range values {
				observer.Observe(value, metric.WithAttributes(
					attribute.String("role", role),
					attribute.String("dc", strconv.Itoa(int(key.dc))),
					attribute.Int("link", key.link),
					attribute.String("queue", key.queue),
				))
			}
		})
		return nil
	}))
	meter.Int64ObservableGauge(name, options...)
}

type middleEndLinkQueueMetricKey struct {
	dc    middleend.DCID
	link  int
	queue string
}

func middleEndLinkQueueValues(snapshot middleend.LinkSnapshot, bytes, highWater bool) (submission, event int) {
	switch {
	case bytes && highWater:
		return snapshot.SubmissionBytesHighWater, snapshot.EventBytesHighWater
	case bytes:
		return snapshot.PendingSubmissionBytes, snapshot.PendingEventBytes
	case highWater:
		return snapshot.SubmissionHighWater, snapshot.EventHighWater
	default:
		return snapshot.PendingSubmissions, snapshot.PendingEvents
	}
}

func boolMetric(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func registerProxyMetrics(meter metric.Meter, provider ProxyStatsProvider) {
	meter.Int64ObservableCounter("telego_handshake_failures_total",
		metric.WithDescription("MTProxy handshake failures by processing stage"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			for _, stat := range provider.HandshakeFailureStats() {
				observer.Observe(metricValue(stat.Total), metric.WithAttributes(attribute.String("stage", stat.Stage)))
			}
			return nil
		}),
	)
	frontend, ok := provider.(middleEndFrontendStatsProvider)
	if !ok {
		return
	}
	registerMiddleEndFrontendMetrics(meter, frontend)
}

func registerMiddleEndFrontendMetrics(meter metric.Meter, provider middleEndFrontendStatsProvider) {
	meter.Int64ObservableGauge("telego_middleend_frontend_routes_active",
		metric.WithDescription("Active public connections committed to ME or direct fallback"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			stats := provider.MiddleEndFrontendStats()
			observer.Observe(stats.MiddleEndBindingsActive, metric.WithAttributes(attribute.String("route", "middleend")))
			observer.Observe(stats.DirectFallbacksActive, metric.WithAttributes(attribute.String("route", "direct_fallback")))
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_middleend_frontend_route_commits_total",
		metric.WithDescription("Public connections committed to ME or direct fallback"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			stats := provider.MiddleEndFrontendStats()
			observer.Observe(metricValue(stats.MiddleEndBindingsTotal), metric.WithAttributes(attribute.String("route", "middleend")))
			observer.Observe(metricValue(stats.DirectFallbacksTotal), metric.WithAttributes(attribute.String("route", "direct_fallback")))
			return nil
		}),
	)
	for _, instrument := range []struct {
		name        string
		description string
		value       func(gproxy.MiddleEndFrontendStats, string) int64
	}{
		{
			name:        "telego_middleend_frontend_buffer_bytes",
			description: "Bytes retained between public gnet connections and the ME binding manager",
			value: func(stats gproxy.MiddleEndFrontendStats, direction string) int64 {
				if direction == "input" {
					return stats.InputBytes
				}
				return stats.OutputBytes
			},
		},
		{
			name:        "telego_middleend_frontend_buffer_high_water_bytes",
			description: "Lifetime high-water bytes retained by the ME public frontend",
			value: func(stats gproxy.MiddleEndFrontendStats, direction string) int64 {
				if direction == "input" {
					return stats.InputBytesHighWater
				}
				return stats.OutputBytesHighWater
			},
		},
		{
			name:        "telego_middleend_frontend_buffer_capacity_bytes",
			description: "Configured byte capacity of the ME public frontend",
			value: func(stats gproxy.MiddleEndFrontendStats, direction string) int64 {
				if direction == "input" {
					return stats.InputBytesLimit
				}
				return stats.OutputBytesLimit
			},
		},
	} {
		meter.Int64ObservableGauge(instrument.name,
			metric.WithDescription(instrument.description),
			metric.WithUnit("By"),
			metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
				stats := provider.MiddleEndFrontendStats()
				for _, direction := range []string{"input", "output"} {
					observer.Observe(instrument.value(stats, direction), metric.WithAttributes(attribute.String("direction", direction)))
				}
				return nil
			}),
		)
	}
	meter.Int64ObservableCounter("telego_middleend_frontend_backpressure_events_total",
		metric.WithDescription("ME public frontend aggregate byte-budget rejections"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			stats := provider.MiddleEndFrontendStats()
			observer.Observe(metricValue(stats.InputBackpressureEvents), metric.WithAttributes(attribute.String("direction", "input")))
			observer.Observe(metricValue(stats.OutputBackpressureEvents), metric.WithAttributes(attribute.String("direction", "output")))
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_middleend_frontend_output_evictions_total",
		metric.WithDescription("ME public clients evicted to release aggregate output pressure"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(metricValue(provider.MiddleEndFrontendStats().OutputEvictions))
			return nil
		}),
	)
}

func registerWebMetrics(meter metric.Meter, provider WebStatsProvider) {
	meter.Int64ObservableGauge("telego_web_websocket_connections_active",
		metric.WithDescription("Active WEB WebSocket carrier connections"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(provider.RuntimeStats().WebSocketsActive)
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_web_sessions_active",
		metric.WithDescription("Active WEB relay sessions"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(int64(provider.RuntimeStats().Capacity.Sessions))
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_web_streams_active",
		metric.WithDescription("Active WEB backend streams"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(int64(provider.RuntimeStats().Capacity.Streams))
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_web_backend_dials_active",
		metric.WithDescription("WEB backend dials in progress"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(int64(provider.RuntimeStats().Capacity.BackendDials))
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_web_pending_bytes",
		metric.WithDescription("Bytes charged to WEB pending queues"),
		metric.WithUnit("By"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(provider.RuntimeStats().Capacity.PendingBytes)
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_web_pending_items",
		metric.WithDescription("Items charged to WEB pending queues"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(provider.RuntimeStats().Capacity.PendingItems)
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_web_sessions_created_total",
		metric.WithDescription("WEB relay sessions created"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(metricValue(provider.RuntimeStats().SessionsCreated))
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_web_sessions_closed_total",
		metric.WithDescription("WEB relay sessions closed by reason"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			for _, counter := range provider.RuntimeStats().SessionsClosed {
				observer.Observe(metricValue(counter.Total), metric.WithAttributes(attribute.String("reason", counter.Label)))
			}
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_web_carrier_retries_total",
		metric.WithDescription("Authenticated WEB carrier retries and replays"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			for _, counter := range provider.RuntimeStats().CarrierRetries {
				observer.Observe(metricValue(counter.Total), metric.WithAttributes(attribute.String("operation", counter.Label)))
			}
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_web_backpressure_total",
		metric.WithDescription("WEB carrier requests delayed by resource backpressure"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			for _, counter := range provider.RuntimeStats().Backpressure {
				observer.Observe(metricValue(counter.Total), metric.WithAttributes(attribute.String("operation", counter.Label)))
			}
			return nil
		}),
	)
}

func metricValue(value uint64) int64 {
	return int64(min(value, uint64(math.MaxInt64)))
}

func registerMetrics(meter metric.Meter, limiter StatsProvider) {
	// Active connections gauge
	meter.Int64ObservableGauge("telego_connections_active",
		metric.WithDescription("Active connections per user"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(s.Connections, metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Active IPs gauge (IPs with at least one connection right now)
	meter.Int64ObservableGauge("telego_ips_active",
		metric.WithDescription("IPs with active connections per user"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(int64(s.ActiveIPs), metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Tracked IPs gauge (unique IPs in LRU cache, may include disconnected)
	meter.Int64ObservableGauge("telego_ips_tracked",
		metric.WithDescription("Unique IPs tracked in LRU cache per user"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(int64(s.TrackedIPs), metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Blocked IPs gauge
	meter.Int64ObservableGauge("telego_ips_blocked",
		metric.WithDescription("Currently blocked IPs per user"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(int64(s.BlockedIPs), metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Blocked total counter
	meter.Int64ObservableCounter("telego_blocked_total",
		metric.WithDescription("Total IP block events per user"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(s.BlockedTotal, metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Traffic in counter
	meter.Int64ObservableCounter("telego_traffic_in_bytes_total",
		metric.WithDescription("Total bytes received from clients per user"),
		metric.WithUnit("By"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(s.BytesIn, metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Traffic out counter
	meter.Int64ObservableCounter("telego_traffic_out_bytes_total",
		metric.WithDescription("Total bytes sent to clients per user"),
		metric.WithUnit("By"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(s.BytesOut, metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)
}

// Start starts the metrics HTTP server in a goroutine.
// Errors during ListenAndServe are silently ignored because metrics are optional.
// The caller should verify the server is accessible if metrics are required.
func (s *Server) Start() error {
	go func() {
		_ = s.httpServer.ListenAndServe()
		// Errors ignored: metrics are optional, and ErrServerClosed is expected on shutdown
	}()
	return nil
}

// Shutdown gracefully shuts down the metrics server.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.provider.Shutdown(shutdownCtx)
}
