// Package metrics provides Prometheus metrics via OpenTelemetry.
package metrics

import (
	"context"
	"math"
	"net"
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
	"github.com/scratch-net/telego/pkg/log"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/webproxy"
)

// Server wraps the metrics HTTP server.
type Server struct {
	httpServer  *http.Server
	provider    *sdkmetric.MeterProvider
	diagnostics *diagnostics
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
	BindAddr    string
	Path        string
	Diagnostics bool
	ProxyStats  ProxyStatsProvider
	WebStats    WebStatsProvider
	MiddleEnd   MiddleEndStatsProvider
}

// NewServer creates a new metrics server.
func NewServer(cfg Config, limiter StatsProvider) (*Server, error) {
	if err := validateDiagnosticsConfig(cfg); err != nil {
		return nil, err
	}
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
	registerLogMetrics(meter, log.DroppedMessages)
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
		Addr:              cfg.BindAddr,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      diagnosticsRequestTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	var profiles *diagnostics
	if cfg.Diagnostics {
		profiles = newDiagnostics()
		profiles.register(mux)
	}

	return &Server{
		httpServer:  httpServer,
		provider:    provider,
		diagnostics: profiles,
	}, nil
}

func registerMiddleEndMetrics(meter metric.Meter, provider MiddleEndStatsProvider) {
	group := &snapshotMetricGroup[middleend.ServiceSnapshot]{meter: meter}
	defer group.register(provider.Snapshot)

	runtimeLinks, _ := meter.Int64ObservableGauge("telego_middleend_runtime_links",
		metric.WithDescription("Currently registered physical ME links, including unpublished generation and refresh candidates until link finalization"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		observer.ObserveInt64(runtimeLinks, int64(collected.RuntimeLinks))
	}, runtimeLinks)
	capacityGauge, _ := meter.Int64ObservableGauge("telego_middleend_capacity",
		metric.WithDescription("Configured Middle-End topology and bounded-queue capacities"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		capacity := collected.Capacity
		for resource, value := range map[string]int{
			"refresh_candidates_per_manager":   capacity.MaxRefreshCandidatesPerManager,
			"event_loops":                      capacity.EventLoops,
			"links_per_dc":                     capacity.LinksPerDC,
			"resident_bindings":                capacity.MaxResidentBindings,
			"link_submission_items":            capacity.LinkSubmissionItems,
			"link_submission_bytes":            capacity.LinkSubmissionBytes,
			"link_event_items":                 capacity.LinkEventItems,
			"link_event_bytes":                 capacity.LinkEventBytes,
			"manager_request_items":            capacity.ManagerRequestItems,
			"manager_request_bytes":            capacity.ManagerRequestBytes,
			"manager_control_items":            capacity.ManagerControlItems,
			"manager_control_bytes":            capacity.ManagerControlBytes,
			"manager_response_items":           capacity.ManagerResponseItems,
			"manager_response_bytes":           capacity.ManagerResponseBytes,
			"binding_response_items":           capacity.BindingResponseItems,
			"binding_response_bytes":           capacity.BindingResponseBytes,
			"response_budget_bytes":            capacity.ResponseBudgetBytes,
			"decoder_bytes_per_link":           capacity.DecoderBytesPerLink,
			"decoder_growth_bytes_per_owner":   capacity.DecoderGrowthBytesPerOwner,
			"decode_plaintext_bytes_per_owner": capacity.DecodePlaintextBytesPerOwner,
		} {
			if capacity.ResponseBudgetBytes > 0 {
				switch resource {
				case "manager_response_items", "manager_response_bytes", "binding_response_items", "binding_response_bytes":
					continue
				}
			}
			observer.ObserveInt64(capacityGauge, int64(value), metric.WithAttributes(attribute.String("resource", resource)))
		}
	}, capacityGauge)
	admitting, _ := meter.Int64ObservableGauge("telego_middleend_admitting",
		metric.WithDescription("Whether a healthy active ME generation admits new bindings"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		observer.ObserveInt64(admitting, boolMetric(collected.Supervisor.Admitting))
	}, admitting)
	repairing, _ := meter.Int64ObservableGauge("telego_middleend_repairing",
		metric.WithDescription("Whether the ME generation supervisor is repairing protection"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		observer.ObserveInt64(repairing, boolMetric(collected.Supervisor.Repairing))
	}, repairing)
	slotRepairs, _ := meter.Int64ObservableGauge("telego_middleend_slot_repairs_active",
		metric.WithDescription("ME physical-link slots currently being replaced by generation role"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		forEachMiddleEndRole(collected.Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
			observer.ObserveInt64(slotRepairs, int64(manager.RepairingSlots), metric.WithAttributes(attribute.String("role", role)))
		})
	}, slotRepairs)
	slotRepairTotal, _ := meter.Int64ObservableCounter("telego_middleend_slot_repair_total",
		metric.WithDescription("ME physical-link replacement outcomes for the service lifetime"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		snapshot := collected.Supervisor
		observer.ObserveInt64(slotRepairTotal, metricValue(snapshot.SlotRepairSuccesses), metric.WithAttributes(attribute.String("result", "success")))
		observer.ObserveInt64(slotRepairTotal, metricValue(snapshot.SlotRepairFailures), metric.WithAttributes(attribute.String("result", "failure")))
	}, slotRepairTotal)
	slotFailures, _ := meter.Int64ObservableCounter("telego_middleend_slot_failure_total",
		metric.WithDescription("ME physical-link failures for the service lifetime"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		observer.ObserveInt64(slotFailures, metricValue(collected.Supervisor.SlotFailures))
	}, slotFailures)
	affectedBindings, _ := meter.Int64ObservableCounter("telego_middleend_slot_failure_affected_bindings_total",
		metric.WithDescription("ME bindings terminated by physical-link failures for the service lifetime"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		observer.ObserveInt64(affectedBindings, metricValue(collected.Supervisor.SlotFailureAffectedBindings))
	}, affectedBindings)
	artifactState, _ := meter.Int64ObservableGauge("telego_middleend_artifact_state",
		metric.WithDescription("Current Telegram ME artifact application state"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		snapshot := collected.Coordinator
		observer.ObserveInt64(artifactState, boolMetric(snapshot.Applied), metric.WithAttributes(attribute.String("state", "applied")))
		observer.ObserveInt64(artifactState, boolMetric(snapshot.Pending), metric.WithAttributes(attribute.String("state", "pending")))
	}, artifactState)
	artifactRefreshes, _ := meter.Int64ObservableCounter("telego_middleend_artifact_refresh_total",
		metric.WithDescription("Telegram ME artifact refresh outcomes"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		snapshot := collected.Coordinator
		observer.ObserveInt64(artifactRefreshes, metricValue(snapshot.RefreshSuccesses), metric.WithAttributes(attribute.String("result", "success")))
		observer.ObserveInt64(artifactRefreshes, metricValue(snapshot.RefreshFailures), metric.WithAttributes(attribute.String("result", "failure")))
	}, artifactRefreshes)
	generationApplies, _ := meter.Int64ObservableCounter("telego_middleend_generation_apply_total",
		metric.WithDescription("Telegram ME generation application outcomes"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		snapshot := collected.Coordinator
		observer.ObserveInt64(generationApplies, metricValue(snapshot.GenerationSuccesses), metric.WithAttributes(attribute.String("result", "success")))
		observer.ObserveInt64(generationApplies, metricValue(snapshot.GenerationFailures), metric.WithAttributes(attribute.String("result", "failure")))
	}, generationApplies)
	links, _ := meter.Int64ObservableGauge("telego_middleend_links",
		metric.WithDescription("ME physical links by generation role, signed DC, and state"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		forEachMiddleEndRole(collected.Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
			counts := make(map[middleEndLinkMetricKey]int64)
			for _, slot := range manager.Slots {
				key := middleEndLinkMetricKey{dc: slot.DCID, state: middleEndLinkState(slot)}
				counts[key]++
			}
			for key, count := range counts {
				observer.ObserveInt64(links, count, metric.WithAttributes(
					attribute.String("role", role),
					attribute.String("dc", strconv.Itoa(int(key.dc))),
					attribute.String("state", key.state),
				))
			}
		})
	}, links)
	activeBindings, _ := meter.Int64ObservableGauge("telego_middleend_bindings_active",
		metric.WithDescription("ME client bindings by generation role and signed DC"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		forEachMiddleEndRole(collected.Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
			byDC := make(map[middleend.DCID]int64)
			for _, slot := range manager.Slots {
				byDC[slot.DCID] += int64(slot.ResidentBindings)
			}
			for dcID, bindings := range byDC {
				observer.ObserveInt64(activeBindings, bindings, metric.WithAttributes(
					attribute.String("role", role),
					attribute.String("dc", strconv.Itoa(int(dcID))),
				))
			}
		})
	}, activeBindings)
	registerMiddleEndManagerQueueMetrics(group)
	registerMiddleEndLinkQueueMetrics(group)
	registerMiddleEndRefreshMetrics(group)
	registerMiddleEndDiagnosticMetrics(group)
	registerMiddleEndResponseMemoryMetrics(group)
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

func registerMiddleEndManagerQueueMetrics(group *snapshotMetricGroup[middleend.ServiceSnapshot]) {
	meter := group.meter

	registerMiddleEndManagerQueueMetric(group, "telego_middleend_manager_queue_items", "Items retained by ME generation-manager queues", false, false)
	registerMiddleEndManagerQueueMetric(group, "telego_middleend_manager_queue_bytes", "Logical bytes queued by ME generation managers; response bytes exclude reserved headroom and allocation metadata", true, false)
	registerMiddleEndManagerQueueMetric(group, "telego_middleend_manager_queue_high_water_items", "Lifetime high-water items retained by ME generation-manager queues", false, true)
	registerMiddleEndManagerQueueMetric(group, "telego_middleend_manager_queue_high_water_bytes", "Generation high-water logical queue bytes; response bytes exclude reserved headroom and allocation metadata", true, true)
	backpressureEvents, _ := meter.Int64ObservableGauge("telego_middleend_manager_backpressure_events",
		metric.WithDescription("Lifetime bounded-queue rejections in the current ME generation manager"),
	)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		forEachMiddleEndRole(collected.Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
			observer.ObserveInt64(backpressureEvents, metricValue(manager.ResponseBackpressureEvents), metric.WithAttributes(
				attribute.String("role", role),
				attribute.String("kind", "response"),
			))
			observer.ObserveInt64(backpressureEvents, metricValue(manager.ControlBackpressureEvents), metric.WithAttributes(
				attribute.String("role", role),
				attribute.String("kind", "control"),
			))
		})
	}, backpressureEvents)
}

func registerMiddleEndManagerQueueMetric(
	group *snapshotMetricGroup[middleend.ServiceSnapshot],
	name string,
	description string,
	bytes bool,
	highWater bool,
) {
	meter := group.meter

	options := []metric.Int64ObservableGaugeOption{metric.WithDescription(description)}
	if bytes {
		options = append(options, metric.WithUnit("By"))
	}

	queueGauge, _ := meter.Int64ObservableGauge(name, options...)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		forEachMiddleEndRole(collected.Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
			request, control, response := middleEndManagerQueueValues(manager, bytes, highWater)
			for queue, value := range map[string]int{
				"request":  request,
				"control":  control,
				"response": response,
			} {
				observer.ObserveInt64(queueGauge, int64(value), metric.WithAttributes(attribute.String("role", role), attribute.String("queue", queue)))
			}
		})
	}, queueGauge)
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

func registerMiddleEndLinkQueueMetrics(group *snapshotMetricGroup[middleend.ServiceSnapshot]) {
	registerMiddleEndLinkQueueMetric(group, "telego_middleend_link_queue_items", "Items pending in ME gnet link queues", false, false)
	registerMiddleEndLinkQueueMetric(group, "telego_middleend_link_queue_bytes", "Bytes pending in ME gnet link queues", true, false)
	registerMiddleEndLinkQueueMetric(group, "telego_middleend_link_queue_high_water_items", "Lifetime high-water items in ME gnet link queues", false, true)
	registerMiddleEndLinkQueueMetric(group, "telego_middleend_link_queue_high_water_bytes", "Lifetime high-water bytes in ME gnet link queues", true, true)
	registerMiddleEndLinkQueueCapacityMetric(group, "telego_middleend_link_queue_capacity_items", "Configured item capacity of each ME gnet link queue", false)
	registerMiddleEndLinkQueueCapacityMetric(group, "telego_middleend_link_queue_capacity_bytes", "Configured byte capacity of each ME gnet link queue", true)
}

func registerMiddleEndLinkQueueCapacityMetric(
	group *snapshotMetricGroup[middleend.ServiceSnapshot],
	name string,
	description string,
	bytes bool,
) {
	meter := group.meter

	options := []metric.Int64ObservableGaugeOption{metric.WithDescription(description)}
	if bytes {
		options = append(options, metric.WithUnit("By"))
	}

	queueGauge, _ := meter.Int64ObservableGauge(name, options...)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		snapshot := collected
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
					observer.ObserveInt64(queueGauge, int64(value), metric.WithAttributes(
						attribute.String("role", role),
						attribute.String("dc", strconv.Itoa(int(slot.DCID))),
						attribute.Int("link", link),
						attribute.String("queue", queue),
					))
				}
			}
		})
	}, queueGauge)
}

func registerMiddleEndLinkQueueMetric(
	group *snapshotMetricGroup[middleend.ServiceSnapshot],
	name string,
	description string,
	bytes bool,
	highWater bool,
) {
	meter := group.meter

	options := []metric.Int64ObservableGaugeOption{metric.WithDescription(description)}
	if bytes {
		options = append(options, metric.WithUnit("By"))
	}

	queueGauge, _ := meter.Int64ObservableGauge(name, options...)
	group.add(func(observer metric.Observer, collected middleend.ServiceSnapshot) {
		forEachMiddleEndRole(collected.Supervisor, func(role string, manager *middleend.FixedBindingManagerSnapshot) {
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
				observer.ObserveInt64(queueGauge, value, metric.WithAttributes(
					attribute.String("role", role),
					attribute.String("dc", strconv.Itoa(int(key.dc))),
					attribute.Int("link", key.link),
					attribute.String("queue", key.queue),
				))
			}
		})
	}, queueGauge)
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
	group := &snapshotMetricGroup[gproxy.MiddleEndFrontendStats]{meter: meter}
	defer group.register(provider.MiddleEndFrontendStats)

	registerMiddleEndResponseWaitMetrics(group)
	routesActive, _ := meter.Int64ObservableGauge("telego_middleend_frontend_routes_active",
		metric.WithDescription("Active public connections committed to ME or direct fallback"),
	)
	group.add(func(observer metric.Observer, collected gproxy.MiddleEndFrontendStats) {
		stats := collected
		observer.ObserveInt64(routesActive, stats.MiddleEndBindingsActive, metric.WithAttributes(attribute.String("route", "middleend")))
		observer.ObserveInt64(routesActive, stats.DirectFallbacksActive, metric.WithAttributes(attribute.String("route", "direct_fallback")))
	}, routesActive)
	routeCommits, _ := meter.Int64ObservableCounter("telego_middleend_frontend_route_commits_total",
		metric.WithDescription("Public connections committed to ME or direct fallback"),
	)
	group.add(func(observer metric.Observer, collected gproxy.MiddleEndFrontendStats) {
		stats := collected
		observer.ObserveInt64(routeCommits, metricValue(stats.MiddleEndBindingsTotal), metric.WithAttributes(attribute.String("route", "middleend")))
		observer.ObserveInt64(routeCommits, metricValue(stats.DirectFallbacksTotal), metric.WithAttributes(attribute.String("route", "direct_fallback")))
	}, routeCommits)
	for _, instrument := range []struct {
		name        string
		description string
		value       func(gproxy.MiddleEndFrontendStats, string) int64
	}{
		{
			name:        "telego_middleend_frontend_buffer_bytes",
			description: "Retained client input or owner-observed unread client output; output excludes retained backing capacity and reserved headroom",
			value: func(stats gproxy.MiddleEndFrontendStats, direction string) int64 {
				if direction == "input" {
					return stats.InputBytes
				}
				return stats.OutputBytes
			},
		},
		{
			name:        "telego_middleend_frontend_buffer_high_water_bytes",
			description: "Lifetime high-water retained input or owner-observed unread output bytes in the ME frontend",
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
		bufferGauge, _ := meter.Int64ObservableGauge(instrument.name,
			metric.WithDescription(instrument.description),
			metric.WithUnit("By"),
		)
		group.add(func(observer metric.Observer, collected gproxy.MiddleEndFrontendStats) {
			stats := collected
			for _, direction := range []string{"input", "output"} {
				if stats.SharedResponseBudget && direction == "output" && instrument.name == "telego_middleend_frontend_buffer_capacity_bytes" {
					continue
				}
				observer.ObserveInt64(bufferGauge, instrument.value(stats, direction), metric.WithAttributes(attribute.String("direction", direction)))
			}
		}, bufferGauge)
	}
	backpressureEvents, _ := meter.Int64ObservableCounter("telego_middleend_frontend_backpressure_events_total",
		metric.WithDescription("ME public frontend aggregate byte-budget rejections"),
	)
	group.add(func(observer metric.Observer, collected gproxy.MiddleEndFrontendStats) {
		stats := collected
		observer.ObserveInt64(backpressureEvents, metricValue(stats.InputBackpressureEvents), metric.WithAttributes(attribute.String("direction", "input")))
		observer.ObserveInt64(backpressureEvents, metricValue(stats.OutputBackpressureEvents), metric.WithAttributes(attribute.String("direction", "output")))
	}, backpressureEvents)
	outputEvictions, _ := meter.Int64ObservableCounter("telego_middleend_frontend_output_evictions_total",
		metric.WithDescription("ME public clients evicted to release aggregate output pressure"),
	)
	group.add(func(observer metric.Observer, collected gproxy.MiddleEndFrontendStats) {
		observer.ObserveInt64(outputEvictions, metricValue(collected.OutputEvictions))
	}, outputEvictions)
}

func registerWebMetrics(meter metric.Meter, provider WebStatsProvider) {
	group := &snapshotMetricGroup[webproxy.RuntimeStats]{meter: meter}
	defer group.register(provider.RuntimeStats)

	webSockets, _ := meter.Int64ObservableGauge("telego_web_websocket_connections_active",
		metric.WithDescription("Active WEB WebSocket carrier connections"),
	)
	group.add(func(observer metric.Observer, collected webproxy.RuntimeStats) {
		observer.ObserveInt64(webSockets, collected.WebSocketsActive)
	}, webSockets)
	sessions, _ := meter.Int64ObservableGauge("telego_web_sessions_active",
		metric.WithDescription("Active WEB relay sessions"),
	)
	group.add(func(observer metric.Observer, collected webproxy.RuntimeStats) {
		observer.ObserveInt64(sessions, int64(collected.Capacity.Sessions))
	}, sessions)
	streams, _ := meter.Int64ObservableGauge("telego_web_streams_active",
		metric.WithDescription("Active WEB backend streams"),
	)
	group.add(func(observer metric.Observer, collected webproxy.RuntimeStats) {
		observer.ObserveInt64(streams, int64(collected.Capacity.Streams))
	}, streams)
	backendDials, _ := meter.Int64ObservableGauge("telego_web_backend_dials_active",
		metric.WithDescription("WEB backend dials in progress"),
	)
	group.add(func(observer metric.Observer, collected webproxy.RuntimeStats) {
		observer.ObserveInt64(backendDials, int64(collected.Capacity.BackendDials))
	}, backendDials)
	pendingBytes, _ := meter.Int64ObservableGauge("telego_web_pending_bytes",
		metric.WithDescription("Bytes charged to WEB pending queues"),
		metric.WithUnit("By"),
	)
	group.add(func(observer metric.Observer, collected webproxy.RuntimeStats) {
		observer.ObserveInt64(pendingBytes, collected.Capacity.PendingBytes)
	}, pendingBytes)
	pendingItems, _ := meter.Int64ObservableGauge("telego_web_pending_items",
		metric.WithDescription("Items charged to WEB pending queues"),
	)
	group.add(func(observer metric.Observer, collected webproxy.RuntimeStats) {
		observer.ObserveInt64(pendingItems, collected.Capacity.PendingItems)
	}, pendingItems)
	sessionsCreated, _ := meter.Int64ObservableCounter("telego_web_sessions_created_total",
		metric.WithDescription("WEB relay sessions created"),
	)
	group.add(func(observer metric.Observer, collected webproxy.RuntimeStats) {
		observer.ObserveInt64(sessionsCreated, metricValue(collected.SessionsCreated))
	}, sessionsCreated)
	sessionsClosed, _ := meter.Int64ObservableCounter("telego_web_sessions_closed_total",
		metric.WithDescription("WEB relay sessions closed by reason"),
	)
	group.add(func(observer metric.Observer, collected webproxy.RuntimeStats) {
		for _, counter := range collected.SessionsClosed {
			observer.ObserveInt64(sessionsClosed, metricValue(counter.Total), metric.WithAttributes(attribute.String("reason", counter.Label)))
		}
	}, sessionsClosed)
	carrierRetries, _ := meter.Int64ObservableCounter("telego_web_carrier_retries_total",
		metric.WithDescription("Authenticated WEB carrier retries and replays"),
	)
	group.add(func(observer metric.Observer, collected webproxy.RuntimeStats) {
		for _, counter := range collected.CarrierRetries {
			observer.ObserveInt64(carrierRetries, metricValue(counter.Total), metric.WithAttributes(attribute.String("operation", counter.Label)))
		}
	}, carrierRetries)
	backpressure, _ := meter.Int64ObservableCounter("telego_web_backpressure_total",
		metric.WithDescription("WEB carrier requests delayed by resource backpressure"),
	)
	group.add(func(observer metric.Observer, collected webproxy.RuntimeStats) {
		for _, counter := range collected.Backpressure {
			observer.ObserveInt64(backpressure, metricValue(counter.Total), metric.WithAttributes(attribute.String("operation", counter.Label)))
		}
	}, backpressure)
}

func metricValue(value uint64) int64 {
	return int64(min(value, uint64(math.MaxInt64)))
}

func registerMetrics(meter metric.Meter, limiter StatsProvider) {
	group := &snapshotMetricGroup[[]gproxy.UserIPStats]{meter: meter}
	defer group.register(limiter.Stats)

	// Active connections gauge
	connections, _ := meter.Int64ObservableGauge("telego_connections_active",
		metric.WithDescription("Active connections per user"),
	)
	group.add(func(o metric.Observer, collected []gproxy.UserIPStats) {
		for _, s := range collected {
			name := s.SecretName
			if name == "" {
				name = "unknown"
			}
			o.ObserveInt64(connections, s.Connections, metric.WithAttributes(attribute.String("user", name)))
		}
	}, connections)

	// Active IPs gauge (IPs with at least one connection right now)
	activeIPs, _ := meter.Int64ObservableGauge("telego_ips_active",
		metric.WithDescription("IPs with active connections per user"),
	)
	group.add(func(o metric.Observer, collected []gproxy.UserIPStats) {
		for _, s := range collected {
			name := s.SecretName
			if name == "" {
				name = "unknown"
			}
			o.ObserveInt64(activeIPs, int64(s.ActiveIPs), metric.WithAttributes(attribute.String("user", name)))
		}
	}, activeIPs)

	// Tracked IPs gauge (unique IPs in LRU cache, may include disconnected)
	trackedIPs, _ := meter.Int64ObservableGauge("telego_ips_tracked",
		metric.WithDescription("Unique IPs tracked in LRU cache per user"),
	)
	group.add(func(o metric.Observer, collected []gproxy.UserIPStats) {
		for _, s := range collected {
			name := s.SecretName
			if name == "" {
				name = "unknown"
			}
			o.ObserveInt64(trackedIPs, int64(s.TrackedIPs), metric.WithAttributes(attribute.String("user", name)))
		}
	}, trackedIPs)

	// Blocked IPs gauge
	blockedIPs, _ := meter.Int64ObservableGauge("telego_ips_blocked",
		metric.WithDescription("Currently blocked IPs per user"),
	)
	group.add(func(o metric.Observer, collected []gproxy.UserIPStats) {
		for _, s := range collected {
			name := s.SecretName
			if name == "" {
				name = "unknown"
			}
			o.ObserveInt64(blockedIPs, int64(s.BlockedIPs), metric.WithAttributes(attribute.String("user", name)))
		}
	}, blockedIPs)

	// Blocked total counter
	blockedTotal, _ := meter.Int64ObservableCounter("telego_blocked_total",
		metric.WithDescription("Total IP block events per user"),
	)
	group.add(func(o metric.Observer, collected []gproxy.UserIPStats) {
		for _, s := range collected {
			name := s.SecretName
			if name == "" {
				name = "unknown"
			}
			o.ObserveInt64(blockedTotal, s.BlockedTotal, metric.WithAttributes(attribute.String("user", name)))
		}
	}, blockedTotal)

	// Traffic in counter
	trafficIn, _ := meter.Int64ObservableCounter("telego_traffic_in_bytes_total",
		metric.WithDescription("Total bytes received from clients per user"),
		metric.WithUnit("By"),
	)
	group.add(func(o metric.Observer, collected []gproxy.UserIPStats) {
		for _, s := range collected {
			name := s.SecretName
			if name == "" {
				name = "unknown"
			}
			o.ObserveInt64(trafficIn, s.BytesIn, metric.WithAttributes(attribute.String("user", name)))
		}
	}, trafficIn)

	// Traffic out counter
	trafficOut, _ := meter.Int64ObservableCounter("telego_traffic_out_bytes_total",
		metric.WithDescription("Total bytes sent to clients per user"),
		metric.WithUnit("By"),
	)
	group.add(func(o metric.Observer, collected []gproxy.UserIPStats) {
		for _, s := range collected {
			name := s.SecretName
			if name == "" {
				name = "unknown"
			}
			o.ObserveInt64(trafficOut, s.BytesOut, metric.WithAttributes(attribute.String("user", name)))
		}
	}, trafficOut)
}

// Start opens the metrics listener and serves HTTP in a goroutine.
// Listener errors are returned before background serving starts.
func (s *Server) Start() error {
	address := s.httpServer.Addr
	if address == "" {
		address = ":http"
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	go func() {
		_ = s.httpServer.Serve(listener)
	}()
	return nil
}

// Shutdown gracefully shuts down the metrics server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.diagnostics != nil {
		s.diagnostics.cancel()
	}
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.provider.Shutdown(shutdownCtx)
}
