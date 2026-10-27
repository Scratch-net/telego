package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	clientprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/webproxy"
)

type changingMetricsProvider struct {
	userCalls, webCalls, frontendCalls, middleEndCalls atomic.Int64
}

func (p *changingMetricsProvider) Stats() []gproxy.UserIPStats {
	value := p.userCalls.Add(1)
	return []gproxy.UserIPStats{{
		Connections: value, ActiveIPs: int(value), TrackedIPs: int(value),
		BlockedIPs: int(value), BlockedTotal: value, BytesIn: value, BytesOut: value,
	}}
}

func (p *changingMetricsProvider) RuntimeStats() webproxy.RuntimeStats {
	value := p.webCalls.Add(1)
	return webproxy.RuntimeStats{
		WebSocketsActive: value,
		Capacity: webproxy.Capacity{
			Sessions: int(value), Streams: int(value), BackendDials: int(value),
			PendingBytes: value, PendingItems: value,
		},
		SessionsCreated: uint64(value),
		SessionsClosed:  []webproxy.RuntimeCounter{{Label: "client", Total: uint64(value)}},
		CarrierRetries:  []webproxy.RuntimeCounter{{Label: "uplink", Total: uint64(value)}},
		Backpressure:    []webproxy.RuntimeCounter{{Label: "uplink", Total: uint64(value)}},
	}
}

func (p *changingMetricsProvider) MiddleEndFrontendStats() gproxy.MiddleEndFrontendStats {
	value := p.frontendCalls.Add(1)
	stats := gproxy.MiddleEndFrontendStats{
		MiddleEndBindingsActive: value, MiddleEndBindingsTotal: uint64(value),
		InputBytes: value, InputBytesHighWater: value, InputBytesLimit: value,
		InputBackpressureEvents: uint64(value), OutputEvictions: uint64(value),
		ResponseStallClosures: uint64(value),
	}
	stats.ResponseWaitsTotal[middleend.ResponseOutputProcessingReserve] = uint64(value)
	stats.ResponseWaitsCompletedTotal[middleend.ResponseOutputProcessingReserve] = uint64(value)
	stats.ResponseWaitDurationMicroseconds[middleend.ResponseOutputProcessingReserve] = uint64(value) * 1e6
	stats.ResponseWaitsActive[middleend.ResponseOutputProcessingReserve] = value
	return stats
}

func (p *changingMetricsProvider) Snapshot() middleend.ServiceSnapshot {
	value := p.middleEndCalls.Add(1)
	snapshot := middleend.ServiceSnapshot{
		RuntimeLinks: int(value),
		Capacity:     middleend.ServiceCapacitySnapshot{EventLoops: int(value)},
		Supervisor: middleend.GenerationSupervisorSnapshot{
			SlotFailures: uint64(value), DiagnosticRecordsDropped: uint64(value),
			DCs: []middleend.FixedBindingDCSnapshot{{DCID: 2, SlotRefreshSuccesses: uint64(value)}},
			Active: &middleend.FixedBindingManagerSnapshot{
				RequestItems: int(value),
				Slots: []middleend.FixedBindingSlotSnapshot{{
					DCID: 2, Link: middleend.LinkSnapshot{PendingSubmissions: int(value)},
				}},
			},
		},
		ResponseBudget: middleend.ResponseBudgetSnapshot{
			LimitBytes: 1 << 20, OrdinaryLimitBytes: 1 << 20, UsedBytes: int(value),
		},
	}
	snapshot.ResponseBudget.ClassBytes[middleend.ResponseMemoryOrdinary] = int(value)
	snapshot.ResponseBudget.StageBytes[middleend.ResponseMemoryQueuePayload] = int(value)
	snapshot.Supervisor.ResponsePressureEvictions[middleend.ResponsePressureSharedBudget] = uint64(value)
	snapshot.Supervisor.ResponsePressureSelections[middleend.ResponsePressureIncomingFallback] = uint64(value)
	return snapshot
}

// A changing source makes both duplicate reads and reuse across collections
// visible in the exported values, including observations in separate files.
func TestMetricSourcesUseOneFreshSnapshotPerScrape(t *testing.T) {
	source := new(changingMetricsProvider)
	registry := clientprometheus.NewRegistry()
	exporter, err := prometheus.New(prometheus.WithRegisterer(registry))
	if err != nil {
		t.Fatal(err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown metrics: %v", err)
		}
	})
	meter := provider.Meter("telego-snapshot-test")
	registerMetrics(meter, source)
	registerWebMetrics(meter, source)
	registerMiddleEndFrontendMetrics(meter, source)
	registerMiddleEndMetrics(meter, source)
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	scrape := func() *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return response
	}
	counts := map[string]*atomic.Int64{
		"user": &source.userCalls, "web": &source.webCalls,
		"frontend": &source.frontendCalls, "middleend": &source.middleEndCalls,
	}
	checkCount := func(want int64) {
		t.Helper()
		for name, calls := range counts {
			if got := calls.Load(); got != want {
				t.Errorf("%s snapshots = %d, want %d", name, got, want)
			}
		}
	}
	for want := int64(1); want <= 2; want++ {
		response := scrape()
		if response.Code != http.StatusOK {
			t.Fatalf("metrics status = %d: %s", response.Code, response.Body.String())
		}
		checkCount(want)
		checkSnapshotSamples(t, response.Body.String(), " "+strconv.FormatInt(want, 10))
	}

	// Concurrent collections must each own their snapshot; registration state
	// must never become a cache shared by callbacks or requests.
	const concurrentScrapes = 8
	responses := make(chan *httptest.ResponseRecorder, concurrentScrapes)
	for range concurrentScrapes {
		go func() { responses <- scrape() }()
	}
	for range concurrentScrapes {
		response := <-responses
		if response.Code != http.StatusOK {
			t.Errorf("concurrent metrics status = %d: %s", response.Code, response.Body.String())
			continue
		}
		checkSnapshotSamples(t, response.Body.String(), "")
	}
	checkCount(2 + concurrentScrapes)
}

func checkSnapshotSamples(t *testing.T, content, expected string) {
	t.Helper()
	type sample struct{ name, label string }
	groups := [][]sample{
		{
			{"telego_connections_active", `user="unknown"`},
			{"telego_ips_active", `user="unknown"`},
			{"telego_ips_tracked", `user="unknown"`},
			{"telego_ips_blocked", `user="unknown"`},
			{"telego_blocked_total", `user="unknown"`},
			{"telego_traffic_in_bytes_total", `user="unknown"`},
			{"telego_traffic_out_bytes_total", `user="unknown"`},
		},
		{
			{"telego_web_websocket_connections_active", ""},
			{"telego_web_sessions_active", ""},
			{"telego_web_streams_active", ""},
			{"telego_web_backend_dials_active", ""},
			{"telego_web_pending_bytes", ""},
			{"telego_web_pending_items", ""},
			{"telego_web_sessions_created_total", ""},
			{"telego_web_sessions_closed_total", `reason="client"`},
			{"telego_web_carrier_retries_total", `operation="uplink"`},
			{"telego_web_backpressure_total", `operation="uplink"`},
		},
		{
			{"telego_middleend_frontend_routes_active", `route="middleend"`},
			{"telego_middleend_frontend_route_commits_total", `route="middleend"`},
			{"telego_middleend_frontend_buffer_bytes", `direction="input"`},
			{"telego_middleend_frontend_buffer_high_water_bytes", `direction="input"`},
			{"telego_middleend_frontend_buffer_capacity_bytes", `direction="input"`},
			{"telego_middleend_frontend_backpressure_events_total", `direction="input"`},
			{"telego_middleend_frontend_output_evictions_total", ""},
			{"telego_middleend_response_admission_waits_total", `reason="processing_reserve"`},
			{"telego_middleend_response_admission_waits_completed_total", `reason="processing_reserve"`},
			{"telego_middleend_response_admission_wait_seconds_total", `reason="processing_reserve"`},
			{"telego_middleend_response_admission_waits_active", `reason="processing_reserve"`},
			{"telego_middleend_response_output_stall_closures_total", ""},
		},
		{
			{"telego_middleend_runtime_links", ""},
			{"telego_middleend_capacity", `resource="event_loops"`},
			{"telego_middleend_slot_failure_total", ""},
			{"telego_middleend_manager_queue_items", `queue="request"`},
			{"telego_middleend_link_queue_items", `queue="submission"`},
			{"telego_middleend_slot_refresh_total", `result="success"`},
			{"telego_middleend_diagnostic_records_dropped_total", ""},
			{"telego_middleend_response_memory_used_bytes", ""},
			{"telego_middleend_response_memory_class_bytes", `class="ordinary"`},
			{"telego_middleend_response_memory_stage_bytes", `stage="queue_payload"`},
			{"telego_middleend_response_pressure_evictions_total", `limit="shared_budget"`},
			{"telego_middleend_response_pressure_selections_total", `rule="incoming_fallback"`},
		},
	}
	for _, group := range groups {
		value := expected
		if value == "" {
			first := group[0]
			for line := range strings.SplitSeq(content, "\n") {
				if strings.HasPrefix(line, first.name+"{") && strings.Contains(line, first.label) {
					fields := strings.Fields(line)
					value = " " + fields[len(fields)-1]
					break
				}
			}
			if value == "" {
				t.Errorf("missing snapshot reference sample %s", first.name)
				continue
			}
		}
		for _, sample := range group {
			if !metricSampleMatches(content, sample.name, []string{sample.label}, value) {
				t.Errorf("%s %s should use snapshot%s: %s", sample.name, sample.label, value, metricLines(content, sample.name))
			}
		}
	}
}
