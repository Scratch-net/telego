package metrics

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/webproxy"
)

// mockStatsProvider implements StatsProvider for testing.
type mockStatsProvider struct {
	stats []gproxy.UserIPStats
}

func (m *mockStatsProvider) Stats() []gproxy.UserIPStats {
	return m.stats
}

// countingStatsProvider wraps to count Stats() calls.
type countingStatsProvider struct {
	callCount *int
	stats     []gproxy.UserIPStats
}

type mockProxyStatsProvider struct{}

func (mockProxyStatsProvider) HandshakeFailureStats() []gproxy.HandshakeFailureStat {
	return []gproxy.HandshakeFailureStat{{Stage: "tls_mtproto", Total: 3}}
}

func (mockProxyStatsProvider) MiddleEndFrontendStats() gproxy.MiddleEndFrontendStats {
	return gproxy.MiddleEndFrontendStats{
		MiddleEndBindingsActive:  4,
		MiddleEndBindingsTotal:   7,
		DirectFallbacksActive:    2,
		DirectFallbacksTotal:     3,
		InputBytes:               1024,
		InputBytesHighWater:      2048,
		InputBytesLimit:          4096,
		InputBackpressureEvents:  2,
		OutputBytes:              512,
		OutputBytesHighWater:     1024,
		OutputBytesLimit:         4096,
		OutputBackpressureEvents: 3,
		OutputEvictions:          1,
	}
}

type mockWebStatsProvider struct{}

func (mockWebStatsProvider) RuntimeStats() webproxy.RuntimeStats {
	return webproxy.RuntimeStats{
		Capacity:         webproxy.Capacity{Sessions: 2, Streams: 4, BackendDials: 1, PendingBytes: 128, PendingItems: 3},
		WebSocketsActive: 2,
		SessionsCreated:  5,
		SessionsClosed:   []webproxy.RuntimeCounter{{Label: "client", Total: 2}},
		CarrierRetries:   []webproxy.RuntimeCounter{{Label: "uplink", Total: 7}},
		Backpressure:     []webproxy.RuntimeCounter{{Label: "uplink", Total: 1}},
	}
}

type mockMiddleEndStatsProvider struct{}

func (mockMiddleEndStatsProvider) Snapshot() middleend.ServiceSnapshot {
	return middleend.ServiceSnapshot{
		Capacity: middleend.ServiceCapacitySnapshot{
			EventLoops:           2,
			LinksPerDC:           4,
			MaxResidentBindings:  10_000,
			LinkSubmissionItems:  4096,
			LinkSubmissionBytes:  2 << 20,
			LinkEventItems:       4096,
			LinkEventBytes:       2 << 20,
			ManagerRequestItems:  4096,
			ManagerRequestBytes:  32 << 20,
			ManagerControlItems:  4096,
			ManagerControlBytes:  48 << 10,
			ManagerResponseItems: 4096,
			ManagerResponseBytes: 32 << 20,
			BindingResponseItems: 768,
			BindingResponseBytes: 2 << 20,
		},
		Coordinator: middleend.GenerationCoordinatorSnapshot{
			Applied:             true,
			RefreshSuccesses:    11,
			RefreshFailures:     2,
			GenerationSuccesses: 7,
			GenerationFailures:  3,
		},
		Supervisor: middleend.GenerationSupervisorSnapshot{
			Admitting:                   true,
			SlotFailures:                17,
			SlotFailureAffectedBindings: 6,
			SlotRepairSuccesses:         13,
			SlotRepairFailures:          2,
			Active: &middleend.FixedBindingManagerSnapshot{
				Ready:                      true,
				Accepting:                  true,
				ResidentBindings:           4,
				RequestItems:               5,
				RequestBytes:               512,
				ControlItems:               2,
				ControlBytes:               64,
				ResponseItems:              3,
				ResponseBytes:              384,
				RequestItemsHighWater:      8,
				RequestBytesHighWater:      2048,
				ControlItemsHighWater:      4,
				ControlBytesHighWater:      128,
				ResponseItemsHighWater:     12,
				ResponseBytesHighWater:     4096,
				ResponseBackpressureEvents: 5,
				ControlBackpressureEvents:  2,
				SlotRepairSuccesses:        3,
				SlotRepairFailures:         1,
				RepairingSlots:             1,
				Slots: []middleend.FixedBindingSlotSnapshot{
					{
						DCID:             -2,
						ResidentBindings: 4,
						Link: middleend.LinkSnapshot{
							State:                    middleend.LinkStateReady,
							PendingSubmissions:       2,
							PendingSubmissionBytes:   256,
							SubmissionHighWater:      9,
							SubmissionBytesHighWater: 1024,
							PendingEvents:            1,
							PendingEventBytes:        128,
							EventHighWater:           6,
							EventBytesHighWater:      768,
						},
					},
				},
			},
		},
	}
}

func (c *countingStatsProvider) Stats() []gproxy.UserIPStats {
	*c.callCount++
	return c.stats
}

// TestMetricsIntegration is the main integration test that exercises all metrics functionality.
// It runs first to avoid global state issues with Prometheus registry.
func TestMetricsIntegration(t *testing.T) {
	cfg := Config{
		BindAddr:   "127.0.0.1:19280",
		Path:       "/metrics",
		ProxyStats: mockProxyStatsProvider{},
		WebStats:   mockWebStatsProvider{},
		MiddleEnd:  mockMiddleEndStatsProvider{},
	}

	// Provider that tracks Stats() calls
	callCount := 0
	provider := &countingStatsProvider{
		callCount: &callCount,
		stats: []gproxy.UserIPStats{
			{SecretName: "user1", Connections: 5, TrackedIPs: 3, ActiveIPs: 2, BlockedIPs: 0, BlockedTotal: 0, BytesIn: 500, BytesOut: 1000},
			{SecretName: "user2", Connections: 15, TrackedIPs: 10, ActiveIPs: 8, BlockedIPs: 2, BlockedTotal: 10, BytesIn: 5000, BytesOut: 10000},
			{SecretName: "", Connections: 3, TrackedIPs: 2, ActiveIPs: 1, BlockedIPs: 0, BlockedTotal: 0, BytesIn: 100, BytesOut: 200}, // Empty name should become "unknown"
		},
	}

	server, err := NewServer(cfg, provider)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	if server == nil {
		t.Fatal("NewServer returned nil")
	}

	if server.httpServer == nil {
		t.Error("httpServer should not be nil")
	}

	if server.provider == nil {
		t.Error("provider should not be nil")
	}

	// Start server
	err = server.Start()
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	// Give server time to start and retry if needed
	var resp *http.Response
	for range 5 {
		time.Sleep(100 * time.Millisecond)
		resp, err = http.Get("http://127.0.0.1:19280/metrics")
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, content)
	}

	// Should have called Stats() at least 7 times (once per metric type)
	if callCount < 7 {
		t.Errorf("expected at least 7 Stats() calls from callbacks, got %d", callCount)
	}

	// Verify all expected metrics are present
	expectedMetrics := []string{
		"telego_connections_active",
		"telego_ips_active",
		"telego_ips_tracked",
		"telego_ips_blocked",
		"telego_blocked_total",
		"telego_traffic_in_bytes_total",
		"telego_traffic_out_bytes_total",
		"telego_handshake_failures_total",
		"telego_web_websocket_connections_active",
		"telego_web_sessions_active",
		"telego_web_streams_active",
		"telego_web_backend_dials_active",
		"telego_web_pending_bytes",
		"telego_web_pending_items",
		"telego_web_sessions_created_total",
		"telego_web_sessions_closed_total",
		"telego_web_carrier_retries_total",
		"telego_web_backpressure_total",
		"telego_middleend_admitting",
		"telego_middleend_capacity",
		"telego_middleend_repairing",
		"telego_middleend_slot_repairs_active",
		"telego_middleend_slot_repair_total",
		"telego_middleend_slot_failure_total",
		"telego_middleend_slot_failure_affected_bindings_total",
		"telego_middleend_artifact_state",
		"telego_middleend_artifact_refresh_total",
		"telego_middleend_generation_apply_total",
		"telego_middleend_links",
		"telego_middleend_bindings_active",
		"telego_middleend_manager_queue_items",
		"telego_middleend_manager_queue_bytes",
		"telego_middleend_manager_queue_high_water_items",
		"telego_middleend_manager_queue_high_water_bytes",
		"telego_middleend_manager_backpressure_events",
		"telego_middleend_link_queue_items",
		"telego_middleend_link_queue_bytes",
		"telego_middleend_link_queue_high_water_items",
		"telego_middleend_link_queue_high_water_bytes",
		"telego_middleend_link_queue_capacity_items",
		"telego_middleend_link_queue_capacity_bytes",
		"telego_middleend_frontend_buffer_bytes",
		"telego_middleend_frontend_buffer_high_water_bytes",
		"telego_middleend_frontend_buffer_capacity_bytes",
		"telego_middleend_frontend_backpressure_events_total",
		"telego_middleend_frontend_output_evictions_total",
		"telego_middleend_frontend_routes_active",
		"telego_middleend_frontend_route_commits_total",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(content, metric) {
			t.Errorf("metrics output should contain %s", metric)
		}
	}
	webSocketGauge := "telego_web_websocket_connections_active"
	foundWebSocketGauge := false
	for line := range strings.SplitSeq(content, "\n") {
		if !strings.HasPrefix(line, webSocketGauge+"{") {
			continue
		}
		foundWebSocketGauge = strings.HasSuffix(line, "} 2") &&
			!strings.Contains(line, "carrier=") && !strings.Contains(line, "mode=") &&
			!strings.Contains(line, "lane=")
	}
	if !foundWebSocketGauge {
		t.Errorf("WebSocket gauge is missing, has a transport label, or has the wrong value")
	}
	if !metricSampleMatches(content, "telego_middleend_links", []string{`dc="-2"`, `role="active"`, `state="ready"`}, " 1") {
		t.Errorf("Middle-End active ready-link gauge is missing or has the wrong labels:\n%s", metricLines(content, "telego_middleend_links"))
	}
	if !metricSampleMatches(content, "telego_middleend_slot_repairs_active", []string{`role="active"`}, " 1") ||
		!metricSampleMatches(content, "telego_middleend_slot_repair_total", []string{`result="success"`}, " 13") ||
		!metricSampleMatches(content, "telego_middleend_slot_repair_total", []string{`result="failure"`}, " 2") {
		t.Errorf("Middle-End slot-repair metrics are missing or have the wrong values:\n%s\n%s",
			metricLines(content, "telego_middleend_slot_repairs_active"),
			metricLines(content, "telego_middleend_slot_repair_total"))
	}
	if !metricSampleMatches(content, "telego_middleend_slot_failure_total", nil, " 17") ||
		!metricSampleMatches(content, "telego_middleend_slot_failure_affected_bindings_total", nil, " 6") {
		t.Errorf("Middle-End slot-failure metrics are missing or have the wrong values:\n%s\n%s",
			metricLines(content, "telego_middleend_slot_failure_total"),
			metricLines(content, "telego_middleend_slot_failure_affected_bindings_total"))
	}
	if !metricSampleMatches(content, "telego_middleend_link_queue_high_water_bytes", []string{`dc="-2"`, `queue="submission"`, `role="active"`}, " 1024") {
		t.Errorf("Middle-End submission byte high-water gauge is missing or has the wrong value:\n%s", metricLines(content, "telego_middleend_link_queue_high_water_bytes"))
	}
	if !metricSampleMatches(content, "telego_middleend_link_queue_capacity_bytes", []string{`dc="-2"`, `queue="submission"`, `role="active"`}, " 2.097152e+06") {
		t.Errorf("Middle-End submission byte-capacity gauge is missing or has the wrong value:\n%s", metricLines(content, "telego_middleend_link_queue_capacity_bytes"))
	}
	if !metricSampleMatches(content, "telego_middleend_frontend_routes_active", []string{`route="middleend"`}, " 4") ||
		!metricSampleMatches(content, "telego_middleend_frontend_routes_active", []string{`route="direct_fallback"`}, " 2") {
		t.Errorf("Middle-End frontend route gauges are missing or have the wrong values:\n%s", metricLines(content, "telego_middleend_frontend_routes_active"))
	}

	// Verify user labels appear
	if !strings.Contains(content, "user1") {
		t.Error("metrics should contain user1 label")
	}
	if !strings.Contains(content, "user2") {
		t.Error("metrics should contain user2 label")
	}

	// Empty name should be replaced with "unknown"
	if !strings.Contains(content, "unknown") {
		t.Error("empty secret name should be replaced with 'unknown'")
	}
}

func metricLines(content, prefix string) string {
	var result []string
	for line := range strings.SplitSeq(content, "\n") {
		if strings.HasPrefix(line, prefix) {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}

func metricSampleMatches(content, prefix string, labels []string, valueSuffix string) bool {
	for line := range strings.SplitSeq(content, "\n") {
		if !strings.HasPrefix(line, prefix+"{") || !strings.HasSuffix(line, valueSuffix) {
			continue
		}
		matches := true
		for _, label := range labels {
			if !strings.Contains(line, label) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

// Tests below don't start HTTP servers or create meter providers to avoid global state conflicts

func TestConfig_Fields(t *testing.T) {
	cfg := Config{
		BindAddr: "0.0.0.0:9090",
		Path:     "/custom-metrics",
	}

	if cfg.BindAddr != "0.0.0.0:9090" {
		t.Errorf("BindAddr: got %s, want 0.0.0.0:9090", cfg.BindAddr)
	}
	if cfg.Path != "/custom-metrics" {
		t.Errorf("Path: got %s, want /custom-metrics", cfg.Path)
	}
}

func TestMockStatsProvider(t *testing.T) {
	provider := &mockStatsProvider{
		stats: []gproxy.UserIPStats{
			{SecretName: "user1", Connections: 10, ActiveIPs: 5},
			{SecretName: "user2", Connections: 20, ActiveIPs: 8},
		},
	}

	stats := provider.Stats()
	if len(stats) != 2 {
		t.Errorf("expected 2 stats, got %d", len(stats))
	}

	if stats[0].SecretName != "user1" {
		t.Errorf("expected user1, got %s", stats[0].SecretName)
	}

	if stats[0].Connections != 10 {
		t.Errorf("expected 10 connections, got %d", stats[0].Connections)
	}
}

func TestCountingStatsProvider(t *testing.T) {
	callCount := 0
	provider := &countingStatsProvider{
		callCount: &callCount,
		stats: []gproxy.UserIPStats{
			{SecretName: "test", Connections: 5},
		},
	}

	// Call Stats multiple times
	provider.Stats()
	provider.Stats()
	provider.Stats()

	if callCount != 3 {
		t.Errorf("expected 3 calls, got %d", callCount)
	}

	stats := provider.Stats()
	if len(stats) != 1 {
		t.Errorf("expected 1 stat, got %d", len(stats))
	}
}

// BenchmarkStatsProvider benchmarks Stats() calls
func BenchmarkStatsProvider(b *testing.B) {
	provider := &mockStatsProvider{
		stats: []gproxy.UserIPStats{
			{SecretName: "user1", Connections: 10, ActiveIPs: 5},
			{SecretName: "user2", Connections: 20, ActiveIPs: 8},
			{SecretName: "user3", Connections: 30, ActiveIPs: 10},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		provider.Stats()
	}
}
