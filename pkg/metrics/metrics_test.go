package metrics

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/gproxy"
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

type mockWebStatsProvider struct{}

func (mockWebStatsProvider) RuntimeStats() webproxy.RuntimeStats {
	return webproxy.RuntimeStats{
		Capacity:        webproxy.Capacity{Sessions: 2, Streams: 4, BackendDials: 1, PendingBytes: 128, PendingItems: 3},
		SessionsCreated: 5,
		SessionsClosed:  []webproxy.RuntimeCounter{{Label: "client", Total: 2}},
		CarrierRetries:  []webproxy.RuntimeCounter{{Label: "uplink", Total: 7}},
		Backpressure:    []webproxy.RuntimeCounter{{Label: "uplink", Total: 1}},
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
		"telego_web_sessions_active",
		"telego_web_streams_active",
		"telego_web_backend_dials_active",
		"telego_web_pending_bytes",
		"telego_web_pending_items",
		"telego_web_sessions_created_total",
		"telego_web_sessions_closed_total",
		"telego_web_carrier_retries_total",
		"telego_web_backpressure_total",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(content, metric) {
			t.Errorf("metrics output should contain %s", metric)
		}
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
