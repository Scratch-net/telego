package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	clientprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

type refreshMetricsProvider struct {
	snapshot middleend.ServiceSnapshot
}

func (p *refreshMetricsProvider) Snapshot() middleend.ServiceSnapshot { return p.snapshot }

func TestMiddleEndRefreshMetricsKeepIncumbentReady(t *testing.T) {
	provider := &refreshMetricsProvider{snapshot: middleend.ServiceSnapshot{
		Capacity: middleend.ServiceCapacitySnapshot{MaxRefreshCandidatesPerManager: 8},
		Supervisor: middleend.GenerationSupervisorSnapshot{
			Admitting: true,
			DCs: []middleend.FixedBindingDCSnapshot{
				{DCID: -2, ReadySlots: 1, RefreshingSlots: 1, SlotRefreshSuccesses: 7, SlotRefreshFailures: 2, SlotRefreshCanceled: 3},
				{DCID: 2},
			},
			LastSlotFailure: middleend.FixedBindingSlotFailureSnapshot{Error: errors.New("private-error-marker")},
			Active: &middleend.FixedBindingManagerSnapshot{
				Ready: true, Accepting: true, RefreshingSlots: 1,
				DCs:   []middleend.FixedBindingDCSnapshot{{DCID: -2, ReadySlots: 1, RefreshingSlots: 1}, {DCID: 2}},
				Slots: []middleend.FixedBindingSlotSnapshot{{DCID: -2, Refreshing: true, Link: middleend.LinkSnapshot{State: middleend.LinkStateReady}}},
			},
		},
	}}
	scrape := newMiddleEndRefreshScraper(t, provider)
	content := scrape()
	for _, sample := range []struct {
		name   string
		labels []string
		value  string
	}{
		{"telego_middleend_links", []string{`role="active"`, `dc="-2"`, `state="ready"`}, " 1"},
		{"telego_middleend_slot_refreshes_active", []string{`role="active"`, `dc="-2"`}, " 1"},
		{"telego_middleend_slot_refreshes_active", []string{`role="active"`, `dc="2"`}, " 0"},
		{"telego_middleend_slot_refresh_total", []string{`dc="-2"`, `result="success"`}, " 7"},
		{"telego_middleend_slot_refresh_total", []string{`dc="-2"`, `result="failure"`}, " 2"},
		{"telego_middleend_slot_refresh_total", []string{`dc="-2"`, `result="canceled"`}, " 3"},
		{"telego_middleend_slot_refresh_total", []string{`dc="2"`, `result="success"`}, " 0"},
		{"telego_middleend_slot_refresh_total", []string{`dc="2"`, `result="failure"`}, " 0"},
		{"telego_middleend_slot_refresh_total", []string{`dc="2"`, `result="canceled"`}, " 0"},
		{"telego_middleend_zero_ready_transitions_total", []string{`dc="-2"`}, " 0"},
		{"telego_middleend_capacity", []string{`resource="refresh_candidates_per_manager"`}, " 8"},
	} {
		if !metricSampleMatches(content, sample.name, sample.labels, sample.value) {
			t.Errorf("missing %s %v%s:\n%s", sample.name, sample.labels, sample.value, metricLines(content, sample.name))
		}
	}
	if strings.Contains(metricLines(content, "telego_middleend_links"), `state="repairing"`) {
		t.Fatal("unpublished candidate hid the ready incumbent")
	}
	for _, forbidden := range []string{"private-error-marker", `endpoint=`, `user=`, `connection_id=`, `error=`} {
		if strings.Contains(content, forbidden) {
			t.Errorf("refresh diagnostics exposed %q", forbidden)
		}
	}

	// Rotation changes live manager views, not the service-owned lifetime counters.
	provider.snapshot.Supervisor.Active = &middleend.FixedBindingManagerSnapshot{
		DCs: []middleend.FixedBindingDCSnapshot{{DCID: -2, ReadySlots: 1}},
	}
	provider.snapshot.Supervisor.DCs[0].RefreshingSlots = 0
	provider.snapshot.Supervisor.DCs[0].SlotRefreshSuccesses++
	provider.snapshot.Supervisor.DCs[0].ZeroReadyTransitions = 1
	content = scrape()
	if !metricSampleMatches(content, "telego_middleend_slot_refresh_total", []string{`dc="-2"`, `result="success"`}, " 8") ||
		!metricSampleMatches(content, "telego_middleend_zero_ready_transitions_total", []string{`dc="-2"`}, " 1") ||
		!metricSampleMatches(content, "telego_middleend_slot_refreshes_active", []string{`role="active"`, `dc="-2"`}, " 0") {
		t.Fatal("rotation lost lifetime counters or retained the old candidate gauge")
	}
}

func newMiddleEndRefreshScraper(t *testing.T, source MiddleEndStatsProvider) func() string {
	t.Helper()
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
	registerMiddleEndMetrics(provider.Meter("telego-refresh-test"), source)
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	return func() string {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("metrics status = %d", response.Code)
		}
		return response.Body.String()
	}
}
