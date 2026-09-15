package metrics

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/transport/middleend"
)

type responseMetricsProvider struct {
	refreshMetricsProvider
	frontend gproxy.MiddleEndFrontendStats
}

func (p *responseMetricsProvider) MiddleEndFrontendStats() gproxy.MiddleEndFrontendStats {
	return p.frontend
}

func TestMiddleEndSharedResponseMetricsAndCapacity(t *testing.T) {
	provider := &responseMetricsProvider{frontend: gproxy.MiddleEndFrontendStats{
		SharedResponseBudget: true, InputBytesLimit: 1024, OutputBytesLimit: 8000, OutputBytes: 144,
		ResponseStallClosures: 7,
	}}
	provider.snapshot.Capacity = middleend.ServiceCapacitySnapshot{
		ResponseBudgetBytes: 4096, ManagerRequestBytes: 1024, ManagerControlBytes: 256,
		ManagerResponseBytes: 8000, ManagerResponseItems: 4096, BindingResponseBytes: 2048, BindingResponseItems: 768,
		DecoderBytesPerLink: 1024, DecoderGrowthBytesPerOwner: 1024, DecodePlaintextBytesPerOwner: 64,
	}
	provider.snapshot.RuntimeLinks = 5
	provider.snapshot.ResponseBudget = middleend.ResponseBudgetSnapshot{
		LimitBytes: 4096, OrdinaryLimitBytes: 3072, ProcessingReserveBytes: 1024,
		UsedBytes: 1000, HighWaterBytes: 2000,
	}
	pool := &provider.snapshot.ResponseBudget
	pool.ClassBytes[middleend.ResponseMemoryOrdinary] = 900
	pool.ClassBytes[middleend.ResponseMemoryProcessing] = 100
	pool.StageBytes[middleend.ResponseMemoryQueuePayload] = 500
	pool.StageBytes[middleend.ResponseMemoryQueueMetadata] = 100
	pool.StageBytes[middleend.ResponseMemoryEncode] = 100
	pool.StageBytes[middleend.ResponseMemoryOutput] = 200
	pool.StageBytes[middleend.ResponseMemoryOwnerMetadata] = 100
	provider.snapshot.Supervisor.Active = &middleend.FixedBindingManagerSnapshot{ResponseBytes: 77}
	provider.snapshot.Supervisor.Retiring = &middleend.FixedBindingManagerSnapshot{ResponseBytes: 33}
	provider.snapshot.Supervisor.ResponsePressureEvictions[middleend.ResponsePressureSharedBudget] = 4
	provider.snapshot.Supervisor.ResponsePressureDiscardedBytes[middleend.ResponsePressureSharedBudget] = 123
	provider.snapshot.Supervisor.ResponsePressureReclaimedBytes[middleend.ResponsePressureSharedBudget] = 300
	provider.snapshot.Supervisor.ResponsePressureSelections[middleend.ResponsePressureStalled] = 3
	provider.snapshot.Supervisor.ResponsePressureSelections[middleend.ResponsePressureIncomingFallback] = 1
	provider.frontend.ResponseWaitsTotal[middleend.ResponseOutputProcessingReserve] = 3
	provider.frontend.ResponseWaitsCompletedTotal[middleend.ResponseOutputProcessingReserve] = 2
	provider.frontend.ResponseWaitDurationMicroseconds[middleend.ResponseOutputProcessingReserve] = 2_500_000
	provider.frontend.ResponseWaitsActive[middleend.ResponseOutputProcessingReserve] = 1
	scrape := newMiddleEndRefreshScraper(t, provider)
	content := scrape()
	for _, sample := range []struct {
		name, label, value string
	}{
		{"telego_middleend_response_memory_used_bytes", "", " 1000"},
		{"telego_middleend_runtime_links", "", " 5"},
		{"telego_middleend_response_memory_limit_bytes", "", " 4096"},
		{"telego_middleend_response_memory_high_water_bytes", "", " 2000"},
		{"telego_middleend_response_memory_class_bytes", `class="ordinary"`, " 900"},
		{"telego_middleend_response_memory_class_bytes", `class="processing"`, " 100"},
		{"telego_middleend_response_memory_class_bytes", `class="control"`, " 0"},
		{"telego_middleend_response_memory_class_limit_bytes", `class="ordinary"`, " 3072"},
		{"telego_middleend_response_memory_class_limit_bytes", `class="processing"`, " 1024"},
		{"telego_middleend_response_memory_class_limit_bytes", `class="control"`, " 0"},
		{"telego_middleend_response_memory_stage_bytes", `stage="queue_payload"`, " 500"},
		{"telego_middleend_response_memory_stage_bytes", `stage="queue_metadata"`, " 100"},
		{"telego_middleend_response_memory_stage_bytes", `stage="decode"`, " 0"},
		{"telego_middleend_response_memory_stage_bytes", `stage="encode"`, " 100"},
		{"telego_middleend_response_memory_stage_bytes", `stage="output"`, " 200"},
		{"telego_middleend_response_memory_stage_bytes", `stage="inflight"`, " 0"},
		{"telego_middleend_response_memory_stage_bytes", `stage="owner_metadata"`, " 100"},
		{"telego_middleend_response_admission_waits_total", `reason="processing_reserve"`, " 3"},
		{"telego_middleend_response_admission_waits_completed_total", `reason="processing_reserve"`, " 2"},
		{"telego_middleend_response_admission_wait_seconds_total", `reason="processing_reserve"`, " 2.5"},
		{"telego_middleend_response_admission_waits_active", `reason="processing_reserve"`, " 1"},
		{"telego_middleend_response_output_stall_closures_total", "", " 7"},
		{"telego_middleend_response_pressure_evictions_total", `limit="shared_budget"`, " 4"},
		{"telego_middleend_response_pressure_discarded_bytes_total", `limit="shared_budget"`, " 123"},
		{"telego_middleend_response_pressure_reclaimed_bytes_total", `limit="shared_budget"`, " 300"},
		{"telego_middleend_response_pressure_selections_total", `rule="stalled"`, " 3"},
		{"telego_middleend_response_pressure_selections_total", `rule="incoming_fallback"`, " 1"},
		{"telego_middleend_frontend_buffer_bytes", `direction="output"`, " 144"},
		{"telego_middleend_frontend_buffer_capacity_bytes", `direction="input"`, " 1024"},
		{"telego_middleend_manager_queue_bytes", `role="active"`, " 77"},
		{"telego_middleend_manager_queue_bytes", `role="retiring"`, " 33"},
		{"telego_middleend_capacity", `resource="response_budget_bytes"`, " 4096"},
		{"telego_middleend_capacity", `resource="manager_request_bytes"`, " 1024"},
		{"telego_middleend_capacity", `resource="decoder_bytes_per_link"`, " 1024"},
		{"telego_middleend_capacity", `resource="decoder_growth_bytes_per_owner"`, " 1024"},
		{"telego_middleend_capacity", `resource="decode_plaintext_bytes_per_owner"`, " 64"},
	} {
		if !metricSampleMatches(content, sample.name, []string{sample.label}, sample.value) {
			t.Errorf("missing %s %s%s: %s", sample.name, sample.label, sample.value, metricLines(content, sample.name))
		}
	}
	for _, resource := range []string{"manager_response_items", "manager_response_bytes", "binding_response_items", "binding_response_bytes"} {
		if strings.Contains(metricLines(content, "telego_middleend_capacity"), `resource="`+resource+`"`) {
			t.Errorf("shared response mode published obsolete capacity %s", resource)
		}
	}
	if strings.Contains(metricLines(content, "telego_middleend_frontend_buffer_capacity_bytes"), `direction="output"`) {
		t.Fatal("shared response mode published the old independent frontend output limit")
	}
	for line := range strings.SplitSeq(content, "\n") {
		if !strings.HasPrefix(line, "telego_middleend_response_") {
			continue
		}
		for _, forbidden := range []string{`role=`, `generation_id=`, `connection_id=`, `client_id=`, `dc=`, `slot=`, `incarnation=`, `rule="unknown"`, `reason="none"`, `reason="unknown"`} {
			if strings.Contains(line, forbidden) {
				t.Errorf("unexpected response metric label in %s", line)
			}
		}
	}
	// Removing both managers cannot reset service/frontend lifetime facts or
	// multiply the shared pool by the number of live generations.
	provider.snapshot.Supervisor.Active, provider.snapshot.Supervisor.Retiring = nil, nil
	provider.snapshot.Supervisor.ResponsePressureReclaimedBytes[middleend.ResponsePressureSharedBudget]++
	provider.frontend.ResponseWaitsCompletedTotal[middleend.ResponseOutputProcessingReserve]++
	provider.frontend.ResponseWaitsActive[middleend.ResponseOutputProcessingReserve] = 0
	content = scrape()
	if !metricSampleMatches(content, "telego_middleend_response_memory_limit_bytes", nil, " 4096") ||
		!metricSampleMatches(content, "telego_middleend_response_pressure_reclaimed_bytes_total", []string{`limit="shared_budget"`}, " 301") ||
		!metricSampleMatches(content, "telego_middleend_response_admission_waits_completed_total", []string{`reason="processing_reserve"`}, " 3") {
		t.Fatal("rotation reset or duplicated service/frontend response telemetry")
	}
}

func TestMiddleEndLegacyResponseMetricsKeepIndependentLimits(t *testing.T) {
	provider := &responseMetricsProvider{frontend: gproxy.MiddleEndFrontendStats{InputBytesLimit: 1024, OutputBytesLimit: 2048}}
	provider.snapshot.Capacity = middleend.ServiceCapacitySnapshot{ManagerResponseBytes: 4096, BindingResponseItems: 768}
	content := newMiddleEndRefreshScraper(t, provider)()
	if metricLines(content, "telego_middleend_response_memory_") != "" {
		t.Fatal("legacy mode published a nonexistent response pool")
	}
	if !metricSampleMatches(content, "telego_middleend_frontend_buffer_capacity_bytes", []string{`direction="output"`}, " 2048") ||
		!metricSampleMatches(content, "telego_middleend_capacity", []string{`resource="manager_response_bytes"`}, " 4096") ||
		!metricSampleMatches(content, "telego_middleend_capacity", []string{`resource="binding_response_items"`}, " 768") {
		t.Fatal("legacy response capacity metrics changed")
	}
}

type changingResponseMetricsProvider struct {
	calls atomic.Int64
}

func (p *changingResponseMetricsProvider) Snapshot() middleend.ServiceSnapshot {
	value := p.calls.Add(1)
	snapshot := middleend.ServiceSnapshot{ResponseBudget: middleend.ResponseBudgetSnapshot{
		LimitBytes: 1 << 20, OrdinaryLimitBytes: 1 << 20, UsedBytes: int(value), HighWaterBytes: int(value),
	}}
	snapshot.ResponseBudget.ClassBytes[middleend.ResponseMemoryOrdinary] = int(value)
	snapshot.ResponseBudget.StageBytes[middleend.ResponseMemoryQueuePayload] = int(value)
	snapshot.Supervisor.ResponsePressureEvictions[middleend.ResponsePressureSharedBudget] = uint64(value)
	snapshot.Supervisor.ResponsePressureSelections[middleend.ResponsePressureIncomingFallback] = uint64(value)
	return snapshot
}

func TestMiddleEndResponseMetricGroupsUseConsistentSnapshots(t *testing.T) {
	content := newMiddleEndRefreshScraper(t, &changingResponseMetricsProvider{})()
	valueOf := func(name, label string) string {
		t.Helper()
		for line := range strings.SplitSeq(content, "\n") {
			if strings.HasPrefix(line, name+"{") && strings.Contains(line, label) {
				fields := strings.Fields(line)
				return " " + fields[len(fields)-1]
			}
		}
		t.Fatalf("missing metric %s %s", name, label)
		return ""
	}
	used := valueOf("telego_middleend_response_memory_used_bytes", "")
	if !metricSampleMatches(content, "telego_middleend_response_memory_class_bytes", []string{`class="ordinary"`}, used) ||
		!metricSampleMatches(content, "telego_middleend_response_memory_stage_bytes", []string{`stage="queue_payload"`}, used) {
		t.Fatal("pool total, class, and stage observations came from different snapshots")
	}
	evictions := valueOf("telego_middleend_response_pressure_evictions_total", `limit="shared_budget"`)
	if !metricSampleMatches(content, "telego_middleend_response_pressure_selections_total", []string{`rule="incoming_fallback"`}, evictions) {
		t.Fatal("eviction reason and selection rule observations came from different snapshots")
	}
}
