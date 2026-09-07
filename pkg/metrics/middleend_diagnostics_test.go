package metrics

import (
	"errors"
	"strings"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestMiddleEndDiagnosticMetricsUseOnlyBoundedCounters(t *testing.T) {
	provider := &refreshMetricsProvider{snapshot: middleend.ServiceSnapshot{
		Supervisor: middleend.GenerationSupervisorSnapshot{
			DiagnosticRecordsDropped: 3,
			ForcedRetirements: []middleend.GenerationForcedRetirementCounter{
				{Reason: middleend.GenerationRetirementArtifactCapacity, Retirements: 4, AffectedBindings: 9},
				{Reason: middleend.GenerationRetirementReason("private-reason-marker"), Retirements: 77},
			},
			LastSlotFailure: middleend.FixedBindingSlotFailureSnapshot{Error: errors.New("credential-marker 192.0.2.1:443 client-marker")},
		},
	}}
	scrape := newMiddleEndRefreshScraper(t, provider)
	content := scrape()
	for _, sample := range []struct {
		name   string
		labels []string
		value  string
	}{
		{"telego_middleend_diagnostic_records_dropped_total", nil, " 3"},
		{"telego_middleend_forced_retirement_total", []string{`reason="artifact_capacity"`}, " 4"},
		{"telego_middleend_forced_retirement_total", []string{`reason="recovery_capacity"`}, " 0"},
		{"telego_middleend_forced_retirement_affected_bindings_total", []string{`reason="artifact_capacity"`}, " 9"},
		{"telego_middleend_forced_retirement_affected_bindings_total", []string{`reason="recovery_capacity"`}, " 0"},
	} {
		if !metricSampleMatches(content, sample.name, sample.labels, sample.value) {
			t.Errorf("missing %s %v%s", sample.name, sample.labels, sample.value)
		}
	}
	for _, forbidden := range []string{
		"credential-marker", "192.0.2.1", "client-marker", "private-reason-marker",
		"generation_id=", "incarnation=", "probe_id=", "error_code=", "error_text=", "endpoint=", "diagnostic_sequence=",
	} {
		if strings.Contains(content, forbidden) {
			t.Errorf("metrics exposed %q", forbidden)
		}
	}
	for _, name := range []string{
		"telego_middleend_diagnostic_records_dropped_total",
		"telego_middleend_forced_retirement_total",
		"telego_middleend_forced_retirement_affected_bindings_total",
	} {
		lines := metricLines(content, name)
		for line := range strings.SplitSeq(lines, "\n") {
			if !strings.HasPrefix(line, name+"{") {
				continue
			}
			_, labels, _ := strings.Cut(line, "{")
			labels, _, _ = strings.Cut(labels, "}")
			for label := range strings.SplitSeq(labels, ",") {
				key, _, _ := strings.Cut(label, "=")
				if strings.HasPrefix(key, "otel_scope_") {
					continue
				}
				if key != "reason" || name == "telego_middleend_diagnostic_records_dropped_total" {
					t.Errorf("unexpected label %q for %s", key, name)
				}
			}
		}
	}
	// Manager removal does not reset the source's service-lifetime counters.
	provider.snapshot.Supervisor.Active = nil
	provider.snapshot.Supervisor.Retiring = nil
	provider.snapshot.Supervisor.DiagnosticRecordsDropped++
	provider.snapshot.Supervisor.ForcedRetirements[0].Retirements++
	content = scrape()
	if !metricSampleMatches(content, "telego_middleend_diagnostic_records_dropped_total", nil, " 4") ||
		!metricSampleMatches(content, "telego_middleend_forced_retirement_total", []string{`reason="artifact_capacity"`}, " 5") {
		t.Fatal("service-lifetime diagnostic counters did not advance")
	}
}
