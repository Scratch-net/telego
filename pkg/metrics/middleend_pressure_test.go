package metrics

import (
	"strings"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestResponsePressureMetricsRemainAcrossGenerations(t *testing.T) {
	provider := &refreshMetricsProvider{snapshot: middleend.ServiceSnapshot{}}
	provider.snapshot.Supervisor.ResponsePressureEvictions[middleend.ResponsePressureBindingBytes] = 9
	provider.snapshot.Supervisor.ResponsePressureDiscardedBytes[middleend.ResponsePressureBindingBytes] = 12345
	scrape := newMiddleEndRefreshScraper(t, provider)
	content := scrape()
	for _, sample := range []struct{ name, value string }{
		{"telego_middleend_response_pressure_evictions_total", " 9"},
		{"telego_middleend_response_pressure_discarded_bytes_total", " 12345"},
	} {
		if !metricSampleMatches(content, sample.name, []string{`limit="binding_bytes"`}, sample.value) {
			t.Errorf("missing %s", sample.name)
		}
		lines := metricLines(content, sample.name)
		for _, forbidden := range []string{"generation_id=", "client_id=", "dc=", "slot=", "eviction_sequence="} {
			if strings.Contains(lines, forbidden) {
				t.Errorf("unbounded metric label %s", forbidden)
			}
		}
	}
	provider.snapshot.Supervisor.Active = nil
	provider.snapshot.Supervisor.ResponsePressureEvictions[middleend.ResponsePressureBindingBytes]++
	if !metricSampleMatches(scrape(), "telego_middleend_response_pressure_evictions_total", []string{`limit="binding_bytes"`}, " 10") {
		t.Fatal("manager removal reset service counter")
	}
}
