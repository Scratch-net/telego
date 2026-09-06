package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetricsDiagnosticsValidation(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9090", "127.0.0.2:1", "[::1]:65535", "[::ffff:127.0.0.1]:9090"} {
		if err := (MetricsConfig{BindTo: address, Diagnostics: true}).Validate(); err != nil {
			t.Errorf("private address %q: %v", address, err)
		}
	}
	for _, address := range []string{"", ":9090", "0.0.0.0:9090", "[::]:9090", "192.0.2.1:9090", "localhost:9090", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:http", "[::1%lo]:9090"} {
		cfg := MetricsConfig{BindTo: address, Diagnostics: true}
		if cfg.Validate() == nil {
			t.Errorf("unsafe address %q accepted", address)
		}
		cfg.Diagnostics = false
		if err := cfg.Validate(); err != nil {
			t.Errorf("disabled diagnostics changed legacy address behavior: %v", err)
		}
	}
	for _, path := range []string{"/debug/pprof", "/debug/pprof/heap", "/debug/%70prof/", "/%64ebug/pprof/heap", "/metrics/{name}", "GET /metrics", "metrics"} {
		if err := (MetricsConfig{BindTo: "127.0.0.1:9090", Path: path, Diagnostics: true}).Validate(); err == nil {
			t.Errorf("conflicting or invalid path %q accepted", path)
		}
	}
}

func TestLoadMetricsDiagnosticsDefaultsAndValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.toml")
	for _, test := range []struct {
		name, document   string
		enabled, invalid bool
	}{
		{name: "default", document: "[metrics]\nbind-to = '0.0.0.0:9090'\n"},
		{name: "private", document: "[metrics]\nbind-to = '127.0.0.1:9090'\ndiagnostics = true\n", enabled: true},
		{name: "empty", document: "[metrics]\ndiagnostics = true\n", invalid: true},
		{name: "public", document: "[metrics]\nbind-to = '0.0.0.0:9090'\ndiagnostics = true\n", invalid: true},
		{name: "escaped", document: "[metrics]\nbind-to = '127.0.0.1:9090'\npath = '/debug/%70prof/'\ndiagnostics = true\n", invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(test.document), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if test.invalid {
				if err == nil || !strings.Contains(err.Error(), "metrics") {
					t.Fatalf("invalid diagnostics configuration: %v", err)
				}
				return
			}
			if err != nil || cfg.Metrics.Diagnostics != test.enabled {
				t.Fatalf("load: config=%v, error=%v", cfg, err)
			}
		})
	}
	_, err := (&Config{Metrics: MetricsConfig{Diagnostics: true}}).ToGProxyConfig()
	if err == nil || !strings.Contains(err.Error(), "metrics diagnostics") {
		t.Fatalf("conversion skipped diagnostics validation: %v", err)
	}
}
