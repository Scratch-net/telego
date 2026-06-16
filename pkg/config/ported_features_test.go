package config

import (
	"testing"
	"time"
)

// TestToGProxyConfig_PortedFlags verifies the new evasion/robustness flags map
// from TOML sections into gproxy.Config.
func TestToGProxyConfig_PortedFlags(t *testing.T) {
	cfg := &Config{
		Secrets: map[string]string{"main": "0123456789abcdef0123456789abcdef"},
		General: GeneralConfig{
			ClockSyncURL: "https://www.cloudflare.com",
		},
		TLSFronting: TLSFrontingConfig{
			MaskHost:        "www.google.com",
			FakeCertSize:    2878,
			MaskSNISafelist: []string{"a.example", "b.example"},
		},
		Performance: PerformanceConfig{
			ClientSilenceClose: Duration(12 * time.Second),
		},
	}

	gCfg, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatalf("ToGProxyConfig failed: %v", err)
	}

	if gCfg.FakeCertSize != 2878 {
		t.Errorf("FakeCertSize: got %d, want 2878", gCfg.FakeCertSize)
	}
	if gCfg.ClockSyncURL != "https://www.cloudflare.com" {
		t.Errorf("ClockSyncURL: got %q", gCfg.ClockSyncURL)
	}
	if gCfg.ClientSilenceClose != 12*time.Second {
		t.Errorf("ClientSilenceClose: got %v, want 12s", gCfg.ClientSilenceClose)
	}
	if len(gCfg.MaskSNISafelist) != 2 || gCfg.MaskSNISafelist[0] != "a.example" {
		t.Errorf("MaskSNISafelist: got %v", gCfg.MaskSNISafelist)
	}
}
