package config

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/dc"
	"github.com/scratch-net/telego/pkg/webproxy"
)

// TestLoad_Valid tests loading a valid TOML configuration.
func TestLoad_Valid(t *testing.T) {
	content := `
bind-to = "0.0.0.0:443"
log-level = "info"

[secrets]
main = "0123456789abcdef0123456789abcdef"
backup = "fedcba9876543210fedcba9876543210"

[tls-fronting]
mask-host = "www.google.com"

[performance]
tcp-buffer-kb = 256
num-event-loops = 4
prefer-ip = "ipv4"
idle-timeout = "5m"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.BindTo != "0.0.0.0:443" {
		t.Errorf("BindTo: got %q, want %q", cfg.BindTo, "0.0.0.0:443")
	}

	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel: got %q, want %q", cfg.LogLevel, "info")
	}

	if len(cfg.Secrets) != 2 {
		t.Errorf("Secrets count: got %d, want 2", len(cfg.Secrets))
	}

	if cfg.Secrets["main"] != "0123456789abcdef0123456789abcdef" {
		t.Error("main secret mismatch")
	}

	if cfg.TLSFronting.MaskHost != "www.google.com" {
		t.Errorf("MaskHost: got %q, want %q", cfg.TLSFronting.MaskHost, "www.google.com")
	}

	if cfg.Performance.TCPBufferKB != 256 {
		t.Errorf("TCPBufferKB: got %d, want 256", cfg.Performance.TCPBufferKB)
	}

	if cfg.Performance.NumEventLoops != 4 {
		t.Errorf("NumEventLoops: got %d, want 4", cfg.Performance.NumEventLoops)
	}

	if cfg.Performance.PreferIP != "ipv4" {
		t.Errorf("PreferIP: got %q, want %q", cfg.Performance.PreferIP, "ipv4")
	}

	if cfg.Performance.IdleTimeout.Duration() != 5*time.Minute {
		t.Errorf("IdleTimeout: got %v, want 5m", cfg.Performance.IdleTimeout.Duration())
	}
}

// TestLoad_MissingFile tests that missing file returns appropriate error.
func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// TestLoad_InvalidTOML tests that syntax error is handled.
func TestLoad_InvalidTOML(t *testing.T) {
	content := `
bind-to = "0.0.0.0:443"
this is invalid toml [
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("expected error for invalid TOML")
	}
}

// TestParseKey_Valid tests parsing a 32-char hex string to 16 bytes.
func TestParseKey_Valid(t *testing.T) {
	keyHex := "0123456789abcdef0123456789abcdef"

	key, err := ParseKey(keyHex)
	if err != nil {
		t.Fatalf("ParseKey failed: %v", err)
	}

	if len(key) != 16 {
		t.Errorf("key length: got %d, want 16", len(key))
	}

	// Verify correct parsing
	expected, _ := hex.DecodeString(keyHex)
	if !bytes.Equal(key, expected) {
		t.Error("key bytes mismatch")
	}
}

// TestParseKey_TooShort tests that short key returns error.
func TestParseKey_TooShort(t *testing.T) {
	testCases := []string{
		"",
		"0123",
		"0123456789abcdef", // 16 chars = 8 bytes (too short)
	}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			_, err := ParseKey(tc)
			if err == nil {
				t.Error("expected error for short key")
			}
		})
	}
}

// TestParseKey_InvalidHex tests that non-hex chars return error.
func TestParseKey_InvalidHex(t *testing.T) {
	testCases := []string{
		"0123456789abcdefghijklmnopqrstuv", // non-hex chars
		"0123456789abcdef0123456789abcdeg", // 'g' is invalid
		"0123456789abcdef012345678 abcdef", // space
	}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			_, err := ParseKey(tc)
			if err == nil {
				t.Error("expected error for invalid hex")
			}
		})
	}
}

// TestParseKey_Whitespace tests that whitespace is trimmed.
func TestParseKey_Whitespace(t *testing.T) {
	keyHex := "  0123456789abcdef0123456789abcdef  "

	key, err := ParseKey(keyHex)
	if err != nil {
		t.Fatalf("ParseKey failed: %v", err)
	}

	if len(key) != 16 {
		t.Errorf("key length: got %d, want 16", len(key))
	}
}

// TestBuildFullSecret tests building full secret string.
func TestBuildFullSecret(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	host := "www.example.com"

	secret := BuildFullSecret(key, host)

	// Format: ee + 16 bytes key + hostname
	// All hex-encoded
	expectedLen := 2 + 32 + len(host)*2 // ee prefix (2) + key (32 hex) + host (chars*2)
	if len(secret) != expectedLen {
		t.Errorf("secret length: got %d, want %d", len(secret), expectedLen)
	}

	// Should start with "ee"
	if secret[:2] != "ee" {
		t.Errorf("secret should start with 'ee', got %q", secret[:2])
	}

	// Decode and verify
	decoded, err := hex.DecodeString(secret)
	if err != nil {
		t.Fatalf("failed to decode secret: %v", err)
	}

	if decoded[0] != 0xee {
		t.Errorf("first byte should be 0xee, got 0x%02x", decoded[0])
	}

	if !bytes.Equal(decoded[1:17], key) {
		t.Error("key portion mismatch")
	}

	if string(decoded[17:]) != host {
		t.Errorf("host portion: got %q, want %q", string(decoded[17:]), host)
	}
}

// TestGenerateKey tests random key generation.
func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Should be 32 hex characters
	if len(key) != 32 {
		t.Errorf("key length: got %d, want 32", len(key))
	}

	// Should be valid hex
	decoded, err := hex.DecodeString(key)
	if err != nil {
		t.Errorf("key is not valid hex: %v", err)
	}

	if len(decoded) != 16 {
		t.Errorf("decoded length: got %d, want 16", len(decoded))
	}
}

// TestGenerateKey_Randomness tests that keys are unique.
func TestGenerateKey_Randomness(t *testing.T) {
	seen := make(map[string]bool)

	for range 100 {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		if seen[key] {
			t.Error("duplicate key generated")
		}
		seen[key] = true
	}
}

// TestToGProxyConfig tests conversion to gproxy.Config.
func TestToGProxyConfig(t *testing.T) {
	cfg := &Config{
		BindTo:   "0.0.0.0:443",
		LogLevel: "info",
		Secrets: map[string]string{
			"main": "0123456789abcdef0123456789abcdef",
		},
		TLSFronting: TLSFrontingConfig{
			MaskHost: "www.google.com",
		},
		Performance: PerformanceConfig{
			IdleTimeout: Duration(5 * time.Minute),
			PreferIP:    "ipv4",
		},
	}

	gCfg, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatalf("ToGProxyConfig failed: %v", err)
	}

	if gCfg.BindAddr != cfg.BindTo {
		t.Errorf("BindAddr: got %q, want %q", gCfg.BindAddr, cfg.BindTo)
	}

	if len(gCfg.Secrets) != 1 {
		t.Errorf("Secrets count: got %d, want 1", len(gCfg.Secrets))
	}

	if gCfg.Secrets[0].Name != "main" {
		t.Errorf("Secret name: got %q, want %q", gCfg.Secrets[0].Name, "main")
	}

	if gCfg.MaskHost != "www.google.com" {
		t.Errorf("MaskHost: got %q, want %q", gCfg.MaskHost, "www.google.com")
	}

	if gCfg.MaskPort != 443 {
		t.Errorf("MaskPort: got %d, want 443", gCfg.MaskPort)
	}

	if gCfg.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout: got %v, want 5m", gCfg.IdleTimeout)
	}

	if gCfg.IPPreference != dc.PreferIPv4 {
		t.Errorf("IPPreference: got %v, want PreferIPv4", gCfg.IPPreference)
	}
}

// TestToGProxyConfig_NoSecrets tests error when no secrets.
func TestToGProxyConfig_NoSecrets(t *testing.T) {
	cfg := &Config{
		BindTo:  "0.0.0.0:443",
		Secrets: map[string]string{},
		TLSFronting: TLSFrontingConfig{
			MaskHost: "www.google.com",
		},
	}

	_, err := cfg.ToGProxyConfig()
	if err == nil {
		t.Error("expected error for no secrets")
	}
}

// TestToGProxyConfig_NoMaskHost tests error when no mask-host.
func TestToGProxyConfig_NoMaskHost(t *testing.T) {
	cfg := &Config{
		BindTo: "0.0.0.0:443",
		Secrets: map[string]string{
			"main": "0123456789abcdef0123456789abcdef",
		},
		TLSFronting: TLSFrontingConfig{
			MaskHost: "",
		},
	}

	_, err := cfg.ToGProxyConfig()
	if err == nil {
		t.Error("expected error for no mask-host")
	}
}

// TestToGProxyConfig_InvalidSecret tests error for invalid secret.
func TestToGProxyConfig_InvalidSecret(t *testing.T) {
	cfg := &Config{
		BindTo: "0.0.0.0:443",
		Secrets: map[string]string{
			"main": "invalid",
		},
		TLSFronting: TLSFrontingConfig{
			MaskHost: "www.google.com",
		},
	}

	_, err := cfg.ToGProxyConfig()
	if err == nil {
		t.Error("expected error for invalid secret")
	}
}

// TestToGProxyConfig_IPPreference tests all IP preference mappings.
func TestToGProxyConfig_IPPreference(t *testing.T) {
	testCases := []struct {
		input    string
		expected dc.IPPreference
	}{
		{"prefer-ipv4", dc.PreferIPv4},
		{"ipv4", dc.PreferIPv4},
		{"prefer-ipv6", dc.PreferIPv6},
		{"ipv6", dc.PreferIPv6},
		{"only-ipv4", dc.OnlyIPv4},
		{"only-ipv6", dc.OnlyIPv6},
		{"PREFER-IPV4", dc.PreferIPv4}, // case insensitive
		{"", dc.PreferIPv4},            // default
		{"invalid", dc.PreferIPv4},     // default for unknown
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			cfg := &Config{
				BindTo: "0.0.0.0:443",
				Secrets: map[string]string{
					"main": "0123456789abcdef0123456789abcdef",
				},
				TLSFronting: TLSFrontingConfig{
					MaskHost: "www.google.com",
				},
				Performance: PerformanceConfig{
					PreferIP: tc.input,
				},
			}

			gCfg, err := cfg.ToGProxyConfig()
			if err != nil {
				t.Fatalf("ToGProxyConfig failed: %v", err)
			}

			if gCfg.IPPreference != tc.expected {
				t.Errorf("IPPreference: got %v, want %v", gCfg.IPPreference, tc.expected)
			}
		})
	}
}

// TestToGProxyConfig_DefaultIdleTimeout tests default idle timeout.
func TestToGProxyConfig_DefaultIdleTimeout(t *testing.T) {
	cfg := &Config{
		BindTo: "0.0.0.0:443",
		Secrets: map[string]string{
			"main": "0123456789abcdef0123456789abcdef",
		},
		TLSFronting: TLSFrontingConfig{
			MaskHost: "www.google.com",
		},
		Performance: PerformanceConfig{
			IdleTimeout: 0, // Not set
		},
	}

	gCfg, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatalf("ToGProxyConfig failed: %v", err)
	}

	if gCfg.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout: got %v, want 5m (default)", gCfg.IdleTimeout)
	}
}

// TestDuration_UnmarshalText tests duration parsing.
func TestDuration_UnmarshalText(t *testing.T) {
	testCases := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"1s", time.Second, false},
		{"5m", 5 * time.Minute, false},
		{"1h30m", 90 * time.Minute, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalText([]byte(tc.input))

			if tc.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if d.Duration() != tc.expected {
				t.Errorf("duration: got %v, want %v", d.Duration(), tc.expected)
			}
		})
	}
}

// TestDuration_Duration tests duration getter.
func TestDuration_Duration(t *testing.T) {
	d := Duration(5 * time.Minute)
	if d.Duration() != 5*time.Minute {
		t.Errorf("Duration(): got %v, want 5m", d.Duration())
	}
}

// TestLoad_GeneralSection tests the new [general] section.
func TestLoad_GeneralSection(t *testing.T) {
	content := `
[general]
bind-to = "0.0.0.0:8443"
log-level = "debug"
proxy-protocol = true
max-ips-per-user = 10

[secrets]
main = "0123456789abcdef0123456789abcdef"

[tls-fronting]
mask-host = "www.google.com"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.General.BindTo != "0.0.0.0:8443" {
		t.Errorf("General.BindTo: got %q, want %q", cfg.General.BindTo, "0.0.0.0:8443")
	}

	if cfg.General.LogLevel != "debug" {
		t.Errorf("General.LogLevel: got %q, want %q", cfg.General.LogLevel, "debug")
	}

	if !cfg.General.ProxyProtocol {
		t.Error("General.ProxyProtocol should be true")
	}

	if cfg.General.MaxIPsPerUser != 10 {
		t.Errorf("General.MaxIPsPerUser: got %d, want 10", cfg.General.MaxIPsPerUser)
	}

	// Test ToGProxyConfig uses [general] values
	gCfg, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatalf("ToGProxyConfig failed: %v", err)
	}

	if gCfg.BindAddr != "0.0.0.0:8443" {
		t.Errorf("gCfg.BindAddr: got %q, want %q", gCfg.BindAddr, "0.0.0.0:8443")
	}

	if !gCfg.ProxyProtocol {
		t.Error("gCfg.ProxyProtocol should be true")
	}

	if gCfg.MaxIPsPerUser != 10 {
		t.Errorf("gCfg.MaxIPsPerUser: got %d, want 10", gCfg.MaxIPsPerUser)
	}
}

// TestLoad_GeneralSectionPrecedence tests [general] takes precedence over top-level.
func TestLoad_GeneralSectionPrecedence(t *testing.T) {
	content := `
# Top-level (deprecated)
bind-to = "0.0.0.0:443"
log-level = "info"

# Should override top-level
[general]
bind-to = "0.0.0.0:8443"
log-level = "debug"

[secrets]
main = "0123456789abcdef0123456789abcdef"

[tls-fronting]
mask-host = "www.google.com"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	gCfg, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatalf("ToGProxyConfig failed: %v", err)
	}

	// [general] should take precedence
	if gCfg.BindAddr != "0.0.0.0:8443" {
		t.Errorf("gCfg.BindAddr: got %q, want %q (from [general])", gCfg.BindAddr, "0.0.0.0:8443")
	}
}

// TestParseMetricsConfig tests parsing new max-ips-per-user and metrics config.
func TestParseMetricsConfig(t *testing.T) {
	content := `
[general]
bind-to = "0.0.0.0:443"
max-ips-per-user = 3
ip-block-timeout = "5m"

[secrets]
test = "0123456789abcdef0123456789abcdef"

[tls-fronting]
mask-host = "www.google.com"

[metrics]
bind-to = "127.0.0.1:9090"
path = "/metrics"
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.General.MaxIPsPerUser != 3 {
		t.Errorf("MaxIPsPerUser = %d, want 3", cfg.General.MaxIPsPerUser)
	}
	if cfg.General.IPBlockTimeout.Duration() != 5*time.Minute {
		t.Errorf("IPBlockTimeout = %v, want 5m", cfg.General.IPBlockTimeout.Duration())
	}
	if cfg.Metrics.BindTo != "127.0.0.1:9090" {
		t.Errorf("Metrics.BindTo = %q, want 127.0.0.1:9090", cfg.Metrics.BindTo)
	}
	if cfg.Metrics.Path != "/metrics" {
		t.Errorf("Metrics.Path = %q, want /metrics", cfg.Metrics.Path)
	}
}

// TestConfigDefaults_MaxIPsPerUser tests default values for new config fields.
func TestConfigDefaults_MaxIPsPerUser(t *testing.T) {
	content := `
[general]
bind-to = "0.0.0.0:443"

[secrets]
test = "0123456789abcdef0123456789abcdef"

[tls-fronting]
mask-host = "www.google.com"
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	proxyCfg, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatal(err)
	}

	// Default: unlimited (0)
	if proxyCfg.MaxIPsPerUser != 0 {
		t.Errorf("MaxIPsPerUser = %d, want 0", proxyCfg.MaxIPsPerUser)
	}
	// Default: 5m
	if proxyCfg.IPBlockTimeout != 5*time.Minute {
		t.Errorf("IPBlockTimeout = %v, want 5m", proxyCfg.IPBlockTimeout)
	}
}

func TestBuildDDSecret(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")

	result := BuildDDSecret(key)

	// Expected: dd + key = "dd" + "0123456789abcdef0123456789abcdef"
	expected := "dd0123456789abcdef0123456789abcdef"

	if result != expected {
		t.Errorf("BuildDDSecret() = %q, want %q", result, expected)
	}

	// Verify length: 1 byte prefix + 16 bytes key = 17 bytes = 34 hex chars
	if len(result) != 34 {
		t.Errorf("BuildDDSecret() length = %d, want 34", len(result))
	}
}

func TestBuildFullSecret_EE(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdef0123456789abcdef")
	host := "www.google.com"

	result := BuildFullSecret(key, host)

	// Expected: ee + key + host_hex
	hostHex := hex.EncodeToString([]byte(host))
	expected := "ee0123456789abcdef0123456789abcdef" + hostHex

	if result != expected {
		t.Errorf("BuildFullSecret() = %q, want %q", result, expected)
	}
}

func TestWebProxyDisabledPreservesLegacyConfig(t *testing.T) {
	cfg := Config{
		Secrets: map[string]string{"alice": "0123456789abcdef0123456789abcdef"},
		TLSFronting: TLSFrontingConfig{
			MaskHost: "www.google.com",
		},
		WebProxy: WebProxyConfig{
			Enabled:       false,
			Hostname:      "INVALID HOSTNAME",
			Backend:       "not an address",
			NumEventLoops: -1,
		},
	}

	legacy, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatalf("ToGProxyConfig: %v", err)
	}
	if legacy.MaskHost != "www.google.com" || len(legacy.Secrets) != 1 {
		t.Fatalf("legacy config changed: %+v", legacy)
	}
	runtime, err := cfg.ToWebProxyRuntimeConfig("0.0.0.0:443")
	if err != nil {
		t.Fatalf("disabled ToWebProxyRuntimeConfig: %v", err)
	}
	if runtime.Enabled || len(runtime.Profiles) != 0 {
		t.Fatalf("disabled runtime = %+v, want zero value", runtime)
	}
}

func TestLoadAndConvertWebProxyConfig(t *testing.T) {
	content := `
[general]
bind-to = "0.0.0.0:443"

[secrets]
alice = "0123456789abcdef0123456789abcdef"

[tls-fronting]
mask-host = "www.google.com"

[web-proxy]
enabled = true
bind-to = "127.0.0.1:9080"
hostname = "proxy.example.com"
carrier = "https-lanes"
trusted-proxy-cidrs = ["127.0.0.1/32"]
num-event-loops = 2
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	proxyConfig, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatalf("ToGProxyConfig: %v", err)
	}
	if proxyConfig.InternalProxyProtocol || proxyConfig.WebProxyFingerprint == "" {
		t.Fatalf("gproxy WEB integration = internal %t fingerprint %q", proxyConfig.InternalProxyProtocol, proxyConfig.WebProxyFingerprint)
	}
	runtime, err := cfg.ToWebProxyRuntimeConfig(cfg.General.BindTo)
	if err != nil {
		t.Fatalf("ToWebProxyRuntimeConfig: %v", err)
	}
	if !runtime.Enabled || runtime.BindAddr != "127.0.0.1:9080" ||
		runtime.Hostname != "proxy.example.com" || runtime.Backend != "" || !runtime.LogicalBackend ||
		runtime.Carrier != webproxy.CarrierHTTPSLanes || runtime.NumEventLoops != 2 || runtime.BackendProxyProtocol {
		t.Fatalf("runtime = %+v", runtime)
	}
	if len(runtime.TrustedProxyCIDRs) != 1 || runtime.TrustedProxyCIDRs[0] != "127.0.0.1/32" {
		t.Fatalf("trusted proxies = %v", runtime.TrustedProxyCIDRs)
	}
	if len(runtime.Profiles) != 2 {
		t.Fatalf("profiles = %d, want 2", len(runtime.Profiles))
	}
	if runtime.Profiles[0].Name() != "alice" || runtime.Profiles[0].Mode() != webproxy.SecretPlain ||
		runtime.Profiles[0].SecretHex() != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("plain profile = name %q mode %v secret %q", runtime.Profiles[0].Name(), runtime.Profiles[0].Mode(), runtime.Profiles[0].SecretHex())
	}
	if runtime.Profiles[1].Name() != "alice" || runtime.Profiles[1].Mode() != webproxy.SecretDD ||
		runtime.Profiles[1].SecretHex() != "dd0123456789abcdef0123456789abcdef" {
		t.Fatalf("dd profile = name %q mode %v secret %q", runtime.Profiles[1].Name(), runtime.Profiles[1].Mode(), runtime.Profiles[1].SecretHex())
	}
}

func TestWebProxyConfigDefaults(t *testing.T) {
	cfg := Config{
		Secrets: map[string]string{"alice": "0123456789abcdef0123456789abcdef"},
		WebProxy: WebProxyConfig{
			Enabled:  true,
			Hostname: "proxy.example.com",
		},
	}
	runtime, err := cfg.ToWebProxyRuntimeConfig("tcp://0.0.0.0:8443")
	if err != nil {
		t.Fatalf("ToWebProxyRuntimeConfig: %v", err)
	}
	if runtime.BindAddr != "127.0.0.1:8080" || runtime.Backend != "" || !runtime.LogicalBackend ||
		runtime.Carrier != webproxy.CarrierHTTPS {
		t.Fatalf("defaults = bind %q backend %q carrier %q", runtime.BindAddr, runtime.Backend, runtime.Carrier)
	}
}

func TestWebProxyConfigAcceptsWebSocketCarriers(t *testing.T) {
	for _, carrier := range []webproxy.CarrierMode{
		webproxy.CarrierWebSocket,
		webproxy.CarrierWebSocketLanes,
	} {
		t.Run(string(carrier), func(t *testing.T) {
			cfg := Config{
				Secrets: map[string]string{"alice": "0123456789abcdef0123456789abcdef"},
				WebProxy: WebProxyConfig{
					Enabled:  true,
					Hostname: "proxy.example.com",
					Carrier:  string(carrier),
				},
			}
			runtime, err := cfg.ToWebProxyRuntimeConfig("0.0.0.0:443")
			if err != nil {
				t.Fatalf("ToWebProxyRuntimeConfig: %v", err)
			}
			if runtime.Carrier != carrier {
				t.Fatalf("carrier = %q, want %q", runtime.Carrier, carrier)
			}
		})
	}
}

func TestWebProxyConfigKeepsUnixListenerMetadataForLogicalBackend(t *testing.T) {
	cfg := Config{
		Secrets:  map[string]string{"alice": "0123456789abcdef0123456789abcdef"},
		WebProxy: WebProxyConfig{Enabled: true, Hostname: "proxy.example.com"},
	}
	runtime, err := cfg.ToWebProxyRuntimeConfig("unix:///run/telego/telego.sock")
	if err != nil {
		t.Fatalf("ToWebProxyRuntimeConfig: %v", err)
	}
	if runtime.Backend != "" || !runtime.LogicalBackend || runtime.MTProxyAddr.String() != "/run/telego/telego.sock" || runtime.MTProxyAddr.Network() != "unix" {
		t.Fatalf("logical backend metadata = %+v", runtime)
	}
}

func TestWebProxyLogicalBackendPreservesListenerAddress(t *testing.T) {
	for _, bind := range []string{":443", "0.0.0.0:443", "[::]:443", "192.0.2.1:8443", "127.0.0.1:0"} {
		t.Run(bind, func(t *testing.T) {
			cfg := Config{
				Secrets:  map[string]string{"alice": "0123456789abcdef0123456789abcdef"},
				WebProxy: WebProxyConfig{Enabled: true, Hostname: "proxy.example.com"},
			}
			runtime, err := cfg.ToWebProxyRuntimeConfig(bind)
			if err != nil {
				t.Fatal(err)
			}
			address, ok := runtime.MTProxyAddr.(*net.TCPAddr)
			if !ok || !address.AddrPort().IsValid() {
				t.Fatalf("logical listener address = %#v", runtime.MTProxyAddr)
			}
			resolved, err := net.ResolveTCPAddr("tcp", bind)
			if err != nil {
				t.Fatal(err)
			}
			if address.Port != resolved.Port {
				t.Fatalf("logical listener port = %d, want configured %d", address.Port, resolved.Port)
			}
			if bind == ":443" && !address.IP.Equal(net.IPv6zero) {
				t.Fatalf("implicit wildcard IP = %s, want gnet IPv6 wildcard", address.IP)
			}
			if !runtime.LogicalBackend || runtime.Backend != "" || runtime.BackendProxyProtocol {
				t.Fatalf("omitted backend opened compatibility route: %+v", runtime)
			}
		})
	}
}

func TestWebProxyExplicitBackendRetainsAuthenticatedSocketRoute(t *testing.T) {
	for _, backend := range []string{"127.0.0.1:443", "[::1]:443", "unix:///run/telego/telego.sock"} {
		cfg := Config{
			Secrets:     map[string]string{"alice": "0123456789abcdef0123456789abcdef"},
			WebProxy:    WebProxyConfig{Enabled: true, Hostname: "proxy.example.com", Backend: backend},
			TLSFronting: TLSFrontingConfig{MaskHost: "proxy.example.com"},
		}
		runtime, err := cfg.ToWebProxyRuntimeConfig(":443")
		if err != nil {
			t.Fatal(err)
		}
		proxyConfig, err := cfg.ToGProxyConfig()
		if err != nil {
			t.Fatal(err)
		}
		if runtime.LogicalBackend || runtime.Backend != backend || !runtime.BackendProxyProtocol || !proxyConfig.InternalProxyProtocol {
			t.Fatalf("explicit backend changed selection: %+v", runtime)
		}
	}
}

func TestWebProxyProfilesAreSortedAndDeduplicated(t *testing.T) {
	cfg := Config{
		Secrets: map[string]string{
			"zulu":  "fedcba9876543210fedcba9876543210",
			"copy":  "0123456789abcdef0123456789abcdef",
			"alice": "0123456789abcdef0123456789abcdef",
		},
		WebProxy: WebProxyConfig{Enabled: true, Hostname: "proxy.example.com"},
	}
	runtime, err := cfg.ToWebProxyRuntimeConfig("0.0.0.0:443")
	if err != nil {
		t.Fatalf("ToWebProxyRuntimeConfig: %v", err)
	}
	if len(runtime.Profiles) != 4 {
		t.Fatalf("profiles = %d, want four unique capabilities", len(runtime.Profiles))
	}
	wantNames := []string{"alice", "alice", "zulu", "zulu"}
	for index, want := range wantNames {
		if runtime.Profiles[index].Name() != want {
			t.Fatalf("profile %d name = %q, want %q", index, runtime.Profiles[index].Name(), want)
		}
	}
	if runtime.Profiles[0].Mode() != webproxy.SecretPlain || runtime.Profiles[1].Mode() != webproxy.SecretDD {
		t.Fatalf("alice modes = %v, %v", runtime.Profiles[0].Mode(), runtime.Profiles[1].Mode())
	}
}

func TestGProxySecretsAreSortedDeterministically(t *testing.T) {
	first := Config{
		Secrets: map[string]string{
			"zulu":  "fedcba9876543210fedcba9876543210",
			"alice": "0123456789abcdef0123456789abcdef",
		},
		TLSFronting: TLSFrontingConfig{MaskHost: "proxy.example.com"},
	}
	second := Config{
		Secrets: map[string]string{
			"alice": "0123456789abcdef0123456789abcdef",
			"zulu":  "fedcba9876543210fedcba9876543210",
		},
		TLSFronting: TLSFrontingConfig{MaskHost: "proxy.example.com"},
	}
	firstRuntime, err := first.ToGProxyConfig()
	if err != nil {
		t.Fatal(err)
	}
	secondRuntime, err := second.ToGProxyConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstRuntime.Secrets, secondRuntime.Secrets) {
		t.Fatalf("secret order differs: %#v != %#v", firstRuntime.Secrets, secondRuntime.Secrets)
	}
	if got := []string{firstRuntime.Secrets[0].Name, firstRuntime.Secrets[1].Name}; !reflect.DeepEqual(got, []string{"alice", "zulu"}) {
		t.Fatalf("secret order = %v", got)
	}
}

func TestDisabledWebProxyFingerprintIgnoresInactiveFields(t *testing.T) {
	base := Config{
		Secrets:     map[string]string{"alice": "0123456789abcdef0123456789abcdef"},
		TLSFronting: TLSFrontingConfig{MaskHost: "proxy.example.com"},
	}
	withInactiveValues := base
	withInactiveValues.WebProxy = WebProxyConfig{
		Hostname:          "ignored.example.com",
		BindTo:            "127.0.0.1:9999",
		Backend:           "unix:///ignored.sock",
		TrustedProxyCIDRs: []string{"192.0.2.0/24"},
		NumEventLoops:     8,
	}
	firstRuntime, err := base.ToGProxyConfig()
	if err != nil {
		t.Fatal(err)
	}
	secondRuntime, err := withInactiveValues.ToGProxyConfig()
	if err != nil {
		t.Fatal(err)
	}
	if firstRuntime.WebProxyFingerprint != "enabled=false" || secondRuntime.WebProxyFingerprint != firstRuntime.WebProxyFingerprint {
		t.Fatalf("disabled fingerprints = %q and %q", firstRuntime.WebProxyFingerprint, secondRuntime.WebProxyFingerprint)
	}
}

func TestDockerWebProxyExampleConfig(t *testing.T) {
	cfg, err := Load("../../examples/web-proxy/telego.toml")
	if err != nil {
		t.Fatalf("Load example: %v", err)
	}
	proxyConfig, err := cfg.ToGProxyConfig()
	if err != nil {
		t.Fatalf("ToGProxyConfig: %v", err)
	}
	runtime, err := cfg.ToWebProxyRuntimeConfig(proxyConfig.BindAddr)
	if err != nil {
		t.Fatalf("ToWebProxyRuntimeConfig: %v", err)
	}
	if runtime.Carrier != webproxy.CarrierHTTPSLanes {
		t.Fatalf("example carrier = %q", runtime.Carrier)
	}
	managerConfig := webproxy.DefaultManagerConfig(runtime.Profiles, runtime.Backend)
	managerConfig.Carrier = runtime.Carrier
	if runtime.LogicalBackend {
		managerConfig.BackendFactory = func(webproxy.BackendOpenOptions) (webproxy.Backend, error) {
			return nil, errors.New("configuration validation does not open logical streams")
		}
	}
	manager, err := webproxy.NewManager(managerConfig)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer func() {
		if err := manager.Shutdown(shutdownContext); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	}()
	if _, err := webproxy.NewHTTPServer(webproxy.HTTPServerConfig{
		Bind:              runtime.BindAddr,
		Hostname:          runtime.Hostname,
		Manager:           manager,
		TrustedProxyCIDRs: runtime.TrustedProxyCIDRs,
	}); err != nil {
		t.Fatalf("NewHTTPServer: %v", err)
	}
}

func TestDockerWebProxyOperationalContracts(t *testing.T) {
	nginxConfig, err := os.ReadFile("../../examples/web-proxy/nginx/nginx.conf")
	if err != nil {
		t.Fatal(err)
	}
	nginxText := string(nginxConfig)
	if strings.Contains(nginxText, "client_max_body_size 2m") {
		t.Fatal("example hard-caps candidate requests at the carrier limit")
	}
	if strings.Count(nginxText, "client_max_body_size 16m") != 2 {
		t.Fatal("example must apply the same 16m policy at public ingress and the public site")
	}
	if strings.Count(nginxText, "proxy_pass http://telego_web;") != 1 ||
		!strings.Contains(nginxText, "location / {\n            proxy_pass http://telego_web;") {
		t.Fatal("example must route every public TLS path through Telego WEB")
	}
	if strings.Contains(nginxText, "location = / {") || strings.Contains(nginxText, "location ^~ /api/v1/ {") {
		t.Fatal("example contains a path-specific WEB route that lets other paths bypass classification")
	}
	for _, required := range []string{
		"http2 on;",
		"error_page 418 = @telego_ordinary;",
		"error_page 419 = @telego_sanitized;",
		"proxy_set_header Authorization \"\";",
		"proxy_set_header Cookie \"\";",
		"proxy_set_header X-Down-Cursor \"\";",
		"proxy_set_header X-Session-Token \"\";",
		"proxy_set_header Sec-WebSocket-Key \"\";",
		"proxy_set_header Sec-WebSocket-Protocol \"\";",
		"proxy_set_header Sec-WebSocket-Version \"\";",
		"proxy_set_header Sec-WebSocket-Extensions \"\";",
	} {
		if !strings.Contains(nginxText, required) {
			t.Fatalf("example lacks required arbitrary-path fallback directive %q", required)
		}
	}

	renewScript, err := os.ReadFile("../../examples/web-proxy/renew-certificate.sh")
	if err != nil {
		t.Fatal(err)
	}
	renewText := string(renewScript)
	renewIndex := strings.Index(renewText, "certbot renew --webroot")
	deployHookIndex := strings.Index(renewText, "--deploy-hook")
	guardIndex := strings.Index(renewText, `if [ -f "$renewed_marker" ]`)
	validateIndex := strings.Index(renewText, "nginx -t")
	reloadIndex := strings.Index(renewText, "nginx -s reload")
	removeMarkerIndex := strings.Index(renewText, `rm -f "$renewed_marker"`)
	if renewIndex < 0 || deployHookIndex <= renewIndex || guardIndex <= deployHookIndex ||
		validateIndex <= guardIndex || reloadIndex <= validateIndex || removeMarkerIndex <= reloadIndex {
		t.Fatal("renewal script must reload Nginx only after the certificate deploy hook sets its marker")
	}

	composeConfig, err := os.ReadFile("../../examples/web-proxy/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	composeText := string(composeConfig)
	if !strings.Contains(composeText, "- proxy.example.com") {
		t.Fatal("example lacks the certificate-host Docker DNS alias")
	}
	for setting, want := range map[string]int{
		"driver: local":     2,
		"max-size: \"10m\"": 2,
		"max-file: \"3\"":   2,
	} {
		if got := strings.Count(composeText, setting); got != want {
			t.Fatalf("example logging setting %q count = %d, want %d", setting, got, want)
		}
	}

	setupGuide, err := os.ReadFile("../../docs/web-proxy.md")
	if err != nil {
		t.Fatal(err)
	}
	setupText := string(setupGuide)
	if !strings.Contains(setupText, "carrier = \"https-lanes\"") ||
		!strings.Contains(setupText, "http2 on;") {
		t.Fatal("setup guide does not enable the recommended lanes carrier with public HTTP/2")
	}
	if !strings.Contains(setupText, "legacy mode intentionally trusts PROXY headers") {
		t.Fatal("setup guide does not qualify legacy public PROXY trust")
	}
	if !strings.Contains(setupText, "Send every TLS request to this listener") ||
		strings.Count(setupText, "include /etc/nginx/snippets/telego-web-ingress.conf;") != 1 {
		t.Fatal("setup guide does not route every TLS path through WEB classification")
	}
	if strings.Count(setupText, "docker compose up -d --force-recreate telego") < 2 {
		t.Fatal("setup guide lacks explicit Telego recreation for configuration changes and rollback")
	}
}

func TestDeployNginxOperationalContracts(t *testing.T) {
	deployScript, err := os.ReadFile("../../deploy-nginx.sh")
	if err != nil {
		t.Fatal(err)
	}
	deployText := string(deployScript)
	if strings.Contains(deployText, "docker stop telego-nginx &&") {
		t.Fatal("deployment script stops Nginx for certificate renewal")
	}
	for _, required := range []string{
		"certbot/certbot renew --webroot",
		"--deploy-hook",
		".telego-renewed",
		"docker exec telego-nginx nginx -t",
		"docker exec telego-nginx nginx -s reload",
		"# telego-cert-renew",
	} {
		if !strings.Contains(deployText, required) {
			t.Fatalf("deployment script lacks renewal contract %q", required)
		}
	}
	for setting, want := range map[string]int{
		"--log-driver local":     2,
		"--log-opt max-size=10m": 2,
		"--log-opt max-file=3":   2,
	} {
		if got := strings.Count(deployText, setting); got != want {
			t.Fatalf("deployment logging setting %q count = %d, want %d", setting, got, want)
		}
	}
}

func TestWebProxyConfigRequiresExplicitValuesWhenNotDerivable(t *testing.T) {
	base := Config{
		Secrets:  map[string]string{"alice": "0123456789abcdef0123456789abcdef"},
		WebProxy: WebProxyConfig{Enabled: true},
	}
	tests := []struct {
		name    string
		mutate  func(*Config)
		bind    string
		wantErr string
	}{
		{name: "hostname", bind: "0.0.0.0:443", wantErr: "web-proxy.hostname is required"},
		{name: "canonical hostname", bind: "0.0.0.0:443", mutate: func(c *Config) { c.WebProxy.Hostname = "Proxy.Example.com" }, wantErr: "invalid web-proxy.hostname"},
		{name: "event loops", bind: "0.0.0.0:443", mutate: func(c *Config) { c.WebProxy.Hostname = "proxy.example.com"; c.WebProxy.NumEventLoops = -1 }, wantErr: "cannot be negative"},
		{name: "carrier", bind: "0.0.0.0:443", mutate: func(c *Config) { c.WebProxy.Hostname = "proxy.example.com"; c.WebProxy.Carrier = "quic" }, wantErr: "unsupported WEB carrier mode"},
		{name: "nonlocal explicit backend", bind: "192.0.2.1:443", mutate: func(c *Config) {
			c.WebProxy.Hostname = "proxy.example.com"
			c.WebProxy.Backend = "192.0.2.1:443"
		}, wantErr: "invalid web-proxy.backend"},
		{name: "noncanonical trusted CIDR", bind: ":443", mutate: func(c *Config) {
			c.WebProxy.Hostname = "proxy.example.com"
			c.WebProxy.TrustedProxyCIDRs = []string{"127.0.0.1/8"}
		}, wantErr: "noncanonical CIDR"},
		{name: "unix HTTP bind", bind: "0.0.0.0:443", mutate: func(c *Config) {
			c.WebProxy.Hostname = "proxy.example.com"
			c.WebProxy.BindTo = "unix:///run/telego-web.sock"
		}, wantErr: "must be a TCP address"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := base
			cfg.WebProxy = base.WebProxy
			if test.mutate != nil {
				test.mutate(&cfg)
			}
			_, err := cfg.ToWebProxyRuntimeConfig(test.bind)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}
