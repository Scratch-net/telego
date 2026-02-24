package config

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/dc"
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

	for i := 0; i < 100; i++ {
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
