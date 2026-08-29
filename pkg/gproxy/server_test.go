package gproxy

import (
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/dc"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Verify expected defaults
	if cfg.MaskPort != 443 {
		t.Errorf("MaskPort: got %d, want 443", cfg.MaskPort)
	}

	if cfg.CertRefreshHours != 5 {
		t.Errorf("CertRefreshHours: got %d, want 5", cfg.CertRefreshHours)
	}

	if cfg.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout: got %v, want 5m", cfg.IdleTimeout)
	}

	if cfg.TimeSkewTolerance != 3*time.Second {
		t.Errorf("TimeSkewTolerance: got %v, want 3s", cfg.TimeSkewTolerance)
	}

	if cfg.IPPreference != dc.PreferIPv4 {
		t.Errorf("IPPreference: got %v, want PreferIPv4", cfg.IPPreference)
	}

	if !cfg.Multicore {
		t.Error("Multicore should be true by default")
	}

	if !cfg.ReusePort {
		t.Error("ReusePort should be true by default")
	}

	if !cfg.LockOSThread {
		t.Error("LockOSThread should be true by default")
	}
}

func TestParseBindAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		isUnix   bool
	}{
		// Explicit Unix socket
		{"unix:///var/run/telego.sock", "unix:///var/run/telego.sock", true},
		{"unix:///tmp/test.sock", "unix:///tmp/test.sock", true},

		// Explicit TCP
		{"tcp://127.0.0.1:8080", "tcp://127.0.0.1:8080", false},
		{"tcp://0.0.0.0:443", "tcp://0.0.0.0:443", false},

		// Auto-detect: path starting with "/" is Unix
		{"/var/run/telego.sock", "unix:///var/run/telego.sock", true},
		{"/tmp/test.sock", "unix:///tmp/test.sock", true},

		// Auto-detect: anything else is TCP
		{"127.0.0.1:8080", "tcp://127.0.0.1:8080", false},
		{"0.0.0.0:443", "tcp://0.0.0.0:443", false},
		{":8080", "tcp://:8080", false},
		{"[::1]:443", "tcp://[::1]:443", false},
	}

	for _, tc := range tests {
		gnetAddr, isUnix := parseBindAddress(tc.input)
		if gnetAddr != tc.expected {
			t.Errorf("parseBindAddress(%q): got addr %q, want %q", tc.input, gnetAddr, tc.expected)
		}
		if isUnix != tc.isUnix {
			t.Errorf("parseBindAddress(%q): got isUnix %v, want %v", tc.input, isUnix, tc.isUnix)
		}
	}
}

func TestIsUnixSocket(t *testing.T) {
	tests := []struct {
		addr   string
		isUnix bool
	}{
		{"/var/run/telego.sock", true},
		{"unix:///tmp/test.sock", true},
		{"127.0.0.1:8080", false},
		{"tcp://0.0.0.0:443", false},
		{":443", false},
	}

	for _, tc := range tests {
		result := IsUnixSocket(tc.addr)
		if result != tc.isUnix {
			t.Errorf("IsUnixSocket(%q): got %v, want %v", tc.addr, result, tc.isUnix)
		}
	}
}

func TestPublicGnetOptionsPinAuditedBufferCaps(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NumEventLoop = 3
	cfg.ClientSilenceClose = time.Second
	var options gnet.Options
	for _, option := range publicGnetOptions(&cfg) {
		option(&options)
	}
	if options.ReadBufferCap != publicReadBufferCap || options.WriteBufferCap != publicWriteBufferCap {
		t.Fatalf("public buffer caps = read %d write %d, want %d and %d", options.ReadBufferCap, options.WriteBufferCap, publicReadBufferCap, publicWriteBufferCap)
	}
	if options.Multicore != cfg.Multicore || options.ReusePort != cfg.ReusePort || options.LockOSThread != cfg.LockOSThread || options.NumEventLoop != cfg.NumEventLoop || !options.Ticker {
		t.Fatalf("public gnet options = %+v", options)
	}
}

func TestPublicGnetOptionsLeaveOptionalOverridesDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NumEventLoop = 0
	cfg.ClientSilenceClose = 0
	var options gnet.Options
	for _, option := range publicGnetOptions(&cfg) {
		option(&options)
	}
	if options.NumEventLoop != 0 || options.Ticker {
		t.Fatalf("optional public gnet options = event loops %d ticker %v", options.NumEventLoop, options.Ticker)
	}
}

func TestDefaultLogger_AllMethods(t *testing.T) {
	// defaultLogger methods should not panic
	logger := defaultLogger{}

	// Test all methods don't panic
	logger.Debug("debug %d", 1)
	logger.Info("info %d", 2)
	logger.Warn("warn %d", 3)
	logger.Error("error %d", 4)

	if logger.DebugEnabled() {
		t.Error("defaultLogger.DebugEnabled() should return false")
	}
}

func TestConfig_Fields(t *testing.T) {
	cfg := Config{
		Secrets: []Secret{
			{Name: "user1", Key: []byte("0123456789abcdef"), Host: "example.com"},
		},
		Host:                "example.com",
		BindAddr:            "0.0.0.0:443",
		MaskHost:            "google.com",
		MaskPort:            443,
		FetchRealCert:       true,
		SpliceUnrecognized:  true,
		CertRefreshHours:    12,
		CertHost:            "cert.example.com",
		CertPort:            443,
		SpliceHost:          "splice.example.com",
		SplicePort:          443,
		SpliceProxyProtocol: 2,
		IPPreference:        dc.PreferIPv6,
		IdleTimeout:         10 * time.Minute,
		TimeSkewTolerance:   5 * time.Second,
		Socks5Addr:          "127.0.0.1:1080",
		ProxyProtocol:       true,
		MaxConnectionsPerIP: 100,
		MaxIPsPerUser:       50,
		IPBlockTimeout:      10 * time.Minute,
		MaxWriteBuffer:      8 * 1024 * 1024,
		Multicore:           true,
		ReusePort:           true,
		LockOSThread:        false,
		NumEventLoop:        4,
	}

	// Verify fields
	if len(cfg.Secrets) != 1 {
		t.Errorf("expected 1 secret, got %d", len(cfg.Secrets))
	}
	if cfg.Secrets[0].Name != "user1" {
		t.Errorf("secret name: got %s, want user1", cfg.Secrets[0].Name)
	}
	if cfg.SpliceProxyProtocol != 2 {
		t.Errorf("SpliceProxyProtocol: got %d, want 2", cfg.SpliceProxyProtocol)
	}
	if cfg.MaxWriteBuffer != 8*1024*1024 {
		t.Errorf("MaxWriteBuffer: got %d, want 8MB", cfg.MaxWriteBuffer)
	}
}

func TestSecret_Fields(t *testing.T) {
	s := Secret{
		Name:   "testuser",
		Key:    []byte("0123456789abcdef"),
		Host:   "test.example.com",
		RawHex: "dd3031323334353637383961626364656673746573742e6578616d706c652e636f6d",
	}

	if s.Name != "testuser" {
		t.Errorf("Name: got %s, want testuser", s.Name)
	}
	if len(s.Key) != 16 {
		t.Errorf("Key length: got %d, want 16", len(s.Key))
	}
	if s.Host != "test.example.com" {
		t.Errorf("Host: got %s, want test.example.com", s.Host)
	}
}
