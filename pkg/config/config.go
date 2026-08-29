// Package config handles TOML configuration parsing.
package config

import (
	cryptoRand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/scratch-net/telego/pkg/dc"
	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/webproxy"
)

// Config is the TOML configuration structure.
type Config struct {
	// Top-level options (can also be set in [general] section)
	BindTo        string `toml:"bind-to"`
	LogLevel      string `toml:"log-level"`
	ProxyProtocol bool   `toml:"proxy-protocol"`

	Secrets map[string]string `toml:"secrets"` // name = "secret"

	General     GeneralConfig     `toml:"general"`
	TLSFronting TLSFrontingConfig `toml:"tls-fronting"`
	Performance PerformanceConfig `toml:"performance"`
	Upstream    UpstreamConfig    `toml:"upstream"`
	Metrics     MetricsConfig     `toml:"metrics"`
	WebProxy    WebProxyConfig    `toml:"web-proxy"`
	MiddleEnd   MiddleEndConfig   `toml:"middle-end"`
}

// GeneralConfig contains general server settings.
type GeneralConfig struct {
	BindTo              string   `toml:"bind-to"`
	LogLevel            string   `toml:"log-level"`              // trace, debug, info, warn, error
	ProxyProtocol       bool     `toml:"proxy-protocol"`         // Accept incoming PROXY protocol
	MaxConnectionsPerIP int      `toml:"max-connections-per-ip"` // Max connections per IP+secret, 0 = unlimited
	MaxIPsPerUser       int      `toml:"max-ips-per-user"`       // Max unique IPs per user, 0 = unlimited
	IPBlockTimeout      Duration `toml:"ip-block-timeout"`       // How long blocked IPs stay blocked
	HandshakeTimeout    Duration `toml:"handshake-timeout"`      // Max time for handshake (default 5s)
	ClockSyncURL        string   `toml:"clock-sync-url"`         // HTTPS URL whose Date header corrects a skewed server clock at startup
}

// TLSFrontingConfig configures TLS fronting.
type TLSFrontingConfig struct {
	MaskHost string `toml:"mask-host"` // Domain to mimic (SNI validation, proxy links)
	MaskPort int    `toml:"mask-port"` // Default port (default: 443)

	// Certificate fetching - where to connect to get real TLS cert
	// Defaults to mask-host:mask-port if not set
	// Useful when cert must be fetched from local nginx bypassing front proxy
	CertHost string `toml:"cert-host"`
	CertPort int    `toml:"cert-port"`

	// FakeCertSize sets the exact size of the fake encrypted-certificate record
	// in the FakeTLS ServerHello. 0 = auto (match the mask backend's real cert
	// record size). Set to the backend's first cert-record size to remove the
	// accept-vs-mask cert-record-length tell.
	FakeCertSize int `toml:"fake-cert-size"`

	// MaskSNISafelist: opt-in extra domains an unauthenticated probe may be
	// fronted to when its ClientHello SNI matches. Empty = off (never a relay).
	MaskSNISafelist []string `toml:"mask-sni-safelist"`

	// Splice target - where to forward unrecognized clients
	// Defaults to mask-host:mask-port if not set
	SpliceHost          string   `toml:"splice-host"`
	SplicePort          int      `toml:"splice-port"`
	SpliceProxyProtocol int      `toml:"splice-proxy-protocol"` // 0=off, 1=v1, 2=v2
	SpliceIdleTimeout   Duration `toml:"splice-idle-timeout"`   // Idle timeout for splice connections (default 30s)

	// Anti-DPI record shaping on the proxy->client direction.
	// Pointers so an absent TOML key keeps the gproxy.DefaultConfig() default (true).
	EnableDRS      *bool `toml:"enable-drs"`       // Chrome-style probe-then-ramp record sizer
	EnableSplitTLS *bool `toml:"enable-split-tls"` // 1-byte first ApplicationData record
}

// PerformanceConfig configures performance settings.
type PerformanceConfig struct {
	TCPBufferKB      int      `toml:"tcp-buffer-kb"`
	NumEventLoops    int      `toml:"num-event-loops"` // gnet event loops (0 = auto, uses all cores)
	PreferIP         string   `toml:"prefer-ip"`
	IdleTimeout      Duration `toml:"idle-timeout"`
	MaxWriteBufferMB int      `toml:"max-write-buffer-mb"` // Max pending bytes per connection (0 = 4MB)
	// ClientSilenceClose: close a relay whose server reply has gone unanswered by
	// the client for this long (breaks the iOS bad_salt "Updating" wedge).
	// 0 = off. If enabled, keep it well above your slowest legitimate response;
	// ~10-15s is a sane starting point.
	ClientSilenceClose Duration `toml:"client-silence-close"`
}

// UpstreamConfig configures upstream (DC) connection settings.
type UpstreamConfig struct {
	Socks5 string `toml:"socks5"` // SOCKS5 proxy address (e.g., "127.0.0.1:1080")
}

// MetricsConfig configures the Prometheus metrics endpoint.
type MetricsConfig struct {
	BindTo string `toml:"bind-to"` // Address to bind metrics server (empty = disabled)
	Path   string `toml:"path"`    // Metrics path (default: /metrics)
}

// WebProxyConfig configures the optional private WEB carrier listener. Nginx
// terminates public TLS and forwards candidate requests to this listener.
type WebProxyConfig struct {
	Enabled           bool     `toml:"enabled"`
	BindTo            string   `toml:"bind-to"`
	Hostname          string   `toml:"hostname"`
	Backend           string   `toml:"backend"`
	Carrier           string   `toml:"carrier"`
	TrustedProxyCIDRs []string `toml:"trusted-proxy-cidrs"`
	NumEventLoops     int      `toml:"num-event-loops"`
}

// MiddleEndConfig enables Telegram's official Middle-End transport. Queue,
// topology, and timeout details are derived by ToMiddleEndRuntimeConfig. The
// two expert bounds can only reduce the production defaults.
type MiddleEndConfig struct {
	Enabled        bool   `toml:"enabled"`
	ProxyTag       string `toml:"proxy-tag"`
	SOCKS5         string `toml:"socks5"`
	SOCKS5Username string `toml:"socks5-username"`
	SOCKS5Password string `toml:"socks5-password"`
	ArtifactProxy  string `toml:"artifact-proxy"`
	NATIP          string `toml:"nat-ip"`
	MaxConnections int    `toml:"max-connections"`
	QueueBudgetMB  int    `toml:"queue-budget-mb"`
}

// WebProxyRuntimeConfig is the validated, immutable input used to construct
// the native WEB manager and its private gnet HTTP listener.
type WebProxyRuntimeConfig struct {
	Enabled              bool
	BindAddr             string
	Hostname             string
	Backend              string
	Carrier              webproxy.CarrierMode
	TrustedProxyCIDRs    []string
	NumEventLoops        int
	Profiles             []webproxy.Profile
	BackendProxyProtocol bool
}

// Duration is a TOML-parseable duration.
type Duration time.Duration

func (d *Duration) UnmarshalText(text []byte) error {
	dur, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// Load loads configuration from a TOML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}

// ToGProxyConfig converts to gproxy.Config.
func (c *Config) ToGProxyConfig() (gproxy.Config, error) {
	cfg := gproxy.DefaultConfig()

	// Bind address: [general] takes precedence over top-level (backwards compat)
	cfg.BindAddr = c.General.BindTo
	if cfg.BindAddr == "" {
		cfg.BindAddr = c.BindTo
	}

	// Parse secrets
	if len(c.Secrets) == 0 {
		return gproxy.Config{}, errors.New("at least one secret is required")
	}

	// Host comes from mask-host
	host := c.TLSFronting.MaskHost
	if host == "" {
		return gproxy.Config{}, errors.New("mask-host is required")
	}

	for _, name := range slices.Sorted(maps.Keys(c.Secrets)) {
		keyHex := c.Secrets[name]
		key, err := ParseKey(keyHex)
		if err != nil {
			return gproxy.Config{}, fmt.Errorf("invalid secret %q: %w", name, err)
		}
		cfg.Secrets = append(cfg.Secrets, gproxy.Secret{
			Name:   name,
			Key:    key,
			Host:   host,
			RawHex: BuildFullSecret(key, host),
		})
	}
	cfg.Host = host

	// TLS Fronting
	cfg.MaskHost = c.TLSFronting.MaskHost
	if cfg.MaskHost == "" {
		cfg.MaskHost = "www.google.com"
	}
	cfg.MaskPort = c.TLSFronting.MaskPort
	if cfg.MaskPort == 0 {
		cfg.MaskPort = 443
	}
	cfg.FetchRealCert = true
	cfg.SpliceUnrecognized = true
	cfg.CertRefreshHours = 1

	// Certificate fetching (defaults to mask-host:mask-port if not set)
	cfg.CertHost = c.TLSFronting.CertHost
	if cfg.CertHost == "" {
		cfg.CertHost = cfg.MaskHost
	}
	cfg.CertPort = c.TLSFronting.CertPort
	if cfg.CertPort == 0 {
		cfg.CertPort = cfg.MaskPort
	}
	cfg.FakeCertSize = c.TLSFronting.FakeCertSize
	cfg.MaskSNISafelist = c.TLSFronting.MaskSNISafelist

	// Splice target (defaults to mask-host:mask-port if not set)
	cfg.SpliceHost = c.TLSFronting.SpliceHost
	if cfg.SpliceHost == "" {
		cfg.SpliceHost = cfg.MaskHost
	}
	cfg.SplicePort = c.TLSFronting.SplicePort
	if cfg.SplicePort == 0 {
		cfg.SplicePort = cfg.MaskPort
	}
	cfg.SpliceProxyProtocol = c.TLSFronting.SpliceProxyProtocol
	cfg.SpliceIdleTimeout = c.TLSFronting.SpliceIdleTimeout.Duration()

	if c.TLSFronting.EnableDRS != nil {
		cfg.EnableDRS = *c.TLSFronting.EnableDRS
	}
	if c.TLSFronting.EnableSplitTLS != nil {
		cfg.EnableSplitTLS = *c.TLSFronting.EnableSplitTLS
	}

	// Performance
	cfg.IdleTimeout = c.Performance.IdleTimeout.Duration()
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	cfg.ClientSilenceClose = c.Performance.ClientSilenceClose.Duration()
	cfg.NumEventLoop = c.Performance.NumEventLoops

	switch strings.ToLower(c.Performance.PreferIP) {
	case "prefer-ipv4", "ipv4":
		cfg.IPPreference = dc.PreferIPv4
	case "prefer-ipv6", "ipv6":
		cfg.IPPreference = dc.PreferIPv6
	case "only-ipv4":
		cfg.IPPreference = dc.OnlyIPv4
	case "only-ipv6":
		cfg.IPPreference = dc.OnlyIPv6
	default:
		cfg.IPPreference = dc.PreferIPv4
	}

	// Upstream settings
	cfg.Socks5Addr = c.Upstream.Socks5

	// General settings
	cfg.ProxyProtocol = c.General.ProxyProtocol || c.ProxyProtocol
	cfg.MaxConnectionsPerIP = c.General.MaxConnectionsPerIP
	cfg.HandshakeTimeout = c.General.HandshakeTimeout.Duration()
	cfg.MaxIPsPerUser = c.General.MaxIPsPerUser
	cfg.ClockSyncURL = c.General.ClockSyncURL
	cfg.IPBlockTimeout = c.General.IPBlockTimeout.Duration()
	if cfg.IPBlockTimeout == 0 {
		cfg.IPBlockTimeout = 5 * time.Minute
	}

	// Backpressure settings
	if c.Performance.MaxWriteBufferMB > 0 {
		cfg.MaxWriteBuffer = c.Performance.MaxWriteBufferMB * 1024 * 1024
	}

	// The native WEB backend always supplies a validated internal PROXY header.
	// Public PROXY behavior remains controlled by [general].proxy-protocol.
	cfg.InternalProxyProtocol = c.WebProxy.Enabled
	cfg.WebProxyFingerprint = c.webProxyFingerprint()
	cfg.MiddleEndFingerprint = c.middleEndFingerprint()
	if c.MiddleEnd.Enabled {
		cfg.MaxConnections = middleEndMaxConnections(c.MiddleEnd.MaxConnections)
	}

	return cfg, nil
}

// ToWebProxyRuntimeConfig validates the optional WEB listener and derives its
// plain and dd profiles from the existing 16-byte [secrets]. Disabled WEB
// configuration is deliberately ignored so legacy configurations retain their
// exact startup behavior.
func (c *Config) ToWebProxyRuntimeConfig(mtProxyBind string) (WebProxyRuntimeConfig, error) {
	if !c.WebProxy.Enabled {
		return WebProxyRuntimeConfig{}, nil
	}

	hostname := c.WebProxy.Hostname
	if hostname == "" {
		return WebProxyRuntimeConfig{}, errors.New("web-proxy.hostname is required when WEB proxy is enabled")
	}
	if err := webproxy.ValidateHostname(hostname); err != nil {
		return WebProxyRuntimeConfig{}, fmt.Errorf("invalid web-proxy.hostname: %w", err)
	}
	if c.WebProxy.NumEventLoops < 0 {
		return WebProxyRuntimeConfig{}, errors.New("web-proxy.num-event-loops cannot be negative")
	}
	carrier, err := webproxy.ParseCarrierMode(c.WebProxy.Carrier)
	if err != nil {
		return WebProxyRuntimeConfig{}, fmt.Errorf("invalid web-proxy.carrier: %w", err)
	}

	bindAddr := c.WebProxy.BindTo
	if bindAddr == "" {
		bindAddr = "127.0.0.1:8080"
	}
	if strings.HasPrefix(bindAddr, "unix://") || strings.HasPrefix(bindAddr, "/") {
		return WebProxyRuntimeConfig{}, errors.New("web-proxy.bind-to must be a TCP address; Unix sockets cannot authenticate the Nginx peer")
	}
	backend := c.WebProxy.Backend
	if backend == "" {
		var err error
		backend, err = deriveLocalWebBackend(mtProxyBind)
		if err != nil {
			return WebProxyRuntimeConfig{}, fmt.Errorf("web-proxy.backend is required: %w", err)
		}
	}

	profiles := make([]webproxy.Profile, 0, len(c.Secrets)*2)
	capabilities := make(map[webproxy.Capability]struct{}, len(c.Secrets)*2)
	for _, name := range slices.Sorted(maps.Keys(c.Secrets)) {
		keyHex := c.Secrets[name]
		key, err := ParseKey(keyHex)
		if err != nil {
			return WebProxyRuntimeConfig{}, fmt.Errorf("invalid secret %q for WEB proxy: %w", name, err)
		}
		derived, err := webproxy.DeriveProfiles(name, hostname, key)
		if err != nil {
			return WebProxyRuntimeConfig{}, fmt.Errorf("derive WEB profiles for secret %q: %w", name, err)
		}
		for _, profile := range derived {
			if _, duplicate := capabilities[profile.Capability()]; duplicate {
				continue
			}
			capabilities[profile.Capability()] = struct{}{}
			profiles = append(profiles, profile)
		}
	}

	return WebProxyRuntimeConfig{
		Enabled:              true,
		BindAddr:             bindAddr,
		Hostname:             hostname,
		Backend:              backend,
		Carrier:              carrier,
		TrustedProxyCIDRs:    append([]string(nil), c.WebProxy.TrustedProxyCIDRs...),
		NumEventLoops:        c.WebProxy.NumEventLoops,
		Profiles:             profiles,
		BackendProxyProtocol: true,
	}, nil
}

func deriveLocalWebBackend(bindAddr string) (string, error) {
	address := strings.TrimPrefix(bindAddr, "tcp://")
	if strings.HasPrefix(address, "unix://") || strings.HasPrefix(address, "/") {
		path := strings.TrimPrefix(address, "unix://")
		if !strings.HasPrefix(path, "/") || path == "/" {
			return "", fmt.Errorf("invalid MTProxy Unix-socket bind %q", bindAddr)
		}
		return "unix://" + path, nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("cannot derive a TCP port from MTProxy bind %q", bindAddr)
	}
	switch host {
	case "", "0.0.0.0", "127.0.0.1":
		return net.JoinHostPort("127.0.0.1", port), nil
	case "::", "::1":
		return net.JoinHostPort("::1", port), nil
	default:
		ip := net.ParseIP(host)
		if ip != nil && ip.IsLoopback() {
			return net.JoinHostPort(host, port), nil
		}
		return "", fmt.Errorf("MTProxy bind %q is not wildcard or loopback", bindAddr)
	}
}

func (c *Config) webProxyFingerprint() string {
	if !c.WebProxy.Enabled {
		return "enabled=false"
	}
	trusted := strings.Join(c.WebProxy.TrustedProxyCIDRs, ",")
	return fmt.Sprintf(
		"enabled=%t\x00bind=%s\x00hostname=%s\x00backend=%s\x00carrier=%s\x00trusted=%s\x00loops=%d",
		c.WebProxy.Enabled,
		c.WebProxy.BindTo,
		c.WebProxy.Hostname,
		c.WebProxy.Backend,
		c.WebProxy.Carrier,
		trusted,
		c.WebProxy.NumEventLoops,
	)
}

// ParseKey parses a 16-byte hex-encoded key (32 hex chars).
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)

	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}

	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes (32 hex chars), got %d", len(key))
	}

	return key, nil
}

// BuildFullSecret builds the full secret string: ee + key + hex(host)
func BuildFullSecret(key []byte, host string) string {
	// [0xee][16 bytes key][hostname bytes]
	full := make([]byte, 1+16+len(host))
	full[0] = 0xee
	copy(full[1:17], key)
	copy(full[17:], host)
	return hex.EncodeToString(full)
}

// BuildDDSecret builds the dd secret string: dd + key (no hostname)
func BuildDDSecret(key []byte) string {
	// [0xdd][16 bytes key]
	full := make([]byte, 1+16)
	full[0] = 0xdd
	copy(full[1:17], key)
	return hex.EncodeToString(full)
}

// GenerateKey generates a new random 16-byte key (returned as 32 hex chars).
func GenerateKey() (string, error) {
	key := make([]byte, 16)
	if _, err := cryptoRand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
