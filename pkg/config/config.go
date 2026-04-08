// Package config handles TOML configuration parsing.
package config

import (
	cryptoRand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/scratch-net/telego/pkg/dc"
	"github.com/scratch-net/telego/pkg/gproxy"
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

	// Splice target - where to forward unrecognized clients
	// Defaults to mask-host:mask-port if not set
	SpliceHost          string   `toml:"splice-host"`
	SplicePort          int      `toml:"splice-port"`
	SpliceProxyProtocol int      `toml:"splice-proxy-protocol"` // 0=off, 1=v1, 2=v2
	SpliceIdleTimeout   Duration `toml:"splice-idle-timeout"`   // Idle timeout for splice connections (default 30s)
}

// PerformanceConfig configures performance settings.
type PerformanceConfig struct {
	TCPBufferKB      int      `toml:"tcp-buffer-kb"`
	NumEventLoops    int      `toml:"num-event-loops"` // gnet event loops (0 = auto, uses all cores)
	PreferIP         string   `toml:"prefer-ip"`
	IdleTimeout      Duration `toml:"idle-timeout"`
	MaxWriteBufferMB int      `toml:"max-write-buffer-mb"` // Max pending bytes per connection (0 = 4MB)
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

	for name, keyHex := range c.Secrets {
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

	// Performance
	cfg.IdleTimeout = c.Performance.IdleTimeout.Duration()
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
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
	cfg.IPBlockTimeout = c.General.IPBlockTimeout.Duration()
	if cfg.IPBlockTimeout == 0 {
		cfg.IPBlockTimeout = 5 * time.Minute
	}

	// Backpressure settings
	if c.Performance.MaxWriteBufferMB > 0 {
		cfg.MaxWriteBuffer = c.Performance.MaxWriteBufferMB * 1024 * 1024
	}

	return cfg, nil
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
