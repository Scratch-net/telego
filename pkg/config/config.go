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
	Secrets  map[string]string `toml:"secrets"` // name = "secret"
	BindTo   string            `toml:"bind-to"`
	LogLevel string            `toml:"log-level"` // trace, debug, info, warn, error

	TLSFronting TLSFrontingConfig `toml:"tls-fronting"`
	Performance PerformanceConfig `toml:"performance"`
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
	SpliceHost          string `toml:"splice-host"`
	SplicePort          int    `toml:"splice-port"`
	SpliceProxyProtocol int    `toml:"splice-proxy-protocol"` // 0=off, 1=v1, 2=v2
}

// PerformanceConfig configures performance settings.
type PerformanceConfig struct {
	TCPBufferKB   int      `toml:"tcp-buffer-kb"`
	NumEventLoops int      `toml:"num-event-loops"` // gnet event loops (0 = auto, uses all cores)
	PreferIP      string   `toml:"prefer-ip"`
	IdleTimeout   Duration `toml:"idle-timeout"`
	PprofAddr     string   `toml:"pprof-addr"` // pprof HTTP server address (e.g., "localhost:6060")
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
	cfg.BindAddr = c.BindTo

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

	// Performance
	cfg.IdleTimeout = c.Performance.IdleTimeout.Duration()
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	cfg.NumEventLoop = c.Performance.NumEventLoops

	cfg.PprofAddr = c.Performance.PprofAddr

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

// GenerateKey generates a new random 16-byte key (returned as 32 hex chars).
func GenerateKey() (string, error) {
	key := make([]byte, 16)
	if _, err := cryptoRand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}
