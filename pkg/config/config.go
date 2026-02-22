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

	"github.com/example/telego/pkg/dc"
	"github.com/example/telego/pkg/proxy"
)

// Config is the TOML configuration structure.
type Config struct {
	Secret string `toml:"secret"`
	BindTo string `toml:"bind-to"`

	MiddleEnd   MiddleEndConfig   `toml:"middle-end"`
	TLSFronting TLSFrontingConfig `toml:"tls-fronting"`
	Performance PerformanceConfig `toml:"performance"`
}

// MiddleEndConfig configures Middle-End support.
type MiddleEndConfig struct {
	Enabled           bool     `toml:"enabled"`
	PoolSize          int      `toml:"pool-size"`
	WarmStandby       int      `toml:"warm-standby"`
	KeepaliveInterval Duration `toml:"keepalive-interval"`
	FallbackToDirect  bool     `toml:"fallback-to-direct"`
	Servers           []string `toml:"servers"`
}

// TLSFrontingConfig configures TLS fronting.
type TLSFrontingConfig struct {
	MaskHost           string `toml:"mask-host"`
	MaskPort           int    `toml:"mask-port"`
	FetchRealCert      bool   `toml:"fetch-real-cert"`
	SpliceUnrecognized bool   `toml:"splice-unrecognized"`
	CertRefreshHours   int    `toml:"cert-refresh-hours"`
}

// PerformanceConfig configures performance settings.
type PerformanceConfig struct {
	TCPBufferKB int      `toml:"tcp-buffer-kb"`
	Concurrency int      `toml:"concurrency"`
	PreferIP    string   `toml:"prefer-ip"`
	IdleTimeout Duration `toml:"idle-timeout"`
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

// ToProxyConfig converts to proxy.Config.
func (c *Config) ToProxyConfig() (proxy.Config, error) {
	secret, host, err := ParseSecret(c.Secret)
	if err != nil {
		return proxy.Config{}, err
	}

	cfg := proxy.DefaultConfig()
	cfg.Secret = secret
	cfg.Host = host
	cfg.BindAddr = c.BindTo

	// Middle-End
	cfg.MEEnabled = c.MiddleEnd.Enabled
	cfg.MEPoolSize = c.MiddleEnd.PoolSize
	cfg.MEServers = c.MiddleEnd.Servers
	cfg.MEFallback = c.MiddleEnd.FallbackToDirect

	if cfg.MEPoolSize == 0 {
		cfg.MEPoolSize = 16
	}
	if len(cfg.MEServers) == 0 {
		cfg.MEServers = dc.DefaultMEServers
	}

	// TLS Fronting
	cfg.MaskHost = c.TLSFronting.MaskHost
	cfg.MaskPort = c.TLSFronting.MaskPort
	cfg.FetchRealCert = c.TLSFronting.FetchRealCert
	cfg.SpliceUnrecognized = c.TLSFronting.SpliceUnrecognized
	cfg.CertRefreshHours = c.TLSFronting.CertRefreshHours

	if cfg.MaskPort == 0 {
		cfg.MaskPort = 443
	}
	if cfg.CertRefreshHours == 0 {
		cfg.CertRefreshHours = 5
	}

	// Performance
	cfg.Concurrency = c.Performance.Concurrency
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 8192
	}

	cfg.IdleTimeout = c.Performance.IdleTimeout.Duration()
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}

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

// ParseSecret parses a hex-encoded secret string.
// The secret must start with 'ee' (FakeTLS prefix).
func ParseSecret(s string) ([]byte, string, error) {
	s = strings.TrimSpace(s)

	// Try hex decode
	secret, err := hex.DecodeString(s)
	if err != nil {
		return nil, "", fmt.Errorf("invalid secret format: %w", err)
	}

	// Must start with 0xee
	if len(secret) == 0 || secret[0] != 0xee {
		return nil, "", errors.New("secret must start with 'ee' (FakeTLS)")
	}

	// Extract key and hostname
	if len(secret) < 17 {
		return nil, "", errors.New("secret too short")
	}

	key := secret[1:17]         // 16 bytes
	host := string(secret[17:]) // Rest is hostname

	return key, host, nil
}

// GenerateSecret generates a new secret with the given hostname.
func GenerateSecret(host string) (string, error) {
	if host == "" {
		return "", errors.New("hostname required")
	}

	// [0xee][16 random bytes][hostname]
	secret := make([]byte, 1+16+len(host))
	secret[0] = 0xee

	// Random key
	if _, err := cryptoRand.Read(secret[1:17]); err != nil {
		return "", err
	}

	// Hostname
	copy(secret[17:], host)

	return hex.EncodeToString(secret), nil
}
