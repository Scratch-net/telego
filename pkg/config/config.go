// Package config handles TOML configuration parsing.
package config

import (
	"bytes"
	"cmp"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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
	MaxConnections      int      `toml:"max-connections"`        // Max concurrent client connections, 0 = derive from RLIMIT_NOFILE
	TrustedProxyCIDRs   []string `toml:"trusted-proxy-cidrs"`    // TCP peers allowed to send PROXY headers, empty = any
	MaxIPsPerUser       int      `toml:"max-ips-per-user"`       // Max unique IPs per user, 0 = unlimited
	IPBlockTimeout      Duration `toml:"ip-block-timeout"`       // How long blocked IPs stay blocked
	HandshakeTimeout    Duration `toml:"handshake-timeout"`      // Max time for handshake (default 5s)
	ClockSyncURL        string   `toml:"clock-sync-url"`         // HTTPS URL whose Date header corrects a skewed server clock at startup
	// DisabledSecrets names [secrets] entries that cannot connect. A config
	// reload closes their live sessions.
	DisabledSecrets []string `toml:"disabled-secrets"`
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
	FakeCertSize           int `toml:"fake-cert-size"`
	ServerHelloSegmentSize int `toml:"server-hello-segment-size"`
	// ServerHelloPaceScope selects what server-hello-segment-size paces:
	// "response" (default) or "first-record".
	ServerHelloPaceScope string `toml:"server-hello-pace-scope"`

	// ProfileCacheDir keeps the last good mask ServerHello profile on disk.
	// Empty = off. Must be an absolute path.
	ProfileCacheDir string `toml:"profile-cache-dir"`

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

	// Domains adds cover domains besides mask-host. Each domain serves the
	// secrets it lists; all other secrets keep mask-host.
	Domains []TLSDomainConfig `toml:"domains"`
}

// TLSDomainConfig is one extra cover domain ([[tls-fronting.domains]]).
// Unset hosts default to host and unset ports to 443, so each domain gets
// its own ServerHello template, certificate and splice target.
type TLSDomainConfig struct {
	Host                string   `toml:"host"`    // SNI of the listed secrets
	Secrets             []string `toml:"secrets"` // Names from [secrets]
	CertHost            string   `toml:"cert-host"`
	CertPort            int      `toml:"cert-port"`
	SpliceHost          string   `toml:"splice-host"`
	SplicePort          int      `toml:"splice-port"`
	SpliceProxyProtocol int      `toml:"splice-proxy-protocol"` // 0=off, 1=v1, 2=v2
	FakeCertSize        int      `toml:"fake-cert-size"`        // 0 = match this domain
}

// PerformanceConfig configures performance settings.
type PerformanceConfig struct {
	TCPBufferKB      int      `toml:"tcp-buffer-kb"`   // Legacy compatibility field; validated but has no effect.
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
	BindTo      string `toml:"bind-to"`     // Address to bind metrics server (empty = disabled)
	Path        string `toml:"path"`        // Metrics path (default: /metrics)
	Diagnostics bool   `toml:"diagnostics"` // Private on-demand runtime profiles (default: disabled)
}

// Validate rejects diagnostics that can bind beyond a literal loopback address.
func (c MetricsConfig) Validate() error {
	if !c.Diagnostics {
		return nil
	}
	address, err := netip.ParseAddrPort(c.BindTo)
	if err != nil || address.Port() == 0 || address.Addr().Zone() != "" || !address.Addr().Unmap().IsLoopback() {
		return errors.New("metrics diagnostics require a literal loopback IP and a port from 1 to 65535")
	}
	if strings.HasPrefix(c.Path, "/debug/pprof") {
		return errors.New("metrics path conflicts with the reserved diagnostics paths")
	}
	if c.Path != "" && (!strings.HasPrefix(c.Path, "/") || strings.ContainsAny(c.Path, " %{}\t\r\n")) {
		return errors.New("metrics path must be an absolute HTTP path without patterns or escapes")
	}
	return nil
}

// WebProxyConfig configures the optional private WEB carrier listener. Nginx
// terminates public TLS and forwards candidate requests to this listener.
type WebProxyConfig struct {
	Enabled           bool     `toml:"enabled"`
	BindTo            string   `toml:"bind-to"`
	Hostname          string   `toml:"hostname"`
	BasePath          string   `toml:"base-path"`
	Backend           string   `toml:"backend"`
	Carrier           string   `toml:"carrier"`
	TrustedProxyCIDRs []string `toml:"trusted-proxy-cidrs"`
	NumEventLoops     int      `toml:"num-event-loops"`
	// CarrierBatchKiB bounds each carrier body and downlink DATA frame.
	// Zero keeps the 2048 KiB protocol default.
	CarrierBatchKiB int `toml:"carrier-batch-kib"`
	// StreamDownload keeps one https downlink response open per batch.
	// Unset = on for the https carrier and off for the other carriers.
	// An explicit true requires the https carrier.
	StreamDownload *bool `toml:"stream-download"`
	// WebSocketFairQueue schedules websocket downlink fairly across streams.
	// Unset = on for the websocket carrier and off for the other carriers.
	// An explicit true requires the websocket carrier.
	WebSocketFairQueue *bool `toml:"websocket-fair-queue"`
	// PadFirstFrames pads the first carrier batches in both directions.
	PadFirstFrames bool `toml:"pad-first-frames"`
}

// MiddleEndConfig configures Telegram's official Middle-End transport, which
// Load enables by default unless the configuration explicitly disables it. Queue,
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
	BasePath             string
	Backend              string
	LogicalBackend       bool
	MTProxyAddr          net.Addr
	Carrier              webproxy.CarrierMode
	TrustedProxyCIDRs    []string
	NumEventLoops        int
	Profiles             []webproxy.Profile
	BackendProxyProtocol bool
	// CarrierBatchBytes is zero when the protocol default applies.
	CarrierBatchBytes  int
	StreamDownload     bool
	WebSocketFairQueue bool
	PadFirstFrames     bool
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

	cfg := Config{MiddleEnd: MiddleEndConfig{Enabled: true}}
	if err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&cfg); err != nil {
		if missing, ok := errors.AsType[*toml.StrictMissingError](err); ok {
			fields := make([]string, len(missing.Errors))
			for i, field := range missing.Errors {
				fields[i] = fmt.Sprintf("%q", strings.Join(field.Key(), "."))
			}
			// StrictMissingError.String includes TOML values, which can contain
			// credentials. Report only the offending field names.
			return nil, fmt.Errorf("failed to parse config: unknown fields %s: %w", strings.Join(fields, ", "), err)
		}
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := cfg.validateScalars(); err != nil {
		return nil, err
	}
	if err := cfg.validateDomains(); err != nil {
		return nil, err
	}
	if err := cfg.Metrics.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validateScalars preserves zero defaults and unlimited settings while rejecting
// values that would disable limits or fail later in runtime initialization.
func (c *Config) validateScalars() error {
	if size := c.TLSFronting.ServerHelloSegmentSize; size != 0 && (size < 64 || size > 1460) {
		return errors.New("tls-fronting.server-hello-segment-size must be 0 or between 64 and 1460 bytes")
	}
	switch c.TLSFronting.ServerHelloPaceScope {
	case "", "response", "first-record":
	default:
		return errors.New(`tls-fronting.server-hello-pace-scope must be "response" or "first-record"`)
	}
	for _, field := range []struct {
		name  string
		value int64
	}{
		{"general.max-connections-per-ip", int64(c.General.MaxConnectionsPerIP)},
		{"general.max-ips-per-user", int64(c.General.MaxIPsPerUser)},
		{"general.ip-block-timeout", int64(c.General.IPBlockTimeout)},
		{"general.handshake-timeout", int64(c.General.HandshakeTimeout)},
		{"tls-fronting.fake-cert-size", int64(c.TLSFronting.FakeCertSize)},
		{"tls-fronting.splice-idle-timeout", int64(c.TLSFronting.SpliceIdleTimeout)},
		{"performance.tcp-buffer-kb", int64(c.Performance.TCPBufferKB)},
		{"performance.num-event-loops", int64(c.Performance.NumEventLoops)},
		{"performance.idle-timeout", int64(c.Performance.IdleTimeout)},
		{"performance.max-write-buffer-mb", int64(c.Performance.MaxWriteBufferMB)},
		{"performance.client-silence-close", int64(c.Performance.ClientSilenceClose)},
	} {
		if field.value < 0 {
			return fmt.Errorf("%s cannot be negative", field.name)
		}
	}
	for _, field := range []struct {
		name  string
		value int
	}{
		{"tls-fronting.mask-port", c.TLSFronting.MaskPort},
		{"tls-fronting.cert-port", c.TLSFronting.CertPort},
		{"tls-fronting.splice-port", c.TLSFronting.SplicePort},
	} {
		if field.value < 0 || field.value > 65535 {
			return fmt.Errorf("%s must be between 0 and 65535 (0 uses the default)", field.name)
		}
	}
	if dir := c.TLSFronting.ProfileCacheDir; dir != "" && !filepath.IsAbs(dir) {
		return errors.New("tls-fronting.profile-cache-dir must be an absolute path")
	}
	if c.TLSFronting.SpliceProxyProtocol < 0 || c.TLSFronting.SpliceProxyProtocol > 2 {
		return errors.New("tls-fronting.splice-proxy-protocol must be 0, 1, or 2")
	}
	// A pre-auth connection holds a descriptor until the handshake timeout.
	if t := c.General.HandshakeTimeout.Duration(); t != 0 && (t < time.Second || t > time.Minute) {
		return errors.New("general.handshake-timeout must be 0 (default 5s) or between 1s and 1m")
	}
	// The silence check runs once per second; shorter values close healthy relays.
	if t := c.Performance.ClientSilenceClose.Duration(); t != 0 && t < time.Second {
		return errors.New("performance.client-silence-close must be 0 (off) or at least 1s")
	}
	// 1024 MiB per connection also fits in a 32-bit int.
	if c.Performance.MaxWriteBufferMB > 1024 {
		return errors.New("performance.max-write-buffer-mb must be at most 1024 (0 uses the default 4)")
	}
	// Disabled optional sections have always ignored dormant settings.
	if c.WebProxy.Enabled && c.WebProxy.NumEventLoops < 0 {
		return errors.New("web-proxy.num-event-loops cannot be negative")
	}
	if c.WebProxy.Enabled {
		if err := validateCarrierBatchKiB(c.WebProxy.CarrierBatchKiB); err != nil {
			return err
		}
	}
	if c.General.MaxConnections < 0 {
		return errors.New("general.max-connections cannot be negative")
	}
	if c.MiddleEnd.Enabled {
		if c.MiddleEnd.MaxConnections < 0 {
			return errors.New("middle-end.max-connections cannot be negative")
		}
		if c.MiddleEnd.QueueBudgetMB < 0 {
			return errors.New("middle-end.queue-budget-mb cannot be negative")
		}
	}
	return nil
}

// validateDomains checks [[tls-fronting.domains]]. Every secret belongs to
// at most one domain, so its ee link and its SNI stay unique.
func (c *Config) validateDomains() error {
	hosts := map[string]bool{strings.ToLower(c.TLSFronting.MaskHost): true}
	owner := make(map[string]string)
	for i, domain := range c.TLSFronting.Domains {
		name := fmt.Sprintf("tls-fronting.domains[%d]", i)
		if !validDomainHost(domain.Host) {
			return fmt.Errorf("%s.host must be a DNS hostname", name)
		}
		if hosts[strings.ToLower(domain.Host)] {
			return fmt.Errorf("%s.host %q repeats mask-host or another domain", name, domain.Host)
		}
		hosts[strings.ToLower(domain.Host)] = true
		for _, port := range []struct {
			option string
			value  int
		}{{"cert-port", domain.CertPort}, {"splice-port", domain.SplicePort}} {
			if port.value < 0 || port.value > 65535 {
				return fmt.Errorf("%s.%s must be between 0 and 65535 (0 uses 443)", name, port.option)
			}
		}
		if domain.SpliceProxyProtocol < 0 || domain.SpliceProxyProtocol > 2 {
			return fmt.Errorf("%s.splice-proxy-protocol must be 0, 1, or 2", name)
		}
		if domain.FakeCertSize < 0 {
			return fmt.Errorf("%s.fake-cert-size cannot be negative", name)
		}
		if len(domain.Secrets) == 0 {
			return fmt.Errorf("%s.secrets must name at least one secret", name)
		}
		for _, secret := range domain.Secrets {
			if _, ok := c.Secrets[secret]; !ok {
				return fmt.Errorf("%s.secrets names unknown secret %q", name, secret)
			}
			if previous, ok := owner[secret]; ok {
				return fmt.Errorf("secret %q is listed for both %q and %q", secret, previous, domain.Host)
			}
			owner[secret] = domain.Host
		}
	}
	return nil
}

// validDomainHost accepts a DNS hostname: letters, digits, hyphens and dots,
// at most 253 bytes, with no empty label.
func validDomainHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		if strings.IndexFunc(label, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-'
		}) >= 0 {
			return false
		}
	}
	return true
}

// ToGProxyConfig converts to gproxy.Config.
func (c *Config) ToGProxyConfig() (gproxy.Config, error) {
	if err := c.validateScalars(); err != nil {
		return gproxy.Config{}, err
	}
	if err := c.validateDomains(); err != nil {
		return gproxy.Config{}, err
	}
	if err := c.Metrics.Validate(); err != nil {
		return gproxy.Config{}, err
	}
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

	secretHosts := make(map[string]string)
	for _, domain := range c.TLSFronting.Domains {
		for _, name := range domain.Secrets {
			secretHosts[name] = domain.Host
		}
	}
	disabled, err := c.disabledSecrets()
	if err != nil {
		return gproxy.Config{}, err
	}
	for _, name := range slices.Sorted(maps.Keys(c.Secrets)) {
		keyHex := c.Secrets[name]
		key, err := ParseKey(keyHex)
		if err != nil {
			return gproxy.Config{}, fmt.Errorf("invalid secret %q: %w", name, err)
		}
		if _, off := disabled[name]; off {
			continue
		}
		secretHost := host
		if domainHost, ok := secretHosts[name]; ok {
			secretHost = domainHost
		}
		cfg.Secrets = append(cfg.Secrets, gproxy.Secret{
			Name:   name,
			Key:    key,
			Host:   secretHost,
			RawHex: BuildFullSecret(key, secretHost),
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
	cfg.ServerHelloSegmentSize = c.TLSFronting.ServerHelloSegmentSize
	cfg.ServerHelloPaceFirstRecord = c.TLSFronting.ServerHelloPaceScope == "first-record"
	cfg.MaskSNISafelist = c.TLSFronting.MaskSNISafelist
	cfg.ProfileCacheDir = c.TLSFronting.ProfileCacheDir

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
	for _, domain := range c.TLSFronting.Domains {
		cfg.Domains = append(cfg.Domains, domain.toGProxy())
	}

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
	for _, value := range c.General.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value {
			return gproxy.Config{}, fmt.Errorf("general.trusted-proxy-cidrs contains noncanonical CIDR %q", value)
		}
		cfg.TrustedProxyPrefixes = append(cfg.TrustedProxyPrefixes, prefix)
	}
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

	// Explicit local WEB backends carry the process-local authentication
	// preface. Logical streams supply trusted metadata directly to the core.
	cfg.InternalProxyProtocol = c.WebProxy.Enabled && c.WebProxy.Backend != ""
	cfg.WebProxyFingerprint = c.webProxyFingerprint()
	cfg.MiddleEndFingerprint = c.middleEndFingerprint()
	// The global cap applies in every mode; Middle-End can only lower it.
	cfg.MaxConnections = generalMaxConnections(c.General.MaxConnections)
	if c.MiddleEnd.Enabled {
		middleEndMax := middleEndMaxConnections(c.MiddleEnd.MaxConnections)
		if cfg.MaxConnections == 0 || middleEndMax < cfg.MaxConnections {
			cfg.MaxConnections = middleEndMax
		}
	}

	return cfg, nil
}

// toGProxy resolves the defaults of one cover domain.
func (d TLSDomainConfig) toGProxy() gproxy.TLSDomain {
	return gproxy.TLSDomain{
		Host:                d.Host,
		CertHost:            cmp.Or(d.CertHost, d.Host),
		CertPort:            cmp.Or(d.CertPort, 443),
		SpliceHost:          cmp.Or(d.SpliceHost, d.Host),
		SplicePort:          cmp.Or(d.SplicePort, 443),
		SpliceProxyProtocol: d.SpliceProxyProtocol,
		FakeCertSize:        d.FakeCertSize,
	}
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
	if err := webproxy.ValidateBasePath(c.WebProxy.BasePath); err != nil {
		return WebProxyRuntimeConfig{}, fmt.Errorf("invalid web-proxy.base-path: %w", err)
	}
	if c.WebProxy.NumEventLoops < 0 {
		return WebProxyRuntimeConfig{}, errors.New("web-proxy.num-event-loops cannot be negative")
	}
	carrier, err := webproxy.ParseCarrierMode(c.WebProxy.Carrier)
	if err != nil {
		return WebProxyRuntimeConfig{}, fmt.Errorf("invalid web-proxy.carrier: %w", err)
	}
	if err := validateCarrierBatchKiB(c.WebProxy.CarrierBatchKiB); err != nil {
		return WebProxyRuntimeConfig{}, err
	}
	if explicitlyOn(c.WebProxy.StreamDownload) && carrier != webproxy.CarrierHTTPS {
		return WebProxyRuntimeConfig{}, errors.New("web-proxy.stream-download requires carrier \"https\"")
	}
	if explicitlyOn(c.WebProxy.WebSocketFairQueue) && carrier != webproxy.CarrierWebSocket {
		return WebProxyRuntimeConfig{}, errors.New("web-proxy.websocket-fair-queue requires carrier \"websocket\"")
	}
	if c.WebProxy.PadFirstFrames && carrier != webproxy.CarrierHTTPS && carrier != webproxy.CarrierWebSocket {
		return WebProxyRuntimeConfig{}, errors.New("web-proxy.pad-first-frames requires carrier \"https\" or \"websocket\"")
	}

	bindAddr := c.WebProxy.BindTo
	if bindAddr == "" {
		bindAddr = "127.0.0.1:8080"
	}
	if strings.HasPrefix(bindAddr, "unix://") || strings.HasPrefix(bindAddr, "/") {
		return WebProxyRuntimeConfig{}, errors.New("web-proxy.bind-to must be a TCP address; Unix sockets cannot authenticate the Nginx peer")
	}
	if strings.Contains(bindAddr, "://") && !strings.HasPrefix(bindAddr, "tcp://") {
		return WebProxyRuntimeConfig{}, errors.New("web-proxy.bind-to must use TCP")
	}
	if _, _, err := net.SplitHostPort(strings.TrimPrefix(bindAddr, "tcp://")); err != nil {
		return WebProxyRuntimeConfig{}, fmt.Errorf("invalid web-proxy.bind-to: %w", err)
	}
	for _, value := range c.WebProxy.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value {
			return WebProxyRuntimeConfig{}, fmt.Errorf("web-proxy.trusted-proxy-cidrs contains noncanonical CIDR %q", value)
		}
	}
	backend := c.WebProxy.Backend
	logicalBackend := backend == ""
	var listenerAddr net.Addr
	if logicalBackend {
		listenerAddr, err = webProxyListenerAddr(mtProxyBind)
		if err != nil {
			return WebProxyRuntimeConfig{}, fmt.Errorf("invalid MTProxy listener for logical WEB streams: %w", err)
		}
	} else if err := webproxy.ValidateLocalBackend(backend); err != nil {
		return WebProxyRuntimeConfig{}, fmt.Errorf("invalid web-proxy.backend: %w", err)
	}

	disabled, err := c.disabledSecrets()
	if err != nil {
		return WebProxyRuntimeConfig{}, err
	}
	profiles := make([]webproxy.Profile, 0, len(c.Secrets)*2)
	capabilities := make(map[webproxy.Capability]struct{}, len(c.Secrets)*2)
	for _, name := range slices.Sorted(maps.Keys(c.Secrets)) {
		if _, off := disabled[name]; off {
			continue
		}
		keyHex := c.Secrets[name]
		key, err := ParseKey(keyHex)
		if err != nil {
			return WebProxyRuntimeConfig{}, fmt.Errorf("invalid secret %q for WEB proxy: %w", name, err)
		}
		derived, err := webproxy.DeriveProfilesForPath(name, hostname, c.WebProxy.BasePath, key)
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
	if len(profiles) == 0 {
		return WebProxyRuntimeConfig{}, errors.New("WEB proxy requires at least one enabled secret")
	}

	return WebProxyRuntimeConfig{
		Enabled:              true,
		BindAddr:             bindAddr,
		Hostname:             hostname,
		BasePath:             c.WebProxy.BasePath,
		Backend:              backend,
		LogicalBackend:       logicalBackend,
		MTProxyAddr:          listenerAddr,
		Carrier:              carrier,
		TrustedProxyCIDRs:    slices.Clone(c.WebProxy.TrustedProxyCIDRs),
		NumEventLoops:        c.WebProxy.NumEventLoops,
		Profiles:             profiles,
		BackendProxyProtocol: !logicalBackend,
		CarrierBatchBytes:    c.WebProxy.CarrierBatchKiB * 1024,
		StreamDownload:       c.WebProxy.streamDownload(carrier),
		WebSocketFairQueue:   c.WebProxy.webSocketFairQueue(carrier),
		PadFirstFrames:       c.WebProxy.PadFirstFrames,
	}, nil
}

// The lower bound keeps every frame header and a useful payload in one body.
// The upper bound is the 2 MiB WEB protocol cap that the bridge also enforces.
const (
	minCarrierBatchKiB = 4
	maxCarrierBatchKiB = 2048
)

func validateCarrierBatchKiB(value int) error {
	if value != 0 && (value < minCarrierBatchKiB || value > maxCarrierBatchKiB) {
		return fmt.Errorf("web-proxy.carrier-batch-kib must be 0 (default %d) or %d through %d",
			maxCarrierBatchKiB, minCarrierBatchKiB, maxCarrierBatchKiB)
	}
	return nil
}

func webProxyListenerAddr(bindAddr string) (net.Addr, error) {
	address := strings.TrimPrefix(bindAddr, "tcp://")
	if strings.HasPrefix(address, "unix://") || strings.HasPrefix(address, "/") {
		path := strings.TrimPrefix(address, "unix://")
		if !strings.HasPrefix(path, "/") || path == "/" {
			return nil, fmt.Errorf("invalid MTProxy Unix-socket bind %q", bindAddr)
		}
		return &net.UnixAddr{Name: path, Net: "unix"}, nil
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	if len(tcpAddr.IP) == 0 {
		// gnet's tcp wildcard listener selects AF_INET6 and maps an empty IP
		// to IPv6 unspecified. Keep the configured port, including zero.
		tcpAddr.IP = net.IPv6zero
	}
	return tcpAddr, nil
}

// explicitlyOn reports whether an optional bool is set to true in the file.
func explicitlyOn(value *bool) bool {
	return value != nil && *value
}

// streamDownload is on by default for the https carrier only. The default
// silently does not apply to other carriers.
func (w WebProxyConfig) streamDownload(carrier webproxy.CarrierMode) bool {
	return carrier == webproxy.CarrierHTTPS && (w.StreamDownload == nil || *w.StreamDownload)
}

// webSocketFairQueue is on by default for the websocket carrier only. The
// default silently does not apply to other carriers.
func (w WebProxyConfig) webSocketFairQueue(carrier webproxy.CarrierMode) bool {
	return carrier == webproxy.CarrierWebSocket && (w.WebSocketFairQueue == nil || *w.WebSocketFairQueue)
}

func (c *Config) webProxyFingerprint() string {
	if !c.WebProxy.Enabled {
		return "enabled=false"
	}
	// The fingerprint holds the effective value, so writing the default
	// explicitly does not ask for a restart. An invalid carrier fails startup
	// and hot reload validation anyway.
	carrier, _ := webproxy.ParseCarrierMode(c.WebProxy.Carrier)
	trusted := strings.Join(c.WebProxy.TrustedProxyCIDRs, ",")
	return fmt.Sprintf(
		"enabled=%t\x00bind=%s\x00hostname=%s\x00base-path=%s\x00backend=%s\x00carrier=%s\x00trusted=%s\x00loops=%d\x00batch=%d\x00stream=%t\x00fair=%t\x00pad=%t",
		c.WebProxy.Enabled,
		c.WebProxy.BindTo,
		c.WebProxy.Hostname,
		c.WebProxy.BasePath,
		c.WebProxy.Backend,
		c.WebProxy.Carrier,
		trusted,
		c.WebProxy.NumEventLoops,
		c.WebProxy.CarrierBatchKiB,
		c.WebProxy.streamDownload(carrier),
		c.WebProxy.webSocketFairQueue(carrier),
		c.WebProxy.PadFirstFrames,
	)
}

// disabledSecrets returns the names in general.disabled-secrets. Each name
// must be a [secrets] entry, so a typo cannot leave a user enabled.
func (c *Config) disabledSecrets() (map[string]struct{}, error) {
	disabled := make(map[string]struct{}, len(c.General.DisabledSecrets))
	for _, name := range c.General.DisabledSecrets {
		if _, ok := c.Secrets[name]; !ok {
			return nil, fmt.Errorf("general.disabled-secrets names unknown secret %q", name)
		}
		disabled[name] = struct{}{}
	}
	return disabled, nil
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
