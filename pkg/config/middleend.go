package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/transport/middleend"
)

const (
	// Telegram's official frontend keeps four to eight Middle-End connections
	// per target. Four links per signed DC are the minimum protected pool.
	middleEndLinksPerDC = 4
	// Telemt's public default is 10,000 accepted connections. Telego permits a
	// lower expert value but does not let a config raise this initial ceiling.
	middleEndDefaultMaxConnections = 10_000
	// Telemt's writer command queue is 4,096 items.
	middleEndQueueItems = 4096
	// Applying telemt's documented 2*max-frame+256 formula, rounded to 16 KiB,
	// to telego's official-client-size-derived frame cap yields exactly 2 MiB.
	middleEndLinkQueueBytes = 2 << 20
	// Telemt's default writer byte budget is 32 MiB plus one 16 KiB permit.
	middleEndDefaultManagerQueueBytes = 32*1024*1024 + 16*1024
	middleEndMinimumQueueBudgetMB     = 2
	middleEndMaximumQueueBudgetMB     = 32
	// Telemt's route channel capacity is 768 items.
	middleEndPerBindingResponseItems = 768
	// Telemt's default reconnect fan-out is eight per DC.
	middleEndDialConcurrency = 8
)

var (
	middleEndArtifactRefreshTimeout = 15 * time.Second
	middleEndCoordinatorRetry       = 30 * time.Second
	middleEndPreparationTimeout     = 100 * time.Second
	middleEndProbeInterval          = 5 * time.Second
	middleEndProbeFailureTimeout    = 100 * time.Second
	middleEndDrainTimeout           = 90 * time.Second
	middleEndRepairBackoffInitial   = 500 * time.Millisecond
	middleEndRepairBackoffMaximum   = 30 * time.Second
	middleEndEndpointDialTimeout    = 3 * time.Second
	middleEndNATProbeTimeout        = 5 * time.Second
	middleEndNATCacheTTL            = 10 * time.Minute
	middleEndNATBackoffInitial      = time.Minute
	middleEndNATBackoffMaximum      = time.Hour
	middleEndOutputRetryInitial     = 25 * time.Millisecond
	middleEndOutputRetryMaximum     = 120 * time.Millisecond
	middleEndOutputStallTimeout     = 100 * time.Second
)

var middleEndNATSTUNServers = []string{
	"stun.l.google.com:5349",
	"stun1.l.google.com:3478",
	"stun.gmx.net:3478",
	"stun.l.google.com:19302",
	"stun.1und1.de:3478",
	"stun1.l.google.com:19302",
	"stun2.l.google.com:19302",
	"stun3.l.google.com:19302",
	"stun4.l.google.com:19302",
	"stun.services.mozilla.com:3478",
	"stun.stunprotocol.org:3478",
	"stun.nextcloud.com:3478",
	"stun.voip.eutelia.it:3478",
}

// MiddleEndRuntimeConfig owns the non-network resources needed to construct a
// complete ME service and frontend. It never exposes proxy credentials or the
// registered proxy tag through formatting.
type MiddleEndRuntimeConfig struct {
	Enabled        bool
	Service        middleend.ServiceConfig
	ProxyTag       *middleend.ProxyTag
	MaxConnections int

	artifactTransport *http.Transport
}

func (MiddleEndRuntimeConfig) String() string {
	return "config.MiddleEndRuntimeConfig{redacted}"
}

func (c MiddleEndRuntimeConfig) GoString() string { return c.String() }

// Frontend derives the fixed production frontend policy for an already-owned
// service source.
func (c MiddleEndRuntimeConfig) Frontend(source gproxy.MiddleEndBindingSource) gproxy.MiddleEndFrontendConfig {
	var tag *middleend.ProxyTag
	if c.ProxyTag != nil {
		tag = new(*c.ProxyTag)
	}
	return gproxy.MiddleEndFrontendConfig{
		Source:                     source,
		PrecommitFailure:           gproxy.MiddleEndPrecommitDirectFallback,
		ProxyTag:                   tag,
		MaxPendingClientBytes:      middleend.MaxMEFrameSize,
		MaxPendingClientBytesTotal: c.Service.BindingLimits.MaxPendingRequestBytes,
		MaxPendingOutputBytesTotal: c.Service.BindingLimits.MaxPendingResponseBytes,
		OutputRetryInitial:         middleEndOutputRetryInitial,
		OutputRetryMax:             middleEndOutputRetryMaximum,
		OutputStallTimeout:         middleEndOutputStallTimeout,
	}
}

// CloseIdleConnections releases artifact-fetch keepalive sockets after the ME
// service has stopped.
func (c MiddleEndRuntimeConfig) CloseIdleConnections() {
	if c.artifactTransport != nil {
		c.artifactTransport.CloseIdleConnections()
	}
}

// ToMiddleEndRuntimeConfig validates the optional ME section and derives every
// nested queue and lifecycle limit. Disabled configuration is ignored.
func (c *Config) ToMiddleEndRuntimeConfig() (MiddleEndRuntimeConfig, error) {
	if c == nil || !c.MiddleEnd.Enabled {
		return MiddleEndRuntimeConfig{}, nil
	}
	maxConnections := middleEndMaxConnections(c.MiddleEnd.MaxConnections)
	if maxConnections <= 0 || maxConnections > middleEndDefaultMaxConnections {
		return MiddleEndRuntimeConfig{}, fmt.Errorf(
			"middle-end.max-connections must be in [1,%d] or zero for the default",
			middleEndDefaultMaxConnections,
		)
	}
	managerQueueBytes, err := middleEndManagerQueueBytes(c.MiddleEnd.QueueBudgetMB)
	if err != nil {
		return MiddleEndRuntimeConfig{}, err
	}
	eventLoops := c.Performance.NumEventLoops
	if eventLoops == 0 {
		eventLoops = runtime.GOMAXPROCS(0)
	}
	if err := (middleend.GnetClientRuntimeConfig{EventLoops: eventLoops}).Validate(); err != nil {
		return MiddleEndRuntimeConfig{}, fmt.Errorf("middle-end gnet event loops: %w", err)
	}

	tag, err := parseMiddleEndProxyTag(c.MiddleEnd.ProxyTag)
	if err != nil {
		return MiddleEndRuntimeConfig{}, err
	}
	socks5, socksProxyURL, err := c.middleEndSOCKS5()
	if err != nil {
		return MiddleEndRuntimeConfig{}, err
	}
	natResolver, err := newMiddleEndNATResolver(c.MiddleEnd.NATIP)
	if err != nil {
		return MiddleEndRuntimeConfig{}, err
	}
	artifactProxy, err := parseMiddleEndArtifactProxy(c.MiddleEnd.ArtifactProxy, socksProxyURL)
	if err != nil {
		return MiddleEndRuntimeConfig{}, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if artifactProxy != nil {
		transport.Proxy = http.ProxyURL(artifactProxy)
	}
	artifactSource, err := middleend.NewHTTPArtifactSource(&http.Client{Transport: transport})
	if err != nil {
		transport.CloseIdleConnections()
		return MiddleEndRuntimeConfig{}, fmt.Errorf("initialize Middle-End artifact source: %w", err)
	}

	perSlotResidents := (maxConnections + middleEndLinksPerDC - 1) / middleEndLinksPerDC
	controlBytes := middleEndQueueItems * middleend.KeepalivePayloadSize
	serviceConfig := middleend.ServiceConfig{
		ArtifactSource:         artifactSource,
		ArtifactRefreshTimeout: middleEndArtifactRefreshTimeout,
		Runtime: middleend.GnetClientRuntimeConfig{
			EventLoops: eventLoops,
		},
		Supervisor: middleend.GenerationSupervisorConfig{
			PreparationTimeout:   middleEndPreparationTimeout,
			ProbeInterval:        middleEndProbeInterval,
			ProbeFailureTimeout:  middleEndProbeFailureTimeout,
			DrainTimeout:         middleEndDrainTimeout,
			RepairBackoffInitial: middleEndRepairBackoffInitial,
			RepairBackoffMaximum: middleEndRepairBackoffMaximum,
		},
		CoordinatorRetry:    middleEndCoordinatorRetry,
		SOCKS5:              socks5,
		NATResolver:         natResolver,
		EndpointDialTimeout: middleEndEndpointDialTimeout,
		DialConcurrency:     middleEndDialConcurrency,
		LinksPerDC:          middleEndLinksPerDC,
		LinkLimits: middleend.LinkLimits{
			MaxPendingSubmissions:     middleEndQueueItems,
			MaxPendingSubmissionBytes: middleEndLinkQueueBytes,
			MaxPendingEvents:          middleEndQueueItems,
			MaxPendingEventBytes:      middleEndLinkQueueBytes,
		},
		BindingLimits: middleend.FixedBindingLimits{
			MaxResidentBindings:               maxConnections,
			MaxResidentBindingsPerSlot:        perSlotResidents,
			MaxPendingRequestItemsPerBinding:  1,
			MaxPendingRequestBytesPerBinding:  middleend.MaxRPCPayloadSize,
			MaxPendingRequestItemsPerSlot:     middleEndQueueItems,
			MaxPendingRequestBytesPerSlot:     managerQueueBytes,
			MaxPendingRequestItems:            middleEndQueueItems,
			MaxPendingRequestBytes:            managerQueueBytes,
			MaxPendingControlItemsPerSlot:     middleEndQueueItems,
			MaxPendingControlBytesPerSlot:     controlBytes,
			MaxPendingControlItems:            middleEndQueueItems,
			MaxPendingControlBytes:            controlBytes,
			MaxPendingResponseItemsPerBinding: middleEndPerBindingResponseItems,
			MaxPendingResponseBytesPerBinding: middleEndLinkQueueBytes,
			MaxPendingResponseItemsPerSlot:    middleEndQueueItems,
			MaxPendingResponseBytesPerSlot:    managerQueueBytes,
			MaxPendingResponseItems:           middleEndQueueItems,
			MaxPendingResponseBytes:           managerQueueBytes,
		},
	}
	if err := serviceConfig.Validate(); err != nil {
		transport.CloseIdleConnections()
		return MiddleEndRuntimeConfig{}, fmt.Errorf("derived Middle-End service config: %w", err)
	}
	return MiddleEndRuntimeConfig{
		Enabled:           true,
		Service:           serviceConfig,
		ProxyTag:          tag,
		MaxConnections:    maxConnections,
		artifactTransport: transport,
	}, nil
}

func newMiddleEndNATResolver(value string) (*middleend.NATResolver, error) {
	var publicIP netip.Addr
	value = strings.TrimSpace(value)
	if value != "" {
		parsed, err := netip.ParseAddr(value)
		if err != nil {
			return nil, errors.New("middle-end.nat-ip must be a public IPv4 or IPv6 address")
		}
		publicIP = parsed
	}
	resolver, err := middleend.NewNATResolver(middleend.NATResolverConfig{
		PublicIP:              publicIP,
		STUNServers:           middleEndNATSTUNServers,
		ProbeTimeout:          middleEndNATProbeTimeout,
		ProbeConcurrency:      len(middleEndNATSTUNServers),
		CacheTTL:              middleEndNATCacheTTL,
		FailureBackoffInitial: middleEndNATBackoffInitial,
		FailureBackoffMaximum: middleEndNATBackoffMaximum,
	})
	if err != nil {
		return nil, fmt.Errorf("invalid middle-end.nat-ip or NAT discovery policy: %w", err)
	}
	return resolver, nil
}

func middleEndMaxConnections(configured int) int {
	if configured == 0 {
		return middleEndDefaultMaxConnections
	}
	return configured
}

func middleEndManagerQueueBytes(configuredMB int) (int, error) {
	if configuredMB == 0 {
		return middleEndDefaultManagerQueueBytes, nil
	}
	if configuredMB < middleEndMinimumQueueBudgetMB || configuredMB > middleEndMaximumQueueBudgetMB {
		return 0, fmt.Errorf(
			"middle-end.queue-budget-mb must be in [%d,%d] or zero for the default",
			middleEndMinimumQueueBudgetMB,
			middleEndMaximumQueueBudgetMB,
		)
	}
	return configuredMB * 1024 * 1024, nil
}

func parseMiddleEndProxyTag(value string) (*middleend.ProxyTag, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(middleend.ProxyTag{}) {
		clear(decoded)
		return nil, errors.New("middle-end.proxy-tag must contain exactly 32 hexadecimal characters")
	}
	var tag middleend.ProxyTag
	copy(tag[:], decoded)
	clear(decoded)
	return new(tag), nil
}

func (c *Config) middleEndSOCKS5() (*middleend.SOCKS5Dialer, *url.URL, error) {
	address := strings.TrimSpace(c.MiddleEnd.SOCKS5)
	if address == "" {
		address = strings.TrimSpace(c.Upstream.Socks5)
	}
	username := c.MiddleEnd.SOCKS5Username
	password := c.MiddleEnd.SOCKS5Password
	if address == "" {
		if username != "" || password != "" {
			return nil, nil, errors.New("middle-end SOCKS5 credentials require a SOCKS5 address")
		}
		return nil, nil, nil
	}
	var credentials *middleend.SOCKS5Credentials
	if username != "" || password != "" {
		if username == "" || password == "" {
			return nil, nil, errors.New("middle-end SOCKS5 username and password must be set together")
		}
		credentials = new(middleend.SOCKS5Credentials{Username: username, Password: password})
	}
	dialer, err := middleend.NewSOCKS5Dialer(address, credentials)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid middle-end SOCKS5 settings: %w", err)
	}
	proxyURL := &url.URL{Scheme: "socks5h", Host: address}
	if credentials != nil {
		proxyURL.User = url.UserPassword(credentials.Username, credentials.Password)
	}
	return dialer, proxyURL, nil
}

func parseMiddleEndArtifactProxy(value string, fallback *url.URL) (*url.URL, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		if fallback == nil {
			return nil, nil
		}
		return fallback.Clone(), nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("middle-end.artifact-proxy must be a proxy URL without a path, query, or fragment")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, errors.New("middle-end.artifact-proxy scheme must be http, https, socks5, or socks5h")
	}
	return parsed, nil
}

func (c *Config) middleEndFingerprint() string {
	if c == nil || !c.MiddleEnd.Enabled {
		return "enabled=false"
	}
	digest := sha256.New()
	_, _ = fmt.Fprintf(
		digest,
		"enabled=%t\x00tag=%s\x00socks=%s\x00user=%s\x00password=%s\x00artifact=%s\x00nat=%s\x00max=%d\x00budget=%d\x00loops=%d\x00upstream=%s",
		c.MiddleEnd.Enabled,
		c.MiddleEnd.ProxyTag,
		c.MiddleEnd.SOCKS5,
		c.MiddleEnd.SOCKS5Username,
		c.MiddleEnd.SOCKS5Password,
		c.MiddleEnd.ArtifactProxy,
		c.MiddleEnd.NATIP,
		c.MiddleEnd.MaxConnections,
		c.MiddleEnd.QueueBudgetMB,
		c.Performance.NumEventLoops,
		c.Upstream.Socks5,
	)
	return "enabled=true;sha256=" + hex.EncodeToString(digest.Sum(nil))
}
