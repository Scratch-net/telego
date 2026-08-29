package config

import (
	"bytes"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func newURLForTest(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestMiddleEndDisabledIgnoresDormantSettings(t *testing.T) {
	config := &Config{MiddleEnd: MiddleEndConfig{
		ProxyTag:       "invalid",
		SOCKS5:         "invalid",
		NATIP:          "invalid",
		MaxConnections: -1,
		QueueBudgetMB:  -1,
	}}
	runtimeConfig, err := config.ToMiddleEndRuntimeConfig()
	if err != nil {
		t.Fatalf("disabled config = %v", err)
	}
	if runtimeConfig.Enabled || config.middleEndFingerprint() != "enabled=false" {
		t.Fatalf("disabled runtime/fingerprint = %v / %q", runtimeConfig.Enabled, config.middleEndFingerprint())
	}
}

func TestMiddleEndRuntimeDefaultsAreDerivedAndValid(t *testing.T) {
	config := &Config{
		Performance: PerformanceConfig{NumEventLoops: 2},
		MiddleEnd:   MiddleEndConfig{Enabled: true},
	}
	runtimeConfig, err := config.ToMiddleEndRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtimeConfig.CloseIdleConnections)
	if !runtimeConfig.Enabled || runtimeConfig.MaxConnections != middleEndDefaultMaxConnections || runtimeConfig.ProxyTag != nil || runtimeConfig.Service.NATResolver == nil {
		t.Fatalf("runtime identity = enabled %v max %d tag %v", runtimeConfig.Enabled, runtimeConfig.MaxConnections, runtimeConfig.ProxyTag)
	}
	service := runtimeConfig.Service
	frontend := runtimeConfig.Frontend(nil)
	if frontend.NATResolver != service.NATResolver {
		t.Fatal("frontend and ME links do not share the NAT resolver")
	}
	if service.Runtime.EventLoops != 2 || service.LinksPerDC != 4 || service.DialConcurrency != 8 {
		t.Fatalf("runtime topology = loops %d links %d dialers %d", service.Runtime.EventLoops, service.LinksPerDC, service.DialConcurrency)
	}
	if service.Supervisor.ProbeInterval != 5*time.Second || service.Supervisor.ProbeFailureTimeout != 100*time.Second || service.Supervisor.DrainTimeout != 90*time.Second {
		t.Fatalf("supervisor durations = %+v", service.Supervisor)
	}
	if service.LinkLimits.MaxPendingSubmissions != 4096 || service.LinkLimits.MaxPendingSubmissionBytes != 2<<20 ||
		service.LinkLimits.MaxPendingEvents != 4096 || service.LinkLimits.MaxPendingEventBytes != 2<<20 {
		t.Fatalf("link limits = %+v", service.LinkLimits)
	}
	limits := service.BindingLimits
	if limits.MaxResidentBindings != 10_000 || limits.MaxResidentBindingsPerSlot != 2_500 ||
		limits.MaxPendingRequestBytes != middleEndDefaultManagerQueueBytes ||
		limits.MaxPendingResponseBytes != middleEndDefaultManagerQueueBytes ||
		limits.MaxPendingResponseItemsPerBinding != 768 {
		t.Fatalf("binding limits = %+v", limits)
	}
	if err := service.Validate(); err != nil {
		t.Fatalf("derived service config = %v", err)
	}
}

func TestMiddleEndRuntimeParsesTagAndProxyWithoutDisclosure(t *testing.T) {
	const (
		tagHex   = "0123456789abcdef0123456789abcdef"
		username = "middle-end-user-marker"
		password = "middle-end-password-marker"
	)
	config := &Config{
		Performance: PerformanceConfig{NumEventLoops: 1},
		MiddleEnd: MiddleEndConfig{
			Enabled:        true,
			ProxyTag:       tagHex,
			SOCKS5:         "127.0.0.1:10808",
			SOCKS5Username: username,
			SOCKS5Password: password,
			NATIP:          "8.8.8.8",
		},
	}
	runtimeConfig, err := config.ToMiddleEndRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtimeConfig.CloseIdleConnections)
	wantTag := middleend.ProxyTag{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	if runtimeConfig.ProxyTag == nil || !bytes.Equal(runtimeConfig.ProxyTag[:], wantTag[:]) {
		t.Fatal("proxy tag was not parsed exactly")
	}
	natIP, err := runtimeConfig.Service.NATResolver.Resolve(t.Context(), middleend.AddressFamilyIPv4)
	if err != nil || natIP != netip.MustParseAddr(config.MiddleEnd.NATIP) {
		t.Fatalf("static NAT IP = %s, %v", natIP, err)
	}
	request := &http.Request{URL: newURLForTest(t, "https://core.telegram.org/getProxySecret")}
	proxyURL, err := runtimeConfig.artifactTransport.Proxy(request)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL == nil || proxyURL.Scheme != "socks5h" || proxyURL.Host != "127.0.0.1:10808" {
		t.Fatalf("artifact proxy routing = scheme %q host %q", proxyURL.Scheme, proxyURL.Host)
	}
	formatted := fmt.Sprintf("%v %#v %v %#v", runtimeConfig, runtimeConfig, runtimeConfig.Service.SOCKS5, runtimeConfig.Service.SOCKS5)
	if strings.Contains(formatted, username) || strings.Contains(formatted, password) || strings.Contains(formatted, tagHex) {
		t.Fatalf("runtime formatting disclosed credentials or tag: %s", formatted)
	}
}

func TestMiddleEndRuntimeUsesUpstreamSOCKSForArtifacts(t *testing.T) {
	config := &Config{
		Performance: PerformanceConfig{NumEventLoops: 1},
		Upstream:    UpstreamConfig{Socks5: "127.0.0.1:10808"},
		MiddleEnd:   MiddleEndConfig{Enabled: true},
	}
	runtimeConfig, err := config.ToMiddleEndRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtimeConfig.CloseIdleConnections)
	request := &http.Request{URL: newURLForTest(t, "https://core.telegram.org/getProxyConfig")}
	proxyURL, err := runtimeConfig.artifactTransport.Proxy(request)
	if err != nil || proxyURL == nil || proxyURL.Scheme != "socks5h" || proxyURL.Host != config.Upstream.Socks5 {
		t.Fatalf("fallback artifact proxy = %v, %v", proxyURL, err)
	}
}

func TestMiddleEndRuntimeRejectsUnsafeExpertOverrides(t *testing.T) {
	for name, configure := range map[string]func(*Config){
		"max negative":         func(config *Config) { config.MiddleEnd.MaxConnections = -1 },
		"max above default":    func(config *Config) { config.MiddleEnd.MaxConnections = middleEndDefaultMaxConnections + 1 },
		"budget below minimum": func(config *Config) { config.MiddleEnd.QueueBudgetMB = middleEndMinimumQueueBudgetMB - 1 },
		"budget above maximum": func(config *Config) { config.MiddleEnd.QueueBudgetMB = middleEndMaximumQueueBudgetMB + 1 },
		"event loops negative": func(config *Config) { config.Performance.NumEventLoops = -1 },
		"partial credentials": func(config *Config) {
			config.MiddleEnd.SOCKS5 = "127.0.0.1:10808"
			config.MiddleEnd.SOCKS5Username = "user"
		},
		"credentials without address": func(config *Config) {
			config.MiddleEnd.SOCKS5Username = "user"
			config.MiddleEnd.SOCKS5Password = "password"
		},
		"invalid tag":         func(config *Config) { config.MiddleEnd.ProxyTag = "abcd" },
		"artifact proxy path": func(config *Config) { config.MiddleEnd.ArtifactProxy = "http://127.0.0.1:10808/path" },
		"malformed NAT IP":    func(config *Config) { config.MiddleEnd.NATIP = "public.example" },
		"private NAT IP":      func(config *Config) { config.MiddleEnd.NATIP = "172.18.0.2" },
	} {
		t.Run(name, func(t *testing.T) {
			config := &Config{
				Performance: PerformanceConfig{NumEventLoops: 1},
				MiddleEnd:   MiddleEndConfig{Enabled: true},
			}
			configure(config)
			if runtimeConfig, err := config.ToMiddleEndRuntimeConfig(); err == nil {
				runtimeConfig.CloseIdleConnections()
				t.Fatal("unsafe override was accepted")
			}
		})
	}
}

func TestMiddleEndFrontendPolicyAndFingerprint(t *testing.T) {
	config := &Config{
		Performance: PerformanceConfig{NumEventLoops: 1},
		MiddleEnd: MiddleEndConfig{
			Enabled:        true,
			ProxyTag:       "0123456789abcdef0123456789abcdef",
			MaxConnections: 2000,
			QueueBudgetMB:  8,
		},
	}
	runtimeConfig, err := config.ToMiddleEndRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtimeConfig.CloseIdleConnections)
	frontend := runtimeConfig.Frontend((*middleend.FixedBindingManager)(nil))
	if frontend.PrecommitFailure != gproxy.MiddleEndPrecommitDirectFallback ||
		frontend.MaxPendingClientBytes != middleend.MaxMEFrameSize ||
		frontend.MaxPendingClientBytesTotal != 8<<20 || frontend.MaxPendingOutputBytesTotal != 8<<20 ||
		frontend.OutputRetryInitial != 25*time.Millisecond || frontend.OutputRetryMax != 120*time.Millisecond ||
		frontend.OutputStallTimeout != 100*time.Second {
		t.Fatalf("frontend policy = %+v", frontend)
	}
	if runtimeConfig.Service.BindingLimits.MaxResidentBindings != 2000 ||
		runtimeConfig.Service.BindingLimits.MaxResidentBindingsPerSlot != 500 ||
		runtimeConfig.Service.BindingLimits.MaxPendingRequestBytes != 8<<20 {
		t.Fatalf("expert reductions = %+v", runtimeConfig.Service.BindingLimits)
	}
	fingerprint := config.middleEndFingerprint()
	if strings.Contains(fingerprint, config.MiddleEnd.ProxyTag) || !strings.HasPrefix(fingerprint, "enabled=true;sha256=") {
		t.Fatalf("fingerprint = %q", fingerprint)
	}
	copyConfig := *config
	copyConfig.MiddleEnd.NATIP = "8.8.8.8"
	if copyConfig.middleEndFingerprint() == fingerprint {
		t.Fatal("restart-only Middle-End change did not alter fingerprint")
	}
}
