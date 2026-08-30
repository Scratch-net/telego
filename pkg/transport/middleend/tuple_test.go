package middleend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func natResolverTestConfig() NATResolverConfig {
	return NATResolverConfig{
		STUNServers:           []string{"stun-a.invalid:3478", "stun-b.invalid:3478"},
		ProbeTimeout:          time.Second,
		ProbeConcurrency:      2,
		CacheTTL:              10 * time.Minute,
		FailureBackoffInitial: time.Minute,
		FailureBackoffMaximum: time.Hour,
	}
}

func cleanupNATResolver(t testing.TB, resolver *NATResolver) {
	t.Helper()
	t.Cleanup(resolver.Close)
}

func TestNATResolverStaticValidationAndRedaction(t *testing.T) {
	config := natResolverTestConfig()
	config.PublicIP = netip.MustParseAddr("8.8.8.8")
	resolver, err := NewNATResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, resolver)
	address, err := resolver.Resolve(t.Context(), AddressFamilyIPv4)
	if err != nil || address != config.PublicIP {
		t.Fatalf("static Resolve = %s, %v", address, err)
	}
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv6); !errors.Is(err, ErrNATPublicIPDiscovery) {
		t.Fatalf("wrong-family static error = %v", err)
	}
	staticSnapshot := resolver.Snapshot()
	if !staticSnapshot.Configured || !staticSnapshot.Static || !staticSnapshot.IPv4.Ready || staticSnapshot.IPv4.PublicIP != config.PublicIP {
		t.Fatalf("static snapshot = %+v", staticSnapshot)
	}
	formatted := fmt.Sprintf("%v %#v %v %#v", config, config, resolver, resolver)
	if strings.Contains(formatted, config.PublicIP.String()) || strings.Contains(formatted, config.STUNServers[0]) {
		t.Fatalf("NAT formatting exposed addresses: %s", formatted)
	}

	for name, configure := range map[string]func(*NATResolverConfig){
		"private static":       func(c *NATResolverConfig) { c.PublicIP = netip.MustParseAddr("172.18.0.2") },
		"documentation static": func(c *NATResolverConfig) { c.PublicIP = netip.MustParseAddr("192.0.2.1") },
		"no servers":           func(c *NATResolverConfig) { c.STUNServers = nil },
		"zero timeout":         func(c *NATResolverConfig) { c.ProbeTimeout = 0 },
		"zero concurrency":     func(c *NATResolverConfig) { c.ProbeConcurrency = 0 },
		"invalid server":       func(c *NATResolverConfig) { c.STUNServers[0] = "missing-port" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := natResolverTestConfig()
			configure(&candidate)
			if _, err := NewNATResolver(candidate); !errors.Is(err, ErrInvalidNATResolver) {
				t.Fatalf("error = %v, want ErrInvalidNATResolver", err)
			}
		})
	}
}

func TestNATResolverSingleflightCacheAndExpiry(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Unix(1_700_000_000, 0).UnixNano())
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	var enterOnce sync.Once
	probe := func(ctx context.Context, family AddressFamily, _ []string, _ int) (natProbeResult, error) {
		calls.Add(1)
		enterOnce.Do(func() { close(entered) })
		select {
		case <-release:
		case <-ctx.Done():
			return natProbeResult{}, context.Cause(ctx)
		}
		if family != AddressFamilyIPv4 {
			return natProbeResult{}, errors.New("unexpected family")
		}
		return natProbeResult{address: netip.MustParseAddr("8.8.8.8"), respondingServers: 2, agreeingServers: 2}, nil
	}
	resolver, err := newNATResolver(
		natResolverTestConfig(),
		func() time.Time { return time.Unix(0, clock.Load()) },
		probe,
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, resolver)

	results := make(chan error, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			address, err := resolver.Resolve(t.Context(), AddressFamilyIPv4)
			if err == nil && address != netip.MustParseAddr("8.8.8.8") {
				err = fmt.Errorf("address = %s", address)
			}
			results <- err
		})
	}
	<-entered
	close(release)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("singleflight probe calls = %d, want 1", calls.Load())
	}
	snapshot := resolver.Snapshot().IPv4
	if !snapshot.Ready || snapshot.Attempts != 1 || snapshot.Successes != 1 || snapshot.Failures != 0 ||
		snapshot.RespondingServers != 2 || snapshot.AgreeingServers != 2 {
		t.Fatalf("successful snapshot = %+v", snapshot)
	}
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); err != nil || calls.Load() != 1 {
		t.Fatalf("cached Resolve error/calls = %v/%d", err, calls.Load())
	}
	clock.Add((10*time.Minute + time.Nanosecond).Nanoseconds())
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); err != nil || calls.Load() != 2 {
		t.Fatalf("expired Resolve error/calls = %v/%d", err, calls.Load())
	}
}

func TestNATResolverRefreshesWithoutTranslationGap(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Unix(1_700_000_000, 0).UnixNano())
	var calls atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseRefresh) }) })

	resolver, err := newNATResolver(
		natResolverTestConfig(),
		func() time.Time { return time.Unix(0, clock.Load()) },
		func(ctx context.Context, _ AddressFamily, _ []string, _ int) (natProbeResult, error) {
			switch calls.Add(1) {
			case 1:
				return natProbeResult{
					address:           netip.MustParseAddr("8.8.8.8"),
					respondingServers: 2,
					agreeingServers:   2,
				}, nil
			case 2:
				close(refreshStarted)
				select {
				case <-releaseRefresh:
				case <-ctx.Done():
					return natProbeResult{}, context.Cause(ctx)
				}
				return natProbeResult{
					address:           netip.MustParseAddr("1.1.1.1"),
					respondingServers: 2,
					agreeingServers:   2,
				}, nil
			default:
				return natProbeResult{}, errors.New("unexpected extra NAT probe")
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, resolver)
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); err != nil {
		t.Fatal(err)
	}

	config := natResolverTestConfig()
	clock.Add((config.CacheTTL - config.ProbeTimeout/2).Nanoseconds())
	private := netip.MustParseAddrPort("172.18.0.2:443")
	translated, err := resolver.TranslateCachedEndpoint(private)
	if err != nil || translated != netip.MustParseAddrPort("8.8.8.8:443") {
		t.Fatalf("translation during early refresh = %s, %v", translated, err)
	}
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("near-expiry translation did not start refresh")
	}

	clock.Add(config.ProbeTimeout.Nanoseconds())
	translated, err = resolver.TranslateCachedEndpoint(private)
	if err != nil || translated != netip.MustParseAddrPort("8.8.8.8:443") {
		t.Fatalf("stale translation during refresh = %s, %v", translated, err)
	}

	releaseOnce.Do(func() { close(releaseRefresh) })
	address, err := resolver.Resolve(t.Context(), AddressFamilyIPv4)
	if err != nil || address != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("refreshed address = %s, %v", address, err)
	}
	translated, err = resolver.TranslateCachedEndpoint(private)
	if err != nil || translated != netip.MustParseAddrPort("1.1.1.1:443") {
		t.Fatalf("translation after refresh = %s, %v", translated, err)
	}
}

func TestNATResolverRefreshesProactivelyWithoutClientTraffic(t *testing.T) {
	config := natResolverTestConfig()
	config.CacheTTL = 100 * time.Millisecond
	config.ProbeTimeout = 20 * time.Millisecond
	var calls atomic.Int32
	refreshed := make(chan struct{}, 1)
	resolver, err := newNATResolver(
		config,
		time.Now,
		func(context.Context, AddressFamily, []string, int) (natProbeResult, error) {
			if calls.Add(1) == 2 {
				refreshed <- struct{}{}
			}
			return natProbeResult{
				address:           netip.MustParseAddr("8.8.8.8"),
				respondingServers: 2,
				agreeingServers:   2,
			}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, resolver)
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); err != nil {
		t.Fatal(err)
	}

	select {
	case <-refreshed:
	case <-time.After(time.Second):
		t.Fatal("cached NAT address did not refresh without client traffic")
	}
}

func TestNATResolverProactiveRefreshRetriesAfterBackoff(t *testing.T) {
	type waitRequest struct {
		delay   time.Duration
		release chan struct{}
	}
	waits := make(chan waitRequest, 4)
	nextWait := func() waitRequest {
		select {
		case request := <-waits:
			return request
		case <-time.After(time.Second):
			t.Fatal("NAT refresh task was not scheduled")
			return waitRequest{}
		}
	}
	wait := func(ctx context.Context, delay time.Duration) bool {
		request := waitRequest{delay: delay, release: make(chan struct{})}
		waits <- request
		select {
		case <-request.release:
			return true
		case <-ctx.Done():
			return false
		}
	}

	var clock atomic.Int64
	clock.Store(time.Unix(1_700_000_000, 0).UnixNano())
	var calls atomic.Int32
	probeErr := errors.New("STUN unavailable")
	resolver, err := newNATResolverWithWait(
		natResolverTestConfig(),
		func() time.Time { return time.Unix(0, clock.Load()) },
		func(context.Context, AddressFamily, []string, int) (natProbeResult, error) {
			switch calls.Add(1) {
			case 1:
				return natProbeResult{
					address:           netip.MustParseAddr("8.8.8.8"),
					respondingServers: 2,
					agreeingServers:   2,
				}, nil
			case 2:
				return natProbeResult{}, probeErr
			case 3:
				return natProbeResult{
					address:           netip.MustParseAddr("1.1.1.1"),
					respondingServers: 2,
					agreeingServers:   2,
				}, nil
			default:
				return natProbeResult{}, errors.New("unexpected extra NAT probe")
			}
		},
		wait,
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, resolver)
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); err != nil {
		t.Fatal(err)
	}

	config := natResolverTestConfig()
	refresh := nextWait()
	if refresh.delay != config.CacheTTL/2 {
		t.Fatalf("proactive refresh delay = %v, want %v", refresh.delay, config.CacheTTL/2)
	}
	clock.Add(refresh.delay.Nanoseconds())
	close(refresh.release)

	retry := nextWait()
	if retry.delay != config.FailureBackoffInitial {
		t.Fatalf("proactive retry delay = %v, want %v", retry.delay, config.FailureBackoffInitial)
	}
	clock.Add(retry.delay.Nanoseconds())
	close(retry.release)

	deadline := time.After(time.Second)
	for resolver.Snapshot().IPv4.Successes != 2 {
		select {
		case <-deadline:
			t.Fatal("proactive retry did not restore the NAT cache")
		case <-time.After(time.Millisecond):
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("proactive probe calls = %d, want 3", calls.Load())
	}
}

func TestNATResolverCloseStopsScheduledRefresh(t *testing.T) {
	waitStarted := make(chan context.Context, 1)
	resolver, err := newNATResolverWithWait(
		natResolverTestConfig(),
		time.Now,
		func(context.Context, AddressFamily, []string, int) (natProbeResult, error) {
			return natProbeResult{
				address:           netip.MustParseAddr("8.8.8.8"),
				respondingServers: 2,
				agreeingServers:   2,
			}, nil
		},
		func(ctx context.Context, _ time.Duration) bool {
			waitStarted <- ctx
			<-ctx.Done()
			return false
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); err != nil {
		t.Fatal(err)
	}
	var lifecycle context.Context
	select {
	case lifecycle = <-waitStarted:
	case <-time.After(time.Second):
		t.Fatal("proactive refresh wait did not start")
	}
	resolver.Close()
	if !errors.Is(context.Cause(lifecycle), ErrNATResolverClosed) {
		t.Fatalf("refresh lifecycle cause = %v", context.Cause(lifecycle))
	}
	if resolver.Prime(AddressFamilyIPv4) {
		t.Fatal("closed resolver started a probe")
	}
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); !errors.Is(err, ErrNATResolverClosed) {
		t.Fatalf("Resolve after Close error = %v", err)
	}
}

func TestNATResolverExpiredCacheRefreshesWithoutFallback(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Unix(1_700_000_000, 0).UnixNano())
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var calls atomic.Int32
	resolver, err := newNATResolver(
		natResolverTestConfig(),
		func() time.Time { return time.Unix(0, clock.Load()) },
		func(ctx context.Context, _ AddressFamily, _ []string, _ int) (natProbeResult, error) {
			if calls.Add(1) == 1 {
				return natProbeResult{
					address:           netip.MustParseAddr("8.8.8.8"),
					respondingServers: 2,
					agreeingServers:   2,
				}, nil
			}
			close(refreshStarted)
			select {
			case <-releaseRefresh:
				return natProbeResult{
					address:           netip.MustParseAddr("8.8.8.8"),
					respondingServers: 2,
					agreeingServers:   2,
				}, nil
			case <-ctx.Done():
				return natProbeResult{}, context.Cause(ctx)
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, resolver)
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); err != nil {
		t.Fatal(err)
	}
	defer close(releaseRefresh)

	config := natResolverTestConfig()
	clock.Add((config.CacheTTL + time.Nanosecond).Nanoseconds())
	private := netip.MustParseAddrPort("172.18.0.2:443")
	translated, err := resolver.TranslateCachedEndpoint(private)
	if err != nil || translated != netip.MustParseAddrPort("8.8.8.8:443") {
		t.Fatalf("translation just after expiry = %s, %v", translated, err)
	}
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("expired translation did not start refresh")
	}
}

func TestNATResolverStaleGraceIsBounded(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Unix(1_700_000_000, 0).UnixNano())
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var calls atomic.Int32
	resolver, err := newNATResolver(
		natResolverTestConfig(),
		func() time.Time { return time.Unix(0, clock.Load()) },
		func(ctx context.Context, _ AddressFamily, _ []string, _ int) (natProbeResult, error) {
			if calls.Add(1) == 1 {
				return natProbeResult{
					address:           netip.MustParseAddr("8.8.8.8"),
					respondingServers: 2,
					agreeingServers:   2,
				}, nil
			}
			close(refreshStarted)
			select {
			case <-releaseRefresh:
				return natProbeResult{}, errors.New("STUN unavailable")
			case <-ctx.Done():
				return natProbeResult{}, context.Cause(ctx)
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, resolver)
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { close(releaseRefresh) })

	config := natResolverTestConfig()
	clock.Add((config.CacheTTL + config.ProbeTimeout + time.Nanosecond).Nanoseconds())
	private := netip.MustParseAddrPort("172.18.0.2:443")
	if _, err := resolver.TranslateCachedEndpoint(private); !errors.Is(err, ErrNATPublicIPDiscovery) {
		t.Fatalf("translation beyond stale grace error = %v", err)
	}
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("expired translation did not start refresh")
	}
}

func TestNATResolverFailedRefreshKeepsOnlyBoundedStaleAddress(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Unix(1_700_000_000, 0).UnixNano())
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var calls atomic.Int32
	probeErr := errors.New("STUN unavailable")
	resolver, err := newNATResolver(
		natResolverTestConfig(),
		func() time.Time { return time.Unix(0, clock.Load()) },
		func(ctx context.Context, _ AddressFamily, _ []string, _ int) (natProbeResult, error) {
			if calls.Add(1) == 1 {
				return natProbeResult{
					address:           netip.MustParseAddr("8.8.8.8"),
					respondingServers: 2,
					agreeingServers:   2,
				}, nil
			}
			close(refreshStarted)
			select {
			case <-releaseRefresh:
				return natProbeResult{}, probeErr
			case <-ctx.Done():
				return natProbeResult{}, context.Cause(ctx)
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, resolver)
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); err != nil {
		t.Fatal(err)
	}

	config := natResolverTestConfig()
	clock.Add((config.CacheTTL - config.ProbeTimeout/2).Nanoseconds())
	private := netip.MustParseAddrPort("172.18.0.2:443")
	translated, err := resolver.TranslateCachedEndpoint(private)
	if err != nil || translated != netip.MustParseAddrPort("8.8.8.8:443") {
		t.Fatalf("translation before failed refresh = %s, %v", translated, err)
	}
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("near-expiry translation did not start failed refresh")
	}
	close(releaseRefresh)

	deadline := time.After(time.Second)
	for resolver.Snapshot().IPv4.Failures != 1 {
		select {
		case <-deadline:
			t.Fatal("failed refresh was not recorded")
		case <-time.After(time.Millisecond):
		}
	}
	translated, err = resolver.TranslateCachedEndpoint(private)
	if err != nil || translated != netip.MustParseAddrPort("8.8.8.8:443") {
		t.Fatalf("translation after early refresh failure = %s, %v", translated, err)
	}

	clock.Add((config.ProbeTimeout + config.ProbeTimeout/2 + time.Nanosecond).Nanoseconds())
	if _, err := resolver.TranslateCachedEndpoint(private); !errors.Is(err, ErrNATPublicIPDiscovery) {
		t.Fatalf("translation after failed-refresh grace error = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("failed refresh calls = %d, want 2 during backoff", calls.Load())
	}
}

func TestNATResolverFailureBackoff(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Unix(1_700_000_000, 0).UnixNano())
	var calls atomic.Int32
	probeErr := errors.New("STUN unavailable")
	resolver, err := newNATResolver(
		natResolverTestConfig(),
		func() time.Time { return time.Unix(0, clock.Load()) },
		func(context.Context, AddressFamily, []string, int) (natProbeResult, error) {
			calls.Add(1)
			return natProbeResult{}, probeErr
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, resolver)
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); !errors.Is(err, ErrNATPublicIPDiscovery) || !errors.Is(err, probeErr) {
		t.Fatalf("first failure = %v", err)
	}
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); !errors.Is(err, ErrNATPublicIPBackoff) || calls.Load() != 1 {
		t.Fatalf("backoff failure/calls = %v/%d", err, calls.Load())
	}
	failedSnapshot := resolver.Snapshot().IPv4
	if failedSnapshot.Ready || failedSnapshot.Attempts != 1 || failedSnapshot.Failures != 1 || !errors.Is(failedSnapshot.LastFailure, probeErr) {
		t.Fatalf("failed snapshot = %+v", failedSnapshot)
	}
	clock.Add((time.Minute + time.Nanosecond).Nanoseconds())
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); !errors.Is(err, probeErr) || calls.Load() != 2 {
		t.Fatalf("post-backoff failure/calls = %v/%d", err, calls.Load())
	}
}

func TestSelectNATProbeResultUsesDeterministicPlurality(t *testing.T) {
	first := netip.MustParseAddr("8.8.8.8")
	second := netip.MustParseAddr("1.1.1.1")
	result, err := selectNATProbeResult([]indexedNATProbeResult{
		{address: first},
		{address: second},
		{address: second},
		{err: errors.New("unavailable")},
	})
	if err != nil || result.address != second || result.respondingServers != 3 || result.agreeingServers != 2 {
		t.Fatalf("plurality result = %+v, %v", result, err)
	}
	tied, err := selectNATProbeResult([]indexedNATProbeResult{{address: first}, {address: second}})
	if err != nil || tied.address != first {
		t.Fatalf("tie result = %+v, %v", tied, err)
	}
}

func TestProbeOneSTUNServerReadsXORMappedAddress(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	served := make(chan error, 1)
	go func() {
		packet := make([]byte, 2048)
		count, peer, err := server.ReadFromUDP(packet)
		if err != nil {
			served <- err
			return
		}
		request := &stun.Message{Raw: packet[:count]}
		if err := request.Decode(); err != nil {
			served <- err
			return
		}
		response, err := stun.Build(
			stun.NewTransactionIDSetter(request.TransactionID),
			stun.BindingSuccess,
			&stun.XORMappedAddress{IP: net.ParseIP("8.8.8.8"), Port: 54321},
		)
		if err == nil {
			_, err = server.WriteToUDP(response.Raw, peer)
		}
		served <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	address, err := probeOneSTUNServer(ctx, AddressFamilyIPv4, server.LocalAddr().String())
	if err != nil || address != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("STUN result = %s, %v", address, err)
	}
	if err := <-served; err != nil {
		t.Fatalf("serve STUN: %v", err)
	}
}

func TestProbeOneSTUNServerHonorsContextDeadline(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := probeOneSTUNServer(ctx, AddressFamilyIPv4, server.LocalAddr().String()); err == nil {
		t.Fatal("silent STUN server returned no error")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("STUN deadline took %v", elapsed)
	}
}

func TestTranslateNATClientAddressRetainsKernelPort(t *testing.T) {
	private := netip.MustParseAddrPort("172.18.0.2:43123")
	publicIP := netip.MustParseAddr("8.8.8.8")
	translated, err := translateNATClientAddress(private, publicIP)
	if err != nil || translated != netip.MustParseAddrPort("8.8.8.8:43123") {
		t.Fatalf("translated endpoint = %s, %v", translated, err)
	}
	alreadyPublic := netip.MustParseAddrPort("1.1.1.1:43123")
	unchanged, err := translateNATClientAddress(alreadyPublic, publicIP)
	if err != nil || unchanged != alreadyPublic {
		t.Fatalf("public endpoint = %s, %v", unchanged, err)
	}
	if _, err := translateNATClientAddress(private, netip.MustParseAddr("2001:4860:4860::8888")); !errors.Is(err, ErrTupleNotAuthoritative) {
		t.Fatalf("mixed-family error = %v", err)
	}
}

func TestNATResolverTranslateCachedEndpoint(t *testing.T) {
	config := natResolverTestConfig()
	config.PublicIP = netip.MustParseAddr("8.8.8.8")
	resolver, err := NewNATResolver(config)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, resolver)

	private := netip.MustParseAddrPort("172.18.0.2:443")
	translated, err := resolver.TranslateCachedEndpoint(private)
	if err != nil || translated != netip.MustParseAddrPort("8.8.8.8:443") {
		t.Fatalf("translated endpoint = %s, %v", translated, err)
	}
	wildcard := netip.MustParseAddrPort("0.0.0.0:443")
	translated, err = resolver.TranslateCachedEndpoint(wildcard)
	if err != nil || translated != netip.MustParseAddrPort("8.8.8.8:443") {
		t.Fatalf("wildcard endpoint = %s, %v", translated, err)
	}
	ipv6Config := natResolverTestConfig()
	ipv6Config.PublicIP = netip.MustParseAddr("2001:4860:4860::8888")
	ipv6Resolver, err := NewNATResolver(ipv6Config)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, ipv6Resolver)
	translated, err = ipv6Resolver.TranslateCachedEndpoint(netip.MustParseAddrPort("[::]:443"))
	if err != nil || translated != netip.MustParseAddrPort("[2001:4860:4860::8888]:443") {
		t.Fatalf("IPv6 wildcard endpoint = %s, %v", translated, err)
	}
	public := netip.MustParseAddrPort("1.1.1.1:443")
	unchanged, err := resolver.TranslateCachedEndpoint(public)
	if err != nil || unchanged != public {
		t.Fatalf("public endpoint = %s, %v", unchanged, err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	automatic, err := newNATResolver(
		natResolverTestConfig(),
		time.Now,
		func(ctx context.Context, _ AddressFamily, _ []string, _ int) (natProbeResult, error) {
			if calls.Add(1) == 1 {
				close(entered)
			}
			select {
			case <-release:
			case <-ctx.Done():
				return natProbeResult{}, context.Cause(ctx)
			}
			return natProbeResult{
				address:           netip.MustParseAddr("8.8.4.4"),
				respondingServers: 2,
				agreeingServers:   2,
			}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cleanupNATResolver(t, automatic)
	if _, err := automatic.TranslateCachedEndpoint(private); !errors.Is(err, ErrNATPublicIPDiscovery) {
		t.Fatalf("uncached translation error = %v", err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("uncached translation did not start background discovery")
	}
	if _, err := automatic.TranslateCachedEndpoint(private); !errors.Is(err, ErrNATPublicIPDiscovery) {
		t.Fatalf("in-flight translation error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("background discovery calls = %d, want 1", calls.Load())
	}
	close(release)
	if _, err := automatic.Resolve(t.Context(), AddressFamilyIPv4); err != nil {
		t.Fatal(err)
	}
	translated, err = automatic.TranslateCachedEndpoint(private)
	if err != nil || translated != netip.MustParseAddrPort("8.8.4.4:443") {
		t.Fatalf("cached translated endpoint = %s, %v", translated, err)
	}
}

func TestSOCKS5AddressTupleAuthority(t *testing.T) {
	server := netip.MustParseAddrPort("149.154.167.50:443")
	tests := []struct {
		name  string
		bound SOCKS5Address
		want  netip.AddrPort
	}{
		{
			name:  "public IPv4",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("93.184.216.34"), Port: 32000},
			want:  netip.MustParseAddrPort("93.184.216.34:32000"),
		},
		{
			name:  "unspecified",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.IPv4Unspecified(), Port: 32000},
		},
		{
			name:  "loopback",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("127.0.0.1"), Port: 32000},
		},
		{
			name:  "private",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("10.0.0.1"), Port: 32000},
		},
		{
			name:  "shared",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("100.64.1.2"), Port: 32000},
		},
		{
			name:  "documentation",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("198.51.100.10"), Port: 32000},
		},
		{
			name:  "domain",
			bound: SOCKS5Address{Type: SOCKS5AddressDomain, Name: "proxy.invalid", Port: 32000},
		},
		{
			name:  "mixed family",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv6, IP: netip.MustParseAddr("2606:4700:4700::1111"), Port: 32000},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotServer, gotClient, err := SOCKS5AddressTuple(server, test.bound)
			if test.want.IsValid() {
				if err != nil {
					t.Fatalf("SOCKS5AddressTuple: %v", err)
				}
				if gotServer != server || gotClient != test.want {
					t.Fatalf("tuple = %s/%s, want %s/%s", gotServer, gotClient, server, test.want)
				}
				return
			}
			if !errors.Is(err, ErrTupleNotAuthoritative) {
				t.Fatalf("error = %v, want %v", err, ErrTupleNotAuthoritative)
			}
		})
	}
}

func TestDirectAddressTupleRejectsLocalAndMismatchedEndpoints(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := listener.AcceptTCP()
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	server := <-accepted
	if server != nil {
		defer server.Close()
	}

	selected := listener.Addr().(*net.TCPAddr).AddrPort()
	if _, _, err := DirectAddressTuple(client, selected); !errors.Is(err, ErrTupleNotAuthoritative) {
		t.Fatalf("loopback tuple error = %v", err)
	}
	if _, _, err := DirectAddressTuple(client, netip.MustParseAddrPort("8.8.8.8:443")); !errors.Is(err, ErrTupleNotAuthoritative) {
		t.Fatalf("mismatch tuple error = %v", err)
	}
}

func TestClientProcessIDIPv4AndIPv6(t *testing.T) {
	uptime := time.Unix(1700000000, 0)
	ipv4, err := ClientProcessID(netip.MustParseAddrPort("1.2.3.4:32000"), 65537, uptime)
	if err != nil {
		t.Fatalf("ClientProcessID IPv4: %v", err)
	}
	if ipv4 != (ProcessID{IP: 0x01020304, PID: 1, Uptime: 1700000000}) {
		t.Fatalf("IPv4 process ID = %+v", ipv4)
	}
	ipv6, err := ClientProcessID(netip.MustParseAddrPort("[2606:4700:4700::1111]:32000"), 42, uptime)
	if err != nil {
		t.Fatalf("ClientProcessID IPv6: %v", err)
	}
	if ipv6.IP != 0 || ipv6.Port != 0 || ipv6.PID != 42 {
		t.Fatalf("IPv6 process ID = %+v", ipv6)
	}
	if _, err := ClientProcessID(netip.MustParseAddrPort("1.2.3.4:32000"), 65536, uptime); !errors.Is(err, ErrBootstrapState) {
		t.Fatalf("truncated zero PID error = %v", err)
	}
}

func TestSelectEndpointDeterministicSignedDC(t *testing.T) {
	snapshot := ArtifactSnapshot{
		defaultDC: -203,
		endpoints: map[DCID][]netip.AddrPort{
			-203: {
				netip.MustParseAddrPort("149.154.167.50:443"),
				netip.MustParseAddrPort("149.154.167.51:443"),
				netip.MustParseAddrPort("[2001:67c:4e8:f004::a]:443"),
			},
			4: {netip.MustParseAddrPort("149.154.167.91:443")},
		},
	}
	dc, endpoint, err := SelectEndpoint(snapshot, nil, AddressFamilyAny, 0)
	if err != nil {
		t.Fatalf("SelectEndpoint default: %v", err)
	}
	if dc != -203 || endpoint != netip.MustParseAddrPort("149.154.167.50:443") {
		t.Fatalf("default selection = %d/%s", dc, endpoint)
	}
	dc, endpoint, err = SelectEndpoint(snapshot, new(DCID(4)), AddressFamilyIPv4, 0)
	if err != nil {
		t.Fatalf("SelectEndpoint explicit: %v", err)
	}
	if dc != 4 || endpoint != netip.MustParseAddrPort("149.154.167.91:443") {
		t.Fatalf("explicit selection = %d/%s", dc, endpoint)
	}
	_, endpoint, err = SelectEndpoint(snapshot, nil, AddressFamilyIPv6, 0)
	if err != nil || !endpoint.Addr().Is6() {
		t.Fatalf("IPv6 selection = %s, %v", endpoint, err)
	}
	if _, _, err := SelectEndpoint(snapshot, nil, AddressFamilyIPv6, 1); !errors.Is(err, ErrEndpointSelection) {
		t.Fatalf("unavailable index error = %v", err)
	}
}
