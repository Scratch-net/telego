package middleend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

var (
	// ErrInvalidNATResolver reports an invalid static address or unsafe
	// discovery bound.
	ErrInvalidNATResolver = errors.New("invalid Middle-End NAT resolver")
	// ErrNATPublicIPDiscovery reports that no authoritative public IP is
	// available for a private direct TCP endpoint.
	ErrNATPublicIPDiscovery = errors.New("discover Middle-End NAT public IP")
	// ErrNATPublicIPBackoff reports a cached discovery failure. The coordinator
	// will retry after the bounded backoff expires.
	ErrNATPublicIPBackoff = errors.New("Middle-End NAT public IP discovery is in backoff")
)

// NATResolverConfig contains the fixed operational policy for public-IP
// translation. PublicIP selects a static operator override. A zero PublicIP
// enables STUN discovery with the remaining mandatory bounds.
type NATResolverConfig struct {
	PublicIP              netip.Addr
	STUNServers           []string
	ProbeTimeout          time.Duration
	ProbeConcurrency      int
	CacheTTL              time.Duration
	FailureBackoffInitial time.Duration
	FailureBackoffMaximum time.Duration
}

// String redacts the static address and discovery endpoints.
func (NATResolverConfig) String() string { return "middleend.NATResolverConfig{redacted}" }

// GoString redacts the static address and discovery endpoints.
func (c NATResolverConfig) GoString() string { return c.String() }

// NATResolver returns one public address for a private direct TCP endpoint.
// Automatic results are singleflight, cached, and failure-backed-off for each
// address family. The TCP source port is never part of this resolver.
type NATResolver struct {
	state *natResolverState
}

type natResolverState struct {
	static                netip.Addr
	servers               []string
	probeTimeout          time.Duration
	probeConcurrency      int
	cacheTTL              time.Duration
	refreshWindow         time.Duration
	failureBackoffInitial time.Duration
	failureBackoffMaximum time.Duration
	now                   func() time.Time
	probe                 natProbeFunc

	mu       sync.Mutex
	families [3]natResolverFamilyState
}

type natResolverFamilyState struct {
	address             netip.Addr
	expiresAt           time.Time
	retryAt             time.Time
	consecutiveFailures uint
	lastErr             error
	lastFailure         error
	inFlight            chan struct{}
	attempts            uint64
	successes           uint64
	failures            uint64
	respondingServers   int
	agreeingServers     int
	priming             bool
}

type natProbeResult struct {
	address           netip.Addr
	respondingServers int
	agreeingServers   int
}

type natProbeFunc func(context.Context, AddressFamily, []string, int) (natProbeResult, error)

// NATResolverSnapshot is a concurrency-safe operational view. PublicIP is the
// server public address and contains no credential or registered proxy tag.
type NATResolverSnapshot struct {
	Configured bool
	Static     bool
	IPv4       NATResolverFamilySnapshot
	IPv6       NATResolverFamilySnapshot
}

// NATResolverFamilySnapshot reports cache and probe state for one family.
type NATResolverFamilySnapshot struct {
	PublicIP          netip.Addr
	Ready             bool
	ExpiresAt         time.Time
	RetryAt           time.Time
	Attempts          uint64
	Successes         uint64
	Failures          uint64
	RespondingServers int
	AgreeingServers   int
	LastFailure       error
}

// NewNATResolver validates and constructs one resolver shared by all ME link
// generations. It performs no network work during construction.
func NewNATResolver(config NATResolverConfig) (*NATResolver, error) {
	return newNATResolver(config, time.Now, probeSTUNPublicIP)
}

func newNATResolver(config NATResolverConfig, now func() time.Time, probe natProbeFunc) (*NATResolver, error) {
	if now == nil || probe == nil {
		return nil, fmt.Errorf("%w: nil internal dependency", ErrInvalidNATResolver)
	}
	if config.PublicIP.IsValid() {
		address := config.PublicIP.Unmap()
		if address.Zone() != "" {
			return nil, fmt.Errorf("%w: public IP must not contain a zone", ErrInvalidNATResolver)
		}
		if err := validatePublicEndpoint("configured NAT", netip.AddrPortFrom(address, 1)); err != nil {
			return nil, fmt.Errorf("%w: public IP: %v", ErrInvalidNATResolver, err)
		}
		return &NATResolver{state: &natResolverState{static: address, now: now, probe: probe}}, nil
	}
	if len(config.STUNServers) == 0 {
		return nil, fmt.Errorf("%w: at least one STUN server is required", ErrInvalidNATResolver)
	}
	if config.ProbeTimeout <= 0 || config.CacheTTL <= 0 || config.FailureBackoffInitial <= 0 ||
		config.FailureBackoffMaximum < config.FailureBackoffInitial {
		return nil, fmt.Errorf("%w: discovery durations are invalid", ErrInvalidNATResolver)
	}
	if config.ProbeConcurrency <= 0 || config.ProbeConcurrency > len(config.STUNServers) {
		return nil, fmt.Errorf("%w: probe concurrency must be in [1,%d]", ErrInvalidNATResolver, len(config.STUNServers))
	}
	servers := make([]string, 0, len(config.STUNServers))
	seen := make(map[string]struct{}, len(config.STUNServers))
	for _, configured := range config.STUNServers {
		server := strings.TrimSpace(configured)
		host, port, err := net.SplitHostPort(server)
		portNumber, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || host == "" || portErr != nil || portNumber == 0 {
			return nil, fmt.Errorf("%w: invalid STUN server address", ErrInvalidNATResolver)
		}
		if _, exists := seen[server]; exists {
			continue
		}
		seen[server] = struct{}{}
		servers = append(servers, server)
	}
	if len(servers) == 0 || config.ProbeConcurrency > len(servers) {
		return nil, fmt.Errorf("%w: probe concurrency exceeds unique STUN servers", ErrInvalidNATResolver)
	}
	return &NATResolver{state: &natResolverState{
		servers:               slices.Clone(servers),
		probeTimeout:          config.ProbeTimeout,
		probeConcurrency:      config.ProbeConcurrency,
		cacheTTL:              config.CacheTTL,
		refreshWindow:         min(config.CacheTTL/2, config.ProbeTimeout),
		failureBackoffInitial: config.FailureBackoffInitial,
		failureBackoffMaximum: config.FailureBackoffMaximum,
		now:                   now,
		probe:                 probe,
	}}, nil
}

// String redacts the static address, discovery endpoints, and cache state.
func (*NATResolver) String() string { return "middleend.NATResolver{redacted}" }

// GoString redacts the static address, discovery endpoints, and cache state.
func (r *NATResolver) GoString() string { return r.String() }

// Snapshot returns static or automatic public-IP state without STUN endpoint
// names. A static resolver is ready for only its configured address family.
func (r *NATResolver) Snapshot() NATResolverSnapshot {
	if r == nil || r.state == nil {
		return NATResolverSnapshot{}
	}
	state := r.state
	if state.static.IsValid() {
		snapshot := NATResolverSnapshot{Configured: true, Static: true}
		family := NATResolverFamilySnapshot{PublicIP: state.static, Ready: true}
		if state.static.Is4() {
			snapshot.IPv4 = family
		} else {
			snapshot.IPv6 = family
		}
		return snapshot
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return NATResolverSnapshot{
		Configured: true,
		IPv4:       state.familySnapshot(AddressFamilyIPv4),
		IPv6:       state.familySnapshot(AddressFamilyIPv6),
	}
}

func (s *natResolverState) familySnapshot(family AddressFamily) NATResolverFamilySnapshot {
	state := s.families[family]
	return NATResolverFamilySnapshot{
		PublicIP:          state.address,
		Ready:             state.address.IsValid() && s.now().Before(state.expiresAt),
		ExpiresAt:         state.expiresAt,
		RetryAt:           state.retryAt,
		Attempts:          state.attempts,
		Successes:         state.successes,
		Failures:          state.failures,
		RespondingServers: state.respondingServers,
		AgreeingServers:   state.agreeingServers,
		LastFailure:       state.lastFailure,
	}
}

// TranslateCachedEndpoint replaces only a non-public or wildcard endpoint IP
// with the cached public IP for the same address family. It retains the
// endpoint port and never waits for network I/O. A near-expiry cache starts
// one bounded background refresh. The last verified address stays available
// for the same bounded window after expiry while that refresh completes.
func (r *NATResolver) TranslateCachedEndpoint(endpoint netip.AddrPort) (netip.AddrPort, error) {
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: invalid proxy endpoint", ErrNATPublicIPDiscovery)
	}
	address := endpoint.Addr().Unmap()
	if address.Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("%w: proxy endpoint is zoned", ErrNATPublicIPDiscovery)
	}
	endpoint = netip.AddrPortFrom(address, endpoint.Port())
	if validatePublicEndpoint("proxy", endpoint) == nil {
		return endpoint, nil
	}

	snapshot := r.Snapshot()
	var (
		family AddressFamily
		cached NATResolverFamilySnapshot
	)
	switch addressFamily(address) {
	case AddressFamilyIPv4:
		family = AddressFamilyIPv4
		cached = snapshot.IPv4
	case AddressFamilyIPv6:
		family = AddressFamilyIPv6
		cached = snapshot.IPv6
	default:
		return netip.AddrPort{}, fmt.Errorf("%w: invalid proxy address family", ErrNATPublicIPDiscovery)
	}
	if !cached.PublicIP.IsValid() {
		r.Prime(family)
		return netip.AddrPort{}, fmt.Errorf("%w: no cached public IP for the proxy address family", ErrNATPublicIPDiscovery)
	}
	r.Prime(family)
	if !cached.Ready && (cached.ExpiresAt.IsZero() || !r.state.now().Before(cached.ExpiresAt.Add(r.state.refreshWindow))) {
		return netip.AddrPort{}, fmt.Errorf("%w: cached public IP expired for the proxy address family", ErrNATPublicIPDiscovery)
	}
	translated, err := translateNATClientAddress(endpoint, cached.PublicIP)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: translate proxy endpoint: %w", ErrNATPublicIPDiscovery, err)
	}
	return translated, nil
}

// Prime starts one bounded background discovery or near-expiry refresh for
// family when no probe or failure backoff exists. It never waits for network
// I/O and returns whether it started a goroutine.
func (r *NATResolver) Prime(family AddressFamily) bool {
	if r == nil || r.state == nil || (family != AddressFamilyIPv4 && family != AddressFamilyIPv6) {
		return false
	}
	state := r.state
	if state.static.IsValid() {
		return false
	}
	state.mu.Lock()
	now := state.now()
	cached := &state.families[family]
	refresh := cached.address.IsValid() && !now.Before(cached.expiresAt.Add(-state.refreshWindow))
	if cached.priming || cached.inFlight != nil || now.Before(cached.retryAt) ||
		(cached.address.IsValid() && !refresh) {
		state.mu.Unlock()
		return false
	}
	cached.priming = true
	state.mu.Unlock()

	go func() {
		_, _ = r.resolve(context.Background(), family, refresh)
		state.mu.Lock()
		state.families[family].priming = false
		state.mu.Unlock()
	}()
	return true
}

// Resolve returns a public address in family. Concurrent cache misses share
// one STUN batch. A failed batch is cached with bounded exponential backoff.
func (r *NATResolver) Resolve(ctx context.Context, family AddressFamily) (netip.Addr, error) {
	return r.resolve(ctx, family, false)
}

func (r *NATResolver) resolve(ctx context.Context, family AddressFamily, forceProbe bool) (netip.Addr, error) {
	if ctx == nil {
		return netip.Addr{}, fmt.Errorf("%w: nil context", ErrNATPublicIPDiscovery)
	}
	if r == nil || r.state == nil {
		return netip.Addr{}, fmt.Errorf("%w: uninitialized resolver", ErrNATPublicIPDiscovery)
	}
	if family != AddressFamilyIPv4 && family != AddressFamilyIPv6 {
		return netip.Addr{}, fmt.Errorf("%w: invalid address family %d", ErrNATPublicIPDiscovery, family)
	}
	state := r.state
	if state.static.IsValid() {
		if addressFamily(state.static) != family {
			return netip.Addr{}, fmt.Errorf("%w: configured public IP has the wrong address family", ErrNATPublicIPDiscovery)
		}
		return state.static, nil
	}

	for {
		state.mu.Lock()
		now := state.now()
		cached := &state.families[family]
		if cached.address.IsValid() && now.Before(cached.expiresAt) && !forceProbe {
			address := cached.address
			state.mu.Unlock()
			return address, nil
		}
		if now.Before(cached.retryAt) {
			lastErr := cached.lastErr
			state.mu.Unlock()
			return netip.Addr{}, fmt.Errorf("%w: %v", ErrNATPublicIPBackoff, lastErr)
		}
		if cached.inFlight != nil {
			inFlight := cached.inFlight
			state.mu.Unlock()
			select {
			case <-inFlight:
				forceProbe = false
				continue
			case <-ctx.Done():
				return netip.Addr{}, fmt.Errorf("%w: wait for shared probe: %w", ErrNATPublicIPDiscovery, context.Cause(ctx))
			}
		}
		cached.inFlight = make(chan struct{})
		inFlight := cached.inFlight
		cached.attempts++
		state.mu.Unlock()

		probeContext, cancelProbe := context.WithTimeoutCause(ctx, state.probeTimeout, ErrNATPublicIPDiscovery)
		result, err := state.probe(probeContext, family, state.servers, state.probeConcurrency)
		cancelProbe()
		if err == nil {
			err = validateNATProbeResult(result, family)
		}

		state.mu.Lock()
		cached = &state.families[family]
		if err == nil {
			cached.address = result.address.Unmap()
			cached.expiresAt = state.now().Add(state.cacheTTL)
			cached.retryAt = time.Time{}
			cached.consecutiveFailures = 0
			cached.lastErr = nil
			cached.successes++
			cached.respondingServers = result.respondingServers
			cached.agreeingServers = result.agreeingServers
		} else {
			cached.consecutiveFailures++
			cached.lastErr = err
			cached.lastFailure = err
			cached.failures++
			cached.respondingServers = 0
			cached.agreeingServers = 0
			cached.retryAt = state.now().Add(state.failureBackoff(cached.consecutiveFailures))
		}
		close(inFlight)
		cached.inFlight = nil
		state.mu.Unlock()

		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: %w", ErrNATPublicIPDiscovery, err)
		}
		return result.address.Unmap(), nil
	}
}

func (s *natResolverState) failureBackoff(failures uint) time.Duration {
	backoff := s.failureBackoffInitial
	for range min(failures-1, uint(6)) {
		if backoff >= s.failureBackoffMaximum/2 {
			return s.failureBackoffMaximum
		}
		backoff *= 2
	}
	return min(backoff, s.failureBackoffMaximum)
}

func validateNATProbeResult(result natProbeResult, family AddressFamily) error {
	address := result.address.Unmap()
	if addressFamily(address) != family {
		return errors.New("STUN result has the wrong address family")
	}
	if result.respondingServers <= 0 || result.agreeingServers <= 0 || result.agreeingServers > result.respondingServers {
		return errors.New("STUN result has invalid agreement counts")
	}
	if err := validatePublicEndpoint("STUN", netip.AddrPortFrom(address, 1)); err != nil {
		return err
	}
	return nil
}

func addressFamily(address netip.Addr) AddressFamily {
	if address.IsValid() && address.Unmap().Is4() {
		return AddressFamilyIPv4
	}
	if address.IsValid() && address.Is6() && !address.Is4In6() {
		return AddressFamilyIPv6
	}
	return AddressFamilyAny
}

type indexedNATProbeResult struct {
	index   int
	address netip.Addr
	err     error
}

func probeSTUNPublicIP(
	ctx context.Context,
	family AddressFamily,
	servers []string,
	concurrency int,
) (natProbeResult, error) {
	if cause := context.Cause(ctx); cause != nil {
		return natProbeResult{}, cause
	}
	jobs := make(chan int, len(servers))
	results := make(chan indexedNATProbeResult, len(servers))
	for index := range servers {
		jobs <- index
	}
	close(jobs)

	var workers sync.WaitGroup
	for range min(concurrency, len(servers)) {
		workers.Go(func() {
			for index := range jobs {
				address, err := probeOneSTUNServer(ctx, family, servers[index])
				results <- indexedNATProbeResult{index: index, address: address, err: err}
			}
		})
	}
	ordered := make([]indexedNATProbeResult, len(servers))
	for range servers {
		result := <-results
		ordered[result.index] = result
	}
	workers.Wait()
	return selectNATProbeResult(ordered)
}

func selectNATProbeResult(ordered []indexedNATProbeResult) (natProbeResult, error) {
	counts := make(map[netip.Addr]int)
	responding := 0
	var selected netip.Addr
	selectedCount := 0
	var representativeErr error
	for _, result := range ordered {
		if result.err != nil {
			if representativeErr == nil {
				representativeErr = result.err
			}
			continue
		}
		responding++
		address := result.address.Unmap()
		counts[address]++
		if counts[address] > selectedCount {
			selected = address
			selectedCount = counts[address]
		}
	}
	if !selected.IsValid() {
		if representativeErr == nil {
			representativeErr = errors.New("no STUN response")
		}
		return natProbeResult{}, fmt.Errorf("zero of %d STUN servers returned a valid public IP: %w", len(ordered), representativeErr)
	}
	return natProbeResult{address: selected, respondingServers: responding, agreeingServers: selectedCount}, nil
}

func probeOneSTUNServer(ctx context.Context, family AddressFamily, server string) (netip.Addr, error) {
	network := "udp4"
	if family == AddressFamilyIPv6 {
		network = "udp6"
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, network, server)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("dial %s: %w", server, err)
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
	})
	defer stopCancellation()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			_ = connection.Close()
			return netip.Addr{}, fmt.Errorf("set %s deadline: %w", server, err)
		}
	}

	client, err := stun.NewClient(connection)
	if err != nil {
		_ = connection.Close()
		return netip.Addr{}, fmt.Errorf("initialize %s STUN client: %w", server, err)
	}
	defer client.Close()
	message, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("build %s STUN request: %w", server, err)
	}
	var responseErr error
	var reflected stun.XORMappedAddress
	if err := client.Do(message, func(event stun.Event) {
		if event.Error != nil {
			responseErr = event.Error
			return
		}
		responseErr = reflected.GetFrom(event.Message)
	}); err != nil {
		return netip.Addr{}, fmt.Errorf("query %s: %w", server, err)
	}
	if responseErr != nil {
		return netip.Addr{}, fmt.Errorf("read %s response: %w", server, responseErr)
	}
	address, ok := netip.AddrFromSlice(reflected.IP)
	if !ok {
		return netip.Addr{}, fmt.Errorf("read %s response: invalid reflected IP", server)
	}
	result := natProbeResult{address: address.Unmap(), respondingServers: 1, agreeingServers: 1}
	if err := validateNATProbeResult(result, family); err != nil {
		return netip.Addr{}, fmt.Errorf("read %s response: %w", server, err)
	}
	return result.address, nil
}
