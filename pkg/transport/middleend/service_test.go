package middleend

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func serviceTestConfig(t *testing.T, source ArtifactSource) ServiceConfig {
	t.Helper()
	natResolver, err := NewNATResolver(NATResolverConfig{PublicIP: netip.MustParseAddr("8.8.8.8")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(natResolver.Close)
	return ServiceConfig{
		ArtifactSource:         source,
		ArtifactRefreshTimeout: time.Second,
		Runtime:                GnetClientRuntimeConfig{EventLoops: 1},
		Supervisor: GenerationSupervisorConfig{
			PreparationTimeout:   time.Second,
			ProbeInterval:        5 * time.Millisecond,
			ProbeFailureTimeout:  30 * time.Millisecond,
			DrainTimeout:         time.Second,
			RepairBackoffInitial: time.Millisecond,
			RepairBackoffMaximum: 5 * time.Millisecond,
		},
		CoordinatorRetry:    5 * time.Millisecond,
		NATResolver:         natResolver,
		EndpointDialTimeout: 30 * time.Millisecond,
		DialConcurrency:     2,
		LinksPerDC:          1,
		LinkLimits: LinkLimits{
			MaxPendingSubmissions:     8,
			MaxPendingSubmissionBytes: 8 << 20,
			MaxPendingEvents:          8,
			MaxPendingEventBytes:      8 << 20,
		},
		BindingLimits: fixedBindingTestLimits(),
	}
}

func TestServiceCloseStopsOwnedNATResolver(t *testing.T) {
	config := serviceTestConfig(t, artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		return RawArtifacts{}, errors.New("unused")
	}))
	resolver := config.NATResolver
	service, err := NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(t.Context(), AddressFamilyIPv4); !errors.Is(err, ErrNATResolverClosed) {
		t.Fatalf("owned resolver after service Close error = %v", err)
	}
}

func TestServiceConfigValidationAndRedaction(t *testing.T) {
	valid := serviceTestConfig(t, artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		return RawArtifacts{}, errors.New("unused")
	}))
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	invalid := []ServiceConfig{
		{},
		func() ServiceConfig {
			config := valid
			config.ArtifactRefreshTimeout = 0
			return config
		}(),
		func() ServiceConfig {
			config := valid
			config.Runtime.EventLoops = 0
			return config
		}(),
		func() ServiceConfig {
			config := valid
			config.CoordinatorRetry = 0
			return config
		}(),
		func() ServiceConfig {
			config := valid
			config.NATResolver = nil
			return config
		}(),
		func() ServiceConfig {
			config := valid
			config.LinksPerDC = 0
			return config
		}(),
	}
	for index, config := range invalid {
		if err := config.Validate(); !errors.Is(err, ErrInvalidServiceConfig) {
			t.Fatalf("invalid config %d error = %v, want ErrInvalidServiceConfig", index, err)
		}
	}
	var typedNil *HTTPArtifactSource
	typedNilConfig := valid
	typedNilConfig.ArtifactSource = typedNil
	if err := typedNilConfig.Validate(); !errors.Is(err, ErrInvalidServiceConfig) {
		t.Fatalf("typed nil source error = %v, want ErrInvalidServiceConfig", err)
	}

	const secretMarker = "SERVICE_SECRET_MUST_NOT_APPEAR"
	credentials := SOCKS5Credentials{Username: secretMarker, Password: secretMarker}
	dialer, err := NewSOCKS5Dialer("127.0.0.1:1080", &credentials)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	valid.SOCKS5 = dialer
	service := &Service{}
	for name, value := range map[string]any{"config": valid, "service": service} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, secretMarker) || !strings.Contains(output, "redacted") {
				t.Fatalf("%s with %s was not redacted: %s", name, format, output)
			}
		}
	}
}

func TestServiceArtifactOutageKeepsDirectFallbackAndRetries(t *testing.T) {
	outage := errors.New("artifact outage")
	var calls atomic.Int32
	source := artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		calls.Add(1)
		return RawArtifacts{}, outage
	})
	service, err := NewService(serviceTestConfig(t, source))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() {
		closeContext, cancelClose := context.WithTimeout(context.Background(), time.Second)
		defer cancelClose()
		if err := service.Close(closeContext); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := service.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	capacity := service.Snapshot().Capacity
	if capacity.EventLoops != 1 || capacity.LinksPerDC != 1 ||
		capacity.MaxResidentBindings != validServiceResidentLimit(t, serviceTestConfig(t, source)) {
		t.Fatalf("capacity snapshot = %+v", capacity)
	}
	if err := service.Start(); err != nil {
		t.Fatalf("repeated Start: %v", err)
	}
	waitServiceCondition(t, service, time.Second, func(snapshot ServiceSnapshot) bool {
		return snapshot.Coordinator.RefreshFailures >= 2
	})
	if calls.Load() < 2 {
		t.Fatalf("artifact source calls = %d, want at least 2", calls.Load())
	}
	if snapshot := service.Snapshot(); snapshot.Supervisor.Admitting || !snapshot.Coordinator.Running {
		t.Fatalf("outage snapshot = %+v", snapshot)
	}
	if _, err := service.Source().Bind(1); !errors.Is(err, ErrGenerationUnavailable) {
		t.Fatalf("Bind during artifact outage error = %v", err)
	}
}

func TestServiceSOCKS5DoesNotPrimeNAT(t *testing.T) {
	probeStarted := make(chan struct{}, 1)
	resolver, err := newNATResolver(
		natResolverTestConfig(),
		time.Now,
		func(context.Context, AddressFamily, []string, int) (natProbeResult, error) {
			select {
			case probeStarted <- struct{}{}:
			default:
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
	dialer, err := NewSOCKS5Dialer("127.0.0.1:1080", nil)
	if err != nil {
		t.Fatal(err)
	}
	config := serviceTestConfig(t, artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		return RawArtifacts{}, errors.New("artifact outage")
	}))
	config.SOCKS5 = dialer
	config.NATResolver = resolver
	service, err := NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeContext, cancelClose := context.WithTimeout(context.Background(), time.Second)
		defer cancelClose()
		if err := service.Close(closeContext); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	waitServiceCondition(t, service, time.Second, func(snapshot ServiceSnapshot) bool {
		return snapshot.Coordinator.RefreshFailures >= 1
	})
	select {
	case <-probeStarted:
		t.Fatal("SOCKS5 service started unused IPv4 NAT discovery")
	default:
	}
	if snapshot := service.Snapshot().NAT.IPv4; snapshot.Attempts != 0 || snapshot.Ready {
		t.Fatalf("unused SOCKS5 NAT state = %+v", snapshot)
	}
}

func validServiceResidentLimit(t *testing.T, config ServiceConfig) int {
	t.Helper()
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	return config.BindingLimits.MaxResidentBindings
}

func TestServiceCloseCancelsAndJoinsArtifactRefresh(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	source := artifactSourceFunc(func(ctx context.Context) (RawArtifacts, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return RawArtifacts{}, context.Cause(ctx)
	})
	service, err := NewService(serviceTestConfig(t, source))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := service.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-started
	if err := service.Close(t.Context()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("service Close returned before artifact refresh stopped")
	}
	select {
	case <-service.Done():
	default:
		t.Fatal("service Done remained open after Close")
	}
	if err := service.Start(); !errors.Is(err, ErrServiceClosed) {
		t.Fatalf("Start after Close error = %v, want ErrServiceClosed", err)
	}
}

func TestServiceCloseTimeoutContinuesAndLaterJoins(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	source := artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		close(started)
		<-release
		return RawArtifacts{}, errors.New("released artifact source")
	})
	service, err := NewService(serviceTestConfig(t, source))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := service.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-started
	closeContext, cancelClose := context.WithTimeout(t.Context(), 10*time.Millisecond)
	err = service.Close(closeContext)
	cancelClose()
	if !errors.Is(err, ErrServiceCloseTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed Close error = %v", err)
	}
	select {
	case <-service.Done():
		t.Fatal("service stopped before the blocked artifact source was released")
	default:
	}
	close(release)
	if err := service.Close(t.Context()); err != nil {
		t.Fatalf("joining Close: %v", err)
	}
}

func waitServiceCondition(
	t testing.TB,
	service *Service,
	timeout time.Duration,
	predicate func(ServiceSnapshot) bool,
) ServiceSnapshot {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot := service.Snapshot()
		if predicate(snapshot) {
			return snapshot
		}
		select {
		case <-deadline.C:
			t.Fatalf("service condition not reached; last snapshot = %+v", snapshot)
		case <-ticker.C:
		}
	}
}
