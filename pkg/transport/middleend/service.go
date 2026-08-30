package middleend

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrInvalidServiceConfig reports a missing dependency or invalid explicit
	// production bound.
	ErrInvalidServiceConfig = errors.New("invalid Middle-End service config")
	// ErrServiceCloseTimeout reports that the caller stopped waiting for the
	// ordered shutdown. Shutdown continues and a later Close call can join it.
	ErrServiceCloseTimeout = errors.New("wait for Middle-End service shutdown")
	// ErrServiceClosed reports Start after ordered shutdown begins.
	ErrServiceClosed = errors.New("Middle-End service is closed")
)

// ServiceConfig contains every production dependency and bound for the
// complete gnet Middle-End subsystem. It has no defaults. ArtifactSource and
// SOCKS5 must already be configured with their intended transports and
// credentials. A successful NewService call transfers NATResolver ownership
// to Service. Formatting this value never exposes credentials.
type ServiceConfig struct {
	ArtifactSource         ArtifactSource
	ArtifactRefreshTimeout time.Duration
	Runtime                GnetClientRuntimeConfig
	Supervisor             GenerationSupervisorConfig
	CoordinatorRetry       time.Duration
	SOCKS5                 *SOCKS5Dialer
	NATResolver            *NATResolver
	EndpointDialTimeout    time.Duration
	DialConcurrency        int
	LinksPerDC             int
	LinkLimits             LinkLimits
	BindingLimits          FixedBindingLimits
}

// String redacts transports, credentials, and all retained capacity policy.
func (ServiceConfig) String() string {
	return "middleend.ServiceConfig{redacted}"
}

// GoString redacts transports, credentials, and all retained capacity policy.
func (c ServiceConfig) GoString() string { return c.String() }

// Validate rejects configuration defects before the gnet runtime starts.
func (c ServiceConfig) Validate() error {
	if nilArtifactSource(c.ArtifactSource) {
		return fmt.Errorf("%w: nil artifact source", ErrInvalidServiceConfig)
	}
	if c.ArtifactRefreshTimeout <= 0 {
		return fmt.Errorf("%w: artifact refresh timeout must be positive", ErrInvalidServiceConfig)
	}
	if err := c.Runtime.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidServiceConfig, err)
	}
	if err := c.Supervisor.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidServiceConfig, err)
	}
	if c.CoordinatorRetry <= 0 {
		return fmt.Errorf("%w: coordinator retry interval must be positive", ErrInvalidServiceConfig)
	}
	if c.NATResolver == nil {
		return fmt.Errorf("%w: nil NAT resolver", ErrInvalidServiceConfig)
	}
	factoryConfig := GnetGenerationFactoryConfig{
		EndpointDialTimeout: c.EndpointDialTimeout,
		DialConcurrency:     c.DialConcurrency,
		LinksPerDC:          c.LinksPerDC,
		LinkLimits:          c.LinkLimits,
		BindingLimits:       c.BindingLimits,
	}
	if err := validateGnetGenerationFactoryLimits(factoryConfig); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidServiceConfig, err)
	}
	return nil
}

// ServiceSnapshot combines the two redacted operational state machines owned
// by Service. It contains no artifact body, endpoint, tag, or credential.
type ServiceSnapshot struct {
	Coordinator GenerationCoordinatorSnapshot
	Supervisor  GenerationSupervisorSnapshot
	NAT         NATResolverSnapshot
	Capacity    ServiceCapacitySnapshot
}

// ServiceCapacitySnapshot contains only non-secret production bounds needed
// to interpret queue and high-water metrics.
type ServiceCapacitySnapshot struct {
	EventLoops           int
	LinksPerDC           int
	MaxResidentBindings  int
	LinkSubmissionItems  int
	LinkSubmissionBytes  int
	LinkEventItems       int
	LinkEventBytes       int
	ManagerRequestItems  int
	ManagerRequestBytes  int
	ManagerControlItems  int
	ManagerControlBytes  int
	ManagerResponseItems int
	ManagerResponseBytes int
	BindingResponseItems int
	BindingResponseBytes int
}

// Service owns the NAT resolver, artifact cache, shared gnet runtime,
// generation supervisor, and coordinator. Start is deliberately tolerant of
// artifact and generation outages: the frontend remains in pre-bind direct
// fallback while repair runs.
type Service struct {
	state *serviceState
}

type serviceState struct {
	cache       *ArtifactCache
	runtime     *GnetClientRuntime
	supervisor  *FixedBindingGenerationSupervisor
	coordinator *GenerationCoordinator
	nat         *NATResolver
	capacity    ServiceCapacitySnapshot

	closeOnce sync.Once
	done      chan struct{}
	mu        sync.Mutex
	closing   bool
	closeErr  error
}

// NewService constructs and starts only the shared gnet client runtime. It
// validates every non-artifact-dependent setting first. Call Start before the
// public listener starts, then keep Service alive until that listener has
// stopped and delivered every connection close callback.
func NewService(config ServiceConfig) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	cache, err := NewArtifactCache(config.ArtifactSource, config.ArtifactRefreshTimeout)
	if err != nil {
		return nil, fmt.Errorf("initialize Middle-End artifact cache: %w", err)
	}
	supervisor, err := NewFixedBindingGenerationSupervisor(config.Supervisor)
	if err != nil {
		_ = cache.Close()
		return nil, fmt.Errorf("initialize Middle-End generation supervisor: %w", err)
	}
	runtime, err := NewGnetClientRuntime(config.Runtime)
	if err != nil {
		_ = supervisor.Close()
		_ = cache.Close()
		return nil, fmt.Errorf("initialize Middle-End gnet runtime: %w", err)
	}
	buildFactory := func(snapshot ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
		factory, err := NewGnetGenerationFactory(GnetGenerationFactoryConfig{
			Runtime:             runtime,
			Snapshot:            snapshot,
			SOCKS5:              config.SOCKS5,
			NATResolver:         config.NATResolver,
			EndpointDialTimeout: config.EndpointDialTimeout,
			DialConcurrency:     config.DialConcurrency,
			LinksPerDC:          config.LinksPerDC,
			LinkLimits:          config.LinkLimits,
			BindingLimits:       config.BindingLimits,
		})
		if err != nil {
			return nil, err
		}
		return factory.Build, nil
	}
	coordinator, err := NewGenerationCoordinator(GenerationCoordinatorConfig{
		Cache:         cache,
		Supervisor:    supervisor,
		BuildFactory:  buildFactory,
		RetryInterval: config.CoordinatorRetry,
	})
	if err != nil {
		_ = supervisor.Close()
		_ = runtime.Stop(context.Background())
		_ = cache.Close()
		return nil, fmt.Errorf("initialize Middle-End generation coordinator: %w", err)
	}
	return &Service{state: &serviceState{
		cache:       cache,
		runtime:     runtime,
		supervisor:  supervisor,
		coordinator: coordinator,
		nat:         config.NATResolver,
		capacity: ServiceCapacitySnapshot{
			EventLoops:           config.Runtime.EventLoops,
			LinksPerDC:           config.LinksPerDC,
			MaxResidentBindings:  config.BindingLimits.MaxResidentBindings,
			LinkSubmissionItems:  config.LinkLimits.MaxPendingSubmissions,
			LinkSubmissionBytes:  config.LinkLimits.MaxPendingSubmissionBytes,
			LinkEventItems:       config.LinkLimits.MaxPendingEvents,
			LinkEventBytes:       config.LinkLimits.MaxPendingEventBytes,
			ManagerRequestItems:  config.BindingLimits.MaxPendingRequestItems,
			ManagerRequestBytes:  config.BindingLimits.MaxPendingRequestBytes,
			ManagerControlItems:  config.BindingLimits.MaxPendingControlItems,
			ManagerControlBytes:  config.BindingLimits.MaxPendingControlBytes,
			ManagerResponseItems: config.BindingLimits.MaxPendingResponseItems,
			ManagerResponseBytes: config.BindingLimits.MaxPendingResponseBytes,
			BindingResponseItems: config.BindingLimits.MaxPendingResponseItemsPerBinding,
			BindingResponseBytes: config.BindingLimits.MaxPendingResponseBytesPerBinding,
		},
		done: make(chan struct{}),
	}}, nil
}

// String redacts every owned subsystem and capacity value.
func (*Service) String() string {
	return "middleend.Service{redacted}"
}

// GoString redacts every owned subsystem and capacity value.
func (s *Service) GoString() string { return s.String() }

// Start launches immediate artifact reconciliation. Operational fetch, dial,
// bootstrap, or liveness failures are retained in Snapshot and retried; they
// do not turn startup direct fallback into a process failure.
func (s *Service) Start() error {
	if s == nil || s.state == nil || s.state.coordinator == nil {
		return fmt.Errorf("%w: uninitialized service", ErrInvalidServiceConfig)
	}
	state := s.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closing {
		return ErrServiceClosed
	}
	return state.coordinator.Start()
}

// Source returns the stable generation supervisor consumed exclusively by the
// gproxy Middle-End frontend. The caller must not close it separately.
func (s *Service) Source() *FixedBindingGenerationSupervisor {
	if s == nil || s.state == nil {
		return nil
	}
	return s.state.supervisor
}

// Snapshot returns redacted coordinator and topology state.
func (s *Service) Snapshot() ServiceSnapshot {
	if s == nil || s.state == nil {
		return ServiceSnapshot{}
	}
	return ServiceSnapshot{
		Coordinator: s.state.coordinator.Snapshot(),
		Supervisor:  s.state.supervisor.Snapshot(),
		NAT:         s.state.nat.Snapshot(),
		Capacity:    s.state.capacity,
	}
}

// Done closes after the full ordered shutdown completes.
func (s *Service) Done() <-chan struct{} {
	if s == nil || s.state == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	return s.state.done
}

// Close starts an idempotent ordered shutdown: coordinator, NAT resolver,
// supervisor, gnet runtime, then artifact cache. If ctx expires, shutdown
// continues and a later Close call can wait for the final result.
func (s *Service) Close(ctx context.Context) error {
	if s == nil || s.state == nil {
		return nil
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrServiceCloseTimeout)
	}
	state := s.state
	state.closeOnce.Do(func() {
		state.mu.Lock()
		state.closing = true
		state.mu.Unlock()
		go state.close()
	})
	select {
	case <-state.done:
		state.mu.Lock()
		defer state.mu.Unlock()
		return state.closeErr
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrServiceCloseTimeout, context.Cause(ctx))
	}
}

func (s *serviceState) close() {
	var result error
	result = errors.Join(result, s.coordinator.Close())
	s.nat.Close()
	result = errors.Join(result, s.supervisor.Close())
	result = errors.Join(result, s.runtime.Stop(context.Background()))
	result = errors.Join(result, s.cache.Close())
	s.mu.Lock()
	s.closeErr = result
	close(s.done)
	s.mu.Unlock()
}
