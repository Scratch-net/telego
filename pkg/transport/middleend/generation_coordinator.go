package middleend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

var (
	// ErrInvalidGenerationCoordinator reports a missing lifecycle dependency or
	// an invalid retry interval.
	ErrInvalidGenerationCoordinator = errors.New("invalid Middle-End generation coordinator")
	// ErrGenerationCoordinatorClosed reports work requested after shutdown began.
	ErrGenerationCoordinatorClosed = errors.New("Middle-End generation coordinator is closed")
)

// GenerationFactoryBuilder constructs the reusable factory for one immutable
// artifact snapshot. The coordinator retains a successful factory until its
// snapshot is fully applied, including across failed Start or Rotate calls.
type GenerationFactoryBuilder func(ArtifactSnapshot) (FixedBindingGenerationFactory, error)

// GenerationCoordinatorConfig contains the externally owned artifact cache and
// supervisor. RetryInterval controls retries after fetch, factory, or generation
// failures. Failed retries add up to 50 percent positive jitter. Daily
// successful refresh timing still comes from ArtifactCache.
type GenerationCoordinatorConfig struct {
	Cache         *ArtifactCache
	Supervisor    *FixedBindingGenerationSupervisor
	BuildFactory  GenerationFactoryBuilder
	RetryInterval time.Duration
}

// Validate rejects invalid dependencies and supervisors that already own a
// generation. One coordinator must be the sole Start and Rotate caller for its
// supervisor.
func (c GenerationCoordinatorConfig) Validate() error {
	if c.Cache == nil || c.Cache.state == nil {
		return fmt.Errorf("%w: nil artifact cache", ErrInvalidGenerationCoordinator)
	}
	if c.Supervisor == nil || c.Supervisor.state == nil {
		return fmt.Errorf("%w: nil generation supervisor", ErrInvalidGenerationCoordinator)
	}
	if c.BuildFactory == nil {
		return fmt.Errorf("%w: nil factory builder", ErrInvalidGenerationCoordinator)
	}
	if c.RetryInterval <= 0 {
		return fmt.Errorf("%w: retry interval must be positive", ErrInvalidGenerationCoordinator)
	}
	select {
	case <-c.Supervisor.Done():
		return fmt.Errorf("%w: generation supervisor is closed", ErrInvalidGenerationCoordinator)
	default:
	}
	snapshot := c.Supervisor.Snapshot()
	if len(snapshot.ActiveDCIDs) != 0 || len(snapshot.RetiringDCIDs) != 0 {
		return fmt.Errorf("%w: generation supervisor is not empty", ErrInvalidGenerationCoordinator)
	}
	return nil
}

// GenerationCoordinatorSnapshot is a concurrency-safe operational view. It
// never contains artifact contents, endpoints, factories, or proxy secrets.
type GenerationCoordinatorSnapshot struct {
	Running             bool
	Applied             bool
	Pending             bool
	AppliedFetchedAt    time.Time
	PendingFetchedAt    time.Time
	LastAttemptAt       time.Time
	LastSuccessAt       time.Time
	RefreshSuccesses    uint64
	RefreshFailures     uint64
	GenerationSuccesses uint64
	GenerationFailures  uint64
	LastError           error
}

// GenerationCoordinator refreshes official artifacts and applies whole
// generations. It does not own or close Cache, Supervisor, or the gnet runtime
// captured by BuildFactory. Close it before closing those dependencies.
type GenerationCoordinator struct {
	state *generationCoordinatorState
}

type generationCoordinatorState struct {
	cache         *ArtifactCache
	supervisor    *FixedBindingGenerationSupervisor
	buildFactory  GenerationFactoryBuilder
	retryInterval time.Duration
	now           func() time.Time

	rootContext context.Context
	cancelRoot  context.CancelFunc
	trigger     chan struct{}
	done        chan struct{}

	mu           sync.Mutex
	started      bool
	closing      bool
	applied      *ArtifactSnapshot
	pending      *ArtifactSnapshot
	pendingBuild FixedBindingGenerationFactory
	lastAttempt  time.Time
	lastSuccess  time.Time
	refreshOK    uint64
	refreshFail  uint64
	applyOK      uint64
	applyFail    uint64
	lastErr      error

	reconcileMu sync.Mutex
	operations  sync.WaitGroup
	workers     sync.WaitGroup
	doneOnce    sync.Once
}

// NewGenerationCoordinator creates a stopped coordinator. Start launches an
// immediate reconciliation attempt followed by bounded background retries.
func NewGenerationCoordinator(config GenerationCoordinatorConfig) (*GenerationCoordinator, error) {
	return newGenerationCoordinator(config, time.Now)
}

func newGenerationCoordinator(config GenerationCoordinatorConfig, now func() time.Time) (*GenerationCoordinator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		return nil, fmt.Errorf("%w: nil clock", ErrInvalidGenerationCoordinator)
	}
	rootContext, cancelRoot := context.WithCancel(context.Background())
	return &GenerationCoordinator{state: &generationCoordinatorState{
		cache:         config.Cache,
		supervisor:    config.Supervisor,
		buildFactory:  config.BuildFactory,
		retryInterval: config.RetryInterval,
		now:           now,
		rootContext:   rootContext,
		cancelRoot:    cancelRoot,
		trigger:       make(chan struct{}, 1),
		done:          make(chan struct{}),
	}}, nil
}

// String redacts lifecycle dependencies and artifact generations.
func (*GenerationCoordinator) String() string {
	return "middleend.GenerationCoordinator{redacted}"
}

// GoString redacts lifecycle dependencies and artifact generations for %#v.
func (c *GenerationCoordinator) GoString() string { return c.String() }

// Start launches the coordinator exactly once. Artifact or generation failures
// do not fail Start: the empty or last-known-good supervisor remains available
// to drive pre-bind direct fallback while reconciliation retries.
func (c *GenerationCoordinator) Start() error {
	if c == nil || c.state == nil {
		return fmt.Errorf("%w: uninitialized coordinator", ErrInvalidGenerationCoordinator)
	}
	state := c.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closing {
		return ErrGenerationCoordinatorClosed
	}
	if state.started {
		return nil
	}
	state.started = true
	state.workers.Go(state.run)
	return nil
}

// Trigger requests an immediate reconciliation without blocking. Repeated
// requests coalesce. The background loop also retries and refreshes on schedule.
func (c *GenerationCoordinator) Trigger() error {
	if c == nil || c.state == nil {
		return fmt.Errorf("%w: uninitialized coordinator", ErrInvalidGenerationCoordinator)
	}
	state := c.state
	state.mu.Lock()
	closing := state.closing
	started := state.started
	state.mu.Unlock()
	if closing {
		return ErrGenerationCoordinatorClosed
	}
	if !started {
		return fmt.Errorf("%w: coordinator is not started", ErrInvalidGenerationCoordinator)
	}
	select {
	case state.trigger <- struct{}{}:
	default:
	}
	return nil
}

func (s *generationCoordinatorState) run() {
	defer s.finish()
	for {
		if context.Cause(s.rootContext) != nil {
			return
		}
		_ = s.reconcile(s.rootContext)
		timer := time.NewTimer(s.nextDelay())
		select {
		case <-s.rootContext.Done():
			timer.Stop()
			return
		case <-s.trigger:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (s *generationCoordinatorState) nextDelay() time.Duration {
	s.mu.Lock()
	pending := s.pending != nil
	s.mu.Unlock()
	if pending || s.cache.RefreshDue(s.now()) {
		return jitteredRetryDelay(s.retryInterval)
	}
	snapshot, ok := s.cache.Snapshot()
	if !ok {
		return jitteredRetryDelay(s.retryInterval)
	}
	delay := snapshot.FetchedAt().Add(TelegramArtifactRefreshInterval).Sub(s.now())
	if delay <= 0 {
		return jitteredRetryDelay(s.retryInterval)
	}
	return delay
}

// Reconcile performs one serialized fetch/build/apply attempt. Production uses
// Start; this method also provides a deterministic operational repair hook.
func (c *GenerationCoordinator) Reconcile(ctx context.Context) error {
	if c == nil || c.state == nil {
		return fmt.Errorf("%w: uninitialized coordinator", ErrInvalidGenerationCoordinator)
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidGenerationCoordinator)
	}
	return c.state.reconcile(ctx)
}

func (s *generationCoordinatorState) reconcile(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return ErrGenerationCoordinatorClosed
	}
	s.operations.Add(1)
	s.lastAttempt = s.now()
	s.mu.Unlock()
	defer s.operations.Done()
	operationContext, cancelOperation := context.WithCancelCause(ctx)
	stopRoot := context.AfterFunc(s.rootContext, func() {
		cancelOperation(context.Cause(s.rootContext))
	})
	defer func() {
		stopRoot()
		cancelOperation(nil)
	}()
	ctx = operationContext

	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}

	if s.hasPending() {
		return s.applyPending(ctx)
	}
	if snapshot, ok := s.cache.Snapshot(); ok && s.needsSnapshot(snapshot) {
		s.setPending(snapshot)
		return s.applyPending(ctx)
	}
	if !s.cache.RefreshDue(s.now()) {
		return nil
	}
	if err := s.cache.Refresh(ctx); err != nil {
		if s.isClosing() {
			return ErrGenerationCoordinatorClosed
		}
		return s.recordRefreshFailure(err)
	}
	s.mu.Lock()
	s.refreshOK++
	s.mu.Unlock()
	snapshot, ok := s.cache.Snapshot()
	if !ok {
		return s.recordRefreshFailure(errors.New("artifact refresh published no snapshot"))
	}
	if !s.needsSnapshot(snapshot) {
		s.mu.Lock()
		if s.applied != nil {
			s.applied = new(snapshot.clone())
		}
		s.lastSuccess = s.now()
		s.lastErr = nil
		s.mu.Unlock()
		return nil
	}
	s.setPending(snapshot)
	return s.applyPending(ctx)
}

func (s *generationCoordinatorState) hasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending != nil
}

func (s *generationCoordinatorState) needsSnapshot(snapshot ArtifactSnapshot) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied == nil || !sameArtifactContent(*s.applied, snapshot)
}

func (s *generationCoordinatorState) setPending(snapshot ArtifactSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = new(snapshot.clone())
	s.pendingBuild = nil
}

func (s *generationCoordinatorState) applyPending(ctx context.Context) error {
	s.mu.Lock()
	if s.pending == nil {
		s.mu.Unlock()
		return nil
	}
	snapshot := s.pending.clone()
	factory := s.pendingBuild
	hasApplied := s.applied != nil
	s.mu.Unlock()

	if factory == nil {
		var err error
		factory, err = s.buildFactory(snapshot)
		if err != nil {
			return s.recordGenerationFailure(fmt.Errorf("build Middle-End generation factory: %w", err))
		}
		if factory == nil {
			return s.recordGenerationFailure(errors.New("build Middle-End generation factory: nil factory"))
		}
		s.mu.Lock()
		if s.pending != nil && sameArtifactContent(*s.pending, snapshot) {
			s.pendingBuild = factory
		}
		s.mu.Unlock()
	}

	var err error
	if hasApplied {
		err = s.supervisor.Rotate(ctx, factory)
	} else {
		err = s.supervisor.Start(ctx, factory)
	}
	if err != nil {
		if s.isClosing() {
			return ErrGenerationCoordinatorClosed
		}
		return s.recordGenerationFailure(err)
	}

	s.mu.Lock()
	s.applied = new(snapshot.clone())
	s.pending = nil
	s.pendingBuild = nil
	s.applyOK++
	s.lastSuccess = s.now()
	s.lastErr = nil
	s.mu.Unlock()
	return nil
}

func (s *generationCoordinatorState) recordRefreshFailure(err error) error {
	classified := fmt.Errorf("refresh Middle-End artifacts: %w", err)
	s.mu.Lock()
	s.refreshFail++
	s.lastErr = classified
	s.mu.Unlock()
	return classified
}

func (s *generationCoordinatorState) isClosing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing
}

func (s *generationCoordinatorState) recordGenerationFailure(err error) error {
	classified := fmt.Errorf("apply Middle-End generation: %w", err)
	s.mu.Lock()
	s.applyFail++
	s.lastErr = classified
	s.mu.Unlock()
	return classified
}

func sameArtifactContent(left, right ArtifactSnapshot) bool {
	if left.defaultDC != right.defaultDC || !bytes.Equal(left.secret, right.secret) {
		return false
	}
	leftDCs := left.DCIDs()
	rightDCs := right.DCIDs()
	if !slices.Equal(leftDCs, rightDCs) {
		return false
	}
	for _, dcID := range leftDCs {
		if !slices.Equal(left.endpoints[dcID], right.endpoints[dcID]) {
			return false
		}
	}
	return true
}

// Snapshot returns redacted coordinator lifecycle and outcome counters.
func (c *GenerationCoordinator) Snapshot() GenerationCoordinatorSnapshot {
	if c == nil || c.state == nil {
		return GenerationCoordinatorSnapshot{}
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	result := GenerationCoordinatorSnapshot{
		Running:             s.started && !s.closing,
		Applied:             s.applied != nil,
		Pending:             s.pending != nil,
		LastAttemptAt:       s.lastAttempt,
		LastSuccessAt:       s.lastSuccess,
		RefreshSuccesses:    s.refreshOK,
		RefreshFailures:     s.refreshFail,
		GenerationSuccesses: s.applyOK,
		GenerationFailures:  s.applyFail,
		LastError:           s.lastErr,
	}
	if s.applied != nil {
		result.AppliedFetchedAt = s.applied.FetchedAt()
	}
	if s.pending != nil {
		result.PendingFetchedAt = s.pending.FetchedAt()
	}
	return result
}

// Done closes after the background loop exits. It is already closed when Close
// is called before Start.
func (c *GenerationCoordinator) Done() <-chan struct{} {
	if c == nil || c.state == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return c.state.done
}

// Close cancels and joins coordinator work. It deliberately leaves the
// supervisor and shared gnet runtime open for their ordered shutdown steps.
func (c *GenerationCoordinator) Close() error {
	if c == nil || c.state == nil {
		return nil
	}
	s := c.state
	s.mu.Lock()
	if !s.closing {
		s.closing = true
		s.cancelRoot()
	}
	started := s.started
	s.mu.Unlock()
	if started {
		s.workers.Wait()
	}
	s.operations.Wait()
	s.finish()
	<-s.done
	return nil
}

func (s *generationCoordinatorState) finish() {
	s.doneOnce.Do(func() { close(s.done) })
}
