package middleend

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrInvalidGenerationSupervisor reports an invalid dependency or duration.
	ErrInvalidGenerationSupervisor = errors.New("invalid fixed-binding generation supervisor")
	// ErrGenerationUnavailable reports that no healthy active generation can
	// accept a new binding. Existing bindings remain on their original manager
	// until that manager drains or fails.
	ErrGenerationUnavailable = errors.New("Middle-End generation is unavailable")
	// ErrGenerationChanged reports a rotation superseded by a concurrent
	// liveness transition.
	ErrGenerationChanged = errors.New("Middle-End generation changed during rotation")
	// ErrGenerationProbe reports a failed all-DC admission or liveness probe.
	ErrGenerationProbe = errors.New("Middle-End generation probe failed")
	// ErrGenerationDrainTimeout reports a retiring generation that did
	// not drain before its explicit hard deadline.
	ErrGenerationDrainTimeout = errors.New("Middle-End generation drain deadline reached")
)

// GenerationSupervisorConfig contains every operational duration used by the
// supervisor. It has no defaults. PreparationTimeout bounds factory, manager
// startup, and initial all-DC probing. ProbeInterval and ProbeFailureTimeout
// control admitted-generation liveness. DrainTimeout is the hard deadline for
// a retiring active generation. RepairBackoffInitial and
// RepairBackoffMaximum bound exponential repair delays. Each delay adds up to
// 50 percent positive jitter.
type GenerationSupervisorConfig struct {
	PreparationTimeout   time.Duration
	ProbeInterval        time.Duration
	ProbeFailureTimeout  time.Duration
	DrainTimeout         time.Duration
	RepairBackoffInitial time.Duration
	RepairBackoffMaximum time.Duration
}

// Validate rejects missing or internally inconsistent durations.
func (c GenerationSupervisorConfig) Validate() error {
	if c.PreparationTimeout <= 0 || c.ProbeInterval <= 0 ||
		c.ProbeFailureTimeout <= 0 || c.DrainTimeout <= 0 ||
		c.RepairBackoffInitial <= 0 || c.RepairBackoffMaximum <= 0 {
		return fmt.Errorf("%w: every duration must be positive", ErrInvalidGenerationSupervisor)
	}
	if c.ProbeFailureTimeout <= c.ProbeInterval {
		return fmt.Errorf("%w: probe failure timeout must exceed probe interval", ErrInvalidGenerationSupervisor)
	}
	if c.RepairBackoffInitial > c.RepairBackoffMaximum {
		return fmt.Errorf("%w: repair backoff initial must not exceed maximum", ErrInvalidGenerationSupervisor)
	}
	return nil
}

// FixedBindingGenerationFactory constructs one unstarted whole generation.
// The supervisor serializes calls. A successful return transfers manager
// ownership to the supervisor. The factory must honor ctx and must leave no
// owned manager behind when it returns an error.
type FixedBindingGenerationFactory func(context.Context) (*FixedBindingManager, error)

// GenerationSupervisorSnapshot is a concurrency-safe operational view. DC
// slices are defensive sorted copies. Admitting is true only for a healthy
// active generation.
type GenerationSupervisorSnapshot struct {
	Admitting                   bool
	ActiveDCIDs                 []DCID
	RetiringDCIDs               []DCID
	Active                      *FixedBindingManagerSnapshot
	Retiring                    *FixedBindingManagerSnapshot
	Repairing                   bool
	SlotFailures                uint64
	SlotFailureAffectedBindings uint64
	LastSlotFailure             FixedBindingSlotFailureSnapshot
	SlotRepairSuccesses         uint64
	SlotRepairFailures          uint64
	LastError                   error
}

// FixedBindingGenerationSupervisor owns one active and at most one retiring
// FixedBindingManager. Artifact rotation prepares one candidate while the
// active generation keeps admitting, publishes it atomically, and then drains
// the previous active. Its pointer-backed representation is safe to copy. It
// implements the binding-source contract consumed by gproxy without importing
// that package.
type FixedBindingGenerationSupervisor struct {
	state *generationSupervisorState
}

type generationSupervisorState struct {
	config GenerationSupervisorConfig

	rootContext context.Context
	cancelRoot  context.CancelFunc

	mu                          sync.Mutex
	active                      *supervisedGeneration
	retiring                    *supervisedGeneration
	sources                     []*supervisedGeneration
	lastFactory                 FixedBindingGenerationFactory
	lastErr                     error
	lastSlotFailure             FixedBindingSlotFailureSnapshot
	slotFailures                uint64
	slotFailureAffectedBindings uint64
	repairing                   bool
	closing                     bool
	closeResult                 error

	ready               chan struct{}
	done                chan struct{}
	readyScanMu         sync.Mutex
	transitions         sync.Mutex
	workers             sync.WaitGroup
	closeOnce           sync.Once
	slotRepairSuccesses atomic.Uint64
	slotRepairFailures  atomic.Uint64
}

type supervisedGeneration struct {
	manager *FixedBindingManager
	factory FixedBindingGenerationFactory
	dcIDs   []DCID

	failed        atomic.Bool
	intentional   atomic.Bool
	slotRepairing atomic.Bool
	liveStop      chan struct{}
	stopOnce      sync.Once
}

// NewFixedBindingGenerationSupervisor constructs an empty source. Call Start
// before expecting admission. An empty or degraded supervisor remains open so
// the frontend can use its configured pre-bind direct fallback.
func NewFixedBindingGenerationSupervisor(config GenerationSupervisorConfig) (*FixedBindingGenerationSupervisor, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	rootContext, cancelRoot := context.WithCancel(context.Background())
	return &FixedBindingGenerationSupervisor{state: &generationSupervisorState{
		config:      config,
		rootContext: rootContext,
		cancelRoot:  cancelRoot,
		ready:       make(chan struct{}, 1),
		done:        make(chan struct{}),
	}}, nil
}

// String redacts managers, factories, and liveness state.
func (*FixedBindingGenerationSupervisor) String() string {
	return "middleend.FixedBindingGenerationSupervisor{redacted}"
}

// GoString redacts managers, factories, and liveness state.
func (s *FixedBindingGenerationSupervisor) GoString() string { return s.String() }

// Start prepares one complete active generation. Calls are serialized. If
// preparation fails, Bind remains unavailable and a bounded background repair
// loop continues with the same factory.
func (s *FixedBindingGenerationSupervisor) Start(ctx context.Context, factory FixedBindingGenerationFactory) error {
	if err := validateGenerationOperation(ctx, factory); err != nil {
		return err
	}
	if s == nil || s.state == nil {
		return ErrGenerationUnavailable
	}
	state := s.state
	state.transitions.Lock()
	state.mu.Lock()
	if state.lastFactory == nil {
		state.lastFactory = factory
	}
	state.mu.Unlock()
	err := state.ensureActive(ctx, factory)
	state.transitions.Unlock()
	if err != nil {
		state.requestRepair()
	}
	return err
}

// Rotate prepares one candidate from factory while the current active remains
// available. Publication is atomic; the old active then quiesces and drains
// naturally until DrainTimeout. Steady state owns one generation and rotation
// owns at most two.
func (s *FixedBindingGenerationSupervisor) Rotate(ctx context.Context, factory FixedBindingGenerationFactory) error {
	if err := validateGenerationOperation(ctx, factory); err != nil {
		return err
	}
	if s == nil || s.state == nil {
		return ErrGenerationUnavailable
	}
	state := s.state
	state.transitions.Lock()
	defer state.transitions.Unlock()

	if err := state.waitForRetiring(ctx); err != nil {
		return err
	}
	state.mu.Lock()
	if state.closing {
		state.mu.Unlock()
		return ErrGenerationUnavailable
	}
	oldActive := state.active
	if !healthyGeneration(oldActive) {
		state.mu.Unlock()
		return fmt.Errorf("%w: rotation requires a healthy active generation", ErrGenerationUnavailable)
	}
	state.mu.Unlock()

	candidate, err := state.prepareGeneration(ctx, factory)
	if err != nil {
		state.recordError(err)
		return err
	}

	state.mu.Lock()
	if state.closing || state.active != oldActive || !healthyGeneration(oldActive) || state.retiring != nil {
		state.mu.Unlock()
		state.closeGeneration(candidate)
		return ErrGenerationChanged
	}
	state.active = candidate
	state.retiring = oldActive
	state.lastFactory = factory
	state.addSourceLocked(candidate)
	state.mu.Unlock()
	state.startGeneration(candidate)
	state.retireRoutine(oldActive)
	return nil
}

func validateGenerationOperation(ctx context.Context, factory FixedBindingGenerationFactory) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidGenerationSupervisor)
	}
	if cause := context.Cause(ctx); cause != nil {
		return fmt.Errorf("%w: %w", ErrGenerationUnavailable, cause)
	}
	if factory == nil {
		return fmt.Errorf("%w: nil generation factory", ErrInvalidGenerationSupervisor)
	}
	return nil
}

func (s *generationSupervisorState) ensureActive(ctx context.Context, fallback FixedBindingGenerationFactory) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return ErrGenerationUnavailable
	}
	if healthyGeneration(s.active) {
		s.mu.Unlock()
		return nil
	}
	if s.active != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: active generation is failed", ErrGenerationUnavailable)
	}
	factory := fallback
	if factory == nil {
		factory = s.lastFactory
	}
	s.mu.Unlock()
	if factory == nil {
		return fmt.Errorf("%w: no recovery factory", ErrGenerationUnavailable)
	}

	candidate, err := s.prepareGeneration(ctx, factory)
	if err != nil {
		s.recordError(err)
		return err
	}

	s.mu.Lock()
	if s.closing || s.active != nil {
		s.mu.Unlock()
		s.closeGeneration(candidate)
		return ErrGenerationChanged
	}
	s.active = candidate
	s.lastFactory = factory
	s.addSourceLocked(candidate)
	s.mu.Unlock()
	s.startGeneration(candidate)
	return nil
}

func (s *generationSupervisorState) prepareGeneration(parent context.Context, factory FixedBindingGenerationFactory) (*supervisedGeneration, error) {
	prepareContext, cancel := context.WithTimeout(parent, s.config.PreparationTimeout)
	stopRoot := context.AfterFunc(s.rootContext, cancel)
	defer func() {
		stopRoot()
		cancel()
	}()

	manager, err := factory(prepareContext)
	if err != nil {
		return nil, fmt.Errorf("prepare Middle-End generation: factory: %w", err)
	}
	if manager == nil || manager.state == nil {
		return nil, fmt.Errorf("%w: factory returned nil manager", ErrInvalidGenerationSupervisor)
	}
	if s.ownsManager(manager) {
		return nil, fmt.Errorf("%w: factory returned a manager already owned by the supervisor", ErrInvalidGenerationSupervisor)
	}
	generation := &supervisedGeneration{
		manager:  manager,
		factory:  factory,
		liveStop: make(chan struct{}),
	}
	manager.state.mu.Lock()
	if manager.state.state != fixedBindingManagerCreated {
		manager.state.mu.Unlock()
		s.closeGeneration(generation)
		return nil, fmt.Errorf("%w: factory returned a manager that was already started", ErrInvalidGenerationSupervisor)
	}
	manager.state.slotFailureObserver = s.recordSlotFailure
	manager.state.mu.Unlock()
	if err := manager.Start(prepareContext); err != nil {
		s.closeGeneration(generation)
		return nil, fmt.Errorf("prepare Middle-End generation: start: %w", err)
	}
	generation.dcIDs = manager.DCIDs()
	if len(generation.dcIDs) == 0 {
		s.closeGeneration(generation)
		return nil, fmt.Errorf("%w: manager has no DCs", ErrInvalidGenerationSupervisor)
	}
	if err := s.probeGeneration(prepareContext, generation, s.config.ProbeFailureTimeout); err != nil {
		s.closeGeneration(generation)
		return nil, err
	}
	return generation, nil
}

func (s *generationSupervisorState) recordSlotFailure(failure FixedBindingSlotFailureSnapshot) {
	s.mu.Lock()
	s.slotFailures++
	s.slotFailureAffectedBindings += uint64(failure.AffectedBindings)
	failure.Sequence = s.slotFailures
	s.lastSlotFailure = failure
	s.mu.Unlock()
}

func (s *generationSupervisorState) ownsManager(manager *FixedBindingManager) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, source := range s.sources {
		if source.manager == manager {
			return true
		}
	}
	return false
}

func (s *generationSupervisorState) addSourceLocked(generation *supervisedGeneration) {
	for _, source := range s.sources {
		if source.manager == generation.manager {
			return
		}
	}
	s.sources = append(s.sources, generation)
}

func (s *generationSupervisorState) startGeneration(generation *supervisedGeneration) {
	s.workers.Go(func() { s.watchGenerationReady(generation) })
	s.workers.Go(func() { s.watchGenerationLiveness(generation) })
}

func (s *generationSupervisorState) watchGenerationReady(generation *supervisedGeneration) {
	for {
		select {
		case <-s.rootContext.Done():
			return
		case <-generation.manager.Done():
			s.signalReady()
			if !generation.intentional.Load() {
				err := generation.manager.Err()
				if err == nil {
					err = ErrFixedBindingManagerClosed
				}
				s.failGeneration(generation, err)
			}
			if !generation.manager.hasReady() {
				s.removeSource(generation)
			}
			return
		case <-generation.manager.Ready():
			s.signalReady()
		}
	}
}

func (s *generationSupervisorState) watchGenerationLiveness(generation *supervisedGeneration) {
	ticker := time.NewTicker(s.config.ProbeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.rootContext.Done():
			return
		case <-generation.liveStop:
			return
		case <-ticker.C:
			if err := s.probeGeneration(s.rootContext, generation, s.config.ProbeFailureTimeout); err != nil {
				if context.Cause(s.rootContext) != nil || generation.intentional.Load() {
					return
				}
				if generation.manager.state.canRepairSlots() {
					s.requestSlotRepair(generation, err)
					continue
				}
				s.failGeneration(generation, err)
				return
			}
		}
	}
}

func (s *generationSupervisorState) requestSlotRepair(generation *supervisedGeneration, cause error) {
	if generation == nil || generation.failed.Load() || generation.intentional.Load() ||
		!generation.slotRepairing.CompareAndSwap(false, true) {
		return
	}
	s.recordError(fmt.Errorf("repair degraded Middle-End generation: %w", cause))
	s.workers.Go(func() {
		defer generation.slotRepairing.Store(false)
		s.repairGenerationSlots(generation)
	})
}

func (s *generationSupervisorState) repairGenerationSlots(generation *supervisedGeneration) {
	backoff := s.config.RepairBackoffInitial
	for {
		if generation.failed.Load() || generation.intentional.Load() {
			return
		}
		repairContext, cancel := context.WithTimeout(s.rootContext, s.config.ProbeFailureTimeout)
		beforeSuccesses, beforeFailures := generation.manager.state.slotRepairCounts()
		err := generation.manager.state.repairFailedSlots(repairContext)
		afterSuccesses, afterFailures := generation.manager.state.slotRepairCounts()
		if afterSuccesses > beforeSuccesses {
			s.slotRepairSuccesses.Add(afterSuccesses - beforeSuccesses)
		}
		if afterFailures > beforeFailures {
			s.slotRepairFailures.Add(afterFailures - beforeFailures)
		}
		cancel()
		if err == nil {
			return
		}
		if context.Cause(s.rootContext) != nil || generation.intentional.Load() {
			return
		}
		s.recordError(err)
		timer := time.NewTimer(jitteredRetryDelay(backoff))
		backoff = nextRepairBackoff(backoff, s.config.RepairBackoffMaximum)
		select {
		case <-s.rootContext.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-generation.liveStop:
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (s *generationSupervisorState) probeGeneration(parent context.Context, generation *supervisedGeneration, timeout time.Duration) error {
	probeContext, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	errorsByDC := make([]error, len(generation.dcIDs))
	var probes sync.WaitGroup
	for index, dcID := range generation.dcIDs {
		probes.Go(func() {
			if err := generation.manager.Probe(probeContext, dcID); err != nil {
				errorsByDC[index] = fmt.Errorf("%w: DC %d: %w", ErrGenerationProbe, dcID, err)
			}
		})
	}
	probes.Wait()
	for _, err := range errorsByDC {
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *generationSupervisorState) failGeneration(generation *supervisedGeneration, cause error) {
	if cause == nil {
		cause = ErrGenerationUnavailable
	}
	if !generation.failed.CompareAndSwap(false, true) {
		return
	}
	generation.stopLiveness()
	s.recordError(fmt.Errorf("%w: %w", ErrGenerationUnavailable, cause))

	s.transitions.Lock()
	defer s.transitions.Unlock()

	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	owned := false
	retire := false
	var displacedRetiring *supervisedGeneration
	switch {
	case s.active == generation:
		owned = true
		s.active = nil
		displacedRetiring = s.retiring
		s.retiring = generation
		retire = true
	case s.retiring == generation:
		owned = true
		s.retiring = nil
	}
	s.mu.Unlock()
	if !owned {
		return
	}

	generation.intentional.Store(true)
	s.signalReady()
	if retire {
		// A liveness probe has already isolated each failed physical link.
		// Quiescing the manager preserves bindings on its remaining healthy
		// links while all new admission moves to the promoted generation.
		s.retireRoutine(generation)
	} else {
		s.closeGeneration(generation)
	}
	if displacedRetiring != nil && displacedRetiring != generation {
		// Free the sole retiring role before repair constructs another active
		// manager, keeping the whole topology at two live generations.
		s.closeGeneration(displacedRetiring)
	}
	s.requestRepair()
}

func (s *generationSupervisorState) requestRepair() {
	s.mu.Lock()
	if s.closing || s.repairing || healthyGeneration(s.active) {
		s.mu.Unlock()
		return
	}
	s.repairing = true
	s.mu.Unlock()
	s.workers.Go(s.repairLoop)
}

func (s *generationSupervisorState) repairLoop() {
	backoff := s.config.RepairBackoffInitial
	for {
		select {
		case <-s.rootContext.Done():
			s.finishRepair()
			return
		default:
		}
		s.transitions.Lock()
		s.mu.Lock()
		factory := s.lastFactory
		if s.active != nil {
			factory = s.active.factory
		}
		s.mu.Unlock()
		err := s.ensureActive(s.rootContext, factory)
		if err == nil {
			s.finishRepair()
			s.transitions.Unlock()
			return
		}
		s.transitions.Unlock()
		s.recordError(err)
		timer := time.NewTimer(jitteredRetryDelay(backoff))
		backoff = nextRepairBackoff(backoff, s.config.RepairBackoffMaximum)
		select {
		case <-s.rootContext.Done():
			if !timer.Stop() {
				<-timer.C
			}
			s.finishRepair()
			return
		case <-timer.C:
		}
	}
}

func jitteredRetryDelay(backoff time.Duration) time.Duration {
	jitterMaximum := backoff / 2
	if jitterMaximum <= 0 {
		return backoff
	}
	return backoff + time.Duration(rand.Int64N(int64(jitterMaximum)+1))
}

func nextRepairBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum-current {
		return maximum
	}
	return min(current*2, maximum)
}

func (s *generationSupervisorState) finishRepair() {
	s.mu.Lock()
	s.repairing = false
	s.mu.Unlock()
}

func (s *generationSupervisorState) retireRoutine(generation *supervisedGeneration) {
	generation.intentional.Store(true)
	generation.stopLiveness()
	drained := generation.manager.Quiesce()
	s.workers.Go(func() {
		timer := time.NewTimer(s.config.DrainTimeout)
		timedOut := false
		select {
		case <-s.rootContext.Done():
			if !timer.Stop() {
				<-timer.C
			}
		case <-drained:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			timedOut = true
		}
		if timedOut {
			s.recordError(ErrGenerationDrainTimeout)
		}
		s.closeGeneration(generation)
		s.mu.Lock()
		if s.retiring == generation {
			s.retiring = nil
		}
		s.mu.Unlock()
	})
}

func (s *generationSupervisorState) closeGeneration(generation *supervisedGeneration) {
	if generation == nil || generation.manager == nil {
		return
	}
	generation.intentional.Store(true)
	generation.stopLiveness()
	generation.manager.Quiesce()
	if err := generation.manager.Close(); err != nil {
		s.recordError(err)
	}
	s.signalReady()
}

func (g *supervisedGeneration) stopLiveness() {
	g.stopOnce.Do(func() { close(g.liveStop) })
}

func healthyGeneration(generation *supervisedGeneration) bool {
	return generation != nil && !generation.failed.Load() && !generation.intentional.Load()
}

func (s *generationSupervisorState) waitForRetiring(ctx context.Context) error {
	for {
		s.mu.Lock()
		retiring := s.retiring
		closing := s.closing
		s.mu.Unlock()
		if closing {
			return ErrGenerationUnavailable
		}
		if retiring == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for retiring Middle-End generation: %w", context.Cause(ctx))
		case <-retiring.manager.Done():
		}
	}
}

// Bind fixes a new client to the current healthy active manager. Selection and
// manager Bind are serialized with failure and rotation publication.
func (s *FixedBindingGenerationSupervisor) Bind(dcID DCID) (*ClientBinding, error) {
	if s == nil || s.state == nil {
		return nil, ErrGenerationUnavailable
	}
	state := s.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closing || !healthyGeneration(state.active) {
		return nil, ErrGenerationUnavailable
	}
	binding, err := state.active.manager.Bind(dcID)
	if err != nil {
		return nil, fmt.Errorf("bind active Middle-End generation DC %d: %w", dcID, err)
	}
	return binding, nil
}

// BindReady is Bind for a ClientReadyToken consumer. The consumer choice is
// fixed atomically with binding creation so a concurrent generation close
// cannot lose its terminal wakeup.
func (s *FixedBindingGenerationSupervisor) BindReady(dcID DCID) (*ClientBinding, error) {
	if s == nil || s.state == nil {
		return nil, ErrGenerationUnavailable
	}
	state := s.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closing || !healthyGeneration(state.active) {
		return nil, ErrGenerationUnavailable
	}
	binding, err := state.active.manager.BindReady(dcID)
	if err != nil {
		return nil, fmt.Errorf("bind active Middle-End generation DC %d for readiness: %w", dcID, err)
	}
	return binding, nil
}

// Ready returns the stable coalesced readiness channel for every published
// manager, including a retiring manager with existing bindings. It is never
// closed; select it together with Done.
func (s *FixedBindingGenerationSupervisor) Ready() <-chan struct{} {
	if s == nil || s.state == nil {
		return nil
	}
	return s.state.ready
}

// TryNextReady leases one manager token. It has one consumer. A closed manager
// remains in the registry only while a BindReady terminal token is queued. A
// leased token owns its state independently; the final empty scan removes the
// manager.
func (s *FixedBindingGenerationSupervisor) TryNextReady() *ClientReadyToken {
	if s == nil || s.state == nil {
		return nil
	}
	state := s.state
	state.readyScanMu.Lock()
	defer state.readyScanMu.Unlock()

	state.mu.Lock()
	sources := slices.Clone(state.sources)
	state.mu.Unlock()
	for _, source := range sources {
		if token := source.manager.TryNextReady(); token != nil {
			return token
		}
		select {
		case <-source.manager.Done():
			state.removeSource(source)
		default:
		}
	}
	return nil
}

func (s *generationSupervisorState) removeSource(target *supervisedGeneration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index, source := range s.sources {
		if source == target {
			copy(s.sources[index:], s.sources[index+1:])
			s.sources[len(s.sources)-1] = nil
			s.sources = s.sources[:len(s.sources)-1]
			return
		}
	}
}

func (s *generationSupervisorState) signalReady() {
	select {
	case s.ready <- struct{}{}:
	default:
	}
}

// Snapshot returns current role coverage and the latest classified failure.
func (s *FixedBindingGenerationSupervisor) Snapshot() GenerationSupervisorSnapshot {
	if s == nil || s.state == nil {
		return GenerationSupervisorSnapshot{}
	}
	state := s.state
	state.mu.Lock()
	result := GenerationSupervisorSnapshot{
		Admitting:                   healthyGeneration(state.active),
		Repairing:                   state.repairing,
		SlotFailures:                state.slotFailures,
		SlotFailureAffectedBindings: state.slotFailureAffectedBindings,
		LastSlotFailure:             state.lastSlotFailure,
		SlotRepairSuccesses:         state.slotRepairSuccesses.Load(),
		SlotRepairFailures:          state.slotRepairFailures.Load(),
		LastError:                   state.lastErr,
	}
	var activeManager, retiringManager *FixedBindingManager
	if state.active != nil {
		result.ActiveDCIDs = slices.Clone(state.active.dcIDs)
		activeManager = state.active.manager
	}
	if state.retiring != nil {
		result.RetiringDCIDs = slices.Clone(state.retiring.dcIDs)
		retiringManager = state.retiring.manager
	}
	state.mu.Unlock()
	if activeManager != nil {
		result.Active = new(activeManager.Snapshot())
	}
	if retiringManager != nil {
		result.Retiring = new(retiringManager.Snapshot())
	}
	return result
}

// Err returns the latest preparation, liveness, drain, or close failure.
func (s *FixedBindingGenerationSupervisor) Err() error {
	if s == nil || s.state == nil {
		return nil
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	return s.state.lastErr
}

func (s *generationSupervisorState) recordError(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
}

// Done closes only after explicit supervisor shutdown completes. Loss of the
// active generation does not close it; that state intentionally drives direct
// pre-bind fallback while repair continues.
func (s *FixedBindingGenerationSupervisor) Done() <-chan struct{} {
	if s == nil || s.state == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return s.state.done
}

// Close stops admission, cancels preparation and liveness work, closes every
// manager ever published but not yet collected, and joins all supervisor
// workers. Calls are concurrent and idempotent.
func (s *FixedBindingGenerationSupervisor) Close() error {
	if s == nil || s.state == nil {
		return nil
	}
	state := s.state
	state.closeOnce.Do(state.close)
	<-state.done
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.closeResult
}

func (s *generationSupervisorState) close() {
	s.mu.Lock()
	s.closing = true
	s.cancelRoot()
	sources := slices.Clone(s.sources)
	s.mu.Unlock()

	s.transitions.Lock()
	var closeErr error
	seen := make(map[*FixedBindingManager]struct{}, len(sources))
	for _, source := range sources {
		if _, duplicate := seen[source.manager]; duplicate {
			continue
		}
		seen[source.manager] = struct{}{}
		source.intentional.Store(true)
		source.stopLiveness()
		source.manager.Quiesce()
		closeErr = errors.Join(closeErr, source.manager.Close())
	}
	s.transitions.Unlock()
	s.workers.Wait()

	s.mu.Lock()
	s.active = nil
	s.retiring = nil
	s.sources = nil
	s.closeResult = closeErr
	close(s.done)
	s.mu.Unlock()
}
