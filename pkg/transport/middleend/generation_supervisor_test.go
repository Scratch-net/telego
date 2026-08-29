package middleend

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var errGenerationTestFactoryExhausted = errors.New("generation test factory exhausted")

type generationTestManager struct {
	manager *FixedBindingManager
	links   map[DCID]*fixedBindingFakeLink
	respond *atomic.Bool
}

type pooledGenerationTestManager struct {
	manager  *FixedBindingManager
	links    []*fixedBindingFakeLink
	responds []*atomic.Bool
}

type generationTestFactoryStep struct {
	manager *FixedBindingManager
	gate    <-chan struct{}
	err     error
}

type generationTestFactory struct {
	mu    sync.Mutex
	steps []generationTestFactoryStep
	calls int
}

func (f *generationTestFactory) build(ctx context.Context) (*FixedBindingManager, error) {
	f.mu.Lock()
	if f.calls >= len(f.steps) {
		f.mu.Unlock()
		return nil, errGenerationTestFactoryExhausted
	}
	step := f.steps[f.calls]
	f.calls++
	f.mu.Unlock()
	if step.gate != nil {
		select {
		case <-step.gate:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
	if step.err != nil {
		return nil, step.err
	}
	return step.manager, nil
}

func (f *generationTestFactory) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newGenerationTestManager(t testing.TB, dcIDs []DCID, responding bool) generationTestManager {
	t.Helper()
	respond := new(atomic.Bool)
	respond.Store(responding)
	links := make(map[DCID]*fixedBindingFakeLink, len(dcIDs))
	slots := make([]FixedBindingSlot, 0, len(dcIDs))
	for _, dcID := range dcIDs {
		link := newFixedBindingFakeLink()
		link.afterTry = func(accepted bool) {
			if !accepted || !respond.Load() {
				return
			}
			attempted := link.attemptedSubmissions()
			if len(attempted) == 0 {
				return
			}
			ping, err := ParsePing(attempted[len(attempted)-1].Payload)
			if err == nil {
				link.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
			}
		}
		links[dcID] = link
		slots = append(slots, FixedBindingSlot{DCID: dcID, Link: link})
	}
	manager, err := NewFixedBindingManager(slots, fixedBindingTestLimits())
	if err != nil {
		t.Fatalf("NewFixedBindingManager: %v", err)
	}
	return generationTestManager{manager: manager, links: links, respond: respond}
}

func newPooledGenerationTestManager(t testing.TB, dcID DCID, responding ...bool) pooledGenerationTestManager {
	t.Helper()
	links := make([]*fixedBindingFakeLink, 0, len(responding))
	responds := make([]*atomic.Bool, 0, len(responding))
	slots := make([]FixedBindingSlot, 0, len(responding))
	for _, initial := range responding {
		respond := new(atomic.Bool)
		respond.Store(initial)
		link := newFixedBindingFakeLink()
		link.afterTry = func(accepted bool) {
			if !accepted || !respond.Load() {
				return
			}
			attempted := link.attemptedSubmissions()
			if len(attempted) == 0 {
				return
			}
			ping, err := ParsePing(attempted[len(attempted)-1].Payload)
			if err == nil {
				link.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
			}
		}
		links = append(links, link)
		responds = append(responds, respond)
		slots = append(slots, FixedBindingSlot{DCID: dcID, Link: link})
	}
	manager, err := NewFixedBindingManager(slots, fixedBindingTestLimits())
	if err != nil {
		t.Fatalf("NewFixedBindingManager: %v", err)
	}
	return pooledGenerationTestManager{manager: manager, links: links, responds: responds}
}

type generationSlotRepairTestFactory struct {
	mu          sync.Mutex
	links       []*fixedBindingFakeLink
	gate        <-chan struct{}
	entered     chan struct{}
	enteredOnce sync.Once
}

func (f *generationSlotRepairTestFactory) build(ctx context.Context, _ DCID) (ClientLink, error) {
	if f.entered != nil {
		f.enteredOnce.Do(func() { close(f.entered) })
	}
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
	link := newFixedBindingFakeLink()
	link.afterTry = func(accepted bool) {
		if !accepted {
			return
		}
		attempted := link.attemptedSubmissions()
		if len(attempted) == 0 {
			return
		}
		ping, err := ParsePing(attempted[len(attempted)-1].Payload)
		if err == nil {
			link.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
		}
	}
	f.mu.Lock()
	f.links = append(f.links, link)
	f.mu.Unlock()
	return link, nil
}

func (f *generationSlotRepairTestFactory) snapshotLinks() []*fixedBindingFakeLink {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.links)
}

func generationTestConfig() GenerationSupervisorConfig {
	return GenerationSupervisorConfig{
		PreparationTimeout:   time.Second,
		ProbeInterval:        time.Hour,
		ProbeFailureTimeout:  2 * time.Hour,
		DrainTimeout:         time.Second,
		RepairBackoffInitial: time.Millisecond,
		RepairBackoffMaximum: 5 * time.Millisecond,
	}
}

func newGenerationTestSupervisor(t testing.TB, config GenerationSupervisorConfig) *FixedBindingGenerationSupervisor {
	t.Helper()
	supervisor, err := NewFixedBindingGenerationSupervisor(config)
	if err != nil {
		t.Fatalf("NewFixedBindingGenerationSupervisor: %v", err)
	}
	t.Cleanup(func() {
		if err := supervisor.Close(); err != nil {
			t.Errorf("Close supervisor: %v", err)
		}
	})
	return supervisor
}

func TestGenerationSupervisorConfigValidationAndRedaction(t *testing.T) {
	valid := generationTestConfig()
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	invalid := []GenerationSupervisorConfig{
		{},
		{PreparationTimeout: time.Second, ProbeInterval: time.Second, ProbeFailureTimeout: time.Second, DrainTimeout: time.Second},
		func() GenerationSupervisorConfig {
			config := valid
			config.RepairBackoffInitial = 2 * time.Second
			config.RepairBackoffMaximum = time.Second
			return config
		}(),
	}
	for index, config := range invalid {
		if err := config.Validate(); !errors.Is(err, ErrInvalidGenerationSupervisor) {
			t.Fatalf("invalid config %d error = %v", index, err)
		}
	}
	supervisor := newGenerationTestSupervisor(t, valid)
	if got := supervisor.String(); got != "middleend.FixedBindingGenerationSupervisor{redacted}" {
		t.Fatalf("String = %q", got)
	}
	if got := supervisor.GoString(); got != supervisor.String() {
		t.Fatalf("GoString = %q", got)
	}
	if _, err := supervisor.Bind(1); !errors.Is(err, ErrGenerationUnavailable) {
		t.Fatalf("Bind before Start error = %v", err)
	}
}

func TestGenerationSupervisorRepairBackoffIsCappedAndJittered(t *testing.T) {
	if got := nextRepairBackoff(500*time.Millisecond, 30*time.Second); got != time.Second {
		t.Fatalf("first repair backoff = %v, want 1s", got)
	}
	if got := nextRepairBackoff(20*time.Second, 30*time.Second); got != 30*time.Second {
		t.Fatalf("capped repair backoff = %v, want 30s", got)
	}
	for range 100 {
		delay := jitteredRetryDelay(500 * time.Millisecond)
		if delay < 500*time.Millisecond || delay > 750*time.Millisecond {
			t.Fatalf("jittered repair delay = %v, want 500ms through 750ms", delay)
		}
	}
}

func TestGenerationSupervisorStartsActiveAndBindsIt(t *testing.T) {
	dcIDs := []DCID{-2, 1}
	active := newGenerationTestManager(t, dcIDs, true)
	factory := &generationTestFactory{steps: []generationTestFactoryStep{
		{manager: active.manager},
	}}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), factory.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	snapshot := supervisor.Snapshot()
	if !snapshot.Admitting || !slices.Equal(snapshot.ActiveDCIDs, dcIDs) {
		t.Fatalf("active snapshot = %+v", snapshot)
	}
	binding, err := supervisor.Bind(-2)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if binding.state.manager != active.manager.state {
		t.Fatal("binding did not select the active generation")
	}
	if err := binding.Close(); err != nil {
		t.Fatalf("Close binding: %v", err)
	}
	if factory.callCount() != 1 {
		t.Fatalf("factory calls = %d, want 1", factory.callCount())
	}
}

func TestGenerationSupervisorRotationCanChangeArtifactCoverage(t *testing.T) {
	oldActive := newGenerationTestManager(t, []DCID{1}, true)
	newActive := newGenerationTestManager(t, []DCID{2}, true)
	initial := &generationTestFactory{steps: []generationTestFactoryStep{{manager: oldActive.manager}}}
	rotation := &generationTestFactory{steps: []generationTestFactoryStep{{manager: newActive.manager}}}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), initial.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := supervisor.Rotate(t.Context(), rotation.build); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, err := supervisor.Bind(1); !errors.Is(err, ErrFixedBindingUnknownDC) {
		t.Fatalf("Bind removed DC error = %v", err)
	}
	binding, err := supervisor.Bind(2)
	if err != nil {
		t.Fatalf("Bind new DC: %v", err)
	}
	if binding.state.manager != newActive.manager.state {
		t.Fatal("binding did not select the rotated generation")
	}
	if err := binding.Close(); err != nil {
		t.Fatalf("Close binding: %v", err)
	}
}

func TestGenerationSupervisorEnsureActiveRejectsFailedPublishedGeneration(t *testing.T) {
	dcIDs := []DCID{1}
	active := newGenerationTestManager(t, dcIDs, true)
	factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), factory.build); err != nil {
		t.Fatalf("Start: %v", err)
	}

	supervisor.state.mu.Lock()
	failed := supervisor.state.active
	failed.failed.Store(true)
	supervisor.state.mu.Unlock()
	t.Cleanup(func() { failed.failed.Store(false) })

	err := supervisor.state.ensureActive(t.Context(), factory.build)
	if !errors.Is(err, ErrGenerationUnavailable) {
		t.Fatalf("ensure active error = %v, want unavailable", err)
	}
}

func TestGenerationSupervisorRemovesDrainedSourceWithoutReadinessConsumer(t *testing.T) {
	dcIDs := []DCID{1}
	oldActive := newGenerationTestManager(t, dcIDs, true)
	newActive := newGenerationTestManager(t, dcIDs, true)
	initial := &generationTestFactory{steps: []generationTestFactoryStep{{manager: oldActive.manager}}}
	rotation := &generationTestFactory{steps: []generationTestFactoryStep{{manager: newActive.manager}}}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), initial.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := supervisor.Rotate(t.Context(), rotation.build); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		supervisor.state.mu.Lock()
		sources := len(supervisor.state.sources)
		supervisor.state.mu.Unlock()
		if sources == 1 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatalf("readiness sources after old active drain = %d, want 1", sources)
		case <-ticker.C:
		}
	}
	if initial.callCount() != 1 || rotation.callCount() != 1 {
		t.Fatalf("factory calls = initial %d, rotation %d; want 1 each", initial.callCount(), rotation.callCount())
	}
}

func TestGenerationSupervisorRotatesAndNaturallyDrainsOldActive(t *testing.T) {
	dcIDs := []DCID{1}
	oldActive := newGenerationTestManager(t, dcIDs, true)
	initial := &generationTestFactory{steps: []generationTestFactoryStep{{manager: oldActive.manager}}}
	newActive := newGenerationTestManager(t, dcIDs, true)
	rotation := &generationTestFactory{steps: []generationTestFactoryStep{{manager: newActive.manager}}}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), initial.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	oldBinding, err := supervisor.Bind(1)
	if err != nil {
		t.Fatalf("Bind old: %v", err)
	}
	if err := supervisor.Rotate(t.Context(), rotation.build); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	snapshot := supervisor.Snapshot()
	if !snapshot.Admitting || !slices.Equal(snapshot.RetiringDCIDs, dcIDs) {
		t.Fatalf("rotated snapshot = %+v", snapshot)
	}
	newBinding, err := supervisor.Bind(1)
	if err != nil {
		t.Fatalf("Bind new: %v", err)
	}
	if newBinding.state.manager != newActive.manager.state {
		t.Fatal("new binding did not select rotated active")
	}
	if err := newBinding.Close(); err != nil {
		t.Fatalf("Close new binding: %v", err)
	}
	if err := oldBinding.Close(); err != nil {
		t.Fatalf("Close old binding: %v", err)
	}
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return len(snapshot.RetiringDCIDs) == 0
	})
}

func TestGenerationSupervisorRotationNeverExceedsTwoLiveManagers(t *testing.T) {
	dcIDs := []DCID{1}
	oldActive := newGenerationTestManager(t, dcIDs, true)
	initial := &generationTestFactory{steps: []generationTestFactoryStep{{manager: oldActive.manager}}}
	newActive := newGenerationTestManager(t, dcIDs, true)
	releaseNewActive := make(chan struct{})
	newActive.links[1].startGate = releaseNewActive
	rotation := &generationTestFactory{steps: []generationTestFactoryStep{{manager: newActive.manager}}}
	managers := []generationTestManager{oldActive, newActive}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), initial.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if live := countStartedLiveGenerationTestManagers(managers); live != 1 {
		t.Fatalf("live managers after Start = %d, want 1", live)
	}
	oldBinding, err := supervisor.Bind(1)
	if err != nil {
		t.Fatalf("Bind old: %v", err)
	}
	rotateResult := make(chan error, 1)
	go func() { rotateResult <- supervisor.Rotate(t.Context(), rotation.build) }()
	waitGenerationTestLinkStarts(t, newActive.links[1], 1)
	if live := countStartedLiveGenerationTestManagers(managers); live != 2 {
		t.Fatalf("live managers while candidate starts = %d, want 2", live)
	}
	close(releaseNewActive)
	if err := <-rotateResult; err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if live := countStartedLiveGenerationTestManagers(managers); live != 2 {
		t.Fatalf("live managers with one retiring = %d, want 2", live)
	}

	secondFactory := &generationTestFactory{}
	waitContext, cancelWait := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancelWait()
	if err := supervisor.Rotate(waitContext, secondFactory.build); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Rotate error = %v, want retiring wait deadline", err)
	}
	if calls := secondFactory.callCount(); calls != 0 {
		t.Fatalf("second rotation factory calls with an existing retiree = %d", calls)
	}
	if live := countStartedLiveGenerationTestManagers(managers); live != 2 {
		t.Fatalf("live managers after rejected overlapping rotation = %d, want 2", live)
	}

	if err := oldBinding.Close(); err != nil {
		t.Fatalf("Close old binding: %v", err)
	}
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return len(snapshot.RetiringDCIDs) == 0
	})
	if live := countStartedLiveGenerationTestManagers(managers); live != 1 {
		t.Fatalf("live managers after drain = %d, want 1", live)
	}
}

func TestGenerationSupervisorRepairsFailedSlotWithoutRetiringGeneration(t *testing.T) {
	const dcID DCID = 1
	config := GenerationSupervisorConfig{
		PreparationTimeout:   time.Second,
		ProbeInterval:        5 * time.Millisecond,
		ProbeFailureTimeout:  30 * time.Millisecond,
		DrainTimeout:         time.Second,
		RepairBackoffInitial: time.Millisecond,
		RepairBackoffMaximum: 5 * time.Millisecond,
	}
	active := newPooledGenerationTestManager(t, dcID, true, true)
	repairs := &generationSlotRepairTestFactory{}
	active.manager.state.repairLink = repairs.build
	factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
	supervisor := newGenerationTestSupervisor(t, config)
	if err := supervisor.Start(t.Context(), factory.build); err != nil {
		t.Fatalf("Start: %v", err)
	}

	failedBinding, err := supervisor.Bind(dcID)
	if err != nil {
		t.Fatalf("Bind failed-link client: %v", err)
	}
	healthyBinding, err := supervisor.Bind(dcID)
	if err != nil {
		t.Fatalf("Bind healthy-link client: %v", err)
	}
	if failedBinding.state.slot.link != active.links[0] || healthyBinding.state.slot.link != active.links[1] {
		t.Fatal("pooled bindings did not distribute across both active links")
	}

	active.responds[0].Store(false)
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		if !snapshot.Admitting || snapshot.Active == nil || snapshot.Retiring != nil {
			return false
		}
		if snapshot.SlotRepairSuccesses != 1 || snapshot.SlotRepairFailures != 0 {
			return false
		}
		if snapshot.Active.SlotRepairSuccesses != 1 || snapshot.Active.RepairingSlots != 0 {
			return false
		}
		for _, slot := range snapshot.Active.Slots {
			if slot.Failed || slot.Repairing {
				return false
			}
		}
		return true
	})
	if calls := factory.callCount(); calls != 1 {
		t.Fatalf("whole-generation factory calls = %d, want 1", calls)
	}

	eventContext, cancelEvent := context.WithTimeout(t.Context(), time.Second)
	defer cancelEvent()
	if _, err := failedBinding.NextEvent(eventContext); !errors.Is(err, ErrFixedBindingSlotFailed) {
		t.Fatalf("failed-link binding event error = %v", err)
	}
	active.links[1].emit(LinkEvent{
		Kind:         LinkEventSimpleAck,
		ConnectionID: healthyBinding.ConnectionID(),
		ConfirmKey:   29,
	})
	event, err := healthyBinding.NextEvent(eventContext)
	if err != nil || event.Kind != LinkEventSimpleAck || event.ConfirmKey != 29 {
		t.Fatalf("healthy binding event = %+v, %v", event, err)
	}

	replacementLinks := repairs.snapshotLinks()
	if len(replacementLinks) != 1 {
		t.Fatalf("replacement links = %d, want 1", len(replacementLinks))
	}
	newBinding, err := supervisor.Bind(dcID)
	if err != nil {
		t.Fatalf("Bind after slot repair: %v", err)
	}
	if newBinding.state.manager != active.manager.state {
		t.Fatal("slot repair moved admission away from the active generation")
	}
	if newBinding.state.slot.link != replacementLinks[0] {
		t.Fatal("new binding did not select the repaired active slot")
	}
	if snapshot := supervisor.Snapshot(); snapshot.Retiring != nil {
		t.Fatalf("slot repair published a retiring generation: %+v", snapshot)
	}

	if err := newBinding.Close(); err != nil {
		t.Fatalf("Close new binding: %v", err)
	}
	if err := healthyBinding.Close(); err != nil {
		t.Fatalf("Close healthy binding: %v", err)
	}
}

func TestGenerationSupervisorRepairsLostDCCoverageWithoutRetiringGeneration(t *testing.T) {
	const dcID DCID = -203
	config := GenerationSupervisorConfig{
		PreparationTimeout:   time.Second,
		ProbeInterval:        5 * time.Millisecond,
		ProbeFailureTimeout:  30 * time.Millisecond,
		DrainTimeout:         time.Second,
		RepairBackoffInitial: time.Millisecond,
		RepairBackoffMaximum: 5 * time.Millisecond,
	}
	active := newPooledGenerationTestManager(t, dcID, true, true, true, true)
	repairs := &generationSlotRepairTestFactory{}
	active.manager.state.repairLink = repairs.build
	factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
	supervisor := newGenerationTestSupervisor(t, config)
	if err := supervisor.Start(t.Context(), factory.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for _, respond := range active.responds {
		respond.Store(false)
	}

	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		if !snapshot.Admitting || snapshot.Active == nil || snapshot.Retiring != nil ||
			snapshot.SlotRepairSuccesses != 4 || snapshot.SlotRepairFailures != 0 {
			return false
		}
		if snapshot.Active.SlotRepairSuccesses != 4 || snapshot.Active.RepairingSlots != 0 {
			return false
		}
		for _, slot := range snapshot.Active.Slots {
			if slot.Failed || slot.Repairing {
				return false
			}
		}
		return true
	})
	if calls := factory.callCount(); calls != 1 {
		t.Fatalf("whole-generation factory calls = %d, want 1", calls)
	}
	if replacementLinks := repairs.snapshotLinks(); len(replacementLinks) != 4 {
		t.Fatalf("replacement links = %d, want 4", len(replacementLinks))
	}
	binding, err := supervisor.Bind(dcID)
	if err != nil {
		t.Fatalf("Bind after complete DC pool repair: %v", err)
	}
	if binding.state.manager != active.manager.state {
		t.Fatal("complete DC pool repair moved admission away from the active generation")
	}
	if err := binding.Close(); err != nil {
		t.Fatalf("Close binding: %v", err)
	}
}

func TestGenerationSupervisorLostOneDCCoverageKeepsOtherDCAdmittingDuringRepair(t *testing.T) {
	const (
		failedDC  DCID = -203
		healthyDC DCID = 2
	)
	config := GenerationSupervisorConfig{
		PreparationTimeout:   time.Second,
		ProbeInterval:        5 * time.Millisecond,
		ProbeFailureTimeout:  200 * time.Millisecond,
		DrainTimeout:         time.Second,
		RepairBackoffInitial: time.Millisecond,
		RepairBackoffMaximum: 5 * time.Millisecond,
	}
	var failedResponders []*atomic.Bool
	slots := make([]FixedBindingSlot, 0, 5)
	for range 4 {
		respond := new(atomic.Bool)
		respond.Store(true)
		link := newFixedBindingFakeLink()
		link.afterTry = func(accepted bool) {
			if !accepted || !respond.Load() {
				return
			}
			attempted := link.attemptedSubmissions()
			ping, err := ParsePing(attempted[len(attempted)-1].Payload)
			if err == nil {
				link.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
			}
		}
		failedResponders = append(failedResponders, respond)
		slots = append(slots, FixedBindingSlot{DCID: failedDC, Link: link})
	}
	healthyLink := newFixedBindingFakeLink()
	healthyLink.afterTry = func(accepted bool) {
		if !accepted {
			return
		}
		attempted := healthyLink.attemptedSubmissions()
		ping, err := ParsePing(attempted[len(attempted)-1].Payload)
		if err == nil {
			healthyLink.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
		}
	}
	slots = append(slots, FixedBindingSlot{DCID: healthyDC, Link: healthyLink})
	releaseRepairs := make(chan struct{})
	repairEntered := make(chan struct{})
	repairs := &generationSlotRepairTestFactory{gate: releaseRepairs, entered: repairEntered}
	active, err := newFixedBindingManager(slots, fixedBindingTestLimits(), repairs.build)
	if err != nil {
		t.Fatal(err)
	}
	factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active}}}
	supervisor := newGenerationTestSupervisor(t, config)
	if err := supervisor.Start(t.Context(), factory.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for _, respond := range failedResponders {
		respond.Store(false)
	}
	select {
	case <-repairEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("complete DC pool repair did not start")
	}
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return snapshot.Admitting && snapshot.Active != nil && snapshot.Active.RepairingSlots == 4 &&
			snapshot.Retiring == nil
	})
	binding, err := supervisor.Bind(healthyDC)
	if err != nil {
		t.Fatalf("Bind healthy DC during other DC repair: %v", err)
	}
	if binding.state.manager != active.state || binding.state.slot.link != healthyLink {
		t.Fatal("healthy DC binding moved away from the active generation during other DC repair")
	}
	if calls := factory.callCount(); calls != 1 {
		t.Fatalf("whole-generation factory calls during DC pool repair = %d, want 1", calls)
	}
	close(releaseRepairs)
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return snapshot.Admitting && snapshot.Active != nil && snapshot.Active.RepairingSlots == 0 &&
			snapshot.SlotRepairSuccesses == 4 && snapshot.Retiring == nil
	})
	if err := binding.Close(); err != nil {
		t.Fatalf("Close binding: %v", err)
	}
}

func TestGenerationSupervisorFailedActiveFallsBackUntilReplacement(t *testing.T) {
	dcIDs := []DCID{1}
	config := GenerationSupervisorConfig{
		PreparationTimeout:   time.Second,
		ProbeInterval:        5 * time.Millisecond,
		ProbeFailureTimeout:  30 * time.Millisecond,
		DrainTimeout:         time.Second,
		RepairBackoffInitial: time.Millisecond,
		RepairBackoffMaximum: 5 * time.Millisecond,
	}
	active := newGenerationTestManager(t, dcIDs, true)
	replacement := newGenerationTestManager(t, dcIDs, true)
	releaseReplacement := make(chan struct{})
	factory := &generationTestFactory{steps: []generationTestFactoryStep{
		{manager: active.manager},
		{manager: replacement.manager, gate: releaseReplacement},
	}}
	supervisor := newGenerationTestSupervisor(t, config)
	if err := supervisor.Start(t.Context(), factory.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	active.respond.Store(false)
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return !snapshot.Admitting && snapshot.Repairing && len(snapshot.ActiveDCIDs) == 0
	})
	if _, err := supervisor.Bind(1); !errors.Is(err, ErrGenerationUnavailable) {
		t.Fatalf("Bind while unprotected error = %v", err)
	}
	close(releaseReplacement)
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return snapshot.Admitting && slices.Equal(snapshot.ActiveDCIDs, dcIDs)
	})
	binding, err := supervisor.Bind(1)
	if err != nil {
		t.Fatalf("Bind after repair: %v", err)
	}
	if binding.state.manager != replacement.manager.state {
		t.Fatal("binding did not use the replacement active generation")
	}
	if err := binding.Close(); err != nil {
		t.Fatalf("Close binding: %v", err)
	}
}

func TestGenerationSupervisorFailedActiveDrainsHealthyPooledBindings(t *testing.T) {
	const dcID DCID = 1
	dcIDs := []DCID{dcID}
	config := GenerationSupervisorConfig{
		PreparationTimeout:   time.Second,
		ProbeInterval:        5 * time.Millisecond,
		ProbeFailureTimeout:  30 * time.Millisecond,
		DrainTimeout:         time.Second,
		RepairBackoffInitial: time.Millisecond,
		RepairBackoffMaximum: 5 * time.Millisecond,
	}
	active := newPooledGenerationTestManager(t, dcID, true, true)
	replacement := newGenerationTestManager(t, dcIDs, true)
	releaseReplacement := make(chan struct{})
	factory := &generationTestFactory{steps: []generationTestFactoryStep{
		{manager: active.manager},
		{manager: replacement.manager, gate: releaseReplacement},
	}}
	supervisor := newGenerationTestSupervisor(t, config)
	if err := supervisor.Start(t.Context(), factory.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	failedBinding, err := supervisor.Bind(dcID)
	if err != nil {
		t.Fatalf("Bind failed-link client: %v", err)
	}
	healthyBinding, err := supervisor.Bind(dcID)
	if err != nil {
		t.Fatalf("Bind healthy-link client: %v", err)
	}
	if failedBinding.state.slot.link != active.links[0] || healthyBinding.state.slot.link != active.links[1] {
		t.Fatal("pooled bindings did not distribute across both active links")
	}

	active.responds[0].Store(false)
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return !snapshot.Admitting && snapshot.Repairing &&
			len(snapshot.ActiveDCIDs) == 0 && slices.Equal(snapshot.RetiringDCIDs, dcIDs)
	})

	eventContext, cancelEvent := context.WithTimeout(t.Context(), time.Second)
	defer cancelEvent()
	if _, err := failedBinding.NextEvent(eventContext); !errors.Is(err, ErrFixedBindingSlotFailed) {
		t.Fatalf("failed-link binding event error = %v", err)
	}
	select {
	case <-active.manager.Done():
		t.Fatal("failed active manager closed while a healthy pooled binding remained")
	default:
	}

	active.links[1].emit(LinkEvent{
		Kind:         LinkEventSimpleAck,
		ConnectionID: healthyBinding.ConnectionID(),
		ConfirmKey:   23,
	})
	event, err := healthyBinding.NextEvent(eventContext)
	if err != nil || event.Kind != LinkEventSimpleAck || event.ConfirmKey != 23 {
		t.Fatalf("healthy retiring binding event = %+v, %v", event, err)
	}

	close(releaseReplacement)
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return snapshot.Admitting && slices.Equal(snapshot.ActiveDCIDs, dcIDs) &&
			slices.Equal(snapshot.RetiringDCIDs, dcIDs)
	})
	select {
	case <-active.manager.Done():
		t.Fatal("repair closed the old active manager before its healthy binding drained")
	default:
	}
	if err := healthyBinding.Close(); err != nil {
		t.Fatalf("Close healthy binding: %v", err)
	}
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return len(snapshot.RetiringDCIDs) == 0
	})
	select {
	case <-active.manager.Done():
	case <-time.After(time.Second):
		t.Fatal("failed active manager did not close after its healthy binding drained")
	}
}

func TestGenerationSupervisorFailedActiveDisplacesOlderRetiringBeforeRepair(t *testing.T) {
	const dcID DCID = 1
	dcIDs := []DCID{dcID}
	config := GenerationSupervisorConfig{
		PreparationTimeout:   time.Second,
		ProbeInterval:        5 * time.Millisecond,
		ProbeFailureTimeout:  30 * time.Millisecond,
		DrainTimeout:         time.Second,
		RepairBackoffInitial: time.Millisecond,
		RepairBackoffMaximum: 5 * time.Millisecond,
	}
	oldActive := newGenerationTestManager(t, dcIDs, true)
	initial := &generationTestFactory{steps: []generationTestFactoryStep{{manager: oldActive.manager}}}
	newActive := newGenerationTestManager(t, dcIDs, true)
	replacement := newGenerationTestManager(t, dcIDs, true)
	releaseReplacement := make(chan struct{})
	rotation := &generationTestFactory{steps: []generationTestFactoryStep{
		{manager: newActive.manager},
		{manager: replacement.manager, gate: releaseReplacement},
	}}
	supervisor := newGenerationTestSupervisor(t, config)
	if err := supervisor.Start(t.Context(), initial.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	oldBinding, err := supervisor.Bind(dcID)
	if err != nil {
		t.Fatalf("Bind old active: %v", err)
	}
	if err := supervisor.Rotate(t.Context(), rotation.build); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	newActive.respond.Store(false)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for rotation.callCount() < 2 {
		select {
		case <-deadline.C:
			t.Fatal("repair did not enter the replacement factory")
		case <-ticker.C:
		}
	}
	select {
	case <-oldActive.manager.Done():
	default:
		t.Fatal("older retiring manager remained live when repair construction began")
	}
	managers := []generationTestManager{oldActive, newActive, replacement}
	if live := countStartedLiveGenerationTestManagers(managers); live > 2 {
		t.Fatalf("live managers during failed-active repair = %d, want at most 2", live)
	}
	eventContext, cancelEvent := context.WithTimeout(t.Context(), time.Second)
	defer cancelEvent()
	if _, err := oldBinding.NextEvent(eventContext); err == nil {
		t.Fatal("displaced retiring binding did not receive a terminal error")
	}

	close(releaseReplacement)
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return snapshot.Admitting && slices.Equal(snapshot.ActiveDCIDs, dcIDs)
	})
}

func TestGenerationSupervisorStartupFailureFallsBackUntilRepair(t *testing.T) {
	dcIDs := []DCID{1}
	config := GenerationSupervisorConfig{
		PreparationTimeout:   time.Second,
		ProbeInterval:        5 * time.Millisecond,
		ProbeFailureTimeout:  30 * time.Millisecond,
		DrainTimeout:         time.Second,
		RepairBackoffInitial: time.Millisecond,
		RepairBackoffMaximum: 5 * time.Millisecond,
	}
	active := newGenerationTestManager(t, dcIDs, true)
	releaseRepair := make(chan struct{})
	factory := &generationTestFactory{steps: []generationTestFactoryStep{
		{err: errGenerationTestFactoryExhausted},
		{manager: active.manager, gate: releaseRepair},
	}}
	supervisor := newGenerationTestSupervisor(t, config)
	if err := supervisor.Start(t.Context(), factory.build); !errors.Is(err, errGenerationTestFactoryExhausted) {
		t.Fatalf("Start error = %v, want factory failure", err)
	}
	if snapshot := supervisor.Snapshot(); snapshot.Admitting || len(snapshot.ActiveDCIDs) != 0 {
		t.Fatalf("failed-start snapshot = %+v", snapshot)
	}
	if _, err := supervisor.Bind(1); !errors.Is(err, ErrGenerationUnavailable) {
		t.Fatalf("Bind during startup repair error = %v", err)
	}
	close(releaseRepair)
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return snapshot.Admitting && !snapshot.Repairing
	})
}

func TestGenerationSupervisorFirstFactoryFailureRetainsRepairFactory(t *testing.T) {
	dcIDs := []DCID{1}
	active := newGenerationTestManager(t, dcIDs, true)
	factory := &generationTestFactory{steps: []generationTestFactoryStep{
		{err: errGenerationTestFactoryExhausted},
		{manager: active.manager},
	}}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), factory.build); !errors.Is(err, errGenerationTestFactoryExhausted) {
		t.Fatalf("Start error = %v, want first factory failure", err)
	}
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return snapshot.Admitting && slices.Equal(snapshot.ActiveDCIDs, dcIDs)
	})
	if calls := factory.callCount(); calls != 2 {
		t.Fatalf("factory calls after repair = %d, want 2", calls)
	}
}

func TestGenerationSupervisorReadinessIncludesRetiringBinding(t *testing.T) {
	dcIDs := []DCID{1}
	oldActive := newGenerationTestManager(t, dcIDs, true)
	initial := &generationTestFactory{steps: []generationTestFactoryStep{{manager: oldActive.manager}}}
	newActive := newGenerationTestManager(t, dcIDs, true)
	rotation := &generationTestFactory{steps: []generationTestFactoryStep{{manager: newActive.manager}}}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), initial.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	binding, err := supervisor.Bind(1)
	if err != nil {
		t.Fatalf("Bind old: %v", err)
	}
	if err := supervisor.Rotate(t.Context(), rotation.build); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	oldActive.links[1].emit(LinkEvent{
		Kind:         LinkEventSimpleAck,
		ConnectionID: binding.ConnectionID(),
		ConfirmKey:   17,
	})
	token := waitGenerationReadyToken(t, supervisor, time.Second)
	if token.ConnectionID() != binding.ConnectionID() || token.DCID() != 1 {
		t.Fatalf("retiring token = %v", token)
	}
	event, ok, err := token.TryNextEvent()
	if err != nil || !ok || event.Kind != LinkEventSimpleAck || event.ConfirmKey != 17 {
		t.Fatalf("retiring event = %+v, %t, %v", event, ok, err)
	}
	if err := token.Ack(); err != nil {
		t.Fatalf("Ack retiring token: %v", err)
	}
	if err := binding.Close(); err != nil {
		t.Fatalf("Close retiring binding: %v", err)
	}
}

func TestGenerationSupervisorDrainDeadlineForceClosesRetiring(t *testing.T) {
	dcIDs := []DCID{1}
	config := generationTestConfig()
	config.DrainTimeout = 20 * time.Millisecond
	oldActive := newGenerationTestManager(t, dcIDs, true)
	initial := &generationTestFactory{steps: []generationTestFactoryStep{{manager: oldActive.manager}}}
	newActive := newGenerationTestManager(t, dcIDs, true)
	rotation := &generationTestFactory{steps: []generationTestFactoryStep{{manager: newActive.manager}}}
	supervisor := newGenerationTestSupervisor(t, config)
	if err := supervisor.Start(t.Context(), initial.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := supervisor.Bind(1); err != nil {
		t.Fatalf("Bind old: %v", err)
	}
	if err := supervisor.Rotate(t.Context(), rotation.build); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return len(snapshot.RetiringDCIDs) == 0 && errors.Is(snapshot.LastError, ErrGenerationDrainTimeout)
	})
	select {
	case <-oldActive.manager.Done():
	case <-time.After(time.Second):
		t.Fatal("retiring manager did not close after drain deadline")
	}
	_, _, closes, _, _ := oldActive.links[1].stats()
	if closes != 1 {
		t.Fatalf("retiring link closes = %d, want 1", closes)
	}
}

func TestGenerationSupervisorRejectsFactoryManagerReuse(t *testing.T) {
	manager := newGenerationTestManager(t, []DCID{1}, true)
	factory := &generationTestFactory{steps: []generationTestFactoryStep{
		{manager: manager.manager},
		{manager: manager.manager},
	}}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), factory.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := supervisor.Rotate(t.Context(), factory.build); !errors.Is(err, ErrInvalidGenerationSupervisor) {
		t.Fatalf("Rotate reused-manager error = %v", err)
	}
	if snapshot := supervisor.Snapshot(); !snapshot.Admitting || snapshot.Retiring != nil {
		t.Fatalf("reused manager disturbed active admission = %+v", snapshot)
	}
	_, _, closes, _, _ := manager.links[1].stats()
	if closes != 0 {
		t.Fatalf("owned manager closed during duplicate rejection = %d", closes)
	}
}

func TestGenerationSupervisorCloseCancelsConcurrentRotation(t *testing.T) {
	dcIDs := []DCID{1}
	active := newGenerationTestManager(t, dcIDs, true)
	initial := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	if err := supervisor.Start(t.Context(), initial.build); err != nil {
		t.Fatalf("Start: %v", err)
	}
	releaseRotation := make(chan struct{})
	rotation := &generationTestFactory{steps: []generationTestFactoryStep{{gate: releaseRotation}}}
	rotateResult := make(chan error, 1)
	go func() { rotateResult <- supervisor.Rotate(t.Context(), rotation.build) }()
	deadline := time.Now().Add(time.Second)
	for rotation.callCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if rotation.callCount() != 1 {
		t.Fatal("rotation factory was not entered")
	}

	const callers = 8
	closeResults := make(chan error, callers)
	for range callers {
		go func() { closeResults <- supervisor.Close() }()
	}
	for range callers {
		if err := <-closeResults; err != nil {
			t.Fatalf("concurrent Close: %v", err)
		}
	}
	if err := <-rotateResult; err == nil {
		t.Fatal("Rotate succeeded during Close")
	}
	select {
	case <-supervisor.Done():
	default:
		t.Fatal("Done did not close")
	}
	if _, err := supervisor.Bind(1); !errors.Is(err, ErrGenerationUnavailable) {
		t.Fatalf("Bind after Close error = %v", err)
	}
}

func waitGenerationCondition(
	t testing.TB,
	supervisor *FixedBindingGenerationSupervisor,
	timeout time.Duration,
	predicate func(GenerationSupervisorSnapshot) bool,
) GenerationSupervisorSnapshot {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot := supervisor.Snapshot()
		if predicate(snapshot) {
			return snapshot
		}
		select {
		case <-deadline.C:
			t.Fatalf("generation condition not reached; last snapshot = %+v", snapshot)
		case <-ticker.C:
		}
	}
}

func waitGenerationReadyToken(
	t testing.TB,
	supervisor *FixedBindingGenerationSupervisor,
	timeout time.Duration,
) *ClientReadyToken {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if token := supervisor.TryNextReady(); token != nil {
			return token
		}
		select {
		case <-supervisor.Ready():
		case <-deadline.C:
			t.Fatal("generation readiness token not published")
		}
	}
}

func waitGenerationTestLinkStarts(t testing.TB, link *fixedBindingFakeLink, want int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		starts, _, _, _, _ := link.stats()
		if starts == want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("link start calls = %d, want %d", starts, want)
		case <-ticker.C:
		}
	}
}

func countStartedLiveGenerationTestManagers(managers []generationTestManager) int {
	live := 0
	for _, manager := range managers {
		started := false
		for _, link := range manager.links {
			starts, _, _, _, _ := link.stats()
			started = started || starts != 0
		}
		if !started {
			continue
		}
		select {
		case <-manager.manager.Done():
		default:
			live++
		}
	}
	return live
}
