package middleend

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestGenerationCoordinatorConfigValidationAndRedaction(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, nil)
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	valid := GenerationCoordinatorConfig{
		Cache:         cache,
		Supervisor:    supervisor,
		BuildFactory:  func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) { return nil, nil },
		RetryInterval: time.Second,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	invalid := []GenerationCoordinatorConfig{
		{},
		func() GenerationCoordinatorConfig { c := valid; c.Cache = nil; return c }(),
		func() GenerationCoordinatorConfig { c := valid; c.Supervisor = nil; return c }(),
		func() GenerationCoordinatorConfig { c := valid; c.BuildFactory = nil; return c }(),
		func() GenerationCoordinatorConfig { c := valid; c.RetryInterval = 0; return c }(),
	}
	for index, config := range invalid {
		if err := config.Validate(); !errors.Is(err, ErrInvalidGenerationCoordinator) {
			t.Fatalf("invalid config %d error = %v", index, err)
		}
	}
	coordinator, err := newGenerationCoordinator(valid, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newGenerationCoordinator: %v", err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	if got := coordinator.String(); got != "middleend.GenerationCoordinator{redacted}" {
		t.Fatalf("String = %q", got)
	}
	if got := coordinator.GoString(); got != coordinator.String() {
		t.Fatalf("GoString = %q", got)
	}
	if err := coordinator.Trigger(); !errors.Is(err, ErrInvalidGenerationCoordinator) {
		t.Fatalf("Trigger before Start error = %v", err)
	}
	if err := coordinator.Reconcile(nil); !errors.Is(err, ErrInvalidGenerationCoordinator) {
		t.Fatalf("Reconcile nil context error = %v", err)
	}
}

func TestGenerationCoordinatorStartsActiveAndSkipsUnchangedRotation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := fixtureArtifacts(t)
	source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: cloneRawArtifacts(raw)}, {raw: cloneRawArtifacts(raw)}}}
	cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
	dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
	active := newGenerationTestManager(t, dcIDs, true)
	factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
	var builderCalls int
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
		builderCalls++
		return factory.build, nil
	}, func() time.Time { return now })

	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("initial Reconcile: %v", err)
	}
	if snapshot := supervisor.Snapshot(); !snapshot.Admitting {
		t.Fatalf("supervisor has no active generation: %+v", snapshot)
	}
	first := coordinator.Snapshot()
	if !first.Applied || first.Pending || first.RefreshSuccesses != 1 || first.GenerationSuccesses != 1 {
		t.Fatalf("initial coordinator snapshot = %+v", first)
	}

	now = now.Add(TelegramArtifactRefreshInterval)
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("unchanged Reconcile: %v", err)
	}
	second := coordinator.Snapshot()
	if second.RefreshSuccesses != 2 || second.GenerationSuccesses != 1 || second.GenerationFailures != 0 {
		t.Fatalf("unchanged coordinator snapshot = %+v", second)
	}
	if !second.AppliedFetchedAt.Equal(now) {
		t.Fatalf("applied fetch time = %v, want %v", second.AppliedFetchedAt, now)
	}
	if builderCalls != 1 || factory.callCount() != 1 {
		t.Fatalf("builder calls = %d, factory calls = %d; want 1 and 1", builderCalls, factory.callCount())
	}
}

func TestGenerationCoordinatorRetainsChangedFactoryAcrossFailedRotation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := fixtureArtifacts(t)
	changed := cloneRawArtifacts(raw)
	changed.IPv4Config = bytes.Replace(changed.IPv4Config, []byte("198.51.100.12:8888"), []byte("198.51.100.112:8888"), 1)
	if bytes.Equal(changed.IPv4Config, raw.IPv4Config) {
		t.Fatal("changed artifact fixture was not modified")
	}
	source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: cloneRawArtifacts(raw)}, {raw: changed}}}
	cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
	dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
	oldActive := newGenerationTestManager(t, dcIDs, true)
	initial := &generationTestFactory{steps: []generationTestFactoryStep{{manager: oldActive.manager}}}
	newActive := newGenerationTestManager(t, dcIDs, true)
	transient := errors.New("transient candidate failure")
	rotation := &generationTestFactory{steps: []generationTestFactoryStep{
		{err: transient},
		{manager: newActive.manager},
	}}
	var builderMu sync.Mutex
	var builderCalls int
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
		builderMu.Lock()
		defer builderMu.Unlock()
		builderCalls++
		if builderCalls == 1 {
			return initial.build, nil
		}
		return rotation.build, nil
	}, func() time.Time { return now })

	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("initial Reconcile: %v", err)
	}
	now = now.Add(TelegramArtifactRefreshInterval)
	if err := coordinator.Reconcile(t.Context()); !errors.Is(err, transient) {
		t.Fatalf("failed rotation error = %v", err)
	}
	failed := coordinator.Snapshot()
	if !failed.Applied || !failed.Pending || failed.GenerationFailures != 1 {
		t.Fatalf("failed rotation snapshot = %+v", failed)
	}
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return snapshot.Admitting
	})
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("rotation retry: %v", err)
	}
	succeeded := coordinator.Snapshot()
	if !succeeded.Applied || succeeded.Pending || succeeded.GenerationSuccesses != 2 || succeeded.GenerationFailures != 1 {
		t.Fatalf("successful retry snapshot = %+v", succeeded)
	}
	builderMu.Lock()
	gotBuilderCalls := builderCalls
	builderMu.Unlock()
	if gotBuilderCalls != 2 || rotation.callCount() != 2 {
		t.Fatalf("builder calls = %d, rotation factory calls = %d; want 2 and 2", gotBuilderCalls, rotation.callCount())
	}
	binding, err := supervisor.Bind(dcIDs[0])
	if err != nil {
		t.Fatalf("Bind after rotation: %v", err)
	}
	if binding.state.manager != newActive.manager.state {
		t.Fatal("rotation retry did not publish the retained factory's active manager")
	}
	if err := binding.Close(); err != nil {
		t.Fatalf("Close binding: %v", err)
	}
}

func TestGenerationCoordinatorRefreshFailureKeepsLastKnownGoodAdmission(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := fixtureArtifacts(t)
	outage := errors.New("artifact endpoint unavailable")
	source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: cloneRawArtifacts(raw)}, {err: outage}}}
	cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
	dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
	active := newGenerationTestManager(t, dcIDs, true)
	factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
	var builderCalls int
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
		builderCalls++
		return factory.build, nil
	}, func() time.Time { return now })
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("initial Reconcile: %v", err)
	}

	now = now.Add(TelegramArtifactRefreshInterval)
	if err := coordinator.Reconcile(t.Context()); !errors.Is(err, outage) {
		t.Fatalf("refresh outage error = %v", err)
	}
	if snapshot := supervisor.Snapshot(); !snapshot.Admitting {
		t.Fatalf("last-known-good admission was lost: %+v", snapshot)
	}
	snapshot := coordinator.Snapshot()
	if !snapshot.Applied || snapshot.Pending || snapshot.RefreshFailures != 1 || snapshot.GenerationSuccesses != 1 {
		t.Fatalf("outage snapshot = %+v", snapshot)
	}
	if builderCalls != 1 {
		t.Fatalf("builder calls = %d, want 1", builderCalls)
	}
}

func TestGenerationCoordinatorBackgroundRetriesFromDirectFallback(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := fixtureArtifacts(t)
	outage := errors.New("first fetch failed")
	source := &sequenceArtifactSource{results: []artifactSourceResult{{err: outage}, {raw: cloneRawArtifacts(raw)}}}
	cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
	dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
	active := newGenerationTestManager(t, dcIDs, true)
	factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: active.manager}}}
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	coordinator, err := newGenerationCoordinator(GenerationCoordinatorConfig{
		Cache:         cache,
		Supervisor:    supervisor,
		BuildFactory:  func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) { return factory.build, nil },
		RetryInterval: time.Millisecond,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newGenerationCoordinator: %v", err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	if err := coordinator.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitGenerationCondition(t, supervisor, time.Second, func(snapshot GenerationSupervisorSnapshot) bool {
		return snapshot.Admitting
	})
	snapshot := coordinator.Snapshot()
	if !snapshot.Running || !snapshot.Applied || snapshot.RefreshFailures != 1 || snapshot.RefreshSuccesses != 1 {
		t.Fatalf("background retry snapshot = %+v", snapshot)
	}
	if err := coordinator.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-coordinator.Done():
	default:
		t.Fatal("Done did not close")
	}
	if err := coordinator.Trigger(); !errors.Is(err, ErrGenerationCoordinatorClosed) {
		t.Fatalf("Trigger after Close error = %v", err)
	}
}

func newGenerationCoordinatorTestCache(
	t testing.TB,
	now func() time.Time,
	source ArtifactSource,
) *ArtifactCache {
	t.Helper()
	if source == nil {
		source = artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
			return RawArtifacts{}, errors.New("unused artifact source")
		})
	}
	cache, err := newArtifactCache(source, time.Second, now)
	if err != nil {
		t.Fatalf("newArtifactCache: %v", err)
	}
	return cache
}

func newGenerationCoordinatorForTest(
	t testing.TB,
	cache *ArtifactCache,
	supervisor *FixedBindingGenerationSupervisor,
	builder GenerationFactoryBuilder,
	now func() time.Time,
) *GenerationCoordinator {
	t.Helper()
	coordinator, err := newGenerationCoordinator(GenerationCoordinatorConfig{
		Cache:         cache,
		Supervisor:    supervisor,
		BuildFactory:  builder,
		RetryInterval: time.Second,
	}, now)
	if err != nil {
		t.Fatalf("newGenerationCoordinator: %v", err)
	}
	t.Cleanup(func() {
		if err := coordinator.Close(); err != nil {
			t.Errorf("Close coordinator: %v", err)
		}
	})
	return coordinator
}

func mustParseGenerationCoordinatorSnapshot(t testing.TB, raw RawArtifacts, fetchedAt time.Time) ArtifactSnapshot {
	t.Helper()
	snapshot, err := parseArtifactSnapshot(raw, fetchedAt)
	if err != nil {
		t.Fatalf("parseArtifactSnapshot: %v", err)
	}
	return snapshot
}

func cloneRawArtifacts(raw RawArtifacts) RawArtifacts {
	return RawArtifacts{
		Secret:     bytes.Clone(raw.Secret),
		IPv4Config: bytes.Clone(raw.IPv4Config),
		IPv6Config: bytes.Clone(raw.IPv6Config),
	}
}
