package middleend

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestGenerationCoordinatorPendingDoesNotBlockDueFetch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := fixtureArtifacts(t)
	pendingRaw := changedCoordinatorArtifacts(t, raw, "198.51.100.112:8888")
	latestRaw := changedCoordinatorArtifacts(t, raw, "198.51.100.212:8888")
	source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: raw}, {raw: pendingRaw}, {raw: latestRaw}}}
	cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
	dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
	initial := newGenerationTestManager(t, dcIDs, true)
	latest := newGenerationTestManager(t, dcIDs, true)
	unavailable := errors.New("pending candidate unavailable")
	initialFactory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: initial.manager}}}
	pendingFactory := &generationTestFactory{steps: []generationTestFactoryStep{{err: unavailable}, {err: unavailable}}}
	latestFactory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: latest.manager}}}
	factories := []*generationTestFactory{initialFactory, pendingFactory, latestFactory}
	var builds int
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
		factory := factories[builds]
		builds++
		return factory.build, nil
	}, func() time.Time { return now })
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	now = now.Add(TelegramArtifactRefreshInterval)
	if err := coordinator.Reconcile(t.Context()); !errors.Is(err, unavailable) {
		t.Fatalf("pending reconcile: %v", err)
	}
	now = now.Add(TelegramArtifactRefreshInterval)
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("latest reconcile retried obsolete pending content: %v", err)
	}
	if builds != 3 || pendingFactory.callCount() != 1 || latestFactory.callCount() != 1 {
		t.Fatalf("builds=%d pending calls=%d latest calls=%d", builds, pendingFactory.callCount(), latestFactory.callCount())
	}
	snapshot := coordinator.Snapshot()
	if snapshot.Pending || snapshot.RefreshSuccesses != 3 || snapshot.GenerationSuccesses != 2 || snapshot.GenerationFailures != 1 {
		t.Fatalf("coordinator snapshot: %+v", snapshot)
	}
	assertCoordinatorActiveManager(t, supervisor, latest.manager)
}

func TestGenerationCoordinatorDueFetchPreservesPendingFactory(t *testing.T) {
	for _, fetchFails := range []bool{false, true} {
		name := "identical_pending"
		if fetchFails {
			name = "fetch_failure"
		}
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1_700_000_000, 0)
			raw := fixtureArtifacts(t)
			changed := changedCoordinatorArtifacts(t, raw, "198.51.100.112:8888")
			outage := errors.New("fetch unavailable")
			last := artifactSourceResult{raw: changed}
			if fetchFails {
				last = artifactSourceResult{err: outage}
			}
			source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: raw}, {raw: changed}, last}}
			cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
			dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
			initial := newGenerationTestManager(t, dcIDs, true)
			latest := newGenerationTestManager(t, dcIDs, true)
			unavailable := errors.New("candidate unavailable")
			initialFactory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: initial.manager}}}
			pendingFactory := &generationTestFactory{steps: []generationTestFactoryStep{{err: unavailable}, {manager: latest.manager}}}
			var builds int
			supervisor := newGenerationTestSupervisor(t, generationTestConfig())
			coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
				builds++
				if builds == 1 {
					return initialFactory.build, nil
				}
				return pendingFactory.build, nil
			}, func() time.Time { return now })
			if err := coordinator.Reconcile(t.Context()); err != nil {
				t.Fatalf("initial reconcile: %v", err)
			}
			now = now.Add(TelegramArtifactRefreshInterval)
			if err := coordinator.Reconcile(t.Context()); !errors.Is(err, unavailable) {
				t.Fatalf("pending reconcile: %v", err)
			}
			plan := coordinator.state.pendingBuild
			pendingFetchedAt := now
			now = now.Add(TelegramArtifactRefreshInterval)
			err := coordinator.Reconcile(t.Context())
			if fetchFails && !errors.Is(err, outage) || !fetchFails && err != nil {
				t.Fatalf("due reconcile: %v", err)
			}
			if builds != 2 || pendingFactory.callCount() != 2 || coordinator.state.appliedBuild != plan {
				t.Fatalf("cached plan not retained: builds=%d calls=%d", builds, pendingFactory.callCount())
			}
			snapshot := coordinator.Snapshot()
			if snapshot.Pending || snapshot.GenerationSuccesses != 2 || snapshot.GenerationFailures != 1 {
				t.Fatalf("generation outcomes: %+v", snapshot)
			}
			if fetchFails {
				if snapshot.RefreshSuccesses != 2 || snapshot.RefreshFailures != 1 || !errors.Is(snapshot.LastError, outage) || !snapshot.AppliedFetchedAt.Equal(pendingFetchedAt) {
					t.Fatalf("independent refresh failure lost: %+v", snapshot)
				}
				assertCoordinatorRetryDelay(t, coordinator)
			} else if snapshot.RefreshSuccesses != 3 || snapshot.RefreshFailures != 0 || snapshot.LastError != nil || !snapshot.AppliedFetchedAt.Equal(now) {
				t.Fatalf("identical refresh outcomes: %+v", snapshot)
			}
			assertCoordinatorActiveManager(t, supervisor, latest.manager)
		})
	}
}

func TestGenerationCoordinatorReversionRestoresAppliedRecoveryFactory(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := fixtureArtifacts(t)
	changed := changedCoordinatorArtifacts(t, raw, "198.51.100.112:8888")
	source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: raw}, {raw: changed}, {raw: raw}}}
	cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
	dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
	initial := newGenerationTestManager(t, dcIDs, true)
	initialFactory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: initial.manager}}}
	unavailable := errors.New("candidate unavailable")
	pendingFactory := &generationTestFactory{steps: []generationTestFactoryStep{{err: unavailable}}}
	var builds int
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
		builds++
		if builds == 1 {
			return initialFactory.build, nil
		}
		return pendingFactory.build, nil
	}, func() time.Time { return now })
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	appliedPlan := coordinator.state.appliedBuild
	binding, err := supervisor.Bind(dcIDs[0])
	if err != nil {
		t.Fatalf("bind initial: %v", err)
	}
	defer binding.Close()
	now = now.Add(TelegramArtifactRefreshInterval)
	if err := coordinator.Reconcile(t.Context()); !errors.Is(err, unavailable) {
		t.Fatalf("pending reconcile: %v", err)
	}
	supervisor.state.mu.Lock()
	lastPlan := supervisor.state.lastPlan
	supervisor.state.mu.Unlock()
	if lastPlan != coordinator.state.pendingBuild || lastPlan == appliedPlan {
		t.Fatal("failed candidate did not become the retained recovery source")
	}
	now = now.Add(TelegramArtifactRefreshInterval)
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("revert reconcile: %v", err)
	}
	assertCoordinatorActiveManager(t, supervisor, initial.manager)
	supervisor.state.mu.Lock()
	lastPlan = supervisor.state.lastPlan
	supervisor.state.mu.Unlock()
	if lastPlan != appliedPlan || coordinator.state.appliedBuild != appliedPlan {
		t.Fatal("reversion did not restore the applied recovery source")
	}
	if builds != 2 || pendingFactory.callCount() != 1 || initialFactory.callCount() != 1 {
		t.Fatalf("reversion rebuilt or applied an obsolete candidate: builds=%d", builds)
	}
	snapshot := coordinator.Snapshot()
	if snapshot.Pending || snapshot.GenerationSuccesses != 1 || snapshot.GenerationFailures != 1 || snapshot.RefreshSuccesses != 3 {
		t.Fatalf("reversion outcomes: %+v", snapshot)
	}
	select {
	case <-initial.manager.Done():
		t.Fatal("unchanged active manager closed during reversion")
	default:
	}
}

func TestGenerationCoordinatorReversionCountsPublicationAfterPendingRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Unix(1_700_000_000, 0)
		raw := fixtureArtifacts(t)
		changed := changedCoordinatorArtifacts(t, raw, "198.51.100.112:8888")
		source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: raw}, {raw: changed}, {raw: raw}}}
		cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
		dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
		initial := newGenerationTestManager(t, dcIDs, true)
		reverted := newGenerationTestManager(t, dcIDs, true)
		recovered := newGenerationTestManager(t, dcIDs, true)
		initialFactory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: initial.manager}, {manager: reverted.manager}}}
		unavailable := errors.New("candidate unavailable")
		pendingFactory := &generationTestFactory{steps: []generationTestFactoryStep{{err: unavailable}, {manager: recovered.manager}}}
		var builds int
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
			builds++
			if builds == 1 {
				return initialFactory.build, nil
			}
			return pendingFactory.build, nil
		}, func() time.Time { return now })
		if err := coordinator.Reconcile(t.Context()); err != nil {
			t.Fatalf("initial reconcile: %v", err)
		}
		appliedPlan := coordinator.state.appliedBuild
		now = now.Add(TelegramArtifactRefreshInterval)
		if err := coordinator.Reconcile(t.Context()); !errors.Is(err, unavailable) {
			t.Fatalf("pending reconcile: %v", err)
		}
		supervisor.state.mu.Lock()
		failed := supervisor.state.active
		supervisor.state.mu.Unlock()
		supervisor.state.failGeneration(failed, errors.New("manager-wide failure"))
		synctest.Wait()
		assertCoordinatorActiveManager(t, supervisor, recovered.manager)
		if coordinator.Snapshot().GenerationSuccesses != 1 {
			t.Fatal("background publication counted as coordinator application before acknowledgment")
		}
		now = now.Add(TelegramArtifactRefreshInterval)
		if err := coordinator.Reconcile(t.Context()); err != nil {
			t.Fatalf("revert reconcile: %v", err)
		}
		assertCoordinatorActiveManager(t, supervisor, reverted.manager)
		if builds != 2 || initialFactory.callCount() != 2 || pendingFactory.callCount() != 2 || coordinator.state.appliedBuild != appliedPlan {
			t.Fatalf("reversion did not reuse the applied factory: builds=%d", builds)
		}
		if snapshot := coordinator.Snapshot(); snapshot.GenerationSuccesses != 2 || snapshot.GenerationFailures != 1 || snapshot.Pending {
			t.Fatalf("actual reversion publication was not counted once: %+v", snapshot)
		}
	})
}

func TestGenerationCoordinatorUnchangedFetchPreservesLiveRetiree(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := fixtureArtifacts(t)
	changed := changedCoordinatorArtifacts(t, raw, "198.51.100.112:8888")
	source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: raw}, {raw: changed}, {raw: changed}}}
	cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
	dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
	initial := newGenerationTestManager(t, dcIDs, true)
	latest := newGenerationTestManager(t, dcIDs, true)
	factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: initial.manager}, {manager: latest.manager}}}
	var builds int
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
		builds++
		return factory.build, nil
	}, func() time.Time { return now })
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	binding, err := supervisor.Bind(dcIDs[0])
	if err != nil {
		t.Fatalf("bind initial: %v", err)
	}
	defer binding.Close()
	for range 2 {
		now = now.Add(TelegramArtifactRefreshInterval)
		if err := coordinator.Reconcile(t.Context()); err != nil {
			t.Fatalf("refresh reconcile: %v", err)
		}
	}
	supervisor.state.mu.Lock()
	retiring := supervisor.state.retiring
	supervisor.state.mu.Unlock()
	if retiring == nil || retiring.manager != initial.manager {
		t.Fatal("unchanged artifact fetch removed the live retiree")
	}
	select {
	case <-initial.manager.Done():
		t.Fatal("unchanged artifact fetch closed the live retiree")
	default:
	}
	if snapshot := coordinator.Snapshot(); snapshot.GenerationSuccesses != 2 || snapshot.RefreshSuccesses != 3 || snapshot.Pending || builds != 2 || factory.callCount() != 2 {
		t.Fatalf("unchanged artifact caused another application: %+v, builds=%d", snapshot, builds)
	}
}

func TestGenerationCoordinatorFactoryValidationPrecedesRetireeEviction(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := fixtureArtifacts(t)
	changed := changedCoordinatorArtifacts(t, raw, "198.51.100.112:8888")
	invalidFactory := changedCoordinatorArtifacts(t, raw, "198.51.100.212:8888")
	source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: raw}, {raw: changed}, {raw: invalidFactory}}}
	cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
	dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
	initial := newGenerationTestManager(t, dcIDs, true)
	latest := newGenerationTestManager(t, dcIDs, true)
	factory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: initial.manager}, {manager: latest.manager}}}
	invalid := errors.New("factory validation failed")
	var builds int
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
		builds++
		if builds > 2 {
			return nil, invalid
		}
		return factory.build, nil
	}, func() time.Time { return now })
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	binding, err := supervisor.Bind(dcIDs[0])
	if err != nil {
		t.Fatalf("bind initial: %v", err)
	}
	defer binding.Close()
	now = now.Add(TelegramArtifactRefreshInterval)
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("rotation reconcile: %v", err)
	}
	now = now.Add(TelegramArtifactRefreshInterval)
	if err := coordinator.Reconcile(t.Context()); !errors.Is(err, invalid) {
		t.Fatalf("invalid factory reconcile: %v", err)
	}
	supervisor.state.mu.Lock()
	retiring := supervisor.state.retiring
	lastPlan := supervisor.state.lastPlan
	supervisor.state.mu.Unlock()
	if retiring == nil || retiring.manager != initial.manager || lastPlan != coordinator.state.appliedBuild {
		t.Fatal("factory validation failure changed the live topology or recovery source")
	}
	select {
	case <-initial.manager.Done():
		t.Fatal("invalid factory evicted the healthy retiree")
	default:
	}
	if coordinator.state.pendingBuild != nil || factory.callCount() != 2 {
		t.Fatal("invalid factory reached generation preparation")
	}
	assertCoordinatorRetryDelay(t, coordinator)
}

func TestGenerationCoordinatorNewArtifactRecoveryUsesLatestValidatedFactory(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	raw := fixtureArtifacts(t)
	changed := changedCoordinatorArtifacts(t, raw, "198.51.100.112:8888")
	source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: raw}, {raw: changed}}}
	cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
	dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
	oldActive := newGenerationTestManager(t, dcIDs, true)
	staleFactory := &generationTestFactory{steps: []generationTestFactoryStep{
		{manager: oldActive.manager},
		{err: errors.New("old artifact credentials no longer work")},
	}}
	newActive := newGenerationTestManager(t, dcIDs, true)
	latestFactory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: newActive.manager}}}
	var builds int
	supervisor := newGenerationTestSupervisor(t, generationTestConfig())
	coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
		builds++
		if builds == 1 {
			return staleFactory.build, nil
		}
		return latestFactory.build, nil
	}, func() time.Time { return now })
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	supervisor.state.mu.Lock()
	failed := supervisor.state.active
	supervisor.state.mu.Unlock()
	supervisor.state.failGeneration(failed, errors.New("manager-wide failure"))
	now = now.Add(TelegramArtifactRefreshInterval)
	if err := coordinator.Reconcile(t.Context()); err != nil {
		t.Fatalf("new validated artifact did not recover absent active generation: %v", err)
	}
	if latestFactory.callCount() != 1 || !supervisor.Snapshot().Admitting {
		t.Fatal("latest factory did not restore admission")
	}
	assertCoordinatorActiveManager(t, supervisor, newActive.manager)
}

func TestGenerationCoordinatorApplyWaitsForMatchingPlanAfterBackgroundRecovery(t *testing.T) {
	for _, test := range []struct {
		name           string
		initialApplied bool
		changed        bool
	}{
		{name: "applied_then_changed", initialApplied: true, changed: true},
		{name: "initial_failure_then_changed", changed: true},
		{name: "initial_failure_then_same_plan"},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Unix(1_700_000_000, 0)
				raw := fixtureArtifacts(t)
				latestRaw := raw
				if test.changed {
					latestRaw = changedCoordinatorArtifacts(t, raw, "198.51.100.112:8888")
				}
				source := &sequenceArtifactSource{results: []artifactSourceResult{{raw: raw}, {raw: latestRaw}}}
				cache := newGenerationCoordinatorTestCache(t, func() time.Time { return now }, source)
				dcIDs := mustParseGenerationCoordinatorSnapshot(t, raw, now).DCIDs()
				initial := newGenerationTestManager(t, dcIDs, true)
				recovered := newGenerationTestManager(t, dcIDs, true)
				latest := newGenerationTestManager(t, dcIDs, true)
				t.Cleanup(func() { _ = initial.manager.Close(); _ = recovered.manager.Close(); _ = latest.manager.Close() })
				entered := make(chan struct{})
				release := make(chan struct{})
				releaseRecovery := sync.OnceFunc(func() { close(release) })
				defer releaseRecovery()
				latestBuilt := make(chan struct{})
				initialFailure := errors.New("initial candidate failed")
				var oldCalls atomic.Int32
				oldFactory := func(ctx context.Context) (*FixedBindingManager, error) {
					switch oldCalls.Add(1) {
					case 1:
						if test.initialApplied {
							return initial.manager, nil
						}
						return nil, initialFailure
					case 2:
						close(entered)
						select {
						case <-release:
							return recovered.manager, nil
						case <-ctx.Done():
							return nil, context.Cause(ctx)
						}
					default:
						return nil, errGenerationTestFactoryExhausted
					}
				}
				latestFactory := &generationTestFactory{steps: []generationTestFactoryStep{{manager: latest.manager}}}
				var builds int
				supervisor := newGenerationTestSupervisor(t, generationTestConfig())
				coordinator := newGenerationCoordinatorForTest(t, cache, supervisor, func(ArtifactSnapshot) (FixedBindingGenerationFactory, error) {
					builds++
					if builds == 1 {
						return oldFactory, nil
					}
					close(latestBuilt)
					return latestFactory.build, nil
				}, func() time.Time { return now })
				err := coordinator.Reconcile(t.Context())
				if test.initialApplied {
					if err != nil {
						t.Fatalf("initial reconcile: %v", err)
					}
					supervisor.state.mu.Lock()
					failed := supervisor.state.active
					supervisor.state.mu.Unlock()
					supervisor.state.failGeneration(failed, errors.New("manager-wide failure"))
				} else if !errors.Is(err, initialFailure) {
					t.Fatalf("initial failure: %v", err)
				}
				<-entered
				now = now.Add(TelegramArtifactRefreshInterval)
				result := make(chan error, 1)
				started := make(chan struct{})
				go func() {
					close(started)
					result <- coordinator.Reconcile(t.Context())
				}()
				<-started
				if test.changed {
					<-latestBuilt
				}
				select {
				case err := <-result:
					t.Fatalf("reconcile returned before gated recovery: %v", err)
				default:
				}
				if snapshot := coordinator.Snapshot(); !snapshot.Pending || snapshot.Applied != test.initialApplied || snapshot.AppliedFetchedAt.Equal(now) {
					t.Fatalf("unpublished content marked applied: %+v", snapshot)
				}
				releaseRecovery()
				if err := <-result; err != nil {
					t.Fatalf("reconcile after old recovery: %v", err)
				}
				wantManager := recovered.manager
				wantBuilds := 1
				if test.changed {
					wantManager = latest.manager
					wantBuilds = 2
				}
				assertCoordinatorActiveManager(t, supervisor, wantManager)
				supervisor.state.mu.Lock()
				activePlan := supervisor.state.active.plan
				supervisor.state.mu.Unlock()
				if activePlan != coordinator.state.appliedBuild || builds != wantBuilds || oldCalls.Load() != 2 {
					t.Fatalf("applied plan mismatch: builds=%d old calls=%d", builds, oldCalls.Load())
				}
				wantSuccesses := uint64(1)
				if test.initialApplied {
					wantSuccesses++
				}
				if snapshot := coordinator.Snapshot(); snapshot.Pending || !snapshot.Applied || !snapshot.AppliedFetchedAt.Equal(now) || snapshot.GenerationSuccesses != wantSuccesses {
					t.Fatalf("application acknowledgment: %+v", snapshot)
				}
			})
		})
	}
}

func assertCoordinatorRetryDelay(t testing.TB, coordinator *GenerationCoordinator) {
	t.Helper()
	for range 20 {
		delay := coordinator.state.nextDelay()
		if delay < time.Second || delay > time.Second+time.Second/2 {
			t.Fatalf("retry delay %v is outside the configured positive-jitter bounds", delay)
		}
	}
}

func changedCoordinatorArtifacts(t testing.TB, raw RawArtifacts, endpoint string) RawArtifacts {
	t.Helper()
	changed := cloneRawArtifacts(raw)
	changed.IPv4Config = bytes.Replace(changed.IPv4Config, []byte("198.51.100.12:8888"), []byte(endpoint), 1)
	if bytes.Equal(changed.IPv4Config, raw.IPv4Config) {
		t.Fatal("changed artifact fixture was not modified")
	}
	return changed
}

func assertCoordinatorActiveManager(t testing.TB, supervisor *FixedBindingGenerationSupervisor, want *FixedBindingManager) {
	t.Helper()
	supervisor.state.mu.Lock()
	defer supervisor.state.mu.Unlock()
	if supervisor.state.active == nil || supervisor.state.active.manager != want {
		t.Fatal("the expected artifact factory did not supply the active manager")
	}
}
