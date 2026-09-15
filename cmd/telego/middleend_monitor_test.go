package main

import (
	"testing"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestMiddleEndPayloadCapacityCountsIndependentBudgetsOnce(t *testing.T) {
	snapshot := middleend.ServiceSnapshot{
		Capacity: middleend.ServiceCapacitySnapshot{
			MaxRefreshCandidatesPerManager: 8,
			LinkSubmissionBytes:            11,
			LinkEventBytes:                 13,
			ManagerRequestBytes:            17,
			ManagerControlBytes:            19,
			ManagerResponseBytes:           23,
			BindingResponseBytes:           1_000,
		},
		Supervisor: middleend.GenerationSupervisorSnapshot{
			Active:   &middleend.FixedBindingManagerSnapshot{Slots: make([]middleend.FixedBindingSlotSnapshot, 2)},
			Retiring: &middleend.FixedBindingManagerSnapshot{Slots: make([]middleend.FixedBindingSlotSnapshot, 1)},
		},
	}
	frontend := gproxy.MiddleEndFrontendStats{InputBytesLimit: 29, OutputBytesLimit: 31}

	live, rotation := middleEndPayloadCapacity(snapshot, frontend)
	const managerCapacity = 17 + 19 + 23
	const perLinkCapacity = 11 + 13
	wantLive := int64(29 + 31 + 2*managerCapacity + (3+2*8)*perLinkCapacity)
	wantRotation := int64(29 + 31 + 2*(managerCapacity+(2+8)*perLinkCapacity))
	if live != wantLive || rotation != wantRotation {
		t.Fatalf("payload capacities = live %d rotation %d, want live %d rotation %d", live, rotation, wantLive, wantRotation)
	}
}

func TestMiddleEndPayloadCapacityHandlesMissingGenerations(t *testing.T) {
	live, rotation := middleEndPayloadCapacity(middleend.ServiceSnapshot{
		Capacity: middleend.ServiceCapacitySnapshot{MaxRefreshCandidatesPerManager: 8},
	}, gproxy.MiddleEndFrontendStats{
		InputBytesLimit:  29,
		OutputBytesLimit: 31,
	})
	if live != 60 || rotation != 60 {
		t.Fatalf("payload capacities = live %d rotation %d, want 60 and 60", live, rotation)
	}
}

func TestMiddleEndSharedCapacityCountsPoolOnceAndSeparatesDecoder(t *testing.T) {
	snapshot := middleend.ServiceSnapshot{
		RuntimeLinks: 5,
		Capacity: middleend.ServiceCapacitySnapshot{
			MaxRefreshCandidatesPerManager: 8,
			LinkSubmissionBytes:            11, LinkEventBytes: 13,
			ManagerRequestBytes: 17, ManagerControlBytes: 19,
			ManagerResponseBytes: 23, BindingResponseBytes: 1000,
			ResponseBudgetBytes: 101, EventLoops: 3,
			DecoderBytesPerLink: 1024, DecoderGrowthBytesPerOwner: 1024, DecodePlaintextBytesPerOwner: 64,
		},
		Supervisor: middleend.GenerationSupervisorSnapshot{
			Active:   &middleend.FixedBindingManagerSnapshot{Slots: make([]middleend.FixedBindingSlotSnapshot, 2)},
			Retiring: &middleend.FixedBindingManagerSnapshot{Slots: make([]middleend.FixedBindingSlotSnapshot, 1)},
		},
	}
	frontend := gproxy.MiddleEndFrontendStats{InputBytesLimit: 29, OutputBytesLimit: 31, SharedResponseBudget: true}
	live, rotation := middleEndPayloadCapacity(snapshot, frontend)
	const managerCapacity = 17 + 19
	const perLinkCapacity = 11 + 13
	wantLive := int64(29 + 101 + 2*managerCapacity + (3+2*8)*perLinkCapacity)
	wantRotation := int64(29 + 101 + 2*(managerCapacity+(2+8)*perLinkCapacity))
	if live != wantLive || rotation != wantRotation {
		t.Fatalf("shared capacities = %d/%d, want %d/%d", live, rotation, wantLive, wantRotation)
	}
	decoderLive, decoderRotation, growth, plaintext := middleEndDecoderCapacity(snapshot)
	if decoderLive != 5*1024 || decoderRotation != 2*(2+8)*1024 || growth != 3*1024 || plaintext != 3*64 {
		t.Fatalf("separate decoder capacities = %d/%d, growth %d, plaintext %d", decoderLive, decoderRotation, growth, plaintext)
	}
	snapshot.Supervisor.Active, snapshot.Supervisor.Retiring = nil, nil
	snapshot.RuntimeLinks = 0
	live, rotation = middleEndPayloadCapacity(snapshot, frontend)
	if live != 29+101 || rotation != 29+101 {
		t.Fatal("missing generations lost the service-wide response pool or added legacy output capacity")
	}
	// An unpublished generation has registered links before it appears in the
	// supervisor's published manager snapshots.
	snapshot.RuntimeLinks = 4
	live, rotation = middleEndPayloadCapacity(snapshot, frontend)
	decoderLive, decoderRotation, _, _ = middleEndDecoderCapacity(snapshot)
	if live != 29+101+4*perLinkCapacity || rotation != live || decoderLive != 4*1024 || decoderRotation != decoderLive {
		t.Fatal("unpublished registered links were omitted from current or projected storage")
	}
}

func TestMiddleEndSharedPressureSkipsObsoleteQueueLimits(t *testing.T) {
	monitor := &middleEndMonitor{pressure: make(map[string]middleEndPressureState)}
	frontend := gproxy.MiddleEndFrontendStats{
		InputBytesHighWater: 90, InputBytesLimit: 100,
		OutputBytesHighWater: 999, OutputBytesLimit: 100,
	}
	monitor.observeFrontendPressure(frontend, middleend.ResponseBudgetSnapshot{LimitBytes: 100, HighWaterBytes: 80})
	if _, exists := monitor.pressure["frontend/output/bytes"]; exists {
		t.Fatal("shared output was compared with the old frontend limit")
	}
	if monitor.pressure["service/response_memory/charged_bytes"].value != 80 || monitor.pressure["frontend/input/bytes"].value != 90 {
		t.Fatal("shared pool or independent input pressure was omitted")
	}
	manager := &middleend.FixedBindingManagerSnapshot{RequestBytesHighWater: 90, ResponseBytesHighWater: 999, ResponseItemsHighWater: 900}
	capacity := middleend.ServiceCapacitySnapshot{ResponseBudgetBytes: 100, ManagerRequestBytes: 100, ManagerResponseBytes: 100, ManagerResponseItems: 768}
	monitor.observeManagerPressure("active", manager, capacity)
	if _, exists := monitor.pressure["active/response/bytes"]; exists {
		t.Fatal("shared response queue was compared with the old manager byte limit")
	}
	if _, exists := monitor.pressure["active/response/items"]; exists {
		t.Fatal("shared response queue was compared with the old manager item limit")
	}
	if monitor.pressure["active/request/bytes"].value != 90 {
		t.Fatal("independent manager request pressure was omitted")
	}
	capacity.ResponseBudgetBytes = 0
	monitor.observeManagerPressure("active", manager, capacity)
	monitor.observeFrontendPressure(frontend, middleend.ResponseBudgetSnapshot{})
	if monitor.pressure["active/response/bytes"].value != 999 || monitor.pressure["frontend/output/bytes"].value != 999 {
		t.Fatal("legacy response pressure thresholds changed")
	}
}

func TestMiddleEndMonitorRefreshTotalsUseServiceLifetimeCounters(t *testing.T) {
	snapshot := middleend.GenerationSupervisorSnapshot{
		DCs: []middleend.FixedBindingDCSnapshot{
			{DCID: -2, SlotRefreshSuccesses: 11, SlotRefreshFailures: 2, SlotRefreshCanceled: 3},
			{DCID: 2, SlotRefreshSuccesses: 17, SlotRefreshFailures: 5, SlotRefreshCanceled: 7},
		},
		Active: &middleend.FixedBindingManagerSnapshot{
			DCs: []middleend.FixedBindingDCSnapshot{{DCID: 2, SlotRefreshSuccesses: 1}},
		},
	}
	successes, failures, canceled := middleEndSlotRefreshTotals(snapshot)
	if successes != 28 || failures != 7 || canceled != 10 {
		t.Fatalf("refresh totals = %d/%d/%d, want 28/7/10", successes, failures, canceled)
	}
}

func TestMiddleEndMonitorAggregatesCurrentGenerationBackpressure(t *testing.T) {
	snapshot := middleend.GenerationSupervisorSnapshot{
		Active:   &middleend.FixedBindingManagerSnapshot{ResponseBackpressureEvents: 2, ControlBackpressureEvents: 3},
		Retiring: &middleend.FixedBindingManagerSnapshot{ResponseBackpressureEvents: 11, ControlBackpressureEvents: 13},
	}
	response, control := middleEndBackpressureTotals(snapshot)
	if response != 13 || control != 16 {
		t.Fatalf("backpressure totals = response %d control %d", response, control)
	}
}

func TestMiddleEndMonitorAggregatesRepairingSlots(t *testing.T) {
	snapshot := middleend.GenerationSupervisorSnapshot{
		Active:   &middleend.FixedBindingManagerSnapshot{RepairingSlots: 1},
		Retiring: &middleend.FixedBindingManagerSnapshot{RepairingSlots: 3},
	}
	if total := middleEndRepairingSlots(snapshot); total != 4 {
		t.Fatalf("repairing slots = %d, want 4", total)
	}
}

func TestMiddleEndMonitorCounterIncrease(t *testing.T) {
	for _, test := range []struct {
		name     string
		current  uint64
		previous uint64
		want     uint64
	}{
		{name: "increase", current: 17, previous: 12, want: 5},
		{name: "unchanged", current: 12, previous: 12},
		{name: "counter reset", current: 3, previous: 12},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := middleEndCounterIncrease(test.current, test.previous); got != test.want {
				t.Fatalf("counter increase = %d, want %d", got, test.want)
			}
		})
	}
}

func TestMiddleEndSlotFailureHasClientImpact(t *testing.T) {
	if middleEndSlotFailureHasClientImpact(0) {
		t.Fatal("slot failure without affected bindings has client impact")
	}
	if !middleEndSlotFailureHasClientImpact(1) {
		t.Fatal("slot failure with an affected binding lacks client impact")
	}
}

func TestMiddleEndGenerationFailureRecovered(t *testing.T) {
	for _, test := range []struct {
		name        string
		coordinator middleend.GenerationCoordinatorSnapshot
		admitting   bool
		want        bool
	}{
		{
			name:        "initial generation repaired by supervisor",
			coordinator: middleend.GenerationCoordinatorSnapshot{Pending: true},
			admitting:   true,
			want:        true,
		},
		{
			name:        "coordinator retry applied generation",
			coordinator: middleend.GenerationCoordinatorSnapshot{Applied: true},
			admitting:   true,
			want:        true,
		},
		{
			name:        "initial generation remains unavailable",
			coordinator: middleend.GenerationCoordinatorSnapshot{Pending: true},
		},
		{
			name:        "rotation remains pending",
			coordinator: middleend.GenerationCoordinatorSnapshot{Applied: true, Pending: true},
			admitting:   true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := middleend.ServiceSnapshot{
				Coordinator: test.coordinator,
				Supervisor:  middleend.GenerationSupervisorSnapshot{Admitting: test.admitting},
			}
			if got := middleEndGenerationFailureRecovered(snapshot); got != test.want {
				t.Fatalf("generation failure recovered = %t, want %t", got, test.want)
			}
		})
	}
}

func TestMiddleEndMonitorPressureThresholdsResetWithGeneration(t *testing.T) {
	monitor := &middleEndMonitor{pressure: make(map[string]middleEndPressureState)}
	monitor.observePressure("active", "response", "bytes", 79, 100)
	if state := monitor.pressure["active/response/bytes"]; state.stage != 0 || state.value != 79 {
		t.Fatalf("below threshold state = %+v", state)
	}
	monitor.observePressure("active", "response", "bytes", 80, 100)
	if state := monitor.pressure["active/response/bytes"]; state.stage != 1 {
		t.Fatalf("80%% state = %+v", state)
	}
	monitor.observePressure("active", "response", "bytes", 96, 100)
	if state := monitor.pressure["active/response/bytes"]; state.stage != 2 {
		t.Fatalf("95%% state = %+v", state)
	}
	monitor.observePressure("active", "response", "bytes", 100, 100)
	if state := monitor.pressure["active/response/bytes"]; state.stage != 3 {
		t.Fatalf("100%% state = %+v", state)
	}
	monitor.observePressure("active", "response", "bytes", 1, 100)
	if state := monitor.pressure["active/response/bytes"]; state.stage != 0 || state.value != 1 {
		t.Fatalf("replacement generation state = %+v", state)
	}
}
