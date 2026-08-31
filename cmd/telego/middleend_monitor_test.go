package main

import (
	"testing"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestMiddleEndPayloadCapacityCountsIndependentBudgetsOnce(t *testing.T) {
	snapshot := middleend.ServiceSnapshot{
		Capacity: middleend.ServiceCapacitySnapshot{
			LinkSubmissionBytes:  11,
			LinkEventBytes:       13,
			ManagerRequestBytes:  17,
			ManagerControlBytes:  19,
			ManagerResponseBytes: 23,
			BindingResponseBytes: 1_000,
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
	wantLive := int64(29 + 31 + 2*managerCapacity + 3*perLinkCapacity)
	wantRotation := int64(29 + 31 + 2*(managerCapacity+2*perLinkCapacity))
	if live != wantLive || rotation != wantRotation {
		t.Fatalf("payload capacities = live %d rotation %d, want live %d rotation %d", live, rotation, wantLive, wantRotation)
	}
}

func TestMiddleEndPayloadCapacityHandlesMissingGenerations(t *testing.T) {
	live, rotation := middleEndPayloadCapacity(middleend.ServiceSnapshot{}, gproxy.MiddleEndFrontendStats{
		InputBytesLimit:  29,
		OutputBytesLimit: 31,
	})
	if live != 60 || rotation != 60 {
		t.Fatalf("payload capacities = live %d rotation %d, want 60 and 60", live, rotation)
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
