package main

import (
	"testing"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestMiddleEndDirectFallbackFDMinimum(t *testing.T) {
	for _, test := range []struct {
		name           string
		maxConnections int
		want           uint64
	}{
		{name: "negative", maxConnections: -1, want: 0},
		{name: "disabled", maxConnections: 0, want: 0},
		{name: "production default", maxConnections: 10_000, want: 20_000},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := middleEndDirectFallbackFDMinimum(test.maxConnections); got != test.want {
				t.Fatalf("middleEndDirectFallbackFDMinimum(%d) = %d, want %d", test.maxConnections, got, test.want)
			}
		})
	}
}

func TestMiddleEndLinkCapacityIncludesCandidateReservations(t *testing.T) {
	for _, test := range []struct {
		name         string
		active       *middleend.FixedBindingManagerSnapshot
		retiring     *middleend.FixedBindingManagerSnapshot
		wantLive     int
		wantRotation int
	}{
		{name: "no manager"},
		{
			name: "steady", active: &middleend.FixedBindingManagerSnapshot{Slots: make([]middleend.FixedBindingSlotSnapshot, 48)},
			wantLive: 56, wantRotation: 112,
		},
		{
			name:     "rotation",
			active:   &middleend.FixedBindingManagerSnapshot{Slots: make([]middleend.FixedBindingSlotSnapshot, 48)},
			retiring: &middleend.FixedBindingManagerSnapshot{Slots: make([]middleend.FixedBindingSlotSnapshot, 44)},
			wantLive: 108, wantRotation: 112,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			live, rotation := middleEndLinkCapacity(middleend.ServiceSnapshot{
				Capacity:   middleend.ServiceCapacitySnapshot{MaxRefreshCandidatesPerManager: 8},
				Supervisor: middleend.GenerationSupervisorSnapshot{Active: test.active, Retiring: test.retiring},
			})
			if live != test.wantLive || rotation != test.wantRotation {
				t.Fatalf("link capacities = %d/%d, want %d/%d", live, rotation, test.wantLive, test.wantRotation)
			}
		})
	}
}
