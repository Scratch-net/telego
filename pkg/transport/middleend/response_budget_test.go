package middleend

import (
	"errors"
	"math"
	"sync"
	"testing"
)

func responseBudgetForTest(t *testing.T, config ResponseBudgetConfig) *ResponseBudget {
	t.Helper()
	budget, err := NewResponseBudget(config)
	if err != nil {
		t.Fatal(err)
	}
	return budget
}

func reserveResponseForTest(t *testing.T, budget *ResponseBudget, capacity int, class ResponseMemoryClass, stage ResponseMemoryStage) *ResponseAllocation {
	t.Helper()
	allocation, ok := budget.TryReserve(capacity, class, stage)
	if !ok {
		t.Fatalf("reserve %d bytes, class %d: %+v", capacity, class, budget.Snapshot())
	}
	return allocation
}

func TestResponseBudgetProtectedReserves(t *testing.T) {
	charge := ResponseAllocationCharge(128)
	budget := responseBudgetForTest(t, ResponseBudgetConfig{
		LimitBytes: 3 * charge, ProcessingReserveBytes: charge, ControlReserveBytes: charge,
	})
	ordinary := reserveResponseForTest(t, budget, 128, ResponseMemoryOrdinary, ResponseMemoryQueuePayload)
	if _, ok := budget.TryReserve(0, ResponseMemoryOrdinary, ResponseMemoryOutput); ok {
		t.Fatal("ordinary queue consumed protected reserve")
	}
	processing := reserveResponseForTest(t, budget, 128, ResponseMemoryProcessing, ResponseMemoryEncode)
	control := reserveResponseForTest(t, budget, 128, ResponseMemoryControl, ResponseMemoryDecode)
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != 3*charge || snapshot.HighWaterBytes != snapshot.LimitBytes {
		t.Fatalf("full budget: %+v", snapshot)
	}
	ordinary.Release()
	processing.Release()
	control.Release()
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.Allocations != 0 {
		t.Fatalf("released budget: %+v", snapshot)
	}
}

func TestResponseBudgetRejectsInvalidBounds(t *testing.T) {
	for _, config := range []ResponseBudgetConfig{
		{}, {LimitBytes: -1}, {LimitBytes: 1, ProcessingReserveBytes: -1},
		{LimitBytes: 1, ControlReserveBytes: -1}, {LimitBytes: 1, ProcessingReserveBytes: 1},
		{LimitBytes: math.MaxInt, ProcessingReserveBytes: math.MaxInt - 1, ControlReserveBytes: 1},
	} {
		if _, err := NewResponseBudget(config); !errors.Is(err, ErrInvalidResponseBudget) {
			t.Fatalf("config %+v: %v", config, err)
		}
	}
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
	for _, capacity := range []int{-1, math.MaxInt} {
		if _, ok := budget.TryReserve(capacity, ResponseMemoryOrdinary, ResponseMemoryQueuePayload); ok {
			t.Fatalf("accepted capacity %d", capacity)
		}
	}
	if _, ok := budget.TryReserve(1, responseMemoryClassCount, ResponseMemoryOutput); ok {
		t.Fatal("accepted invalid class")
	}
	if _, ok := budget.TryReserve(1, ResponseMemoryOrdinary, responseMemoryStageCount); ok {
		t.Fatal("accepted invalid stage")
	}
}

func TestResponseBudgetAtomicPromotion(t *testing.T) {
	charge := ResponseAllocationCharge(128)
	budget := responseBudgetForTest(t, ResponseBudgetConfig{
		LimitBytes: 3 * charge, ProcessingReserveBytes: 2 * charge,
	})
	input := reserveResponseForTest(t, budget, 128, ResponseMemoryOrdinary, ResponseMemoryQueuePayload)
	encoded := reserveResponseForTest(t, budget, 128, ResponseMemoryProcessing, ResponseMemoryEncode)
	output := reserveResponseForTest(t, budget, 128, ResponseMemoryProcessing, ResponseMemoryEncode)
	before := budget.Snapshot()
	if output.TryMove(ResponseMemoryOrdinary, ResponseMemoryOutput) {
		t.Fatal("promoted output without releasing consumed input")
	}
	if output.TryMoveReplacing(ResponseMemoryOrdinary, ResponseMemoryOutput, input, input) {
		t.Fatal("accepted duplicate consumed handle")
	}
	if after := budget.Snapshot(); before != after {
		t.Fatalf("failed promotion changed counters: before %+v, after %+v", before, after)
	}
	if !output.TryMoveReplacing(ResponseMemoryOrdinary, ResponseMemoryOutput, input, encoded) {
		t.Fatal("atomic promotion failed")
	}
	if input.Bytes() != 0 || encoded.Bytes() != 0 || output.Bytes() != charge {
		t.Fatal("ownership transfer changed retained output or kept consumed charges")
	}
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != charge || snapshot.StageBytes[ResponseMemoryOutput] != charge || snapshot.ClassBytes[ResponseMemoryProcessing] != 0 {
		t.Fatalf("promoted budget: %+v", snapshot)
	}
	input.Release()
	encoded.Release()
	output.Release()
}

func TestResponseBudgetReleaseAndShrink(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
	allocation := reserveResponseForTest(t, budget, 256, ResponseMemoryOrdinary, ResponseMemoryOutput)
	if allocation.Shrink(257) || !allocation.Shrink(128) || allocation.Bytes() != ResponseAllocationCharge(128) {
		t.Fatal("invalid reservation shrink")
	}
	var group sync.WaitGroup
	for range 32 {
		group.Go(allocation.Release)
	}
	group.Wait()
	if allocation.Shrink(0) || allocation.TryMove(ResponseMemoryOrdinary, ResponseMemoryOutput) {
		t.Fatal("reused a released handle")
	}
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.Allocations != 0 {
		t.Fatalf("concurrent exact-once release: %+v", snapshot)
	}
}

func TestResponseBudgetRejectsForeignPromotion(t *testing.T) {
	first := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
	second := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
	output := reserveResponseForTest(t, first, 16, ResponseMemoryOrdinary, ResponseMemoryOutput)
	foreign := reserveResponseForTest(t, second, 16, ResponseMemoryOrdinary, ResponseMemoryQueuePayload)
	if output.TryMoveReplacing(ResponseMemoryOrdinary, ResponseMemoryOutput, foreign) {
		t.Fatal("accepted a charge from another service")
	}
	if foreign.Bytes() == 0 {
		t.Fatal("foreign charge released on rejection")
	}
	output.Release()
	foreign.Release()
}

func TestResponseAllocationZeroValue(t *testing.T) {
	var allocation ResponseAllocation
	allocation.Release()
	if allocation.Bytes() != 0 || allocation.Shrink(0) || allocation.TryMove(ResponseMemoryOrdinary, ResponseMemoryOutput) {
		t.Fatal("zero allocation acquired ownership")
	}
}

func TestResponseBudgetAtomicMoveAndGrow(t *testing.T) {
	ordinaryLimit := ResponseAllocationCharge(128)
	budget := responseBudgetForTest(t, ResponseBudgetConfig{
		LimitBytes: 2 * ordinaryLimit, ProcessingReserveBytes: ordinaryLimit,
	})
	occupied := reserveResponseForTest(t, budget, 64, ResponseMemoryOrdinary, ResponseMemoryOutput)
	allocation := reserveResponseForTest(t, budget, 64, ResponseMemoryProcessing, ResponseMemoryDecode)
	before := budget.Snapshot()
	if allocation.TryMoveAtLeast(128, ResponseMemoryOrdinary, ResponseMemoryQueuePayload) {
		t.Fatal("grew into occupied capacity")
	}
	if after := budget.Snapshot(); after != before {
		t.Fatalf("failed growth changed ownership: before %+v, after %+v", before, after)
	}
	occupied.Release()
	if !allocation.TryMoveAtLeast(128, ResponseMemoryOrdinary, ResponseMemoryQueuePayload) {
		t.Fatal("move with envelope expansion failed")
	}
	if !allocation.TryMoveAtLeast(32, ResponseMemoryOrdinary, ResponseMemoryQueuePayload) || allocation.Bytes() != ordinaryLimit {
		t.Fatal("minimum-capacity move shrank an existing allocation")
	}
	if allocation.TryMoveAtLeast(math.MaxInt, ResponseMemoryOrdinary, ResponseMemoryQueuePayload) {
		t.Fatal("accepted overflow expansion")
	}
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != ordinaryLimit || snapshot.ClassBytes[ResponseMemoryProcessing] != 0 || snapshot.StageBytes[ResponseMemoryQueuePayload] != ordinaryLimit {
		t.Fatalf("move with growth lost accounting: %+v", snapshot)
	}
	allocation.Release()
}
