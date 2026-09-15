package middleend

import (
	"context"
	"errors"
	"testing"
)

func TestServiceResponseSnapshotCountsOneSharedPool(t *testing.T) {
	config := serviceTestConfig(t, artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		return RawArtifacts{}, errors.New("unused")
	}))
	config.Runtime.EventLoops = 2
	config.ResponseBudget = &ResponseBudgetConfig{LimitBytes: 8 << 20, ProcessingReserveBytes: 2 << 20}
	service, err := NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close(context.Background()) })
	pool := service.ResponseBudget()
	first := reserveResponseForTest(t, pool, 128, ResponseMemoryOrdinary, ResponseMemoryOutput)
	second := reserveResponseForTest(t, pool, 256, ResponseMemoryProcessing, ResponseMemoryEncode)
	snapshot := service.Snapshot()
	if snapshot.ResponseBudget != pool.Snapshot() || snapshot.ResponseBudget.UsedBytes != first.Bytes()+second.Bytes() ||
		snapshot.Capacity.ResponseBudgetBytes != config.ResponseBudget.LimitBytes || snapshot.Capacity.EventLoops != 2 ||
		snapshot.Capacity.DecoderBytesPerLink != MaxMEFrameSize || snapshot.Capacity.DecoderGrowthBytesPerOwner != MaxMEFrameSize ||
		snapshot.Capacity.DecodePlaintextBytesPerOwner != maxBootstrapBorrowedFeedSize || snapshot.RuntimeLinks != 0 {
		t.Fatalf("service pool/capacity snapshot: %+v", snapshot)
	}
	first.Release()
	second.Release()
	if snapshot := service.Snapshot(); snapshot.ResponseBudget.UsedBytes != 0 || snapshot.ResponseBudget.HighWaterBytes == 0 {
		t.Fatalf("release lost current/high-water distinction: %+v", snapshot.ResponseBudget)
	}
}
