package webproxy

import (
	"bytes"
	"runtime"
	"testing"
)

func TestPollLeaseCloseKeepsLiveResponseOwnership(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	session.mu.Lock()
	queued := session.queueFrameLocked(FrameData, 1, bytes.Repeat([]byte{0x6c}, MaxFramePayload))
	session.mu.Unlock()
	if !queued {
		t.Fatal("cannot queue response")
	}
	body, _, lease, err := session.PollCarrier(t.Context(), 0)
	if err != nil || lease == nil {
		t.Fatalf("poll lease=%v error=%v", lease, err)
	}
	t.Cleanup(lease.Release)
	before := manager.Capacity()
	session.Close()
	if after := manager.Capacity(); after.PendingBytes != before.PendingBytes || after.PendingItems != before.PendingItems {
		t.Fatalf("close released live response: before=%+v after=%+v", before, after)
	}
	runtime.KeepAlive(body)
	lease.Release()
	lease.Release()
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("drained closed response retained ownership: %+v", capacity)
	}
}

func TestPollLeaseReplaySharesChargeAndPreservesMutableResponse(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	payload := []byte("unchanged replay")
	session.mu.Lock()
	queued := session.queueFrameLocked(FrameData, 1, payload)
	session.mu.Unlock()
	if !queued {
		t.Fatal("cannot queue response")
	}
	before := manager.Capacity()
	body, cursor, lease, err := session.PollCarrier(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Release)
	body[len(body)-1] ^= 1
	lease.Release()
	replay, next, replayLease, err := session.PollCarrier(t.Context(), 0)
	if err != nil || next != cursor {
		t.Fatalf("replay cursor=%d error=%v", next, err)
	}
	t.Cleanup(replayLease.Release)
	assertSingleDataFrame(t, replay, 1, payload)
	if after := manager.Capacity(); after.PendingBytes != before.PendingBytes || after.PendingItems != before.PendingItems {
		t.Fatalf("replay changed logical batch charge: before=%+v after=%+v", before, after)
	}
	replayLease.Release()
	session.Close()
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("replay-only close retained ownership: %+v", capacity)
	}
}

func TestPollLeaseRetiredLaneKeepsResponseOwnership(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) { config.Carrier = CarrierWebSocketLanes }, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	lane := session.AcquireWebSocketLane(41)
	if lane == nil {
		t.Fatal("cannot acquire lane")
	}
	session.mu.Lock()
	queued := session.queueFrameLocked(FrameData, 41, []byte("retired response"))
	session.mu.Unlock()
	if !queued {
		t.Fatal("cannot queue lane response")
	}
	body, _, _, lease, err := lane.PollCarrier(t.Context(), 0)
	if err != nil || lease == nil {
		t.Fatalf("lane poll lease=%v error=%v", lease, err)
	}
	t.Cleanup(lease.Release)
	before := manager.Capacity()
	lane.Release()
	if after := manager.Capacity(); after.PendingBytes != before.PendingBytes || after.PendingItems != before.PendingItems {
		t.Fatalf("retirement released live response: before=%+v after=%+v", before, after)
	}
	runtime.KeepAlive(body)
	replacement := session.AcquireWebSocketLane(41)
	if replacement == nil {
		t.Fatal("cannot acquire replacement lane")
	}
	t.Cleanup(replacement.Release)
	lease.Release()
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("retired response retained ownership: %+v", capacity)
	}
}
