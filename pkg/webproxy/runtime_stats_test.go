package webproxy

import (
	"context"
	"testing"
)

func TestManagerRuntimeStatsTrackLifecycleRetriesAndBackpressure(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, nil, dialer.DialContext)
	bootstrap, err := manager.IssueBootstrap(profiles[0].Capability(), "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})
	created, err := manager.Create(bootstrap, "192.0.2.10", hello)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(bootstrap, "198.51.100.20", hello); err != nil {
		t.Fatal(err)
	}

	open := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 7})
	if _, err := created.Session.ProcessUp(1, open); err != nil {
		t.Fatal(err)
	}
	peer := dialer.Peer(t)
	t.Cleanup(func() { _ = peer.Close() })
	if _, err := created.Session.ProcessUp(1, open); err != nil {
		t.Fatal(err)
	}

	created.Session.mu.Lock()
	created.Session.carrierLanes[0].upActive = true
	created.Session.mu.Unlock()
	if _, err := created.Session.ProcessUp(2, testFrameBatch(t, Frame{Type: FramePong})); err != ErrBackpressure {
		t.Fatalf("backpressure error = %v", err)
	}
	created.Session.mu.Lock()
	created.Session.carrierLanes[0].upActive = false
	if !created.Session.queueFrameLocked(FrameClose, 7, nil) {
		created.Session.mu.Unlock()
		t.Fatal("queue downlink frame")
	}
	created.Session.mu.Unlock()

	body, cursor, err := created.Session.Poll(context.Background(), 0)
	if err != nil || len(body) == 0 || cursor != 1 {
		t.Fatalf("first poll = %x, %d, %v", body, cursor, err)
	}
	if _, replayCursor, err := created.Session.Poll(context.Background(), 0); err != nil || replayCursor != cursor {
		t.Fatalf("replay poll = %d, %v", replayCursor, err)
	}

	stats := manager.RuntimeStats()
	if stats.Capacity.Sessions != 1 || stats.SessionsCreated != 1 {
		t.Fatalf("active/created sessions = %d/%d", stats.Capacity.Sessions, stats.SessionsCreated)
	}
	assertRuntimeCounter(t, stats.CarrierRetries, "create", 1)
	assertRuntimeCounter(t, stats.CarrierRetries, "uplink", 1)
	assertRuntimeCounter(t, stats.CarrierRetries, "downlink", 1)
	assertRuntimeCounter(t, stats.Backpressure, "uplink", 1)

	if err := manager.Close(created.Token); err != nil {
		t.Fatal(err)
	}
	created.Session.wait()
	stats = manager.RuntimeStats()
	if stats.Capacity.Sessions != 0 {
		t.Fatalf("active sessions after close = %d", stats.Capacity.Sessions)
	}
	assertRuntimeCounter(t, stats.SessionsClosed, "client", 1)
}

func assertRuntimeCounter(t *testing.T, counters []RuntimeCounter, label string, want uint64) {
	t.Helper()
	for _, counter := range counters {
		if counter.Label == label {
			if counter.Total != want {
				t.Fatalf("counter %q = %d, want %d", label, counter.Total, want)
			}
			return
		}
	}
	t.Fatalf("counter %q is missing", label)
}
