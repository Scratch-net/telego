package webproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestHTTPSLanesHaveIndependentSequencesAndDownlinkCursors(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierHTTPSLanes
	}, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session

	for _, test := range []struct {
		id      uint32
		payload string
	}{
		{id: 31, payload: "first lane"},
		{id: 32, payload: "second lane"},
	} {
		body := testFrameBatch(t,
			Frame{Type: FrameOpen, StreamID: test.id},
			Frame{Type: FrameData, StreamID: test.id, Payload: []byte(test.payload)},
		)
		ack, err := session.ProcessUpLane(test.id, 1, body)
		if err != nil || ack != 1 {
			t.Fatalf("ProcessUpLane(%d) = %d, %v", test.id, ack, err)
		}
		if retry, err := session.ProcessUpLane(test.id, 1, bytes.Clone(body)); err != nil || retry != 1 {
			t.Fatalf("ProcessUpLane(%d) retry = %d, %v", test.id, retry, err)
		}
		peer := dialer.Peer(t)
		t.Cleanup(func() { _ = peer.Close() })
		received := make([]byte, len(test.payload))
		if _, err := io.ReadFull(peer, received); err != nil {
			t.Fatal(err)
		}
		if string(received) != test.payload {
			t.Fatalf("lane %d backend received %q", test.id, received)
		}
		if _, err := peer.Write([]byte("reply " + test.payload)); err != nil {
			t.Fatal(err)
		}
		body, cursor, closed, err := session.PollLane(context.Background(), test.id, 0)
		if err != nil || cursor != 1 || closed {
			t.Fatalf("PollLane(%d) = cursor %d, closed %t, %v", test.id, cursor, closed, err)
		}
		frames, err := ParseBatch(body)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, frame := range frames {
			if frame.StreamID != test.id {
				t.Fatalf("lane %d received stream %d", test.id, frame.StreamID)
			}
			if frame.Type == FrameData && bytes.Equal(frame.Payload, []byte("reply "+test.payload)) {
				found = true
			}
		}
		if !found {
			t.Fatalf("lane %d omitted backend DATA: %#v", test.id, frames)
		}
	}
}

func TestHTTPSLaneRejectsCrossLaneFramesAndRequiresOpen(t *testing.T) {
	newLaneSession := func(t *testing.T) *Session {
		t.Helper()
		profiles := testProfiles(t)
		manager := testManager(t, profiles, func(config *ManagerConfig) {
			config.Carrier = CarrierHTTPSLanes
		}, nil)
		return createTestSession(t, manager, profiles[0]).Session
	}

	for name, body := range map[string][]byte{
		"cross lane":          testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 42}),
		"invalid first frame": {byte(FramePing), 0, 0, 41, 0, 0, 0, 0},
	} {
		t.Run(name, func(t *testing.T) {
			session := newLaneSession(t)
			if _, err := session.ProcessUpLane(41, 1, body); !errors.Is(err, ErrProtocol) {
				t.Fatalf("ProcessUpLane error = %v", err)
			}
			if _, _, _, err := session.PollLane(context.Background(), 41, 0); !errors.Is(err, ErrClosed) {
				t.Fatalf("PollLane after protocol failure = %v", err)
			}
		})
	}
}

func TestHTTPSLaneCloseReplaysBeforeCompletion(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierHTTPSLanes
		config.Timeouts.LongPoll = 20 * time.Millisecond
	}, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session
	const laneID = 51
	if _, err := session.ProcessUpLane(laneID, 1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: laneID})); err != nil {
		t.Fatal(err)
	}
	peer := dialer.Peer(t)
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}

	var first []byte
	var cursor uint64
	eventually(t, time.Second, func() bool {
		var closed bool
		var err error
		first, cursor, closed, err = session.PollLane(context.Background(), laneID, 0)
		return err == nil && !closed && len(first) != 0
	})
	frames, err := ParseBatch(first)
	if err != nil || len(frames) != 1 || frames[0].Type != FrameClose || frames[0].StreamID != laneID {
		t.Fatalf("lane close batch = %#v, %v", frames, err)
	}
	replay, replayCursor, closed, err := session.PollLane(context.Background(), laneID, 0)
	if err != nil || replayCursor != cursor || closed || !bytes.Equal(replay, first) {
		t.Fatalf("lane replay = cursor %d, closed %t, %v", replayCursor, closed, err)
	}
	body, finalCursor, closed, err := session.PollLane(context.Background(), laneID, cursor)
	if err != nil || len(body) != 0 || finalCursor != cursor || !closed {
		t.Fatalf("lane completion = %x, cursor %d, closed %t, %v", body, finalCursor, closed, err)
	}
}

func TestHTTPSLaneTombstoneEvictionReleasesUnackedBudget(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierHTTPSLanes
		config.Limits.MaxClosedStreamIDs = 1
	}, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session

	openLane := func(laneID uint32) net.Conn {
		t.Helper()
		body := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: laneID})
		if _, err := session.ProcessUpLane(laneID, 1, body); err != nil {
			t.Fatal(err)
		}
		return dialer.Peer(t)
	}
	closeLane := func(laneID uint32) {
		t.Helper()
		body := testFrameBatch(t, Frame{Type: FrameClose, StreamID: laneID})
		if _, err := session.ProcessUpLane(laneID, 2, body); err != nil {
			t.Fatal(err)
		}
	}

	firstPeer := openLane(61)
	t.Cleanup(func() { _ = firstPeer.Close() })
	session.mu.Lock()
	if !session.queueFrameLocked(FrameData, 61, []byte("unacknowledged")) {
		session.mu.Unlock()
		t.Fatal("queue first lane data")
	}
	session.mu.Unlock()
	body, cursor, closed, err := session.PollLane(context.Background(), 61, 0)
	if err != nil || len(body) == 0 || cursor != 1 || closed {
		t.Fatalf("first lane poll = %x, %d, %t, %v", body, cursor, closed, err)
	}
	closeLane(61)

	secondPeer := openLane(62)
	t.Cleanup(func() { _ = secondPeer.Close() })
	closeLane(62)

	session.mu.Lock()
	_, retained := session.carrierLanes[61]
	pendingCost := session.pendingCost
	pendingItems := session.pendingItems
	session.mu.Unlock()
	if retained {
		t.Fatal("evicted lane state is retained")
	}
	if pendingCost != 0 || pendingItems != 0 {
		t.Fatalf("pending budget after eviction = %d bytes, %d items", pendingCost, pendingItems)
	}
}
