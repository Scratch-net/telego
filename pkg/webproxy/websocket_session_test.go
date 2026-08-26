package webproxy

import (
	"errors"
	"io"
	"sync"
	"testing"
)

func TestParseWebSocketCarrierModes(t *testing.T) {
	tests := []struct {
		value         string
		want          CarrierMode
		usesLanes     bool
		usesWebSocket bool
	}{
		{want: CarrierHTTPS},
		{value: "https", want: CarrierHTTPS},
		{value: "https-lanes", want: CarrierHTTPSLanes, usesLanes: true},
		{value: "websocket", want: CarrierWebSocket, usesWebSocket: true},
		{value: "websocket-lanes", want: CarrierWebSocketLanes, usesLanes: true, usesWebSocket: true},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			mode, err := ParseCarrierMode(test.value)
			if err != nil {
				t.Fatalf("ParseCarrierMode: %v", err)
			}
			if mode != test.want || mode.usesLanes() != test.usesLanes ||
				mode.usesWebSocket() != test.usesWebSocket || !mode.valid() {
				t.Fatalf(
					"mode = %q, lanes %t, websocket %t, valid %t",
					mode,
					mode.usesLanes(),
					mode.usesWebSocket(),
					mode.valid(),
				)
			}
		})
	}
	if _, err := ParseCarrierMode("quic"); err == nil {
		t.Fatal("ParseCarrierMode accepted unsupported carrier")
	}
}

func TestWebSocketSessionAllowsOneParentAndClosesOnParentLoss(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	session := createTestSession(t, manager, profiles[0]).Session

	if !session.AcquireWebSocket() {
		t.Fatal("first WebSocket attachment was rejected")
	}
	if session.AcquireWebSocket() {
		t.Fatal("duplicate WebSocket attachment was accepted")
	}
	pong := testFrameBatch(t, Frame{Type: FramePong, Payload: []byte("probe")})
	if acknowledged, err := session.ProcessUp(1, pong); err != nil || acknowledged != 1 {
		t.Fatalf("ProcessUp = %d, %v", acknowledged, err)
	}

	session.Close()
	if session.AcquireWebSocket() {
		t.Fatal("closed session accepted a replacement WebSocket")
	}
	if _, err := session.ProcessUp(2, pong); !errors.Is(err, ErrClosed) {
		t.Fatalf("ProcessUp after parent loss = %v", err)
	}
}

func TestWebSocketLaneAttachmentValidationAndUnopenedReuse(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocketLanes
	}, nil)
	session := createTestSession(t, manager, profiles[0]).Session

	if session.AcquireWebSocketLane(0) != nil {
		t.Fatal("lane zero was accepted")
	}
	if session.AcquireWebSocketLane(MaxStreamID+1) != nil {
		t.Fatal("out-of-range lane was accepted")
	}
	lane := session.AcquireWebSocketLane(41)
	if lane == nil {
		t.Fatal("first lane attachment was rejected")
	}
	if session.AcquireWebSocketLane(41) != nil {
		t.Fatal("duplicate lane attachment was accepted")
	}
	lane.Release()
	if session.AcquireWebSocketLane(41) == nil {
		t.Fatal("unopened released lane could not be reused")
	}
}

func TestWebSocketLaneProtocolFailureIsIsolated(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocketLanes
	}, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session

	const failedLane = 51
	const survivingLane = 52
	failed := session.AcquireWebSocketLane(failedLane)
	surviving := session.AcquireWebSocketLane(survivingLane)
	if failed == nil || surviving == nil {
		t.Fatal("lane attachment was rejected")
	}
	failedOpen := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: failedLane})
	if _, err := failed.ProcessUp(1, failedOpen); err != nil {
		t.Fatal(err)
	}
	failedPeer := dialer.Peer(t)
	t.Cleanup(func() { _ = failedPeer.Close() })
	survivingOpen := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: survivingLane})
	if _, err := surviving.ProcessUp(1, survivingOpen); err != nil {
		t.Fatal(err)
	}
	survivingPeer := dialer.Peer(t)
	t.Cleanup(func() { _ = survivingPeer.Close() })

	differentRetry := testFrameBatch(t, Frame{Type: FrameData, StreamID: failedLane, Payload: []byte("bad retry")})
	if _, err := failed.ProcessUp(1, differentRetry); !errors.Is(err, ErrProtocol) {
		t.Fatalf("failed lane retry = %v", err)
	}
	if session.AcquireWebSocketLane(failedLane) != nil {
		t.Fatal("opened released lane was reused")
	}

	payload := []byte("surviving lane")
	data := testFrameBatch(t, Frame{Type: FrameData, StreamID: survivingLane, Payload: payload})
	if acknowledged, err := surviving.ProcessUp(2, data); err != nil || acknowledged != 2 {
		t.Fatalf("surviving ProcessUpLane = %d, %v", acknowledged, err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(survivingPeer, received); err != nil {
		t.Fatal(err)
	}
	if string(received) != string(payload) {
		t.Fatalf("surviving backend received %q, want %q", received, payload)
	}
}

func TestWebSocketLanesRequireAcquisition(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocketLanes
	}, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	const laneID = 61
	open := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: laneID})

	if _, err := session.ProcessUpLane(laneID, 1, open); !errors.Is(err, ErrProtocol) {
		t.Fatalf("session ProcessUpLane = %v", err)
	}
	if _, _, _, _, err := session.PollCarrierLane(t.Context(), laneID, 0); !errors.Is(err, ErrProtocol) {
		t.Fatalf("session PollCarrierLane = %v", err)
	}
	lane := session.AcquireWebSocketLane(laneID)
	if lane == nil {
		t.Fatal("lane acquisition was rejected")
	}
	if acknowledged, err := lane.ProcessUp(1, open); err != nil || acknowledged != 1 {
		t.Fatalf("lease ProcessUp = %d, %v", acknowledged, err)
	}
}

func TestWebSocketLaneStaleReleaseCannotDeleteReplacement(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocketLanes
	}, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	const laneID = 71

	stale := session.AcquireWebSocketLane(laneID)
	if stale == nil {
		t.Fatal("first lane acquisition was rejected")
	}
	invalid := testFrameBatch(t, Frame{Type: FrameData, StreamID: laneID, Payload: []byte("without OPEN")})
	if _, err := stale.ProcessUp(1, invalid); !errors.Is(err, ErrProtocol) {
		t.Fatalf("invalid first message = %v", err)
	}
	replacement := session.AcquireWebSocketLane(laneID)
	if replacement == nil {
		t.Fatal("replacement lane acquisition was rejected")
	}

	stale.Release()
	open := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: laneID})
	if acknowledged, err := replacement.ProcessUp(1, open); err != nil || acknowledged != 1 {
		t.Fatalf("replacement ProcessUp = %d, %v", acknowledged, err)
	}
}

func TestWebSocketLaneConcurrentReleaseIsIdempotent(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocketLanes
	}, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	const laneID = 81
	lane := session.AcquireWebSocketLane(laneID)
	if lane == nil {
		t.Fatal("lane acquisition was rejected")
	}

	var releases sync.WaitGroup
	for range 32 {
		releases.Go(lane.Release)
	}
	releases.Wait()
	if session.AcquireWebSocketLane(laneID) == nil {
		t.Fatal("released unopened lane could not be acquired again")
	}
}
