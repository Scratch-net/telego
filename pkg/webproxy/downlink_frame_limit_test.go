package webproxy

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// collectDownlink polls until want bytes of stream 1 DATA arrive. It fails if
// a response body or one of its frames exceeds limit.
func collectDownlink(t *testing.T, session *Session, want, limit int) []byte {
	t.Helper()
	var received []byte
	cursor := uint64(0)
	deadline := time.Now().Add(5 * time.Second)
	for len(received) < want {
		if time.Now().After(deadline) {
			t.Fatalf("received %d of %d downlink bytes", len(received), want)
		}
		body, next, err := session.Poll(context.Background(), cursor)
		if err != nil {
			t.Fatal(err)
		}
		cursor = next
		if len(body) == 0 {
			continue
		}
		if len(body) > limit {
			t.Fatalf("downlink body has %d bytes, limit %d", len(body), limit)
		}
		frames, err := ParseBatch(body)
		if err != nil {
			t.Fatal(err)
		}
		for _, frame := range frames {
			if FrameHeaderSize+len(frame.Payload) > limit {
				t.Fatalf("downlink frame has %d bytes, limit %d", FrameHeaderSize+len(frame.Payload), limit)
			}
			if frame.Type == FrameData && frame.StreamID == 1 {
				received = append(received, frame.Payload...)
			}
		}
	}
	return received
}

func TestDownlinkFrameLimitBoundsDialedBackendResponses(t *testing.T) {
	const limit = 4096
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Limits.CarrierBatchBytes = limit
		config.DownlinkFrameBytes = limit
	}, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session
	if _, err := session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	peer := dialer.Peer(t)
	defer peer.Close()
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1500)
	go func() { _, _ = peer.Write(payload) }()
	if received := collectDownlink(t, session, len(payload), limit); !bytes.Equal(received, payload) {
		t.Fatal("downlink payload changed")
	}
}

func TestDownlinkFrameLimitBoundsOwnerBackendResponses(t *testing.T) {
	const limit = 4096
	app := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(config *ManagerConfig) {
		config.Limits.CarrierBatchBytes = limit
		config.DownlinkFrameBytes = limit
		config.BackendFactory = GnetBackendFactory(nil)
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	// The echo backend returns the uplink payload as backend reads.
	payload := bytes.Repeat([]byte("fedcba9876543210"), 1500)
	if _, err := session.ProcessUp(1, testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 1},
		Frame{Type: FrameData, StreamID: 1, Payload: payload},
	)); err != nil {
		t.Fatal(err)
	}
	if received := collectDownlink(t, session, len(payload), limit); !bytes.Equal(received, payload) {
		t.Fatal("downlink payload changed")
	}
}

func TestDownlinkFrameLimitDefaultKeepsFrameSizes(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, newPipeDialer().DialContext)
	session := createTestSession(t, manager, profiles[0]).Session
	if session.downPayloadLimit(RelayDataChunk) != RelayDataChunk ||
		session.downPayloadLimit(MaxFramePayload) != MaxFramePayload {
		t.Fatal("default session changed DATA frame bounds")
	}
}

func TestManagerRejectsInvalidDownlinkFrameLimit(t *testing.T) {
	profiles := testProfiles(t)
	for _, value := range []int{-1, FrameHeaderSize, maxCarrierBatchBytes + 1} {
		config := DefaultManagerConfig(profiles, "127.0.0.1:443")
		config.DownlinkFrameBytes = value
		if manager, err := NewManager(config); manager != nil || !errors.Is(err, ErrInvalidManagerConfig) {
			t.Fatalf("DownlinkFrameBytes=%d: NewManager = %p, %v", value, manager, err)
		}
	}
}
