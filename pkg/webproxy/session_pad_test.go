package webproxy

import (
	"bytes"
	"context"
	"testing"
)

func TestPadLengthFollowsVisionDefaults(t *testing.T) {
	low := func(int) int { return 0 }
	high := func(limit int) int { return limit - 1 }
	for _, test := range []struct {
		content int
		random  func(int) int
		want    int
	}{
		{100, low, padShortContent - 100 - FrameHeaderSize},
		{100, high, padShortContent + padShortJitter - 100 - FrameHeaderSize},
		{899, low, 0},
		{900, low, 0},
		{900, high, padLongJitter},
		{5000, high, padLongJitter},
	} {
		if got := padLength(test.content, test.random); got != test.want {
			t.Errorf("padLength(%d) = %d, want %d", test.content, got, test.want)
		}
	}
}

func padTestSession(t *testing.T, carrier CarrierMode, batch int) (*Manager, *Session) {
	t.Helper()
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = carrier
		config.PadFirstFrames = true
		if batch != 0 {
			config.Limits.CarrierBatchBytes = batch
		}
	}, newPipeDialer().DialContext)
	return manager, createTestSession(t, manager, profiles[0]).Session
}

func TestPadFirstDownlinkBatches(t *testing.T) {
	for _, carrier := range []CarrierMode{CarrierHTTPS, CarrierWebSocket} {
		t.Run(string(carrier), func(t *testing.T) {
			manager, session := padTestSession(t, carrier, 0)
			baseline := manager.Capacity()
			window, _ := WindowPayload(1)
			cursor := uint64(0)
			for batch := range padDownlinkBatches + 2 {
				queueTestFrames(t, session, Frame{Type: FrameWindow, StreamID: 1, Payload: window})
				body, next, err := session.Poll(context.Background(), cursor)
				if err != nil {
					t.Fatal(err)
				}
				cursor = next
				frames, err := ParseBatch(body)
				if err != nil {
					t.Fatal(err)
				}
				padded := frames[len(frames)-1].Type == FramePad
				if padded != (batch < padDownlinkBatches) {
					t.Fatalf("batch %d padded=%t", batch, padded)
				}
				if padded && (len(frames) != 2 || len(body) < padShortContent || len(body) > padShortContent+padShortJitter) {
					t.Fatalf("batch %d: %d frames, %d bytes", batch, len(frames), len(body))
				}
			}
			if _, _, err := session.Poll(context.Background(), cursor); err != nil {
				t.Fatal(err)
			}
			if capacity := manager.Capacity(); capacity.PendingBytes != baseline.PendingBytes || capacity.PendingItems != baseline.PendingItems {
				t.Fatalf("capacity = %+v, want %+v", capacity, baseline)
			}
		})
	}
}

func TestPadNeverExceedsCarrierBatch(t *testing.T) {
	const batch = 1024
	_, session := padTestSession(t, CarrierHTTPS, batch)
	cursor := uint64(0)
	for _, size := range []int{batch - 2*FrameHeaderSize - 4, batch - FrameHeaderSize - 2} {
		queueTestFrames(t, session, Frame{Type: FrameData, StreamID: 1, Payload: bytes.Repeat([]byte{1}, size)})
		body, next, err := session.Poll(context.Background(), cursor)
		if err != nil {
			t.Fatal(err)
		}
		cursor = next
		if len(body) > batch {
			t.Fatalf("padded batch has %d bytes, limit %d", len(body), batch)
		}
		if _, err := ParseBatch(body); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPadSkipsLaneCarriers(t *testing.T) {
	for _, carrier := range []CarrierMode{CarrierHTTPSLanes, CarrierWebSocketLanes} {
		profiles := testProfiles(t)
		manager := testManager(t, profiles, func(config *ManagerConfig) {
			config.Carrier = carrier
			config.PadFirstFrames = true
		}, newPipeDialer().DialContext)
		if manager.padFirstFrames {
			t.Fatalf("carrier %s enabled padding", carrier)
		}
	}
}

func TestUplinkPadFramesAreDiscarded(t *testing.T) {
	for _, pad := range []bool{false, true} {
		profiles := testProfiles(t)
		dialer := newPipeDialer()
		manager := testManager(t, profiles, func(config *ManagerConfig) { config.PadFirstFrames = pad }, dialer.DialContext)
		session := createTestSession(t, manager, profiles[0]).Session
		body := testFrameBatch(t,
			Frame{Type: FrameOpen, StreamID: 1},
			Frame{Type: FrameData, StreamID: 1, Payload: []byte("hello")},
			Frame{Type: FramePad, Payload: make([]byte, 700)},
		)
		if _, err := session.ProcessUp(1, body); err != nil {
			t.Fatalf("pad=%t: %v", pad, err)
		}
		peer := dialer.Peer(t)
		received := make([]byte, 5)
		if _, err := peer.Read(received); err != nil || string(received) != "hello" {
			t.Fatalf("backend read %q, %v", received, err)
		}
		_ = peer.Close()
	}
}
