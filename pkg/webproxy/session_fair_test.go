package webproxy

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/gobwas/ws"
)

func fairTestSession(t *testing.T, fair bool) (*Manager, *Session) {
	t.Helper()
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
		config.WebSocketFairQueue = fair
	}, newPipeDialer().DialContext)
	return manager, createTestSession(t, manager, profiles[0]).Session
}

func queueTestFrames(t *testing.T, session *Session, frames ...Frame) {
	t.Helper()
	session.mu.Lock()
	defer session.mu.Unlock()
	for _, frame := range frames {
		if !session.queueFrameLocked(frame.Type, frame.StreamID, frame.Payload) {
			t.Fatalf("cannot queue %#v", frame.Type)
		}
	}
}

type frameKey struct {
	frameType FrameType
	streamID  uint32
	size      int
}

func pollFrameKeys(t *testing.T, session *Session, cursor uint64) ([]frameKey, int, uint64) {
	t.Helper()
	body, next, err := session.Poll(context.Background(), cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		return nil, 0, next
	}
	frames, err := ParseBatch(body)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]frameKey, 0, len(frames))
	for _, frame := range frames {
		keys = append(keys, frameKey{frame.Type, frame.StreamID, len(frame.Payload)})
	}
	return keys, len(body), next
}

func TestFairDownlinkSchedulesControlFirstAndRotatesStreams(t *testing.T) {
	manager, session := fairTestSession(t, true)
	baseline := manager.Capacity()
	window, _ := WindowPayload(7)
	big := bytes.Repeat([]byte{1}, 100000)
	queueTestFrames(t, session,
		Frame{Type: FrameData, StreamID: 1, Payload: big},
		Frame{Type: FrameData, StreamID: 3, Payload: big},
		Frame{Type: FrameData, StreamID: 1, Payload: big},
		Frame{Type: FrameData, StreamID: 3, Payload: []byte("small")},
		Frame{Type: FrameWindow, StreamID: 5, Payload: window},
		Frame{Type: FrameClose, StreamID: 7},
	)
	want := [][]frameKey{
		{{FrameWindow, 5, 4}, {FrameData, 1, 100000}, {FrameClose, 7, 0}},
		{{FrameData, 3, 100000}, {FrameData, 3, 5}},
		{{FrameData, 1, 100000}},
	}
	cursor := uint64(0)
	for index, expected := range want {
		keys, size, next := pollFrameKeys(t, session, cursor)
		cursor = next
		if !slicesEqual(keys, expected) {
			t.Fatalf("batch %d = %v, want %v", index, keys, expected)
		}
		if len(keys) > 1 && size > webSocketFairMessageBytes {
			t.Fatalf("batch %d has %d bytes", index, size)
		}
	}
	session.mu.Lock()
	pending := len(session.carrierLanes[0].pendingFrames)
	session.mu.Unlock()
	if pending != 0 {
		t.Fatalf("%d frames remain queued", pending)
	}
	// The final poll acknowledges the last batch and returns its charge.
	if keys, _, _ := pollFrameKeys(t, session, cursor); keys != nil {
		t.Fatalf("unexpected batch %v", keys)
	}
	if capacity := manager.Capacity(); capacity.PendingBytes != baseline.PendingBytes || capacity.PendingItems != baseline.PendingItems {
		t.Fatalf("capacity = %+v, want %+v", capacity, baseline)
	}
}

func slicesEqual(left, right []frameKey) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestFairDownlinkTakesLargeFrameAfterControlFrames(t *testing.T) {
	_, session := fairTestSession(t, true)
	window, _ := WindowPayload(1)
	queueTestFrames(t, session,
		Frame{Type: FrameWindow, StreamID: 2, Payload: window},
		Frame{Type: FrameData, StreamID: 1, Payload: bytes.Repeat([]byte{1}, webSocketFairMessageBytes-FrameHeaderSize)},
	)
	keys, _, _ := pollFrameKeys(t, session, 0)
	if len(keys) != 2 || keys[1].frameType != FrameData {
		t.Fatalf("batch = %v", keys)
	}
}

func TestFairDownlinkKeepsWindowCoalescingIndexes(t *testing.T) {
	_, session := fairTestSession(t, true)
	window, _ := WindowPayload(3)
	big := bytes.Repeat([]byte{1}, 100000)
	queueTestFrames(t, session,
		Frame{Type: FrameData, StreamID: 1, Payload: big},
		Frame{Type: FrameData, StreamID: 3, Payload: big},
	)
	if keys, _, _ := pollFrameKeys(t, session, 0); len(keys) != 1 {
		t.Fatalf("first batch = %v", keys)
	}
	// Stream 3 DATA remains queued. Two WINDOW frames must coalesce into one.
	queueTestFrames(t, session,
		Frame{Type: FrameWindow, StreamID: 9, Payload: window},
		Frame{Type: FrameWindow, StreamID: 9, Payload: window},
	)
	body, _, err := session.Poll(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := ParseBatch(body)
	if err != nil || len(frames) != 2 || frames[0].Type != FrameWindow || frames[1].StreamID != 3 {
		t.Fatalf("second batch = %#v, %v", frames, err)
	}
	if delta, _ := WindowDelta(frames[0].Payload); delta != 6 {
		t.Fatalf("coalesced WINDOW delta = %d", delta)
	}
}

func TestFairDownlinkCapsCoalescedDataFrames(t *testing.T) {
	_, session := fairTestSession(t, true)
	chunk := bytes.Repeat([]byte{1}, RelayDataChunk)
	for range 4 {
		queueTestFrames(t, session, Frame{Type: FrameData, StreamID: 1, Payload: chunk})
	}
	cursor := uint64(0)
	total := 0
	for total < 4*RelayDataChunk {
		keys, size, next := pollFrameKeys(t, session, cursor)
		cursor = next
		if size > webSocketFairMessageBytes {
			t.Fatalf("message has %d bytes", size)
		}
		for _, key := range keys {
			total += key.size
		}
	}
}

func TestFairDownlinkOnlyForMultiplexedWebSocket(t *testing.T) {
	for _, carrier := range []CarrierMode{CarrierHTTPS, CarrierHTTPSLanes, CarrierWebSocketLanes} {
		profiles := testProfiles(t)
		manager := testManager(t, profiles, func(config *ManagerConfig) {
			config.Carrier = carrier
			config.WebSocketFairQueue = true
		}, newPipeDialer().DialContext)
		if manager.fairDown {
			t.Fatalf("carrier %s enabled fair scheduling", carrier)
		}
	}
	_, session := fairTestSession(t, false)
	if session.fairDown || session.downFrameBytes != 0 {
		t.Fatal("websocket session with the fair queue off changed downlink scheduling")
	}
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, newPipeDialer().DialContext)
	session = createTestSession(t, manager, profiles[0]).Session
	if !manager.fairDown || !session.fairDown || session.downFrameBytes != webSocketFairMessageBytes {
		t.Fatalf("default websocket session: fair = %t, frame bytes = %d", session.fairDown, session.downFrameBytes)
	}
}

// TestWebSocketEchoTransferFairAndFIFO checks that fair scheduling delivers
// every byte of several concurrent streams in order through the real gnet
// WebSocket path, and logs the transfer rate and the delay of a small reply
// that starts during the bulk transfer. Set TELEGO_WEB_FAIR_STREAM_MIB to
// move more data per stream (at most 4, the initial stream window).
func TestWebSocketEchoTransferFairAndFIFO(t *testing.T) {
	perStream := 2 << 20
	if value, err := strconv.Atoi(os.Getenv("TELEGO_WEB_FAIR_STREAM_MIB")); err == nil && value > 0 && value <= 4 {
		perStream = value << 20
	}
	for _, fair := range []bool{false, true} {
		name := "fifo"
		if fair {
			name = "fair"
		}
		t.Run(name, func(t *testing.T) {
			elapsed, reply := runWebSocketEchoTransfer(t, fair, 4, perStream)
			t.Logf("%s: %d MiB echoed in %v (%.1f MiB/s); small reply delay %v",
				name, 4*perStream>>20, elapsed, float64(4*perStream)/(1<<20)/elapsed.Seconds(), reply)
		})
	}
}

func runWebSocketEchoTransfer(t *testing.T, fair bool, streams, perStream int) (time.Duration, time.Duration) {
	t.Helper()
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
		config.WebSocketFairQueue = fair
	}, nil)
	created := createTestSession(t, app.manager, app.profiles[0])
	client, response := dialWebSocketTest(t, app.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != 101 {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()

	const replyStream = 99
	pattern := func(stream, offset int) byte { return byte(stream*31 + offset%251) }
	var opens []Frame
	for stream := 1; stream <= streams; stream++ {
		opens = append(opens, Frame{Type: FrameOpen, StreamID: uint32(stream)})
	}
	opens = append(opens, Frame{Type: FrameOpen, StreamID: replyStream})
	client.write(t, ws.OpBinary, true, testFrameBatch(t, opens...))

	writeErr := make(chan error, 1)
	replySent := make(chan time.Time, 1)
	go func() {
		const chunk = 32 * 1024
		for offset := 0; offset < perStream; offset += chunk {
			var batch []byte
			for stream := 1; stream <= streams; stream++ {
				payload := make([]byte, min(chunk, perStream-offset))
				for index := range payload {
					payload[index] = pattern(stream, offset+index)
				}
				batch, _ = AppendFrame(batch, Frame{Type: FrameData, StreamID: uint32(stream), Payload: payload})
			}
			if offset == perStream/4 {
				batch, _ = AppendFrame(batch, Frame{Type: FrameData, StreamID: replyStream, Payload: []byte("ping")})
				replySent <- time.Now()
			}
			if err := ws.WriteFrame(client.connection, ws.MaskFrame(ws.NewFrame(ws.OpBinary, true, batch))); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	started := time.Now()
	received := make([]int, streams+1)
	var replyDelay time.Duration
	remaining := streams * perStream
	for remaining > 0 || replyDelay == 0 {
		frames, err := readWebSocketBatchResult(t, client, 10*time.Second)
		if err != nil {
			t.Fatalf("read downlink with %d bytes left: %v", remaining, err)
		}
		for _, frame := range frames {
			if frame.Type != FrameData {
				continue
			}
			if frame.StreamID == replyStream {
				if !bytes.Equal(frame.Payload, []byte("ping")) {
					t.Fatalf("reply payload = %q", frame.Payload)
				}
				replyDelay = time.Since(<-replySent)
				continue
			}
			stream := int(frame.StreamID)
			for index, value := range frame.Payload {
				if value != pattern(stream, received[stream]+index) {
					t.Fatalf("stream %d byte %d changed", stream, received[stream]+index)
				}
			}
			received[stream] += len(frame.Payload)
			remaining -= len(frame.Payload)
		}
	}
	elapsed := time.Since(started)
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	for stream := 1; stream <= streams; stream++ {
		if received[stream] != perStream {
			t.Fatalf("stream %d received %d bytes", stream, received[stream])
		}
	}
	return elapsed, replyDelay
}
