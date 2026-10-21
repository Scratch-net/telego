package webproxy

import (
	"bytes"
	"io"
	"runtime"
	"testing"

	"github.com/gobwas/ws"
)

func TestWebSocketQueuedInputsKeepApplicationAndCoalescingProgress(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
		config.Limits.MaxSessions = 3
		config.Limits.MaxPendingGlobal = config.Limits.MaxPendingPerSession
		config.Limits.MaxPendingItemsGlobal = config.Limits.MaxPendingItemsPerSession
	}, dialer.DialContext)
	payload := bytes.Repeat([]byte("x"), 32*1024)
	body := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1}, Frame{Type: FrameData, StreamID: 1, Payload: payload})
	type queued struct {
		socket *webSocketConnection
		input  webSocketInbound
	}
	inputs := make([]queued, 2)
	for i := range inputs {
		session := createTestSession(t, manager, profiles[0]).Session
		socket, err := newWebSocketConnection(session, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(socket.cancel)
		owner, ok := newWebSocketOwnedInput(session, socket.inboundBudget, len(body)+webSocketFragmentBytes)
		if !ok {
			t.Fatal("cannot admit queued input")
		}
		t.Cleanup(owner.Release)
		input := webSocketInbound{body: body[:3], fragments: &webSocketFragment{payload: body[3:]},
			payloadBytes: len(body), chunked: true, reservation: owner}
		cost, items, valid := input.applicationBound()
		if !valid || !owner.session.sealApplication(cost, items) {
			t.Fatal("cannot prepay completed input")
		}
		inputs[i] = queued{socket: socket, input: input}
	}
	fillHTTPProgressBudget(t, manager, profiles[0])
	for _, queued := range inputs {
		if code := queued.socket.processUplink(1, queued.input); code != 0 {
			t.Fatalf("globally full input cannot coalesce/apply: close=%d", code)
		}
		peer := dialer.Peer(t)
		t.Cleanup(func() { _ = peer.Close() })
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(peer, received); err != nil || !bytes.Equal(received, payload) {
			t.Fatalf("prepaid application lost data: %v", err)
		}
		if owned, items := queued.socket.inboundBudget.snapshot(); owned != 0 || items != 0 {
			t.Fatalf("released worker retained local ownership: bytes=%d items=%d", owned, items)
		}
	}
}

func TestWebSocketCloseKeepsLiveInputOwnership(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) { config.Carrier = CarrierWebSocket }, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	body := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1},
		Frame{Type: FrameData, StreamID: 1, Payload: bytes.Repeat([]byte{0x7b}, MaxFramePayload)})
	owner, ok := session.reserveWebSocketInput(len(body))
	if !ok {
		t.Fatal("cannot reserve input")
	}
	t.Cleanup(owner.Release)
	before := manager.Capacity()
	session.Close()
	if after := manager.Capacity(); after.PendingBytes != before.PendingBytes || after.PendingItems != before.PendingItems {
		t.Fatalf("close released live input: before=%+v after=%+v", before, after)
	}
	runtime.KeepAlive(body)
	if owner.resize(len(body) + 1) {
		t.Fatal("closed input grew storage")
	}
	owner.Release()
	owner.Release()
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("released closed input retained ownership: %+v", capacity)
	}
}

func TestWebSocketApplicationBoundAcrossFragmentedHeaders(t *testing.T) {
	body := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1},
		Frame{Type: FrameData, StreamID: 1, Payload: []byte("first")},
		Frame{Type: FrameClose, StreamID: 1}, Frame{Type: FrameData, StreamID: 1, Payload: []byte("late")})
	for split := 1; split < FrameHeaderSize; split++ {
		input := webSocketInbound{body: body[:split], payloadBytes: len(body), chunked: true}
		tail := &input.fragments
		for offset := split; offset < len(body); {
			end := min(offset+split, len(body))
			*tail = &webSocketFragment{payload: body[offset:end]}
			tail = &(*tail).next
			offset = end
		}
		if cost, items, ok := input.applicationBound(); !ok || items != 2 || cost != len("firstlate")+2*queueItemCost {
			t.Fatalf("split=%d cost=%d items=%d valid=%t", split, cost, items, ok)
		}
	}
	pong := testFrameBatch(t, Frame{Type: FramePong})
	for _, input := range []webSocketInbound{
		{body: body[:FrameHeaderSize-1]},
		{body: body[:len(body)-1]},
		{body: bytes.Repeat(pong, MaxBatchFrames+1)},
	} {
		if _, _, valid := input.applicationBound(); valid {
			t.Fatal("malformed batch acquired a smaller application bound")
		}
	}
	if cost, items, valid := (webSocketInbound{body: bytes.Repeat(pong, MaxBatchFrames)}).applicationBound(); !valid || cost != 0 || items != 0 {
		t.Fatalf("maximum control frame batch: cost=%d items=%d valid=%t", cost, items, valid)
	}
}

func TestWebSocketMalformedInputReleasesPrepaidOwnership(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) { config.Carrier = CarrierWebSocket }, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	socket, err := newWebSocketConnection(session, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.cancel()
	body := testFrameBatch(t, Frame{Type: FramePong})[:FrameHeaderSize-1]
	owner, ok := newWebSocketOwnedInput(session, socket.inboundBudget, len(body))
	if !ok {
		t.Fatal("cannot reserve malformed input")
	}
	if code := socket.processUplink(1, webSocketInbound{body: body, reservation: owner}); code != ws.StatusProtocolError {
		t.Fatalf("malformed input close=%d", code)
	}
	if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("malformed input retained ownership: %+v", capacity)
	}
}
