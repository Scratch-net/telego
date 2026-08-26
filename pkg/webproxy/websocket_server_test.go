package webproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
)

type webSocketTestClient struct {
	connection net.Conn
	reader     *bufio.Reader
}

func TestHTTPServerWebSocketMultiplexEndToEnd(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token,
		"Origin: https://unrelated.example\r\nCookie: site=value\r\n", nil)
	if response.StatusCode != http.StatusSwitchingProtocols ||
		response.Header.Get("Sec-WebSocket-Protocol") != webSocketProtocolPrefix+created.Token ||
		response.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatalf("upgrade = %d, headers %#v", response.StatusCode, response.Header)
	}
	defer client.close()

	payload := []byte("websocket echo")
	client.write(t, ws.OpBinary, true, testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 1},
		Frame{Type: FrameData, StreamID: 1, Payload: payload},
	))
	found := false
	var received []Frame
	for range 4 {
		frames, err := readWebSocketBatchResult(t, client, time.Second)
		if err != nil {
			created.Session.mu.Lock()
			lane := created.Session.carrierLanes[0]
			pendingFrames := len(lane.pendingFrames)
			unackedBytes := len(lane.unacked)
			lastUpSequence := lane.lastUpSequence
			upActive := lane.upActive
			downActive := lane.downActive
			streams := len(created.Session.streams)
			created.Session.mu.Unlock()
			t.Fatalf("read downlink: %v (pending=%d unacked=%d up-seq=%d up-active=%v down-active=%v streams=%d)",
				err, pendingFrames, unackedBytes, lastUpSequence, upActive, downActive, streams)
		}
		received = append(received, frames...)
		for _, frame := range frames {
			if frame.Type == FrameData && frame.StreamID == 1 && bytes.Equal(frame.Payload, payload) {
				found = true
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatalf("downlink omitted echo: %#v", received)
	}
}

func TestHTTPServerWebSocketActiveConnectionMetricLifecycle(t *testing.T) {
	for _, test := range []struct {
		name     string
		carrier  CarrierMode
		protocol func(string, uint32) string
	}{
		{
			name:    "multiplex",
			carrier: CarrierWebSocket,
			protocol: func(token string, _ uint32) string {
				return webSocketProtocolPrefix + token
			},
		},
		{
			name:    "lane",
			carrier: CarrierWebSocketLanes,
			protocol: func(token string, laneID uint32) string {
				return webSocketLaneProtocolPrefix + token + "." + strconv.FormatUint(uint64(laneID), 10)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
				config.Carrier = test.carrier
			}, nil)
			if active := application.manager.RuntimeStats().WebSocketsActive; active != 0 {
				t.Fatalf("initial active WebSockets = %d", active)
			}

			created := createTestSession(t, application.manager, application.profiles[0])
			client, response := dialWebSocketTest(t, application.address, test.protocol(created.Token, 41), "", nil)
			if response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade = %d", response.StatusCode)
			}
			eventually(t, time.Second, func() bool {
				return application.manager.RuntimeStats().WebSocketsActive == 1
			})

			rejected, _, rejectedResponse := dialRawWebSocketTest(t, application.address, webSocketPath,
				test.protocol(strings.Repeat("A", 43), 42), "", nil)
			_ = rejected.Close()
			_ = readHTTPBody(t, rejectedResponse)
			if rejectedResponse.StatusCode != defaultSanitizedFallbackStatus ||
				application.manager.RuntimeStats().WebSocketsActive != 1 {
				t.Fatalf("rejection = %d, active = %d", rejectedResponse.StatusCode,
					application.manager.RuntimeStats().WebSocketsActive)
			}

			client.close()
			eventually(t, time.Second, func() bool {
				return application.manager.RuntimeStats().WebSocketsActive == 0
			})
			client.close()
			if active := application.manager.RuntimeStats().WebSocketsActive; active != 0 {
				t.Fatalf("duplicate close active WebSockets = %d", active)
			}

			shutdownSession := createTestSession(t, application.manager, application.profiles[0])
			shutdownClient, shutdownResponse := dialWebSocketTest(t, application.address,
				test.protocol(shutdownSession.Token, 43), "", nil)
			if shutdownResponse.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("shutdown upgrade = %d", shutdownResponse.StatusCode)
			}
			defer shutdownClient.close()
			eventually(t, time.Second, func() bool {
				return application.manager.RuntimeStats().WebSocketsActive == 1
			})
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err := application.server.Stop(ctx); err != nil {
				t.Fatal(err)
			}
			if active := application.manager.RuntimeStats().WebSocketsActive; active != 0 {
				t.Fatalf("shutdown active WebSockets = %d", active)
			}
		})
	}
}

func TestHTTPServerWebSocketChunkedLargeUplinkExact(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 2*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	payload := bytes.Repeat([]byte("chunked-uplink"), 16*1024)
	client.write(t, ws.OpBinary, true, testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 103},
		Frame{Type: FrameData, StreamID: 103, Payload: payload},
	))
	received := make([]byte, 0, len(payload))
	for range 32 {
		frames := readWebSocketBatch(t, client, 2*time.Second)
		for _, frame := range frames {
			if frame.Type == FrameData && frame.StreamID == 103 {
				received = append(received, frame.Payload...)
			}
		}
		if len(received) >= len(payload) {
			break
		}
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("chunked uplink changed before ProcessUp: got %d bytes, want %d", len(received), len(payload))
	}
}

func TestHTTPServerWebSocketHandshakeSecurityAndFallbacks(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	protocol := webSocketProtocolPrefix + created.Token
	first, response := dialWebSocketTest(t, application.address, protocol, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("first upgrade = %d", response.StatusCode)
	}
	defer first.close()
	authorizationProtocol := webSocketProtocolPrefix + createTestSession(t, application.manager, application.profiles[0]).Token
	trailingProtocol := webSocketProtocolPrefix + createTestSession(t, application.manager, application.profiles[0]).Token

	for name, test := range map[string]struct {
		path     string
		protocol string
		extra    string
		trailing []byte
		status   int
		class    string
	}{
		"duplicate": {
			path: webSocketPath, protocol: protocol, status: defaultSanitizedFallbackStatus,
			class: FallbackSanitizedPublic,
		},
		"wrong token": {
			path: webSocketPath, protocol: webSocketProtocolPrefix + strings.Repeat("A", 43),
			status: defaultSanitizedFallbackStatus, class: FallbackSanitizedPublic,
		},
		"authorization": {
			path: webSocketPath, protocol: authorizationProtocol, extra: "Authorization: Bearer " + created.Token + "\r\n",
			status: defaultSanitizedFallbackStatus, class: FallbackSanitizedPublic,
		},
		"trailing frame": {
			path: webSocketPath, protocol: trailingProtocol, trailing: maskedClientFrame(t, ws.OpPing, true, nil),
			status: defaultSanitizedFallbackStatus, class: FallbackSanitizedPublic,
		},
		"ordinary upgrade": {
			path: "/socket?site=1", protocol: "site-v1", status: defaultPassthroughStatus,
			class: FallbackOrdinarySite,
		},
	} {
		t.Run(name, func(t *testing.T) {
			connection, _, fallback := dialRawWebSocketTest(
				t,
				application.address,
				test.path,
				test.protocol,
				test.extra,
				test.trailing,
			)
			_ = connection.Close()
			_ = readHTTPBody(t, fallback)
			if fallback.StatusCode != test.status || fallback.Header.Get(FallbackClassificationHeader) != test.class {
				t.Fatalf("fallback = %d, headers %#v", fallback.StatusCode, fallback.Header)
			}
		})
	}
}

func TestHTTPServerWebSocketLaneIsolation(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocketLanes
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	first, firstResponse := dialWebSocketTest(t, application.address,
		webSocketLaneProtocolPrefix+created.Token+".41", "", nil)
	if firstResponse.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("first lane upgrade = %d", firstResponse.StatusCode)
	}
	defer first.close()
	second, secondResponse := dialWebSocketTest(t, application.address,
		webSocketLaneProtocolPrefix+created.Token+".42", "Origin: https://wrong.example\r\n", nil)
	if secondResponse.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("second lane upgrade = %d", secondResponse.StatusCode)
	}
	defer second.close()

	for _, test := range []struct {
		client  *webSocketTestClient
		laneID  uint32
		payload string
	}{
		{first, 41, "first lane"},
		{second, 42, "second lane"},
	} {
		test.client.write(t, ws.OpBinary, true, testFrameBatch(t,
			Frame{Type: FrameOpen, StreamID: test.laneID},
			Frame{Type: FrameData, StreamID: test.laneID, Payload: []byte(test.payload)},
		))
		frames := readWebSocketUntilData(t, test.client, test.laneID, time.Second)
		if len(frames) == 0 {
			t.Fatalf("lane %d returned no frames", test.laneID)
		}
		for _, frame := range frames {
			if frame.StreamID != test.laneID {
				t.Fatalf("lane %d received stream %d", test.laneID, frame.StreamID)
			}
		}
	}

	first.write(t, ws.OpText, true, []byte("invalid"))
	expectWebSocketClosed(t, first, time.Second)
	second.write(t, ws.OpBinary, true, testFrameBatch(t,
		Frame{Type: FrameData, StreamID: 42, Payload: []byte("still alive")},
	))
	frames := readWebSocketUntilData(t, second, 42, time.Second)
	if len(frames) == 0 {
		t.Fatal("surviving lane stopped after sibling protocol failure")
	}
}

func TestHTTPServerWebSocketFragmentationControlAndMasking(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	body := testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 5},
		Frame{Type: FrameData, StreamID: 5, Payload: []byte("fragmented")},
	)
	mid := len(body) / 2
	client.write(t, ws.OpBinary, false, body[:mid])
	client.write(t, ws.OpPing, true, []byte("probe"))
	client.write(t, ws.OpContinuation, true, body[mid:])

	foundPong := false
	foundBinary := false
	for !foundPong || !foundBinary {
		opcode, payload := client.read(t, time.Second)
		switch opcode {
		case ws.OpPong:
			foundPong = bytes.Equal(payload, []byte("probe"))
		case ws.OpPing:
			client.write(t, ws.OpPong, true, payload)
		case ws.OpBinary:
			frames, err := ParseBatch(payload)
			if err != nil {
				t.Fatal(err)
			}
			for _, frame := range frames {
				if frame.Type == FrameData && frame.StreamID == 5 && bytes.Equal(frame.Payload, []byte("fragmented")) {
					foundBinary = true
				}
			}
		}
	}

	partialPayload := testFrameBatch(t,
		Frame{Type: FrameData, StreamID: 5, Payload: []byte("split TCP frame")},
	)
	partialHeader := maskedClientHeader(t, ws.OpBinary, true, len(partialPayload))
	if _, err := client.connection.Write(partialHeader); err != nil {
		t.Fatal(err)
	}
	maskedPayload := bytes.Clone(partialPayload)
	ws.Cipher(maskedPayload, [4]byte{1, 2, 3, 4}, 0)
	if _, err := client.connection.Write(maskedPayload); err != nil {
		t.Fatal(err)
	}
	foundSplit := false
	for range 4 {
		frames := readWebSocketBatch(t, client, time.Second)
		for _, frame := range frames {
			if frame.Type == FrameData && frame.StreamID == 5 && bytes.Equal(frame.Payload, []byte("split TCP frame")) {
				foundSplit = true
			}
		}
		if foundSplit {
			break
		}
	}
	if !foundSplit {
		t.Fatal("split TCP frame produced no downlink")
	}

	unmaskedSession := createTestSession(t, application.manager, application.profiles[0])
	unmasked, unmaskedResponse := dialWebSocketTest(t, application.address,
		webSocketProtocolPrefix+unmaskedSession.Token, "", nil)
	if unmaskedResponse.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("unmasked test upgrade = %d", unmaskedResponse.StatusCode)
	}
	defer unmasked.close()
	frame := serverFrame(t, ws.OpBinary, true, []byte("unmasked"))
	if _, err := unmasked.connection.Write(frame); err != nil {
		t.Fatal(err)
	}
	expectWebSocketCloseCode(t, unmasked, ws.StatusProtocolError, time.Second)
	eventually(t, time.Second, func() bool {
		_, err := application.manager.Get(unmaskedSession.Token)
		return err != nil
	})
}

func TestHTTPServerWebSocketDenseFragmentFloodCloses1011(t *testing.T) {
	for name, payload := range map[string][]byte{
		"zero": nil,
		"tiny": {1},
	} {
		t.Run(name, func(t *testing.T) {
			application := newHTTPTestApplicationWithConfig(t, 5*time.Second, func(config *ManagerConfig) {
				config.Carrier = CarrierWebSocket
			}, nil)
			created := createTestSession(t, application.manager, application.profiles[0])
			client, response := dialWebSocketTest(t, application.address,
				webSocketProtocolPrefix+created.Token, "", nil)
			if response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade = %d", response.StatusCode)
			}
			defer client.close()

			continuation := maskedClientFrame(t, ws.OpContinuation, false, payload)
			wire := maskedClientFrame(t, ws.OpBinary, false, []byte("start"))
			floodBytes := maxWebSocketControlInputBytes + 4*1024
			for len(wire)+len(continuation) <= floodBytes {
				wire = append(wire, continuation...)
			}
			client.writeRaw(t, wire)
			expectWebSocketCloseCode(t, client, ws.StatusInternalServerError, 2*time.Second)
		})
	}
}

func TestHTTPServerWebSocketDensePongFloodDuringFragmentCloses1011(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 5*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address,
		webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()

	pong := maskedClientFrame(t, ws.OpPong, true, nil)
	wire := maskedClientFrame(t, ws.OpBinary, false, []byte("start"))
	floodBytes := maxWebSocketControlInputBytes + 4*1024
	for len(wire)+len(pong) <= floodBytes {
		wire = append(wire, pong...)
	}
	client.writeRaw(t, wire)
	expectWebSocketCloseCode(t, client, ws.StatusInternalServerError, 2*time.Second)
}

func TestHTTPServerWebSocketDenseControlFloodCloses1011(t *testing.T) {
	for _, test := range []struct {
		name   string
		opcode ws.OpCode
	}{
		{name: "ping", opcode: ws.OpPing},
		{name: "pong", opcode: ws.OpPong},
	} {
		t.Run(test.name, func(t *testing.T) {
			application := newHTTPTestApplicationWithConfig(t, 30*time.Second, func(config *ManagerConfig) {
				config.Carrier = CarrierWebSocket
			}, nil)
			created := createTestSession(t, application.manager, application.profiles[0])
			client, response := dialWebSocketTest(t, application.address,
				webSocketProtocolPrefix+created.Token, "", nil)
			if response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade = %d", response.StatusCode)
			}
			defer client.close()

			control := maskedClientFrame(t, test.opcode, true, bytes.Repeat([]byte{0x5a}, 125))
			wire := make([]byte, 0, maxWebSocketControlInputBytes+4*1024)
			for len(wire)+len(control) <= cap(wire) {
				wire = append(wire, control...)
			}
			client.writeRaw(t, wire)
			expectWebSocketCloseCode(t, client, ws.StatusInternalServerError, 5*time.Second)
		})
	}
}

func TestHTTPServerWebSocketControlBurstBelowBoundCarriesBinary(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 5*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address,
		webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()

	wire := make([]byte, 0, 1024)
	for range maxWebSocketOutboundMessages - 1 {
		wire = append(wire, maskedClientFrame(t, ws.OpPong, true, []byte("ordinary"))...)
	}
	wire = append(wire, maskedClientFrame(t, ws.OpBinary, true, testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 108},
		Frame{Type: FrameData, StreamID: 108, Payload: []byte("after controls")},
	))...)
	client.writeRaw(t, wire)
	frames := readWebSocketUntilData(t, client, 108, time.Second)
	if len(frames) == 0 {
		t.Fatal("ordinary control burst prevented the following binary message")
	}
}

func TestHTTPServerWebSocketDrainedPingBurstsDoNotAccumulate(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 5*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address,
		webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()

	payload := bytes.Repeat([]byte{0x4b}, 125)
	controlWireBytes := ws.MinHeaderSize + 4 + len(payload)
	for range maxWebSocketControlInputBytes/controlWireBytes + 2 {
		client.write(t, ws.OpPing, true, payload)
		opcode, responsePayload := client.read(t, time.Second)
		if opcode != ws.OpPong || !bytes.Equal(responsePayload, payload) {
			t.Fatalf("Ping response = opcode %v, payload length %d", opcode, len(responsePayload))
		}
	}
	client.write(t, ws.OpBinary, true, testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 109},
		Frame{Type: FrameData, StreamID: 109, Payload: []byte("after drained controls")},
	))
	if frames := readWebSocketUntilData(t, client, 109, time.Second); len(frames) == 0 {
		t.Fatal("drained control bursts closed the WebSocket")
	}
}

func TestHTTPServerWebSocketInterleavedPongKeepsFragmentAlive(t *testing.T) {
	const longPoll = 60 * time.Millisecond
	application := newHTTPTestApplicationWithConfig(t, longPoll, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address,
		webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()

	payload := []byte("alive across fragmented pongs")
	body := testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 107},
		Frame{Type: FrameData, StreamID: 107, Payload: payload},
	)
	mid := len(body) / 2
	client.write(t, ws.OpBinary, false, body[:mid])
	started := time.Now()
	for range 4 {
		opcode, pingPayload := client.read(t, 3*longPoll)
		if opcode != ws.OpPing {
			t.Fatalf("liveness frame = %v", opcode)
		}
		client.write(t, ws.OpPong, true, pingPayload)
	}
	if elapsed := time.Since(started); elapsed < 2*longPoll {
		t.Fatalf("interleaved Pong proof ran for only %v", elapsed)
	}
	client.write(t, ws.OpContinuation, true, body[mid:])
	frames := readWebSocketUntilData(t, client, 107, time.Second)
	found := false
	for _, frame := range frames {
		if frame.Type == FrameData && frame.StreamID == 107 && bytes.Equal(frame.Payload, payload) {
			found = true
		}
	}
	if !found {
		t.Fatalf("fragmented message after interleaved Pong = %#v", frames)
	}
}

func TestHTTPServerWebSocketMaximumMessageWithNormalFragmentsSucceeds(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 5*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	backend := newWebSocketRecordingBackend()
	application.manager.dialBackend = func(context.Context, string, string, string) (net.Conn, error) {
		return backend, nil
	}
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()

	firstPayload := bytes.Repeat([]byte{0x61}, MaxFramePayload)
	secondPayload := bytes.Repeat([]byte{0x62}, maxWebSocketMessageBytes-MaxFramePayload-3*FrameHeaderSize)
	body := testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 106},
		Frame{Type: FrameData, StreamID: 106, Payload: firstPayload},
		Frame{Type: FrameData, StreamID: 106, Payload: secondPayload},
	)
	if len(body) != maxWebSocketMessageBytes {
		t.Fatalf("maximum carrier body = %d, want %d", len(body), maxWebSocketMessageBytes)
	}
	const fragmentBytes = 2 * maxWebSocketPayloadBytesPerTraffic
	wire := make([]byte, 0, len(body)+ws.MaxHeaderSize*(len(body)/fragmentBytes+1))
	for offset := 0; offset < len(body); offset += fragmentBytes {
		end := min(offset+fragmentBytes, len(body))
		opcode := ws.OpContinuation
		if offset == 0 {
			opcode = ws.OpBinary
		}
		wire = append(wire, maskedClientFrame(t, opcode, end == len(body), body[offset:end])...)
	}
	client.writeRaw(t, wire)

	for index, want := range [][]byte{firstPayload, secondPayload} {
		select {
		case got := <-backend.writes:
			if !bytes.Equal(got, want) {
				t.Fatalf("backend write %d = %d changed bytes, want %d", index, len(got), len(want))
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("backend write %d did not arrive", index)
		}
	}
}

func TestHTTPServerWebSocketCommitsBinaryBeforeCoalescedSuffix(t *testing.T) {
	for name, suffix := range map[string][]byte{
		"close":   maskedClientFrame(t, ws.OpClose, true, []byte{0x03, 0xe8}),
		"invalid": maskedClientFrame(t, ws.OpText, true, []byte("invalid")),
	} {
		t.Run(name, func(t *testing.T) {
			application := newHTTPTestApplicationWithConfig(t, 2*time.Second, func(config *ManagerConfig) {
				config.Carrier = CarrierWebSocket
			}, nil)
			backend := newWebSocketRecordingBackend()
			application.manager.dialBackend = func(context.Context, string, string, string) (net.Conn, error) {
				return backend, nil
			}
			created := createTestSession(t, application.manager, application.profiles[0])
			t.Cleanup(func() {
				created.Session.mu.Lock()
				if lane := created.Session.carrierLanes[0]; lane != nil {
					lane.upActive = false
				}
				created.Session.mu.Unlock()
			})

			client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
			if response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade = %d", response.StatusCode)
			}
			defer client.close()
			client.write(t, ws.OpBinary, true, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 91}))
			select {
			case <-backend.ready:
			case <-time.After(time.Second):
				t.Fatal("initial OPEN did not establish the backend")
			}
			created.Session.mu.Lock()
			lane := created.Session.carrierLanes[0]
			lane.upActive = true
			created.Session.mu.Unlock()
			binary := maskedClientFrame(t, ws.OpBinary, true, testFrameBatch(t,
				Frame{Type: FrameData, StreamID: 91, Payload: []byte("accepted first")},
			))
			backpressureBefore := application.manager.backpressure[carrierOperationUplink].Load()
			if _, err := client.connection.Write(append(binary, suffix...)); err != nil {
				t.Fatal(err)
			}
			eventually(t, time.Second, func() bool {
				return application.manager.backpressure[carrierOperationUplink].Load() > backpressureBefore
			})
			created.Session.mu.Lock()
			beforeRelease := lane.lastUpSequence
			lane.upActive = false
			created.Session.mu.Unlock()
			if beforeRelease != 1 {
				t.Fatalf("uplink advanced while forced into backpressure: %d", beforeRelease)
			}
			deadline := time.Now().Add(time.Second)
			for {
				created.Session.mu.Lock()
				committed := lane.lastUpSequence
				created.Session.mu.Unlock()
				if committed == 2 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("ProcessUp sequence was not committed before coalesced %s suffix teardown: %d", name, committed)
				}
				time.Sleep(time.Millisecond)
			}
			expectWebSocketClosed(t, client, time.Second)
		})
	}
}

func TestWebSocketUnreadInputBoundAppliesAtFrameLimitOrControlEvent(t *testing.T) {
	decoder := testWebSocketDecoder(t, maxWebSocketMessageBytes)
	start := maskedClientFrame(t, ws.OpBinary, false, []byte("start"))
	if _, _, emitted, err := decoder.Decode(start); err != nil || emitted {
		t.Fatalf("fragment start: emitted=%t err=%v", emitted, err)
	}
	transport := &webSocketConnection{decoder: decoder}
	buffer := &webSocketTestInboundBuffer{data: make([]byte, maxWebSocketControlInputBytes)}
	overflow, err := transport.boundUnreadInput(buffer,
		webSocketDecodeWork{limit: webSocketDecodeFrameLimit}, webSocketMessage{}, false, false, false)
	if err != nil || overflow || len(buffer.data) != maxWebSocketControlInputBytes {
		t.Fatalf("at-limit frame exhaustion: overflow=%t bytes=%d err=%v", overflow, len(buffer.data), err)
	}
	buffer.data = append(buffer.data, 1)
	overflow, err = transport.boundUnreadInput(buffer,
		webSocketDecodeWork{limit: webSocketDecodePayloadLimit}, webSocketMessage{}, false, false, false)
	if err != nil || overflow || len(buffer.data) != maxWebSocketControlInputBytes+1 {
		t.Fatalf("payload progress: overflow=%t bytes=%d err=%v", overflow, len(buffer.data), err)
	}
	controlBuffer := &webSocketTestInboundBuffer{data: bytes.Clone(buffer.data)}
	overflow, err = transport.boundUnreadInput(controlBuffer, webSocketDecodeWork{},
		webSocketMessage{typeID: webSocketMessagePong}, true, true, false)
	if err != nil || !overflow || len(controlBuffer.data) != 0 {
		t.Fatalf("control event: overflow=%t bytes=%d err=%v", overflow, len(controlBuffer.data), err)
	}
	overflow, err = transport.boundUnreadInput(buffer,
		webSocketDecodeWork{limit: webSocketDecodeFrameLimit}, webSocketMessage{}, false, false, false)
	if err != nil || !overflow || len(buffer.data) != 0 {
		t.Fatalf("frame exhaustion: overflow=%t bytes=%d err=%v", overflow, len(buffer.data), err)
	}

	decoder.Reset()
	unfragmented := &webSocketTestInboundBuffer{data: make([]byte, maxWebSocketControlInputBytes+1)}
	overflow, err = transport.boundUnreadInput(unfragmented, webSocketDecodeWork{},
		webSocketMessage{typeID: webSocketMessagePing}, true, true, false)
	if err != nil || !overflow || len(unfragmented.data) != 0 {
		t.Fatalf("unfragmented control event: overflow=%t bytes=%d err=%v", overflow, len(unfragmented.data), err)
	}
}

func TestWebSocketControlInputCounterResetsBetweenDrainedBursts(t *testing.T) {
	transport := &webSocketConnection{}
	buffer := &webSocketTestInboundBuffer{}
	control := webSocketMessage{typeID: webSocketMessagePong}
	controlWireBytes := ws.MinHeaderSize + 4
	burstCount := maxWebSocketControlInputBytes/controlWireBytes + 2
	for range burstCount {
		overflow, err := transport.boundUnreadInput(
			buffer, webSocketDecodeWork{}, control, true, true, false,
		)
		if err != nil || overflow {
			t.Fatalf("drained control burst overflowed: overflow=%t err=%v", overflow, err)
		}
		transport.resetControlBurstIfDrained(buffer)
	}
	if transport.controlInputBytes != 0 {
		t.Fatalf("drained control counter = %d", transport.controlInputBytes)
	}

	transport.controlOutputItems = 1
	for range maxWebSocketControlInputBytes / controlWireBytes {
		overflow, err := transport.boundUnreadInput(
			buffer, webSocketDecodeWork{}, control, true, true, false,
		)
		if err != nil || overflow {
			t.Fatalf("queued control output overflowed early: overflow=%t err=%v", overflow, err)
		}
		transport.resetControlBurstIfDrained(buffer)
	}
	overflow, err := transport.boundUnreadInput(
		buffer, webSocketDecodeWork{}, control, true, true, false,
	)
	if err != nil || !overflow {
		t.Fatalf("undrained control burst: overflow=%t err=%v", overflow, err)
	}
}

func TestHTTPServerWebSocketQueuesDesktopBurstDuringBackpressure(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 2*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	backend := newWebSocketRecordingBackendWithCapacity(128)
	application.manager.dialBackend = func(context.Context, string, string, string) (net.Conn, error) {
		return backend, nil
	}
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	client.write(t, ws.OpBinary, true, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 94}))
	select {
	case <-backend.ready:
	case <-time.After(time.Second):
		t.Fatal("initial OPEN did not establish the backend")
	}
	created.Session.mu.Lock()
	created.Session.carrierLanes[0].upActive = true
	created.Session.mu.Unlock()
	t.Cleanup(func() {
		created.Session.mu.Lock()
		if lane := created.Session.carrierLanes[0]; lane != nil {
			lane.upActive = false
		}
		created.Session.mu.Unlock()
	})
	const (
		desktopPendingBytes = 4 * 1024 * 1024
		desktopFrameBytes   = 64 * 1024
		desktopFrameCount   = desktopPendingBytes / desktopFrameBytes
	)
	client.write(t, ws.OpBinary, true, testFrameBatch(t, Frame{
		Type: FrameData, StreamID: 94, Payload: bytes.Repeat([]byte{0}, desktopFrameBytes),
	}))
	eventually(t, time.Second, func() bool {
		return application.manager.backpressure[carrierOperationUplink].Load() != 0
	})
	pendingBeforeBurst := application.manager.Capacity()
	burst := make([]byte, 0, desktopPendingBytes)
	for index := 1; index < desktopFrameCount; index++ {
		body := testFrameBatch(t, Frame{
			Type: FrameData, StreamID: 94, Payload: bytes.Repeat([]byte{byte(index)}, desktopFrameBytes),
		})
		burst = append(burst, maskedClientFrame(t, ws.OpBinary, true, body)...)
	}
	if err := client.connection.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client.writeRaw(t, burst)
	if err := client.connection.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	queuedDeadline := time.Now().Add(2 * time.Second)
	for {
		capacity := application.manager.Capacity()
		if capacity.PendingBytes >= pendingBeforeBurst.PendingBytes+desktopPendingBytes/2 {
			break
		}
		if time.Now().After(queuedDeadline) {
			t.Fatalf("decoded burst reserved %d additional bytes and %d items",
				capacity.PendingBytes-pendingBeforeBurst.PendingBytes,
				capacity.PendingItems-pendingBeforeBurst.PendingItems)
		}
		time.Sleep(time.Millisecond)
	}
	fallback := application.do(t, &http.Client{Timeout: time.Second}, http.MethodGet, "/health", nil, nil)
	_ = readHTTPBody(t, fallback)
	if fallback.StatusCode != defaultPassthroughStatus {
		t.Fatalf("fallback while desktop burst is queued = %d", fallback.StatusCode)
	}
	created.Session.mu.Lock()
	created.Session.carrierLanes[0].upActive = false
	created.Session.mu.Unlock()
	for index := range desktopFrameCount {
		select {
		case written := <-backend.writes:
			if len(written) != desktopFrameBytes || !bytes.Equal(written, bytes.Repeat([]byte{byte(index)}, desktopFrameBytes)) {
				t.Fatalf("backend write %d was corrupted", index)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("backend write %d did not arrive", index)
		}
	}
	client.write(t, ws.OpPing, true, []byte("still open"))
	foundPong := false
	for !foundPong {
		opcode, payload := client.read(t, 2*time.Second)
		if opcode == ws.OpPong && bytes.Equal(payload, []byte("still open")) {
			foundPong = true
		} else if opcode == ws.OpPing {
			client.write(t, ws.OpPong, true, payload)
		}
	}
}

func TestHTTPServerWebSocketPendingUplinkOutlivesLivenessDeadline(t *testing.T) {
	const longPoll = 50 * time.Millisecond
	application := newHTTPTestApplicationWithConfig(t, longPoll, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, func(config *HTTPServerConfig) {
		config.webSocketBackpressureTimeout = time.Second
		config.webSocketBackpressureRetry = 5 * time.Millisecond
	})
	backend := newWebSocketRecordingBackend()
	application.manager.dialBackend = func(context.Context, string, string, string) (net.Conn, error) {
		return backend, nil
	}
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	client.write(t, ws.OpBinary, true, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 95}))
	select {
	case <-backend.ready:
	case <-time.After(time.Second):
		t.Fatal("initial OPEN did not establish the backend")
	}
	created.Session.mu.Lock()
	created.Session.carrierLanes[0].upActive = true
	created.Session.mu.Unlock()
	client.write(t, ws.OpBinary, true, testFrameBatch(t,
		Frame{Type: FrameData, StreamID: 95, Payload: []byte("commit after liveness expiry")},
	))
	eventually(t, time.Second, func() bool {
		return application.manager.backpressure[carrierOperationUplink].Load() != 0
	})
	time.Sleep(3 * longPoll)
	created.Session.mu.Lock()
	created.Session.carrierLanes[0].upActive = false
	created.Session.mu.Unlock()
	select {
	case written := <-backend.writes:
		if string(written) != "commit after liveness expiry" {
			t.Fatalf("backend received %q", written)
		}
	case <-time.After(time.Second):
		t.Fatal("liveness expiry dropped the accepted uplink")
	}
	expectWebSocketClosed(t, client, 2*time.Second)
}

func TestHTTPServerWebSocketBackpressureTimeoutSeam(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, func(config *HTTPServerConfig) {
		config.webSocketBackpressureTimeout = 60 * time.Millisecond
		config.webSocketBackpressureRetry = 5 * time.Millisecond
	})
	created := createTestSession(t, application.manager, application.profiles[0])
	created.Session.mu.Lock()
	created.Session.carrierLanes[0].upActive = true
	created.Session.mu.Unlock()
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	client.write(t, ws.OpBinary, true, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 96}))
	expectWebSocketCloseCode(t, client, ws.StatusInternalServerError, time.Second)
	if retries := application.manager.backpressure[carrierOperationUplink].Load(); retries < 2 {
		t.Fatalf("backpressure attempts = %d, want at least 2", retries)
	}
}

func TestHTTPServerWebSocketLivenessRefreshRules(t *testing.T) {
	const longPoll = 60 * time.Millisecond

	t.Run("ping does not refresh", func(t *testing.T) {
		application := newHTTPTestApplicationWithConfig(t, longPoll, func(config *ManagerConfig) {
			config.Carrier = CarrierWebSocket
		}, nil)
		created := createTestSession(t, application.manager, application.profiles[0])
		client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
		if response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade = %d", response.StatusCode)
		}
		defer client.close()
		frame := ws.MaskFrame(ws.NewFrame(ws.OpPing, true, []byte("not-live")))
		deadline := time.Now().Add(4 * longPoll)
		for time.Now().Before(deadline) {
			if err := ws.WriteFrame(client.connection, frame); err != nil {
				break
			}
			time.Sleep(longPoll / 3)
		}
		expectWebSocketClosed(t, client, time.Second)
	})

	t.Run("unfinished fragments do not refresh", func(t *testing.T) {
		application := newHTTPTestApplicationWithConfig(t, longPoll, func(config *ManagerConfig) {
			config.Carrier = CarrierWebSocket
		}, nil)
		created := createTestSession(t, application.manager, application.profiles[0])
		client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
		if response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade = %d", response.StatusCode)
		}
		defer client.close()
		client.write(t, ws.OpBinary, false, []byte("unfinished"))
		continuation := ws.MaskFrame(ws.NewFrame(ws.OpContinuation, false, nil))
		deadline := time.Now().Add(4 * longPoll)
		for time.Now().Before(deadline) {
			if err := ws.WriteFrame(client.connection, continuation); err != nil {
				break
			}
			time.Sleep(longPoll / 3)
		}
		expectWebSocketClosed(t, client, time.Second)
	})

	t.Run("pong refreshes", func(t *testing.T) {
		application := newHTTPTestApplicationWithConfig(t, longPoll, func(config *ManagerConfig) {
			config.Carrier = CarrierWebSocket
		}, nil)
		created := createTestSession(t, application.manager, application.profiles[0])
		client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
		if response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade = %d", response.StatusCode)
		}
		defer client.close()
		for range 4 {
			opcode, payload := client.read(t, 3*longPoll)
			if opcode != ws.OpPing {
				t.Fatalf("liveness frame = %v", opcode)
			}
			client.write(t, ws.OpPong, true, payload)
		}
		payload := []byte("alive after pong")
		client.write(t, ws.OpBinary, true, testFrameBatch(t,
			Frame{Type: FrameOpen, StreamID: 92},
			Frame{Type: FrameData, StreamID: 92, Payload: payload},
		))
		frames := readWebSocketUntilData(t, client, 92, time.Second)
		if len(frames) == 0 {
			t.Fatal("pong-refreshed connection stopped carrying data")
		}
	})

	t.Run("complete binary refreshes", func(t *testing.T) {
		application := newHTTPTestApplicationWithConfig(t, longPoll, func(config *ManagerConfig) {
			config.Carrier = CarrierWebSocket
		}, nil)
		created := createTestSession(t, application.manager, application.profiles[0])
		client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
		if response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade = %d", response.StatusCode)
		}
		defer client.close()
		client.write(t, ws.OpBinary, true, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 93}))
		for sequence := range 4 {
			client.write(t, ws.OpBinary, true, testFrameBatch(t,
				Frame{Type: FrameData, StreamID: 93, Payload: []byte{byte(sequence)}},
			))
			time.Sleep(longPoll / 2)
		}
		frames := readWebSocketUntilData(t, client, 93, time.Second)
		if len(frames) == 0 {
			t.Fatal("binary-refreshed connection stopped carrying data")
		}
	})
}

func TestHTTPServerWebSocketWrongCarrierAndConfiguredOversize(t *testing.T) {
	t.Run("wrong carrier", func(t *testing.T) {
		application := newHTTPTestApplication(t, 100*time.Millisecond)
		created := createTestSession(t, application.manager, application.profiles[0])
		connection, _, response := dialRawWebSocketTest(
			t,
			application.address,
			webSocketPath,
			webSocketProtocolPrefix+created.Token,
			"",
			nil,
		)
		defer connection.Close()
		_ = readHTTPBody(t, response)
		if response.StatusCode != defaultSanitizedFallbackStatus ||
			response.Header.Get(FallbackClassificationHeader) != FallbackSanitizedPublic {
			t.Fatalf("wrong-carrier response = %d, headers %#v", response.StatusCode, response.Header)
		}
	})

	t.Run("configured message limit", func(t *testing.T) {
		application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
			config.Carrier = CarrierWebSocket
			config.Limits.MaxBodyBytes = 32
			config.Limits.CarrierBatchBytes = 32
		}, nil)
		created := createTestSession(t, application.manager, application.profiles[0])
		client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
		if response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade = %d", response.StatusCode)
		}
		defer client.close()
		header := maskedClientHeader(t, ws.OpBinary, true, 33)
		if _, err := client.connection.Write(header); err != nil {
			t.Fatal(err)
		}
		expectWebSocketCloseCode(t, client, ws.StatusMessageTooBig, time.Second)
	})
}

func TestHTTPServerWebSocketResourceExhaustionCloses1011(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	costLimit, _ := created.Session.uplinkPendingLimits()
	fill := costLimit - queueItemCost
	created.Session.mu.Lock()
	reserved := created.Session.reservePendingLocked(fill, 0, pendingUplink)
	created.Session.mu.Unlock()
	if !reserved {
		t.Fatal("failed to exhaust session uplink budget")
	}
	if _, err := client.connection.Write(maskedClientHeader(t, ws.OpBinary, true, 1)); err != nil {
		t.Fatal(err)
	}
	expectWebSocketCloseCode(t, client, ws.StatusInternalServerError, time.Second)
}

func TestHTTPServerWebSocketLargeFrameYieldsEventLoop(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 2*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	baseline := application.manager.Capacity()
	header := maskedClientHeader(t, ws.OpBinary, true, maxWebSocketMessageBytes)
	if written, err := client.connection.Write(header); err != nil || written != len(header) {
		t.Fatalf("write large-frame header = %d, %v", written, err)
	}
	eventually(t, time.Second, func() bool {
		capacity := application.manager.Capacity()
		return capacity.PendingBytes >= baseline.PendingBytes+int64(maxWebSocketMessageBytes+queueItemCost) &&
			capacity.PendingItems == baseline.PendingItems+1
	})
	payload := bytes.Repeat([]byte{0x7f}, maxWebSocketMessageBytes)
	ws.Cipher(payload, [4]byte{1, 2, 3, 4}, 0)
	if err := client.connection.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		for len(payload) != 0 {
			written, err := client.connection.Write(payload)
			if err != nil {
				writeDone <- err
				return
			}
			if written == 0 {
				writeDone <- io.ErrNoProgress
				return
			}
			payload = payload[written:]
		}
		writeDone <- nil
	}()
	started := time.Now()
	fallback := application.do(t, &http.Client{Timeout: time.Second}, http.MethodGet, "/health", nil, nil)
	_ = readHTTPBody(t, fallback)
	if fallback.StatusCode != defaultPassthroughStatus {
		t.Fatalf("fallback during large frame = %d", fallback.StatusCode)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("large frame blocked the event loop for %v", elapsed)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("large frame made no upload progress")
	}
	expectWebSocketClosed(t, client, 2*time.Second)
}

func TestWebSocketInputReservationUsesSessionAndGlobalBudgets(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	before := manager.Capacity()
	reservation, ok := session.reserveWebSocketInput(16)
	if !ok {
		t.Fatal("initial reservation failed")
	}
	afterReserve := manager.Capacity()
	if afterReserve.PendingBytes-before.PendingBytes != 16+queueItemCost ||
		afterReserve.PendingItems-before.PendingItems != 1 {
		t.Fatalf("reservation delta = %d bytes, %d items", afterReserve.PendingBytes-before.PendingBytes,
			afterReserve.PendingItems-before.PendingItems)
	}
	if !reservation.resize(32) {
		t.Fatal("reservation resize failed")
	}
	afterResize := manager.Capacity()
	if afterResize.PendingBytes-before.PendingBytes != 32+queueItemCost {
		t.Fatalf("resized delta = %d bytes", afterResize.PendingBytes-before.PendingBytes)
	}
	reservation.Release()
	reservation.Release()
	afterRelease := manager.Capacity()
	if afterRelease.PendingBytes != before.PendingBytes || afterRelease.PendingItems != before.PendingItems {
		t.Fatalf("released capacity = %#v, want %#v", afterRelease, before)
	}
}

func TestWebSocketDecoderReservationRejectsExhaustedLiveBudgets(t *testing.T) {
	profiles := testProfiles(t)

	t.Run("session", func(t *testing.T) {
		manager := testManager(t, profiles, func(config *ManagerConfig) {
			config.Carrier = CarrierWebSocket
		}, nil)
		session := createTestSession(t, manager, profiles[0]).Session
		transport, err := newWebSocketConnection(session, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			transport.releaseInbound()
			transport.cancel()
		})
		baseline := manager.Capacity()
		costLimit, _ := session.uplinkPendingLimits()
		fill := costLimit - queueItemCost
		session.mu.Lock()
		reserved := session.reservePendingLocked(fill, 0, pendingUplink)
		session.mu.Unlock()
		if !reserved {
			t.Fatal("failed to exhaust session uplink budget")
		}
		afterFill := manager.Capacity()
		assertWebSocketHeaderReservationRejected(t, transport)
		if got := manager.Capacity(); got.PendingBytes != afterFill.PendingBytes || got.PendingItems != afterFill.PendingItems {
			t.Fatalf("failed decode changed capacity: got %#v, want %#v", got, afterFill)
		}
		session.mu.Lock()
		session.releasePendingLocked(fill, 0)
		session.mu.Unlock()
		if got := manager.Capacity(); got.PendingBytes != baseline.PendingBytes || got.PendingItems != baseline.PendingItems {
			t.Fatalf("released capacity = %#v, want %#v", got, baseline)
		}
	})

	t.Run("global", func(t *testing.T) {
		manager := testManager(t, profiles, func(config *ManagerConfig) {
			config.Carrier = CarrierWebSocket
		}, nil)
		session := createTestSession(t, manager, profiles[0]).Session
		transport, err := newWebSocketConnection(session, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			transport.releaseInbound()
			transport.cancel()
		})
		baseline := manager.Capacity()
		reserveBytes, _, ok := pendingControlReserve(manager.limits)
		if !ok {
			t.Fatal("invalid control reserve")
		}
		reserveBytes, ok = checkedMulInt(reserveBytes, manager.limits.MaxSessions)
		if !ok {
			t.Fatal("control reserve overflow")
		}
		byteLimit := manager.limits.MaxPendingGlobal - reserveBytes
		fill := byteLimit - queueItemCost
		if !manager.changePendingBudget(fill, 0, pendingUplink) {
			t.Fatal("failed to exhaust global uplink budget")
		}
		afterFill := manager.Capacity()
		assertWebSocketHeaderReservationRejected(t, transport)
		if got := manager.Capacity(); got.PendingBytes != afterFill.PendingBytes || got.PendingItems != afterFill.PendingItems {
			t.Fatalf("failed decode changed capacity: got %#v, want %#v", got, afterFill)
		}
		if !manager.changePendingBudget(-fill, 0, pendingUplink) {
			t.Fatal("failed to release global uplink budget")
		}
		if got := manager.Capacity(); got.PendingBytes != baseline.PendingBytes || got.PendingItems != baseline.PendingItems {
			t.Fatalf("released capacity = %#v, want %#v", got, baseline)
		}
	})
}

func TestWebSocketFragmentErrorReleasesAllInputBudgets(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	transport, err := newWebSocketConnection(session, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.cancel()
	baseline := manager.Capacity()
	fragment := maskedClientFrame(t, ws.OpBinary, false, []byte("reserved fragment"))
	if _, _, emitted, decodeErr := transport.decoder.Decode(fragment); decodeErr != nil || emitted {
		t.Fatalf("fragment decode: emitted=%t err=%v", emitted, decodeErr)
	}
	reserved := manager.Capacity()
	if reserved.PendingBytes <= baseline.PendingBytes || reserved.PendingItems != baseline.PendingItems+1 {
		t.Fatalf("fragment did not reserve input capacity: before %#v, after %#v", baseline, reserved)
	}
	invalid := maskedClientFrame(t, ws.OpText, true, []byte("invalid"))
	if _, _, _, decodeErr := transport.decoder.Decode(invalid); !errors.Is(decodeErr, errWebSocketProtocol) {
		t.Fatalf("fragment error = %v", decodeErr)
	}
	transport.releaseInbound()
	if bytesOwned, itemsOwned := transport.inboundBudget.snapshot(); bytesOwned != 0 || itemsOwned != 0 {
		t.Fatalf("local budget after release = %d bytes, %d items", bytesOwned, itemsOwned)
	}
	if got := manager.Capacity(); got.PendingBytes != baseline.PendingBytes || got.PendingItems != baseline.PendingItems {
		t.Fatalf("fragment error leaked capacity: got %#v, want %#v", got, baseline)
	}
}

func TestWebSocketLaneLocalInputBudgetAndSiblingCapacity(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocketLanes
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	messageLimit := min(created.Session.limits.MaxBodyBytes, maxWebSocketMessageBytes)
	local := &webSocketInboundBudget{maxBytes: 3 * messageLimit, maxItems: 1}
	firstReservation, ok := newWebSocketOwnedInput(created.Session, local, messageLimit)
	if !ok {
		t.Fatal("first lane-local reservation failed")
	}
	if _, ok := newWebSocketOwnedInput(created.Session, local, 1); ok {
		t.Fatal("lane-local budget accepted a second input item")
	}
	if !firstReservation.resize(3*messageLimit) || firstReservation.resize(3*messageLimit+1) {
		t.Fatal("lane-local byte cap was not enforced")
	}
	firstReservation.Release()
	if bytesOwned, itemsOwned := local.snapshot(); bytesOwned != 0 || itemsOwned != 0 {
		t.Fatalf("released local budget = %d bytes, %d items", bytesOwned, itemsOwned)
	}

	baseline := application.manager.Capacity()
	stalled, stalledResponse := dialWebSocketTest(t, application.address,
		webSocketLaneProtocolPrefix+created.Token+".101", "", nil)
	if stalledResponse.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("stalled lane upgrade = %d", stalledResponse.StatusCode)
	}
	defer stalled.close()
	if _, err := stalled.connection.Write(maskedClientHeader(t, ws.OpBinary, true, messageLimit)); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		capacity := application.manager.Capacity()
		return capacity.PendingBytes >= baseline.PendingBytes+int64(messageLimit+queueItemCost) &&
			capacity.PendingItems == baseline.PendingItems+1
	})

	sibling, siblingResponse := dialWebSocketTest(t, application.address,
		webSocketLaneProtocolPrefix+created.Token+".102", "", nil)
	if siblingResponse.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("sibling lane upgrade = %d", siblingResponse.StatusCode)
	}
	defer sibling.close()
	payload := []byte("sibling remains usable")
	sibling.write(t, ws.OpBinary, true, testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 102},
		Frame{Type: FrameData, StreamID: 102, Payload: payload},
	))
	frames := readWebSocketUntilData(t, sibling, 102, time.Second)
	if len(frames) == 0 {
		t.Fatal("stalled lane consumed sibling capacity")
	}
	stalled.close()
	eventually(t, time.Second, func() bool {
		capacity := application.manager.Capacity()
		return capacity.PendingBytes == baseline.PendingBytes && capacity.PendingItems == baseline.PendingItems
	})
}

func assertWebSocketHeaderReservationRejected(t *testing.T, transport *webSocketConnection) {
	t.Helper()
	header := maskedClientHeader(t, ws.OpBinary, true, 1)
	consumed, transformed, _, emitted, err := transport.decoder.DecodeBounded(
		header,
		maxWebSocketPayloadBytesPerTraffic,
	)
	if !errors.Is(err, errWebSocketResource) || consumed != 0 || transformed != 0 || emitted {
		t.Fatalf("header reservation: consumed=%d transformed=%d emitted=%t err=%v", consumed, transformed, emitted, err)
	}
	if transport.decoder.pending != nil || transport.fragmentReservation != nil {
		t.Fatal("rejected header retained decoder-owned input")
	}
	if bytesOwned, itemsOwned := transport.inboundBudget.snapshot(); bytesOwned != 0 || itemsOwned != 0 {
		t.Fatalf("rejected header retained %d bytes, %d items", bytesOwned, itemsOwned)
	}
}

func TestHTTPServerWebSocketSlowReaderHoldsPollLeaseUntilDrain(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 30*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, func(config *HTTPServerConfig) {
		config.SocketSendBuffer = 4096
	})
	created := createTestSession(t, application.manager, application.profiles[0])
	before := application.manager.Capacity()
	payloadSize := MaxFramePayload - FrameHeaderSize
	created.Session.mu.Lock()
	queued := created.Session.queueFrameLocked(FrameData, 1, bytes.Repeat([]byte{0x61}, payloadSize)) &&
		created.Session.queueFrameLocked(FrameData, 2, bytes.Repeat([]byte{0x62}, payloadSize))
	created.Session.mu.Unlock()
	if !queued {
		t.Fatal("failed to queue slow-reader downlink")
	}
	queuedCapacity := application.manager.Capacity()
	if queuedCapacity.PendingBytes <= before.PendingBytes {
		t.Fatal("queued downlink did not reserve pending capacity")
	}

	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	if tcp, ok := client.connection.(*net.TCPConn); ok {
		if err := tcp.SetReadBuffer(1024); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, time.Second, func() bool {
		created.Session.mu.Lock()
		defer created.Session.mu.Unlock()
		return len(created.Session.carrierLanes[0].unacked) != 0
	})
	time.Sleep(100 * time.Millisecond)
	duringDrain := application.manager.Capacity()
	if duringDrain.PendingBytes != queuedCapacity.PendingBytes || duringDrain.PendingItems != queuedCapacity.PendingItems {
		t.Fatalf("slow-reader lease released before drain: capacity %#v, want %#v", duringDrain, queuedCapacity)
	}
	if tcp, ok := client.connection.(*net.TCPConn); ok {
		if err := tcp.SetReadBuffer(4 * maxWebSocketMessageBytes); err != nil {
			t.Fatal(err)
		}
	}

	opcode, payload := client.read(t, 30*time.Second)
	if opcode != ws.OpBinary || len(payload) != 2*(FrameHeaderSize+payloadSize) {
		t.Fatalf("large downlink = opcode %v, %d bytes", opcode, len(payload))
	}
	frames, err := ParseBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 || frames[0].StreamID != 1 || frames[1].StreamID != 2 ||
		!bytes.Equal(frames[0].Payload, bytes.Repeat([]byte{0x61}, payloadSize)) ||
		!bytes.Equal(frames[1].Payload, bytes.Repeat([]byte{0x62}, payloadSize)) {
		t.Fatal("AsyncWritev corrupted the leased downlink payload")
	}
	eventually(t, time.Second, func() bool {
		capacity := application.manager.Capacity()
		return capacity.PendingBytes == before.PendingBytes && capacity.PendingItems == before.PendingItems
	})
}

func TestHTTPServerWebSocketSlowReaderRemainsFullDuplexUntilPollLeaseDrain(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 30*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, func(config *HTTPServerConfig) {
		config.SocketSendBuffer = 4096
	})
	created := createTestSession(t, application.manager, application.profiles[0])
	before := application.manager.Capacity()
	payloadSize := MaxFramePayload - FrameHeaderSize
	created.Session.mu.Lock()
	queued := created.Session.queueFrameLocked(FrameData, 1, bytes.Repeat([]byte{0x71}, payloadSize)) &&
		created.Session.queueFrameLocked(FrameData, 2, bytes.Repeat([]byte{0x72}, payloadSize))
	created.Session.mu.Unlock()
	if !queued {
		t.Fatal("failed to queue slow-reader downlink")
	}
	queuedCapacity := application.manager.Capacity()

	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	if tcp, ok := client.connection.(*net.TCPConn); ok {
		if err := tcp.SetReadBuffer(1024); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, time.Second, func() bool {
		created.Session.mu.Lock()
		defer created.Session.mu.Unlock()
		return len(created.Session.carrierLanes[0].unacked) != 0
	})
	if err := client.connection.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	uplinkPayload := bytes.Repeat([]byte{0x55}, 2*maxWebSocketPayloadBytesPerTraffic)
	client.writeRaw(t, maskedClientFrame(t, ws.OpBinary, true, testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 3},
		Frame{Type: FrameData, StreamID: 3, Payload: uplinkPayload},
	)))
	if err := client.connection.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if tcp, ok := client.connection.(*net.TCPConn); ok {
		if err := tcp.SetReadBuffer(4 * maxWebSocketMessageBytes); err != nil {
			t.Fatal(err)
		}
	}

	opcode, payload := client.read(t, 30*time.Second)
	if opcode != ws.OpBinary || len(payload) != 2*(FrameHeaderSize+payloadSize) {
		t.Fatalf("large downlink = opcode %v, %d bytes", opcode, len(payload))
	}
	frames, err := ParseBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 || frames[0].StreamID != 1 || frames[1].StreamID != 2 ||
		!bytes.Equal(frames[0].Payload, bytes.Repeat([]byte{0x71}, payloadSize)) ||
		!bytes.Equal(frames[1].Payload, bytes.Repeat([]byte{0x72}, payloadSize)) {
		t.Fatal("full-duplex input corrupted the leased downlink payload")
	}
	frames = readWebSocketUntilData(t, client, 3, 5*time.Second)
	foundUplink := false
	for _, frame := range frames {
		if frame.Type == FrameData && frame.StreamID == 3 && bytes.Equal(frame.Payload, uplinkPayload) {
			foundUplink = true
		}
	}
	if !foundUplink {
		t.Fatal("uplink did not remain active while the downlink PollLease drained")
	}
	eventually(t, time.Second, func() bool {
		capacity := application.manager.Capacity()
		return capacity.PendingBytes == before.PendingBytes && capacity.PendingItems == before.PendingItems
	})
	if queuedCapacity.PendingBytes <= before.PendingBytes {
		t.Fatal("test did not reserve a PollLease-backed downlink")
	}
	client.write(t, ws.OpPing, true, []byte("full duplex"))
	for {
		opcode, controlPayload := client.read(t, 2*time.Second)
		if opcode == ws.OpPong && bytes.Equal(controlPayload, []byte("full duplex")) {
			break
		}
		if opcode == ws.OpPing {
			client.write(t, ws.OpPong, true, controlPayload)
		}
	}
}

func TestHTTPServerWebSocketBackpressureRetryDoesNotBlockEventLoop(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 5*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	created.Session.mu.Lock()
	created.Session.carrierLanes[0].upActive = true
	created.Session.mu.Unlock()
	defer func() {
		created.Session.mu.Lock()
		if lane := created.Session.carrierLanes[0]; lane != nil {
			lane.upActive = false
		}
		created.Session.mu.Unlock()
	}()

	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	payload := []byte("after backpressure")
	client.write(t, ws.OpBinary, true, testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 7},
		Frame{Type: FrameData, StreamID: 7, Payload: payload},
	))
	eventually(t, time.Second, func() bool {
		return application.manager.backpressure[carrierOperationUplink].Load() != 0
	})
	started := time.Now()
	fallback := application.do(t, &http.Client{Timeout: time.Second}, http.MethodGet, "/health", nil, nil)
	_ = readHTTPBody(t, fallback)
	if fallback.StatusCode != defaultPassthroughStatus {
		t.Fatalf("fallback while retrying = %d", fallback.StatusCode)
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("backpressure retry blocked event loop for %v", elapsed)
	}

	created.Session.mu.Lock()
	created.Session.carrierLanes[0].upActive = false
	created.Session.mu.Unlock()
	frames := readWebSocketUntilData(t, client, 7, 2*time.Second)
	found := false
	for _, frame := range frames {
		if frame.Type == FrameData && frame.StreamID == 7 && bytes.Equal(frame.Payload, payload) {
			found = true
		}
	}
	if !found {
		t.Fatalf("retried uplink did not reach backend: %#v", frames)
	}
}

func TestHTTPServerWebSocketShutdownClosesConnection(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := application.server.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	expectWebSocketClosed(t, client, time.Second)
}

func TestHTTPServerWebSocketClosesWhenClientStopsResponding(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 50*time.Millisecond, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, nil)
	created := createTestSession(t, application.manager, application.profiles[0])
	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	expectWebSocketClosed(t, client, time.Second)
}

func dialWebSocketTest(
	t *testing.T,
	address, protocol, extra string,
	trailing []byte,
) (*webSocketTestClient, *http.Response) {
	t.Helper()
	connection, reader, response := dialRawWebSocketTest(t, address, webSocketPath, protocol, extra, trailing)
	return &webSocketTestClient{connection: connection, reader: reader}, response
}

func dialRawWebSocketTest(
	t *testing.T,
	address, path, protocol, extra string,
	trailing []byte,
) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	connection := dialHTTPTest(t, address)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 16))
	request := "GET " + path + " HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Protocol: " + protocol + "\r\n" + extra + "\r\n"
	packet := append([]byte(request), trailing...)
	if _, err := connection.Write(packet); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		connection.Close()
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	return connection, reader, response
}

func (c *webSocketTestClient) write(t *testing.T, opcode ws.OpCode, final bool, payload []byte) {
	t.Helper()
	frame := ws.MaskFrame(ws.NewFrame(opcode, final, payload))
	if err := ws.WriteFrame(c.connection, frame); err != nil {
		t.Fatal(err)
	}
}

func (c *webSocketTestClient) writeRaw(t *testing.T, payload []byte) {
	t.Helper()
	for len(payload) != 0 {
		written, err := c.connection.Write(payload)
		if err != nil {
			t.Fatal(err)
		}
		if written == 0 {
			t.Fatal(io.ErrNoProgress)
		}
		payload = payload[written:]
	}
}

func (c *webSocketTestClient) read(t *testing.T, timeout time.Duration) (ws.OpCode, []byte) {
	t.Helper()
	opcode, payload, err := c.readResult(timeout)
	if err != nil {
		t.Fatal(err)
	}
	return opcode, payload
}

func (c *webSocketTestClient) readResult(timeout time.Duration) (ws.OpCode, []byte, error) {
	if err := c.connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, nil, err
	}
	header, err := ws.ReadHeader(c.reader)
	if err != nil {
		return 0, nil, err
	}
	if header.Masked || header.Length < 0 || header.Length > maxWebSocketMessageBytes {
		return 0, nil, fmt.Errorf("invalid server frame header: %#v", header)
	}
	payload := make([]byte, int(header.Length))
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, nil, err
	}
	return header.OpCode, payload, nil
}

func (c *webSocketTestClient) close() {
	if c != nil && c.connection != nil {
		_ = c.connection.Close()
	}
}

func readWebSocketBatch(t *testing.T, client *webSocketTestClient, timeout time.Duration) []Frame {
	t.Helper()
	frames, err := readWebSocketBatchResult(t, client, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return frames
}

func readWebSocketBatchResult(
	t *testing.T,
	client *webSocketTestClient,
	timeout time.Duration,
) ([]Frame, error) {
	t.Helper()
	for {
		opcode, payload, readErr := client.readResult(timeout)
		if readErr != nil {
			return nil, readErr
		}
		switch opcode {
		case ws.OpBinary:
			frames, err := ParseBatch(payload)
			if err != nil {
				return nil, err
			}
			return frames, nil
		case ws.OpPing:
			client.write(t, ws.OpPong, true, payload)
		case ws.OpClose:
			return nil, fmt.Errorf("unexpected close: %x", payload)
		}
	}
}

func readWebSocketUntilData(
	t *testing.T,
	client *webSocketTestClient,
	streamID uint32,
	timeout time.Duration,
) []Frame {
	t.Helper()
	var received []Frame
	for range 4 {
		frames := readWebSocketBatch(t, client, timeout)
		received = append(received, frames...)
		for _, frame := range frames {
			if frame.Type == FrameData && frame.StreamID == streamID {
				return received
			}
		}
	}
	return received
}

func expectWebSocketClosed(t *testing.T, client *webSocketTestClient, timeout time.Duration) {
	t.Helper()
	if err := client.connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	for {
		header, err := ws.ReadHeader(client.reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return
			}
			if connectionErr, ok := errors.AsType[net.Error](err); ok {
				if connectionErr.Timeout() {
					t.Fatalf("WebSocket remained open for %v: %v", timeout, err)
				}
				return
			}
			t.Fatalf("unexpected WebSocket close read error: %v", err)
		}
		if header.Length > 0 {
			if _, err := io.CopyN(io.Discard, client.reader, header.Length); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return
				}
				if connectionErr, ok := errors.AsType[net.Error](err); ok {
					if connectionErr.Timeout() {
						t.Fatalf("WebSocket close frame did not finish within %v: %v", timeout, err)
					}
					return
				}
				t.Fatalf("unexpected WebSocket close payload read error: %v", err)
			}
		}
		if header.OpCode == ws.OpClose {
			return
		}
	}
}

func expectWebSocketCloseCode(
	t *testing.T,
	client *webSocketTestClient,
	want ws.StatusCode,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		opcode, payload, err := client.readResult(time.Until(deadline))
		if err != nil {
			t.Fatalf("read close code: %v", err)
		}
		switch opcode {
		case ws.OpClose:
			if len(payload) < 2 {
				t.Fatalf("close payload = %x", payload)
			}
			if got := ws.StatusCode(binary.BigEndian.Uint16(payload[:2])); got != want {
				t.Fatalf("close code = %d, want %d", got, want)
			}
			return
		case ws.OpPing:
			client.write(t, ws.OpPong, true, payload)
		}
	}
}

type webSocketRecordingBackend struct {
	writes    chan []byte
	ready     chan struct{}
	closed    chan struct{}
	readyOnce sync.Once
	closeOnce sync.Once
}

type webSocketTestInboundBuffer struct {
	data []byte
}

func (b *webSocketTestInboundBuffer) InboundBuffered() int { return len(b.data) }

func (b *webSocketTestInboundBuffer) Discard(size int) (int, error) {
	if size < 0 || size > len(b.data) {
		return 0, io.ErrUnexpectedEOF
	}
	b.data = b.data[size:]
	return size, nil
}

func newWebSocketRecordingBackend() *webSocketRecordingBackend {
	return newWebSocketRecordingBackendWithCapacity(4)
}

func newWebSocketRecordingBackendWithCapacity(writeCapacity int) *webSocketRecordingBackend {
	return &webSocketRecordingBackend{
		writes: make(chan []byte, writeCapacity),
		ready:  make(chan struct{}),
		closed: make(chan struct{}),
	}
}

func (c *webSocketRecordingBackend) markReady() {
	c.readyOnce.Do(func() { close(c.ready) })
}

func (c *webSocketRecordingBackend) Read([]byte) (int, error) {
	c.markReady()
	<-c.closed
	return 0, io.EOF
}

func (c *webSocketRecordingBackend) Write(payload []byte) (int, error) {
	c.writes <- bytes.Clone(payload)
	return len(payload), nil
}

func (c *webSocketRecordingBackend) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *webSocketRecordingBackend) LocalAddr() net.Addr              { return testNetAddr("local") }
func (c *webSocketRecordingBackend) RemoteAddr() net.Addr             { return testNetAddr("remote") }
func (c *webSocketRecordingBackend) SetDeadline(time.Time) error      { return nil }
func (c *webSocketRecordingBackend) SetReadDeadline(time.Time) error  { return nil }
func (c *webSocketRecordingBackend) SetWriteDeadline(time.Time) error { return nil }
