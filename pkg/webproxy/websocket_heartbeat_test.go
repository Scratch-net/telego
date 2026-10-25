package webproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/panjf2000/gnet/v2"
)

func TestHTTPServerWebSocketHeartbeatDuringContinuousDownlink(t *testing.T) {
	const longPoll = 100 * time.Millisecond
	for _, carrier := range []CarrierMode{CarrierWebSocket, CarrierWebSocketLanes} {
		for _, respond := range []bool{true, false} {
			name := string(carrier) + "/silent-peer"
			if respond {
				name = string(carrier) + "/responsive-peer"
			}
			t.Run(name, func(t *testing.T) {
				application := newHTTPTestApplicationWithConfig(t, longPoll, func(config *ManagerConfig) {
					config.Carrier = carrier
				}, nil)
				created := createTestSession(t, application.manager, application.profiles[0])
				protocol, streamID := webSocketProtocolPrefix+created.Token, uint32(1)
				if carrier == CarrierWebSocketLanes {
					protocol, streamID = webSocketLaneProtocolPrefix+created.Token+".41", 41
				}
				client, response := dialWebSocketTest(t, application.address, protocol, "", nil)
				if response.StatusCode != http.StatusSwitchingProtocols {
					t.Fatalf("upgrade = %d", response.StatusCode)
				}
				defer client.close()
				queue := func(sequence uint32) bool {
					payload := binary.BigEndian.AppendUint32(nil, sequence)
					created.Session.mu.Lock()
					queued := created.Session.queueFrameLocked(FrameData, streamID, payload)
					created.Session.mu.Unlock()
					return queued
				}
				if !queue(0) {
					t.Fatal("cannot queue initial downlink")
				}
				deadline := time.Now().Add(6 * longPoll)
				var received uint32
				pings := 0
				for time.Now().Before(deadline) {
					opcode, payload, err := client.readResult(3 * longPoll)
					if err != nil {
						if respond {
							t.Fatalf("responsive peer lost continuous downlink after %d frames and %d pings: %v", received, pings, err)
						}
						if network, ok := errors.AsType[net.Error](err); ok && network.Timeout() {
							t.Fatalf("silent peer did not close: %v", err)
						}
						if received == 0 {
							t.Fatal("silent peer received no downlink before closure")
						}
						return
					}
					switch opcode {
					case ws.OpPing:
						pings++
						if respond {
							client.write(t, ws.OpPong, true, payload)
						}
					case ws.OpBinary:
						want := testFrameBatch(t, Frame{Type: FrameData, StreamID: streamID,
							Payload: binary.BigEndian.AppendUint32(nil, received)})
						if !bytes.Equal(payload, want) {
							t.Fatalf("downlink frame %d changed: got %x, want %x", received, payload, want)
						}
						received++
						if !queue(received) && respond {
							t.Fatalf("responsive peer lost its downlink after %d frames and %d pings", received, pings)
						}
						time.Sleep(longPoll / 10)
					default:
						t.Fatalf("unexpected downlink opcode %v", opcode)
					}
				}
				if !respond {
					t.Fatal("continuous output refreshed silent-peer liveness")
				}
				if pings < 3 {
					t.Fatalf("continuous downlink received only %d pings", pings)
				}
			})
		}
	}
}

type heartbeatTestConn struct {
	gnet.Conn
	owner    *budgetTestOwner
	buffered int
	wakes    atomic.Int32
	writes   [][]byte
	callback gnet.AsyncCallback
}

func (c *heartbeatTestConn) EventLoop() gnet.EventLoop { return c.owner }
func (c *heartbeatTestConn) OutboundBuffered() int     { return c.buffered }
func (*heartbeatTestConn) InboundBuffered() int        { return 0 }
func (*heartbeatTestConn) Discard(int) (int, error)    { return 0, nil }

func (c *heartbeatTestConn) Wake(gnet.AsyncCallback) error {
	c.wakes.Add(1)
	return nil
}

func (c *heartbeatTestConn) AsyncWritev(parts [][]byte, callback gnet.AsyncCallback) error {
	c.writes = append(c.writes, bytes.Join(parts, nil))
	c.callback = callback
	return nil
}

type heartbeatTestFixture struct {
	transport  *webSocketConnection
	connection *heartbeatTestConn
	state      *httpConnectionState
	handler    *httpEventHandler
}

func newHeartbeatTestFixture(t *testing.T) *heartbeatTestFixture {
	t.Helper()
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
		config.Timeouts.LongPoll = 10 * time.Millisecond
	}, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	transport, err := newWebSocketConnection(session, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport.phase = webSocketOpen
	fixture := &heartbeatTestFixture{
		transport:  transport,
		connection: &heartbeatTestConn{owner: &budgetTestOwner{queue: make(chan gnet.Runnable, 32)}},
		state:      &httpConnectionState{},
		handler:    &httpEventHandler{server: &HTTPServer{config: HTTPServerConfig{WriteTimeout: time.Hour}}},
	}
	t.Cleanup(func() { fixture.state.close(); transport.close() })
	return fixture
}

func pendingHeartbeatTick(t *testing.T, connection *heartbeatTestConn) gnet.Runnable {
	t.Helper()
	select {
	case run := <-connection.owner.queue:
		return run
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not schedule owner-loop work")
		return nil
	}
}

func TestWebSocketHeartbeatWaitsForCurrentWriteDrain(t *testing.T) {
	f := newHeartbeatTestFixture(t)
	w, connection := f.transport, f.connection
	w.session.mu.Lock()
	queued := w.session.queueFrameLocked(FrameData, 1, []byte("leased downlink"))
	w.session.mu.Unlock()
	if !queued {
		t.Fatal("cannot queue leased downlink")
	}
	body, _, lease, err := w.session.PollCarrier(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	item := &webSocketOutbound{message: webSocketMessage{typeID: webSocketMessageBinary, payload: body}, lease: lease}
	if !w.enqueueOutbound(item) || f.handler.pumpWebSocketWrites(connection, f.state, w) != gnet.None {
		t.Fatal("cannot start leased output")
	}
	writeDeadline, liveness := f.state.deadlineID, w.livenessID
	w.armHeartbeat(connection)
	for range 3 {
		connection.owner.next(t)
		if len(w.outbound) != 1 || !w.heartbeatPending || w.heartbeatDue {
			t.Fatal("heartbeat ticks accumulated behind the current write")
		}
		if w.current != item || !w.asyncWritePending || f.state.deadlineID != writeDeadline || w.livenessID != liveness {
			t.Fatal("heartbeat changed current output or deadlines")
		}
	}
	w.controlInputBytes = 123
	w.resetControlBurstIfDrained(connection)
	if w.controlOutputItems != 0 || w.controlInputBytes != 0 {
		t.Fatal("server heartbeat retained peer-control accounting")
	}
	connection.buffered = 1
	if err := connection.callback(connection, nil); err != nil {
		t.Fatal(err)
	}
	if f.handler.pumpWebSocketWrites(connection, f.state, w) != gnet.None || w.current != item {
		t.Fatal("heartbeat interrupted a partially drained frame")
	}
	w.session.mu.Lock()
	slots := len(lease.lane.downSlot)
	w.session.mu.Unlock()
	if slots != 0 || f.state.deadlineID != writeDeadline {
		t.Fatal("heartbeat released the live response or changed its write deadline")
	}
	connection.buffered = 0
	if f.handler.pumpWebSocketWrites(connection, f.state, w) != gnet.None || w.current == nil || !w.current.heartbeat {
		t.Fatal("heartbeat did not follow the drained data frame")
	}
	w.session.mu.Lock()
	slots = len(lease.lane.downSlot)
	w.session.mu.Unlock()
	if slots != 1 || len(connection.writes) != 2 || !w.heartbeatPending {
		t.Fatal("drain did not release the data lease and retain the heartbeat")
	}
	wantHeader, _, err := encodeWebSocketServerParts(item.message)
	if err != nil || !bytes.Equal(connection.writes[0], bytes.Join([][]byte{wantHeader, body}, nil)) ||
		!bytes.Equal(connection.writes[1], []byte{0x89, 0}) {
		t.Fatal("heartbeat changed frame bytes or order")
	}
	if err := connection.callback(connection, nil); err != nil {
		t.Fatal(err)
	}
	if f.handler.pumpWebSocketWrites(connection, f.state, w) != gnet.None || w.heartbeatPending || w.current != nil {
		t.Fatal("completed heartbeat retained its pending marker")
	}
	if w.livenessID != liveness {
		t.Fatal("outgoing heartbeat refreshed peer liveness")
	}
}

func TestWebSocketHeartbeatFullQueueRetriesOnWriterProgress(t *testing.T) {
	f := newHeartbeatTestFixture(t)
	w, connection := f.transport, f.connection
	for range maxWebSocketOutboundMessages {
		if !w.enqueueOutbound(&webSocketOutbound{message: webSocketMessage{
			typeID: webSocketMessageBinary, payload: testFrameBatch(t, Frame{Type: FramePong}),
		}}) {
			t.Fatal("cannot fill output queue")
		}
	}
	w.armHeartbeat(connection)
	connection.owner.next(t)
	if !w.heartbeatDue || w.heartbeatPending || len(w.outbound) != maxWebSocketOutboundMessages || connection.wakes.Load() != 0 {
		t.Fatal("full queue did not defer the heartbeat within its existing capacity")
	}
	timerID := w.heartbeatID
	if f.handler.pumpWebSocketWrites(connection, f.state, w) != gnet.None {
		t.Fatal("writer could not free one output slot")
	}
	if w.heartbeatDue || !w.heartbeatPending || len(w.outbound) != maxWebSocketOutboundMessages || w.heartbeatID != timerID {
		t.Fatal("freed slot did not admit heartbeat before another timer tick")
	}
	for range 3 {
		connection.owner.next(t)
		if w.heartbeatDue || len(w.outbound) != maxWebSocketOutboundMessages || len(w.failures) != 0 {
			t.Fatal("pending heartbeat accumulated ticks or caused capacity failure")
		}
	}
	w.close()
	if w.heartbeatPending || w.heartbeatDue || len(w.outbound) != 0 {
		t.Fatal("close retained queued heartbeat state")
	}
}

func TestWebSocketHeartbeatQueuedTickCannotOutliveClose(t *testing.T) {
	for _, begin := range []bool{true, false} {
		t.Run(map[bool]string{true: "begin-close", false: "close"}[begin], func(t *testing.T) {
			f := newHeartbeatTestFixture(t)
			w, connection := f.transport, f.connection
			for range maxWebSocketOutboundMessages {
				w.enqueueOutbound(&webSocketOutbound{message: webSocketMessage{
					typeID: webSocketMessageBinary, payload: testFrameBatch(t, Frame{Type: FramePong}),
				}})
			}
			w.armHeartbeat(connection)
			connection.owner.next(t)
			run := pendingHeartbeatTick(t, connection)
			if begin {
				if w.beginClose(connection, ws.StatusNormalClosure, nil) {
					t.Fatal("full queue unexpectedly admitted close output")
				}
			} else {
				w.close()
			}
			queued, wakes := len(w.outbound), connection.wakes.Load()
			if err := run.Run(t.Context()); err != nil {
				t.Fatal(err)
			}
			if w.heartbeat != nil || w.heartbeatDue || w.heartbeatPending || len(w.outbound) != queued || connection.wakes.Load() != wakes {
				t.Fatal("stale heartbeat revived closed output")
			}
		})
	}
}

func TestWebSocketEmptyPollsReleaseLeasesWithoutPing(t *testing.T) {
	f := newHeartbeatTestFixture(t)
	w := f.transport
	w.workers.Go(func() { w.downlinkLoop(f.connection) })
	t.Cleanup(func() { w.cancel(); w.workers.Wait() })
	var first chan struct{}
	eventually(t, time.Second, func() bool {
		w.session.mu.Lock()
		defer w.session.mu.Unlock()
		first = w.session.carrierLanes[0].superseded
		return first != nil
	})
	eventually(t, time.Second, func() bool {
		w.session.mu.Lock()
		defer w.session.mu.Unlock()
		next := w.session.carrierLanes[0].superseded
		return next != nil && next != first
	})
	if len(w.outbound) != 0 || f.connection.wakes.Load() != 0 {
		t.Fatal("empty long poll produced another heartbeat source")
	}
}

func TestWebSocketHeartbeatStaleLaneTickKeepsReplacementAndSibling(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocketLanes
		config.Timeouts.LongPoll = 10 * time.Millisecond
	}, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	old, sibling := session.AcquireWebSocketLane(41), session.AcquireWebSocketLane(42)
	if old == nil || sibling == nil {
		t.Fatal("cannot acquire independent lanes")
	}
	t.Cleanup(sibling.Release)
	w, err := newWebSocketConnection(session, old, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.close)
	w.phase = webSocketOpen
	connection := &heartbeatTestConn{owner: &budgetTestOwner{queue: make(chan gnet.Runnable, 8)}}
	w.armHeartbeat(connection)
	run := pendingHeartbeatTick(t, connection)
	w.close()
	replacement := session.AcquireWebSocketLane(41)
	if replacement == nil {
		t.Fatal("cannot acquire replacement lane")
	}
	t.Cleanup(replacement.Release)
	if err := run.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	intact := session.carrierLanes[41] == replacement.lane && session.carrierLanes[42] == sibling.lane && !session.closed
	session.mu.Unlock()
	if !intact || w.heartbeat != nil || len(w.outbound) != 0 || connection.wakes.Load() != 0 {
		t.Fatal("retired heartbeat disturbed replacement or sibling lane")
	}
}
