package webproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/gobwas/ws"
	"github.com/panjf2000/gnet/v2"
)

type closingWebSocketConn struct {
	gnet.Conn
	buffered int
	discards int
	err      error
}

func (c *closingWebSocketConn) InboundBuffered() int { return c.buffered }

func (c *closingWebSocketConn) Discard(n int) (int, error) {
	c.discards++
	if c.err != nil {
		return 0, c.err
	}
	c.buffered -= n
	return n, nil
}

func TestWebSocketClosingDiscardsInputWhileCloseWritePending(t *testing.T) {
	handler := &httpEventHandler{}
	state := &httpConnectionState{}
	transport := &webSocketConnection{
		phase: webSocketClosing, current: &webSocketOutbound{}, asyncWritePending: true,
	}
	connection := &closingWebSocketConn{}
	// A stalled close write must not let successive read callbacks accumulate
	// input. A nil decoder also proves closing traffic is never decoded.
	for range 32 {
		connection.buffered += maxWebSocketControlInputBytes
		if action := handler.onWebSocketTraffic(connection, state, transport); action != gnet.None {
			t.Fatalf("pending close write action = %v", action)
		}
		if connection.buffered != 0 {
			t.Fatalf("closing callback retained %d input bytes", connection.buffered)
		}
	}
	if connection.discards != 32 || !transport.asyncWritePending || transport.current == nil {
		t.Fatal("closing input disposal changed pending output ownership")
	}
	connection.buffered = 1
	connection.err = errors.New("discard failed")
	if action := handler.onWebSocketTraffic(connection, state, transport); action != gnet.Close {
		t.Fatalf("discard failure action = %v", action)
	}
}

type pendingUplinkWebSocketConn struct {
	closingWebSocketConn
	input []byte
}

func (c *pendingUplinkWebSocketConn) Peek(n int) ([]byte, error) { return c.input[:n], nil }

func (*pendingUplinkWebSocketConn) Wake(gnet.AsyncCallback) error { return nil }

func TestWebSocketPendingUplinkBoundsUnreadControlInput(t *testing.T) {
	for _, test := range []struct {
		name   string
		opcode ws.OpCode
	}{
		{name: "ping", opcode: ws.OpPing},
		{name: "pong", opcode: ws.OpPong},
		{name: "close", opcode: ws.OpClose},
	} {
		t.Run(test.name, func(t *testing.T) {
			decoder, err := newWebSocketDecoder(maxWebSocketMessageBytes, func(int) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			current := &webSocketOutbound{}
			transport := &webSocketConnection{
				phase: webSocketOpen, uplinkPending: 1, decoder: decoder,
				ctx: ctx, cancel: cancel, current: current, asyncWritePending: true,
				outbound: make(chan *webSocketOutbound, maxWebSocketOutboundMessages),
			}
			input := make([]byte, maxWebSocketControlInputBytes+1)
			copy(input, maskedClientFrame(t, test.opcode, true, nil))
			connection := &pendingUplinkWebSocketConn{
				buffered: maxWebSocketControlInputBytes,
				input:    input,
			}
			handler := &httpEventHandler{}
			state := &httpConnectionState{}
			if action := handler.onWebSocketTraffic(connection, state, transport); action != gnet.None {
				t.Fatalf("at-limit action = %v", action)
			}
			if connection.buffered != maxWebSocketControlInputBytes || connection.discards != 0 || transport.phase != webSocketOpen {
				t.Fatal("at-limit input did not remain pending")
			}
			connection.buffered++
			if action := handler.onWebSocketTraffic(connection, state, transport); action != gnet.None {
				t.Fatalf("overflow action = %v", action)
			}
			if connection.buffered != 0 || connection.discards != 1 || transport.phase != webSocketClosing || ctx.Err() == nil {
				t.Fatalf("overflow retained %d bytes, discards=%d, phase=%v, context error=%v",
					connection.buffered, connection.discards, transport.phase, ctx.Err())
			}
			select {
			case closeFrame := <-transport.outbound:
				if !closeFrame.closeAfter || closeFrame.message.typeID != webSocketMessageClose ||
					len(closeFrame.message.payload) != 2 || ws.StatusCode(binary.BigEndian.Uint16(closeFrame.message.payload)) != ws.StatusInternalServerError {
					t.Fatal("overflow did not queue the capacity close frame")
				}
			default:
				t.Fatal("overflow did not queue a close frame")
			}
			connection.buffered = maxWebSocketControlInputBytes
			if action := handler.onWebSocketTraffic(connection, state, transport); action != gnet.None || connection.buffered != 0 {
				t.Fatalf("closing input action=%v, retained=%d", action, connection.buffered)
			}
			if transport.current != current || !transport.asyncWritePending {
				t.Fatal("input overflow changed pending output ownership")
			}
		})
	}
}
