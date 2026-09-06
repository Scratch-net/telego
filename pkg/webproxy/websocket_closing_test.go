package webproxy

import (
	"errors"
	"testing"

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
