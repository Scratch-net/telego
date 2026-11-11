package webproxy

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

type deadlineTestLoop struct {
	gnet.EventLoop
	closes atomic.Int32
}

func (l *deadlineTestLoop) Execute(ctx context.Context, r gnet.Runnable) error { return r.Run(ctx) }
func (l *deadlineTestLoop) Close(gnet.Conn) error                              { l.closes.Add(1); return nil }

type deadlineTestConn struct {
	gnet.Conn
	loop *deadlineTestLoop
}

func (c *deadlineTestConn) EventLoop() gnet.EventLoop { return c.loop }
func (c *deadlineTestConn) OutboundBuffered() int     { return 0 }
func (c *deadlineTestConn) Fd() int                   { return -1 }

// The timer fires while the owner holds s.mu and cancels the deadline without
// arming a new one, as the WebSocket pump does after a message drains. The
// expiry that was already in flight must not close the connection.
func TestHTTPDeadlineInvalidateRacingFiredTimerDoesNotClose(t *testing.T) {
	loop := &deadlineTestLoop{}
	connection := &deadlineTestConn{loop: loop}
	state := &httpConnectionState{}
	state.armWriteDeadline(connection, 5*time.Millisecond)
	state.mu.Lock()
	time.Sleep(30 * time.Millisecond) // The timer fires and blocks on state.mu.
	state.invalidateDeadlineLocked()
	state.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	if n := loop.closes.Load(); n != 0 {
		t.Fatalf("invalidated deadline closed the connection %d time(s)", n)
	}
}
