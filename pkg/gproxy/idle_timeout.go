package gproxy

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// authenticatedIdleTimer keeps one timer per session. Payload activity moves
// the monotonic deadline without scheduling a timer or a task per packet.
// Only the owning event loop decides that the session has expired.
type authenticatedIdleTimer struct {
	mu       sync.Mutex
	timeout  time.Duration
	deadline time.Time
	timer    *time.Timer
	closed   bool
	conn     clientEndpoint
	owner    gnet.EventLoop
	ctx      *ConnContext
}

// startAuthenticatedIdle runs on the client owner at authentication. Hot
// reloads affect later activations; a live session keeps this timeout value.
func (ctx *ConnContext) startAuthenticatedIdle(conn clientEndpoint, timeout time.Duration) {
	ctx.startConnectionIdle(conn, timeout)
}

// startConnectionIdle also serves unauthenticated TLS splices. Authentication
// policy determines when the caller may replace the handshake timer.
func (ctx *ConnContext) startConnectionIdle(conn clientEndpoint, timeout time.Duration) {
	ctx.stopHandshakeTimer()
	if timeout <= 0 || ctx.State() == StateClosed || ctx.authenticatedIdle.Load() != nil {
		return
	}
	timer := &authenticatedIdleTimer{
		timeout:  timeout,
		deadline: time.Now().Add(timeout),
		conn:     conn,
		owner:    clientOwner(conn),
		ctx:      ctx,
	}
	timer.mu.Lock()
	ctx.authenticatedIdle.Store(timer)
	timer.timer = time.AfterFunc(timeout, timer.enqueueExpiry)
	timer.mu.Unlock()
}

func (timer *authenticatedIdleTimer) enqueueExpiry() {
	timer.mu.Lock()
	closed := timer.closed
	timer.mu.Unlock()
	if closed {
		return
	}
	if err := timer.owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		timer.expireOnOwner()
		return nil
	})); err != nil {
		// Execute can fail during engine shutdown. Close is also thread-safe.
		_ = timer.conn.Close()
	}
}

func (timer *authenticatedIdleTimer) expireOnOwner() {
	timer.mu.Lock()
	if timer.closed || timer.ctx.State() == StateClosed {
		timer.mu.Unlock()
		return
	}
	if remaining := time.Until(timer.deadline); remaining > 0 {
		timer.timer.Reset(remaining)
		timer.mu.Unlock()
		return
	}
	timer.closed = true
	timer.mu.Unlock()
	_ = timer.conn.Close()
}

// recordClientActivity and recordServerActivity may run on either relay loop.
// Wakeups, empty reads, and flow-control retries do not count as activity.
func (ctx *ConnContext) recordClientActivity() {
	ctx.lastClientByteMs.Store(time.Now().UnixMilli())
	ctx.refreshAuthenticatedIdle()
}

func (ctx *ConnContext) recordServerActivity() {
	ctx.lastServerByteMs.Store(time.Now().UnixMilli())
	ctx.refreshAuthenticatedIdle()
}

func (ctx *ConnContext) refreshAuthenticatedIdle() {
	if timer := ctx.authenticatedIdle.Load(); timer != nil {
		timer.mu.Lock()
		if !timer.closed {
			timer.deadline = time.Now().Add(timer.timeout)
		}
		timer.mu.Unlock()
	}
}

func (ctx *ConnContext) stopHandshakeTimer() {
	if timer := ctx.handshakeTimer.Swap(nil); timer != nil {
		timer.Stop()
	}
}

func (ctx *ConnContext) stopConnectionTimers() {
	ctx.stopHandshakeTimer()
	if timer := ctx.authenticatedIdle.Swap(nil); timer != nil {
		timer.mu.Lock()
		timer.closed = true
		timer.timer.Stop()
		timer.mu.Unlock()
	}
}

func (h *ProxyHandler) startHandshakeTimer(conn clientEndpoint, ctx *ConnContext, timeout time.Duration) {
	owner := clientOwner(conn)
	ctx.handshakeTimer.Store(time.AfterFunc(timeout, func() {
		if err := owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
			state := ctx.State()
			switch state {
			case StateClosed, StateRelaying, StateSplicing, StateDialingDC, StateMiddleEnd:
				return nil
			}
			h.recordHandshakeFailure(ctx, handshakeStageForState(state))
			h.logger.Info("[#%d] handshake timeout from %s in state %s (active: %d)",
				ctx.id, conn.RemoteAddr(), state, atomic.LoadInt64(&h.activeConns))
			return conn.Close()
		})); err != nil {
			_ = conn.Close()
		}
	}))
}
