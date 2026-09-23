package gproxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	webCloseIdle uint32 = iota + 1
	webCloseMiddleEnd
)

type webCloseDiagnosticWindow struct {
	mu         sync.Mutex
	start      time.Time
	count      int
	suppressed uint64
}

func (w *webCloseDiagnosticWindow) claim(now time.Time) (uint64, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.start.IsZero() || now.Sub(w.start) >= time.Minute {
		w.start, w.count = now, 0
	}
	if w.count >= 128 {
		w.suppressed++
		return 0, false
	}
	w.count++
	suppressed := w.suppressed
	w.suppressed = 0
	return suppressed, true
}

func webStreamCloseReason(reason uint32) string {
	switch reason {
	case webCloseIdle:
		return "idle_timeout"
	case webCloseMiddleEnd:
		return "middleend_close"
	default:
		return "unspecified"
	}
}

func webStreamCloseError(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.EPIPE):
		return "broken_pipe"
	case errors.Is(err, syscall.ETIMEDOUT):
		return "timeout"
	default:
		return "error"
	}
}

func (ctx *ConnContext) noteWebClose(reason uint32) {
	if ctx.webDiagnostics {
		ctx.webCloseReason.CompareAndSwap(0, reason)
	}
}

// Only process-authenticated WEB streams reach this debug log. The marker says
// where Telego observed the close, not whether the external network caused it.
func (h *ProxyHandler) logWebStreamClose(ctx *ConnContext, err error) {
	now := time.Now()
	suppressed, allowed := h.webCloseDiagnostics.claim(now)
	if !allowed {
		return
	}
	idle := func(last int64) int64 {
		if last == 0 {
			return -1
		}
		return max(0, now.UnixMilli()-last)
	}
	h.logger.Debug("WEB proxy stream closed connection=%q dc_id=%d reason=%s error_category=%s age_ms=%d client_idle_ms=%d server_idle_ms=%d suppressed=%d",
		ctx.LogPrefix(), ctx.DCID(), webStreamCloseReason(ctx.webCloseReason.Load()), webStreamCloseError(err),
		now.Sub(ctx.connTime).Milliseconds(), idle(ctx.lastClientByteMs.Load()), idle(ctx.lastServerByteMs.Load()), suppressed)
}
