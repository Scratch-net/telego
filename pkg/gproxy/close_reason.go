package gproxy

import (
	"errors"
	"io"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

// connCloseReason is the cause of an established connection's close. The
// site that starts the close records it; the first recorded reason wins.
type connCloseReason uint32

const (
	closeReasonUnset connCloseReason = iota
	closeReasonClientEOF
	closeReasonClientError
	closeReasonUpstreamClosed
	closeReasonMiddleEndClosed
	closeReasonMiddleEndBackpressure
	closeReasonMiddleEndTerminal
	closeReasonIdleTimeout
	closeReasonRelayStallDownlink
	closeReasonRelayStallUplink
	closeReasonOutputStall
	closeReasonClientSilence
	closeReasonShutdown
	closeReasonOther
	closeReasonCount
)

var closeReasonNames = [...]string{
	"",
	"client_eof",
	"client_error",
	"upstream_closed",
	"middleend_closed",
	"middleend_backpressure",
	"middleend_terminal",
	"idle_timeout",
	"relay_stall_downlink",
	"relay_stall_uplink",
	"output_stall",
	"client_silence",
	"shutdown",
	"other",
}

// Route of an established connection. Zero means the connection never
// reached a relay session, so its close is not counted.
const (
	routeNone uint32 = iota
	routeDirect
	routeMiddleEnd
)

var routeNames = [...]string{"none", "direct", "middleend"}

// ConnectionCloseStat is one cumulative counter of established connection
// closes, by reason.
type ConnectionCloseStat struct {
	Reason string
	Total  uint64
}

// noteClose records the cause of a close that the caller is about to start.
// It is safe on any goroutine.
func (ctx *ConnContext) noteClose(reason connCloseReason) {
	if ctx != nil {
		ctx.closeReason.CompareAndSwap(uint32(closeReasonUnset), uint32(reason))
	}
}

// MarkShutdown records that process shutdown has started. Later closes without
// a recorded cause count as shutdown. It changes no connection behavior.
func (h *ProxyHandler) MarkShutdown() {
	h.shutdownStarted.Store(true)
}

func (h *ProxyHandler) stopping() bool {
	return h.shutdownStarted.Load() || h.upstreamStopRequested.Load()
}

// noteUpstreamClose classifies a client close caused by its upstream. The
// shutdown sequence closes upstreams first, so it takes precedence there.
func (h *ProxyHandler) noteUpstreamClose(ctx *ConnContext, reason connCloseReason) {
	if h.stopping() {
		reason = closeReasonShutdown
	}
	ctx.noteClose(reason)
}

// middleEndTerminalReason classifies a terminal binding. A nil error without
// an earlier CloseExternal event is a proxy-side manager close or retirement.
func middleEndTerminalReason(err error) connCloseReason {
	if errors.Is(err, middleend.ErrFixedBindingResponseBackpressure) {
		return closeReasonMiddleEndBackpressure
	}
	return closeReasonMiddleEndTerminal
}

// recordConnectionClose runs once per established connection. A close without
// a recorded cause was started by the client socket, by shutdown, or by a
// site that does not classify its cause.
func (h *ProxyHandler) recordConnectionClose(ctx *ConnContext, err error) connCloseReason {
	reason := connCloseReason(ctx.closeReason.Load())
	if reason == closeReasonUnset {
		switch {
		case h.stopping():
			reason = closeReasonShutdown
		case err == nil:
			reason = closeReasonOther
		case errors.Is(err, io.EOF):
			reason = closeReasonClientEOF
		default:
			reason = closeReasonClientError
		}
	}
	h.connectionCloses[reason].Add(1)
	return reason
}

// ConnectionCloseStats returns one stable counter for each close reason.
func (h *ProxyHandler) ConnectionCloseStats() []ConnectionCloseStat {
	result := make([]ConnectionCloseStat, 0, closeReasonCount-1)
	for reason := closeReasonClientEOF; reason < closeReasonCount; reason++ {
		result = append(result, ConnectionCloseStat{
			Reason: closeReasonNames[reason],
			Total:  h.connectionCloses[reason].Load(),
		})
	}
	return result
}
