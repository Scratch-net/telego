package webproxy

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/gobwas/ws"
)

// WebSocketClose describes an observed server-side close. It contains no
// addresses, tokens, payloads, or peer-supplied reason text.
type WebSocketClose struct {
	User          string
	Carrier       CarrierMode
	BridgeID      uint64
	LaneID        uint32
	Reason        string
	StreamOrigin  string
	ErrorCategory string
	CloseCode     uint16
	PeerCloseCode uint16
	AgeMS         int64
	ReceivedBytes uint64
	SentBytes     uint64
	Suppressed    uint64
}

func diagnosticNetworkError(err error) string {
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

// Allocated only for debug diagnostics. Fields belong to the WebSocket owner;
// worker failures carry their reason through the existing failure channel.
type webSocketDiagnostic struct {
	createdAt     time.Time
	onClose       func(WebSocketClose)
	closeReason   string
	closeError    string
	closeCode     uint16
	peerCloseCode uint16
	receivedBytes uint64
	sentBytes     uint64
}

func (w *webSocketConnection) noteClose(reason string, code ws.StatusCode) {
	if d := w.diagnostic; d != nil && d.closeReason == "" {
		d.closeReason, d.closeCode = reason, uint16(code)
	}
}

func (w *webSocketConnection) reportClose() {
	stats := w.diagnostic
	if stats == nil || w.session.diagnostic == nil {
		return
	}
	d := w.session.diagnostic
	laneID := uint32(0)
	origin := ""
	if w.lane != nil {
		laneID = w.lane.laneID
		w.session.mu.Lock()
		origin = w.lane.lane.closeOrigin
		w.session.mu.Unlock()
	}
	suppressed, allowed := d.claimLane(laneID, 1, time.Now())
	if !allowed {
		return
	}
	reason := stats.closeReason
	if reason == "" {
		reason = "transport_closed"
	}
	errorCategory := stats.closeError
	if errorCategory == "" {
		errorCategory = "none"
	}
	stats.onClose(WebSocketClose{
		User: d.user, Carrier: w.session.carrier, BridgeID: d.id, LaneID: laneID,
		Reason: reason, StreamOrigin: origin, ErrorCategory: errorCategory,
		CloseCode: stats.closeCode, PeerCloseCode: stats.peerCloseCode,
		AgeMS:         max(0, time.Since(stats.createdAt).Milliseconds()),
		ReceivedBytes: stats.receivedBytes, SentBytes: stats.sentBytes, Suppressed: suppressed,
	})
}
