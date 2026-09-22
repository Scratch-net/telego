package webproxy

import (
	"encoding/json/v2"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

var bridgeDiagnosticIDs atomic.Uint64

const (
	bridgeDiagnosticPath     = "/api/v1/diagnostic"
	maxBridgeDiagnosticBytes = 512
)

// BridgeFailure contains client-reported diagnostics, never exception text,
// URLs, credentials, frame contents, or WebSocket close reason strings.
type BridgeFailure struct {
	BridgeID      uint64      `json:"-"`
	Suppressed    uint64      `json:"-"`
	User          string      `json:"-"`
	Carrier       CarrierMode `json:"-"`
	Reason        string      `json:"reason"`
	Error         string      `json:"error"`
	LaneID        uint32      `json:"lane_id"`
	CloseCode     uint16      `json:"close_code"`
	ReadyState    uint8       `json:"ready_state"`
	HTTPStatus    uint16      `json:"http_status"`
	ElapsedMS     uint64      `json:"elapsed_ms"`
	OperationMS   uint64      `json:"operation_ms"`
	QueuedBytes   uint64      `json:"queued_bytes"`
	QueuedItems   uint32      `json:"queued_items"`
	BufferedBytes uint64      `json:"buffered_bytes"`
	WasClean      bool        `json:"was_clean,omitzero"`
}

func (f BridgeFailure) IsLaneClosure() bool {
	return f.Reason == "ws_lane_closed_client" || f.Reason == "ws_lane_closed_server" || f.Reason == "ws_lane_closed_transport"
}

// One shared allowance follows a bridge from bootstrap through session cleanup.
// Existing manager limits and token expiry bound its lifetime and storage.
type bridgeDiagnosticState struct {
	id       uint64
	user     string
	reported atomic.Bool
	mu       sync.Mutex
	lanes    [2]laneDiagnosticWindow // browser and server allowances are independent
}

type laneDiagnosticWindow struct {
	start      time.Time
	count      int
	recent     [64]uint32
	next       int
	suppressed uint64
}

// Each source gets 32 reports per minute, with a fixed recent-ID cache.
// Lane churn never consumes the separate bridge-failure allowance.
func (d *bridgeDiagnosticState) claimLane(lane uint32, source int, now time.Time) (uint64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	w := &d.lanes[source]
	if lane != 0 && slices.Contains(w.recent[:], lane) {
		return 0, false
	}
	if w.start.IsZero() || now.Sub(w.start) >= time.Minute {
		w.start, w.count = now, 0
	}
	if w.count >= 32 {
		w.suppressed++
		return 0, false
	}
	w.count++
	w.recent[w.next] = lane
	w.next = (w.next + 1) % len(w.recent)
	suppressed := w.suppressed
	w.suppressed = 0
	return suppressed, true
}

func (m *Manager) authenticateBridgeDiagnostic(token string) *bridgeDiagnosticState {
	hash, err := parseTokenHash(token)
	if err != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	if session := m.sessions[hash]; session != nil {
		return session.diagnostic
	}
	now := time.Now()
	if entry := m.bootstraps[hash]; entry != nil && now.Before(entry.expires) {
		return entry.diagnostic
	}
	if entry := m.closedTokens[hash]; entry != nil && now.Before(entry.expires) {
		return entry.diagnostic
	}
	return nil
}

func parseBridgeFailure(body []byte) (BridgeFailure, bool) {
	var failure BridgeFailure
	if len(body) == 0 || len(body) > maxBridgeDiagnosticBytes ||
		json.Unmarshal(body, &failure, json.RejectUnknownMembers(true)) != nil {
		return BridgeFailure{}, false
	}
	if !slices.Contains([]string{
		"session_create", "carrier_queue", "up_frames", "up_capacity", "up_send", "down_poll",
		"lane_capacity", "lane_up", "lane_down", "hello_size", "pre_session_frames",
		"pre_session_capacity", "native_frames", "ws_open", "ws_receive_type", "ws_closed",
		"ws_capacity", "ws_send", "ws_lane_receive_type", "ws_lane_frames", "ws_lane_cross_lane",
		"ws_lane_open", "ws_lane_limit", "ws_lane_capacity", "ws_lane_send",
		"ws_lane_closed_client", "ws_lane_closed_server", "ws_lane_closed_transport",
	}, failure.Reason) || !slices.Contains([]string{
		"none", "error", "type_error", "range_error", "abort", "network", "security",
		"invalid_state", "timeout", "ws_error", "ws_close", "invalid_frame", "response_size",
		"response_length", "response_missing", "response_deadline", "retry_deadline", "retry_limit",
		"session_rejected", "session_invalid", "up_rejected", "down_rejected", "down_invalid",
		"lane_reused", "lane_missing_open", "cross_lane",
	}, failure.Error) {
		return BridgeFailure{}, false
	}
	if failure.IsLaneClosure() && failure.LaneID == 0 {
		return BridgeFailure{}, false
	}
	const maxDiagnosticMS = 30 * 24 * 60 * 60 * 1000
	if failure.LaneID > MaxStreamID || failure.CloseCode > 4999 || failure.ReadyState > 3 ||
		failure.HTTPStatus > 599 || failure.ElapsedMS > maxDiagnosticMS || failure.OperationMS > maxDiagnosticMS ||
		failure.QueuedBytes > 1<<30 || failure.QueuedItems > 1<<20 || failure.BufferedBytes > 1<<30 {
		return BridgeFailure{}, false
	}
	return failure, true
}
