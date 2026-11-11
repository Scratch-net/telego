package webproxy

type carrierOperation uint8

const (
	carrierOperationBridge carrierOperation = iota
	carrierOperationCreate
	carrierOperationUplink
	carrierOperationDownlink
	carrierOperationCount
)

var carrierOperationNames = [...]string{"bridge", "create", "uplink", "downlink"}

type sessionCloseReason uint8

const (
	sessionCloseClient sessionCloseReason = iota
	sessionCloseExpired
	sessionCloseProtocol
	sessionCloseResource
	sessionCloseShutdown
	sessionCloseReasonCount
)

var sessionCloseReasonNames = [...]string{"client", "expired", "protocol", "resource", "shutdown"}

// webSocketCloseReason indexes the fixed WebSocket close reasons. The names
// are the strings that the transport passes to noteClose. A close without a
// recorded reason is transport_closed.
type webSocketCloseReason uint8

const webSocketCloseReasonCount = webSocketCloseReason(len(webSocketCloseReasonNames))

var webSocketCloseReasonNames = [...]string{
	"transport_closed",
	"session_closed",
	"downlink_error",
	"lane_closed",
	"output_capacity",
	"liveness_timeout",
	"server_close",
	"uplink_error",
	"input_capacity",
	"decode_error",
	"peer_close",
	"encode_error",
	"write_error",
	"write_timeout",
}

func webSocketCloseReasonFor(reason string) webSocketCloseReason {
	for index, name := range webSocketCloseReasonNames {
		if name == reason {
			return webSocketCloseReason(index)
		}
	}
	return 0
}

// RuntimeCounter is one labeled cumulative WEB counter.
type RuntimeCounter struct {
	Label string
	Total uint64
}

// RuntimeStats is a point-in-time view of WEB capacity and cumulative events.
type RuntimeStats struct {
	Capacity         Capacity
	WebSocketsActive int64
	SessionsCreated  uint64
	SessionsClosed   []RuntimeCounter
	CarrierRetries   []RuntimeCounter
	Backpressure     []RuntimeCounter
	// WebSocketCloses counts each opened WebSocket carrier once, by reason.
	WebSocketCloses []RuntimeCounter
	// HTTPWriteTimeouts counts HTTP carrier connections closed because a
	// response write made no progress before the write timeout.
	HTTPWriteTimeouts uint64
}

// RuntimeStats returns WEB diagnostics without bearer or client identifiers.
func (m *Manager) RuntimeStats() RuntimeStats {
	stats := RuntimeStats{
		Capacity:         m.Capacity(),
		WebSocketsActive: m.webSocketsActive.Load(),
		SessionsCreated:  m.sessionsCreated.Load(),
		SessionsClosed:   make([]RuntimeCounter, 0, sessionCloseReasonCount),
		CarrierRetries:   make([]RuntimeCounter, 0, carrierOperationCount),
		Backpressure:     make([]RuntimeCounter, 0, carrierOperationCount),
		WebSocketCloses:  make([]RuntimeCounter, 0, webSocketCloseReasonCount),
	}
	stats.HTTPWriteTimeouts = m.httpWriteTimeouts.Load()
	for reason := range webSocketCloseReasonCount {
		stats.WebSocketCloses = append(stats.WebSocketCloses, RuntimeCounter{
			Label: webSocketCloseReasonNames[reason],
			Total: m.webSocketCloses[reason].Load(),
		})
	}
	for reason := range sessionCloseReasonCount {
		stats.SessionsClosed = append(stats.SessionsClosed, RuntimeCounter{
			Label: sessionCloseReasonNames[reason],
			Total: m.sessionsClosed[reason].Load(),
		})
	}
	for operation := range carrierOperationCount {
		stats.CarrierRetries = append(stats.CarrierRetries, RuntimeCounter{
			Label: carrierOperationNames[operation],
			Total: m.carrierRetries[operation].Load(),
		})
		stats.Backpressure = append(stats.Backpressure, RuntimeCounter{
			Label: carrierOperationNames[operation],
			Total: m.backpressure[operation].Load(),
		})
	}
	return stats
}

func (m *Manager) recordCarrierRetry(operation carrierOperation) {
	if operation < carrierOperationCount {
		m.carrierRetries[operation].Add(1)
	}
}

func (m *Manager) recordBackpressure(operation carrierOperation) {
	if operation < carrierOperationCount {
		m.backpressure[operation].Add(1)
	}
}
