package gproxy

import "github.com/panjf2000/gnet/v2"

type handshakeFailureStage uint8

const (
	handshakeFailureProtocolDetection handshakeFailureStage = iota
	handshakeFailureProxyProtocol
	handshakeFailureTLSClientHello
	handshakeFailureTLSServerHello
	handshakeFailureTLSMTProto
	handshakeFailureDirectMTProto
	handshakeFailureAdmission
	handshakeFailureBackendDial
	handshakeFailureStageCount
)

var handshakeFailureStageNames = [...]string{
	"protocol_detection",
	"proxy_protocol",
	"tls_client_hello",
	"tls_server_hello",
	"tls_mtproto",
	"direct_mtproto",
	"admission",
	"backend_dial",
}

// HandshakeFailureStat is one cumulative MTProxy handshake failure counter.
type HandshakeFailureStat struct {
	Stage string
	Total uint64
}

// HandshakeFailureStats returns one stable counter for each processing stage.
func (h *ProxyHandler) HandshakeFailureStats() []HandshakeFailureStat {
	result := make([]HandshakeFailureStat, 0, handshakeFailureStageCount)
	for stage := range handshakeFailureStageCount {
		result = append(result, HandshakeFailureStat{
			Stage: handshakeFailureStageNames[stage],
			Total: h.handshakeFailures[stage].Load(),
		})
	}
	return result
}

// MiddleEndFrontendStats returns aggregate public-side ME buffer pressure. A
// direct-only handler returns a zero snapshot.
func (h *ProxyHandler) MiddleEndFrontendStats() MiddleEndFrontendStats {
	if h == nil || h.middleEnd == nil {
		return MiddleEndFrontendStats{}
	}
	return h.middleEnd.stats()
}

func (h *ProxyHandler) failHandshake(ctx *ConnContext, stage handshakeFailureStage) gnet.Action {
	h.recordHandshakeFailure(ctx, stage)
	return gnet.Close
}

func (h *ProxyHandler) recordHandshakeFailure(ctx *ConnContext, stage handshakeFailureStage) {
	if ctx == nil || stage >= handshakeFailureStageCount || !ctx.handshakeFailureRecorded.CompareAndSwap(false, true) {
		return
	}
	h.handshakeFailures[stage].Add(1)
}

func handshakeStageForState(state ConnState) handshakeFailureStage {
	switch state {
	case StateReadProxyProto:
		return handshakeFailureProxyProtocol
	case StateReadTLSHeader, StateReadTLSPayload:
		return handshakeFailureTLSClientHello
	case StateReadO2Frame:
		return handshakeFailureTLSMTProto
	case StateReadDDFrame:
		return handshakeFailureDirectMTProto
	case StateDialingDC:
		return handshakeFailureBackendDial
	default:
		return handshakeFailureProtocolDetection
	}
}
