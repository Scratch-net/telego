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

type maskFallbackReason uint8

const (
	maskFallbackMalformed maskFallbackReason = iota
	maskFallbackUnknownSNI
	maskFallbackUnknownSecret
	maskFallbackBadTimestamp
	maskFallbackReplay
	maskFallbackReasonCount
)

var maskFallbackReasonNames = [...]string{
	"malformed",
	"unknown_sni",
	"unknown_secret",
	"bad_timestamp",
	"replay",
}

// MaskFallbackStat is one cumulative counter of connections sent to the
// mask host, by reason.
type MaskFallbackStat struct {
	Reason string
	Total  uint64
}

func (h *ProxyHandler) recordMaskFallback(reason maskFallbackReason) {
	h.maskFallbacks[reason].Add(1)
}

// MaskFallbackStats returns one stable counter for each fallback reason.
func (h *ProxyHandler) MaskFallbackStats() []MaskFallbackStat {
	result := make([]MaskFallbackStat, 0, maskFallbackReasonCount)
	for reason := range maskFallbackReasonCount {
		result = append(result, MaskFallbackStat{
			Reason: maskFallbackReasonNames[reason],
			Total:  h.maskFallbacks[reason].Load(),
		})
	}
	return result
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

// ReplayCacheEvictions returns replay cache entries evicted before their TTL.
func (h *ProxyHandler) ReplayCacheEvictions() uint64 {
	return h.replayCache.Evictions()
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
	case StateWriteServerHello:
		return handshakeFailureTLSServerHello
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
