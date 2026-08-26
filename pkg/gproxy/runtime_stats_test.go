package gproxy

import "testing"

func TestHandshakeFailureStatsAreStageLabeledAndOneShot(t *testing.T) {
	config := DefaultConfig()
	handler := NewProxyHandler(&config, nil)
	context := NewConnContext()

	handler.recordHandshakeFailure(context, handshakeFailureTLSMTProto)
	handler.recordHandshakeFailure(context, handshakeFailureBackendDial)

	stats := handler.HandshakeFailureStats()
	if len(stats) != int(handshakeFailureStageCount) {
		t.Fatalf("stage count = %d", len(stats))
	}
	for _, stat := range stats {
		want := uint64(0)
		if stat.Stage == "tls_mtproto" {
			want = 1
		}
		if stat.Total != want {
			t.Fatalf("stage %q total = %d, want %d", stat.Stage, stat.Total, want)
		}
	}
}

func TestHandshakeStageForState(t *testing.T) {
	for state, want := range map[ConnState]handshakeFailureStage{
		StateDetectProtocol: handshakeFailureProtocolDetection,
		StateReadProxyProto: handshakeFailureProxyProtocol,
		StateReadTLSHeader:  handshakeFailureTLSClientHello,
		StateReadTLSPayload: handshakeFailureTLSClientHello,
		StateReadO2Frame:    handshakeFailureTLSMTProto,
		StateReadDDFrame:    handshakeFailureDirectMTProto,
		StateDialingDC:      handshakeFailureBackendDial,
	} {
		if got := handshakeStageForState(state); got != want {
			t.Errorf("state %s stage = %d, want %d", state, got, want)
		}
	}
}
