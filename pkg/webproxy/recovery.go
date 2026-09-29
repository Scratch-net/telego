package webproxy

import "encoding/json/v2"

const bridgeRecoveryMediaType = "application/vnd.telego.web-recovery+json"

type bridgeRecovery struct {
	Version   int         `json:"version"`
	Bootstrap string      `json:"bootstrap"`
	Carrier   CarrierMode `json:"carrier"`
	Batch     int         `json:"batch"`
	Streams   int         `json:"streams"`
}

// issueRecovery permits an unknown old bearer after a process restart, but a
// live bearer must belong to the capability's profile before it can be retired.
func (m *Manager) issueRecovery(capability Capability, oldToken, clientIP string) (string, error) {
	profile, matched := m.MatchCapability(capability)
	if !matched {
		return "", ErrAuthentication
	}
	var previous *Session
	if oldToken != "" {
		if _, err := parseTokenHash(oldToken); err != nil {
			return "", ErrAuthentication
		}
		previous, _ = m.Get(oldToken)
		if previous != nil && !previous.Profile().Capability().Equal(profile.Capability()) {
			return "", ErrAuthentication
		}
	}
	// Allocate first: failed admission must leave a working session intact.
	token, err := m.IssueBootstrap(capability, clientIP)
	if err != nil {
		return "", err
	}
	if previous != nil {
		previous.Close()
	}
	return token, nil
}

func (h *httpEventHandler) serveRecovery(request *preparedRequest) carrierResponse {
	m := h.server.config.Manager
	token, err := m.issueRecovery(request.capability, request.token, request.clientIP)
	if err != nil {
		if err == ErrAuthentication {
			return h.sanitizedFallback()
		}
		return retryResponse()
	}
	body, err := json.Marshal(bridgeRecovery{1, token, m.CarrierMode(), m.limits.CarrierBatchBytes, m.limits.MaxStreamsPerSession})
	if err != nil {
		return rejectResponse(500)
	}
	return carrierResponse{status: 200, body: body, headers: []responseHeader{
		{"Content-Type", bridgeRecoveryMediaType},
		{"Cache-Control", "no-store"},
		{"Referrer-Policy", "no-referrer"},
		{"X-Content-Type-Options", "nosniff"},
	}}
}
