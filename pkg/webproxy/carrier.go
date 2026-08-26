package webproxy

import (
	"fmt"
)

// CarrierMode selects the HTTP transport for one WEB relay session.
type CarrierMode string

const (
	CarrierHTTPS          CarrierMode = "https"
	CarrierHTTPSLanes     CarrierMode = "https-lanes"
	CarrierWebSocket      CarrierMode = "websocket"
	CarrierWebSocketLanes CarrierMode = "websocket-lanes"
)

// ParseCarrierMode returns a supported carrier mode. An empty value preserves
// the serialized HTTPS mode used before carrier selection was configurable.
func ParseCarrierMode(value string) (CarrierMode, error) {
	switch mode := CarrierMode(value); mode {
	case "", CarrierHTTPS:
		return CarrierHTTPS, nil
	case CarrierHTTPSLanes, CarrierWebSocket, CarrierWebSocketLanes:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported WEB carrier mode %q", value)
	}
}

func (m CarrierMode) valid() bool {
	return m == CarrierHTTPS || m == CarrierHTTPSLanes ||
		m == CarrierWebSocket || m == CarrierWebSocketLanes
}

func (m CarrierMode) usesLanes() bool {
	return m == CarrierHTTPSLanes || m == CarrierWebSocketLanes
}

func (m CarrierMode) usesWebSocket() bool {
	return m == CarrierWebSocket || m == CarrierWebSocketLanes
}
