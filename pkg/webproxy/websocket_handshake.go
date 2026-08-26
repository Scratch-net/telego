package webproxy

import (
	"crypto/sha1" //nolint:gosec // RFC 6455 requires SHA-1 for Sec-WebSocket-Accept.
	"encoding/base64"
	"errors"
	"strings"
)

const (
	webSocketPath               = "/api/v1/ws"
	webSocketProtocolPrefix     = "tproxy-v1."
	webSocketLaneProtocolPrefix = "tproxy-lane-v1."
	webSocketAcceptGUID         = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

var errInvalidWebSocketUpgrade = errors.New("invalid WEB WebSocket upgrade")

type webSocketUpgrade struct {
	protocol string
	token    string
	accept   string
	laneID   uint32
	lanes    bool
}

// validateWebSocketUpgrade validates only the RFC 6455 and WEB wire shape.
// Routing must reject trailing bytes, authenticate the token, match the session
// carrier, and acquire its socket or lane before emitting 101 Switching Protocols.
func validateWebSocketUpgrade(request carrierRequest) (webSocketUpgrade, error) {
	var result webSocketUpgrade
	if request.method != "GET" || request.path != webSocketPath || request.query != "" ||
		!emptyRequestBody(request) || request.headers["authorization"] != "" ||
		!request.upgrade || !validUpgradeProtocolList(request.headers["upgrade"], "websocket") ||
		request.headers["sec-websocket-version"] != "13" {
		return result, errInvalidWebSocketUpgrade
	}

	key := request.headers["sec-websocket-key"]
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decodedKey) != 16 || base64.StdEncoding.EncodeToString(decodedKey) != key {
		return result, errInvalidWebSocketUpgrade
	}

	protocol := request.headers["sec-websocket-protocol"]
	token, laneID, lanes, ok := parseWebSocketSubprotocol(protocol)
	if !ok {
		return result, errInvalidWebSocketUpgrade
	}
	result = webSocketUpgrade{
		protocol: protocol,
		token:    token,
		accept:   webSocketAccept(key),
		laneID:   laneID,
		lanes:    lanes,
	}
	return result, nil
}

func parseWebSocketSubprotocol(protocol string) (token string, laneID uint32, lanes, ok bool) {
	if protocol == "" || strings.ContainsAny(protocol, ", \t") {
		return "", 0, false, false
	}
	if token, matched := strings.CutPrefix(protocol, webSocketProtocolPrefix); matched {
		if _, err := parseTokenHash(token); err != nil {
			return "", 0, false, false
		}
		return token, 0, false, true
	}

	tokenAndLane, matched := strings.CutPrefix(protocol, webSocketLaneProtocolPrefix)
	if !matched {
		return "", 0, false, false
	}
	token, laneText, found := strings.CutLast(tokenAndLane, ".")
	if !found {
		return "", 0, false, false
	}
	if _, err := parseTokenHash(token); err != nil {
		return "", 0, false, false
	}
	lane, canonical := canonicalDecimal(laneText)
	if !canonical || lane == 0 || lane > MaxStreamID {
		return "", 0, false, false
	}
	return token, uint32(lane), true, true
}

func webSocketAccept(key string) string {
	digest := sha1.Sum([]byte(key + webSocketAcceptGUID))
	return base64.StdEncoding.EncodeToString(digest[:])
}

func validUpgradeProtocolList(value, want string) bool {
	found := false
	for field := range strings.SplitSeq(value, ",") {
		protocol := strings.Trim(field, " \t")
		name, version, hasVersion := strings.Cut(protocol, "/")
		if name == "" || !validHeaderName([]byte(name)) ||
			hasVersion && (version == "" || !validHeaderName([]byte(version))) {
			return false
		}
		if !hasVersion && strings.EqualFold(name, want) {
			found = true
		}
	}
	return found
}
