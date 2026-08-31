package webproxy

import (
	"encoding/base64"
	"errors"
	"maps"
	"strings"
	"testing"
)

func TestValidateWebSocketUpgrade(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	base := carrierRequest{
		method:  "GET",
		path:    webSocketPath,
		upgrade: true,
		headers: map[string]string{
			"host":                     "proxy.example.com",
			"connection":               "upgrade",
			"upgrade":                  "websocket",
			"sec-websocket-key":        "dGhlIHNhbXBsZSBub25jZQ==",
			"sec-websocket-version":    "13",
			"sec-websocket-protocol":   webSocketProtocolPrefix + token,
			"sec-websocket-extensions": "permessage-deflate",
		},
	}

	upgrade, err := validateWebSocketUpgrade(base)
	if err != nil {
		t.Fatal(err)
	}
	if upgrade.protocol != webSocketProtocolPrefix+token || upgrade.token != token ||
		upgrade.lanes || upgrade.laneID != 0 || upgrade.accept != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("upgrade = %#v", upgrade)
	}
	for name, mutate := range map[string]func(*carrierRequest){
		"cookie": func(r *carrierRequest) {
			r.headers["cookie"] = "site=value; session=untrusted"
		},
		"arbitrary origin": func(r *carrierRequest) {
			r.headers["origin"] = "https://unrelated.example"
		},
		"missing origin": func(r *carrierRequest) {
			delete(r.headers, "origin")
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := cloneCarrierRequest(base)
			mutate(&request)
			if _, securityErr := validateWebSocketUpgrade(request); securityErr != nil {
				t.Fatalf("security-neutral handshake rejected: %v", securityErr)
			}
		})
	}
	protocolListRequest := cloneCarrierRequest(base)
	protocolListRequest.headers["upgrade"] = "h2c/1, WebSocket"
	if _, err := validateWebSocketUpgrade(protocolListRequest); err != nil {
		t.Fatalf("valid Upgrade protocol list: %v", err)
	}

	laneRequest := cloneCarrierRequest(base)
	laneRequest.headers["sec-websocket-protocol"] = webSocketLaneProtocolPrefix + token + ".16777215"
	laneUpgrade, err := validateWebSocketUpgrade(laneRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !laneUpgrade.lanes || laneUpgrade.laneID != MaxStreamID || laneUpgrade.token != token {
		t.Fatalf("lane upgrade = %#v", laneUpgrade)
	}

	tests := map[string]func(*carrierRequest){
		"method":        func(r *carrierRequest) { r.method = "POST" },
		"path":          func(r *carrierRequest) { r.path = "/socket" },
		"query":         func(r *carrierRequest) { r.query = "x=1" },
		"body":          func(r *carrierRequest) { r.hasContentLength, r.contentLength = true, 1 },
		"authorization": func(r *carrierRequest) { r.headers["authorization"] = "Bearer " + token },
		"not upgrade":   func(r *carrierRequest) { r.upgrade = false },
		"wrong upgrade": func(r *carrierRequest) { r.headers["upgrade"] = "h2c" },
		"invalid upgrade element": func(r *carrierRequest) {
			r.headers["upgrade"] = "websocket, invalid value"
		},
		"empty upgrade element": func(r *carrierRequest) {
			r.headers["upgrade"] = "websocket,,h2c"
		},
		"missing upgrade name": func(r *carrierRequest) {
			r.headers["upgrade"] = "websocket, /1"
		},
		"missing upgrade version": func(r *carrierRequest) {
			r.headers["upgrade"] = "websocket, h2c/"
		},
		"multiple upgrade slashes": func(r *carrierRequest) {
			r.headers["upgrade"] = "websocket, h2c/1/2"
		},
		"versioned websocket": func(r *carrierRequest) {
			r.headers["upgrade"] = "websocket/13"
		},
		"wrong version": func(r *carrierRequest) { r.headers["sec-websocket-version"] = "12" },
		"short key": func(r *carrierRequest) {
			r.headers["sec-websocket-key"] = base64.StdEncoding.EncodeToString(make([]byte, 15))
		},
		"noncanonical key":   func(r *carrierRequest) { r.headers["sec-websocket-key"] = " dGhlIHNhbXBsZSBub25jZQ==" },
		"missing protocol":   func(r *carrierRequest) { delete(r.headers, "sec-websocket-protocol") },
		"multiple protocols": func(r *carrierRequest) { r.headers["sec-websocket-protocol"] += ", other" },
		"wrong protocol":     func(r *carrierRequest) { r.headers["sec-websocket-protocol"] = "other" },
		"invalid token":      func(r *carrierRequest) { r.headers["sec-websocket-protocol"] = webSocketProtocolPrefix + "invalid" },
		"lane zero": func(r *carrierRequest) {
			r.headers["sec-websocket-protocol"] = webSocketLaneProtocolPrefix + token + ".0"
		},
		"lane leading zero": func(r *carrierRequest) {
			r.headers["sec-websocket-protocol"] = webSocketLaneProtocolPrefix + token + ".01"
		},
		"lane too large": func(r *carrierRequest) {
			r.headers["sec-websocket-protocol"] = webSocketLaneProtocolPrefix + token + ".16777216"
		},
		"lane missing": func(r *carrierRequest) { r.headers["sec-websocket-protocol"] = webSocketLaneProtocolPrefix + token },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := cloneCarrierRequest(base)
			mutate(&request)
			if _, validateErr := validateWebSocketUpgrade(request); !errors.Is(validateErr, errInvalidWebSocketUpgrade) {
				t.Fatalf("error = %v, want invalid upgrade", validateErr)
			}
		})
	}
}

func TestWebSocketSubprotocolRequiresExactlyOneCanonicalCredential(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		value  string
		token  string
		laneID uint32
		lanes  bool
		ok     bool
	}{
		{webSocketProtocolPrefix + token, token, 0, false, true},
		{webSocketLaneProtocolPrefix + token + ".1", token, 1, true, true},
		{"", "", 0, false, false},
		{webSocketProtocolPrefix + token + ",x", "", 0, false, false},
		{webSocketProtocolPrefix + token + " x", "", 0, false, false},
		{webSocketLaneProtocolPrefix + token + ".00", "", 0, false, false},
	}
	for _, test := range tests {
		gotToken, gotLane, gotLanes, gotOK := parseWebSocketSubprotocol(test.value)
		if gotToken != test.token || gotLane != test.laneID || gotLanes != test.lanes || gotOK != test.ok {
			t.Errorf("parseWebSocketSubprotocol(%q) = %q, %d, %v, %v", test.value, gotToken, gotLane, gotLanes, gotOK)
		}
	}
}

func FuzzParseWebSocketSubprotocol(f *testing.F) {
	token := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, seed := range []string{
		webSocketProtocolPrefix + token,
		webSocketLaneProtocolPrefix + token + ".1",
		"tproxy-v1.invalid",
		"tproxy-lane-v1." + token + ".01",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		token, laneID, lanes, ok := parseWebSocketSubprotocol(value)
		if !ok {
			return
		}
		if strings.ContainsAny(value, ", \t") {
			t.Fatalf("accepted multi-value protocol %q", value)
		}
		if _, err := parseTokenHash(token); err != nil {
			t.Fatalf("accepted invalid token %q", token)
		}
		if lanes && (laneID == 0 || laneID > MaxStreamID) || !lanes && laneID != 0 {
			t.Fatalf("accepted invalid lane %d (lanes=%v)", laneID, lanes)
		}
	})
}

func cloneCarrierRequest(request carrierRequest) carrierRequest {
	cloned := request
	cloned.headers = make(map[string]string, len(request.headers))
	maps.Copy(cloned.headers, request.headers)
	return cloned
}
