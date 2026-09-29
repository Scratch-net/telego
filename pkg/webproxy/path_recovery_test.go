package webproxy

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
)

func TestHTTPBasePathAllCarriers(t *testing.T) {
	for _, carrier := range []CarrierMode{CarrierHTTPS, CarrierHTTPSLanes, CarrierWebSocket, CarrierWebSocketLanes} {
		t.Run(string(carrier), func(t *testing.T) {
			profiles, err := DeriveProfilesForPath("path", "proxy.example.com", "Trial/web", []byte("0123456789abcdef"))
			if err != nil {
				t.Fatal(err)
			}
			app := newHTTPTestApplicationWithConfig(t, 50*time.Millisecond, func(c *ManagerConfig) {
				c.Carrier = carrier
				c.Profiles = profiles[:]
			}, func(c *HTTPServerConfig) { c.BasePath = "Trial/web" })
			client := &http.Client{Timeout: 2 * time.Second}
			bridge := app.do(t, client, "GET", "/Trial/web/?bridge="+profiles[0].Capability().String(), nil, nil)
			page := readHTTPBody(t, bridge)
			if bridge.StatusCode != 200 || !bytes.Contains(page, []byte(`relayOrigin="https://proxy.example.com/Trial/web"`)) {
				t.Fatalf("path bridge: %d", bridge.StatusCode)
			}
			bootstrap := extractBridgeBootstrap(t, page)
			created := app.do(t, client, "POST", "/Trial/web/api/v1/session", testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}}), map[string]string{
				"Authorization": "Bearer " + bootstrap, "Content-Type": "application/octet-stream",
			})
			_ = readHTTPBody(t, created)
			if created.StatusCode != 200 {
				t.Fatalf("create: %d", created.StatusCode)
			}
			token := created.Header.Get("X-Session-Token")
			payload := []byte("prefixed echo")
			batch := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1}, Frame{Type: FrameData, StreamID: 1, Payload: payload})
			if carrier.usesWebSocket() {
				protocol := webSocketProtocolPrefix + token
				if carrier == CarrierWebSocketLanes {
					protocol = webSocketLaneProtocolPrefix + token + ".1"
				}
				conn, reader, response := dialRawWebSocketTest(t, app.address, "/Trial/web/api/v1/ws", protocol, "", nil)
				defer conn.Close()
				if response.StatusCode != 101 {
					t.Fatalf("upgrade: %d", response.StatusCode)
				}
				socket := &webSocketTestClient{connection: conn, reader: reader}
				socket.write(t, ws.OpBinary, true, batch)
				found := false
				for range 4 {
					for _, frame := range readWebSocketBatch(t, socket, time.Second) {
						if frame.Type == FrameData && bytes.Equal(frame.Payload, payload) {
							found = true
						}
					}
					if found {
						break
					}
				}
				if !found {
					t.Fatal("missing path WebSocket echo")
				}
			} else {
				headers := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream", "X-Up-Seq": "1"}
				if carrier == CarrierHTTPSLanes {
					headers["X-Lane-ID"] = "1"
				}
				up := app.do(t, client, "POST", "/Trial/web/api/v1/up", batch, headers)
				_ = readHTTPBody(t, up)
				if up.StatusCode != 204 {
					t.Fatalf("up: %d", up.StatusCode)
				}
				delete(headers, "Content-Type")
				delete(headers, "X-Up-Seq")
				headers["X-Down-Cursor"] = "0"
				found := false
				for range 4 {
					down := app.do(t, client, "POST", "/Trial/web/api/v1/down", nil, headers)
					body := readHTTPBody(t, down)
					if down.StatusCode != 200 {
						t.Fatalf("down: %d", down.StatusCode)
					}
					headers["X-Down-Cursor"] = down.Header.Get("X-Down-Cursor")
					frames, err := ParseBatch(body)
					if err != nil {
						t.Fatal(err)
					}
					for _, frame := range frames {
						if frame.Type == FrameData && bytes.Equal(frame.Payload, payload) {
							found = true
						}
					}
					if found {
						break
					}
				}
				if !found {
					t.Fatal("missing path HTTP echo")
				}
			}
			for _, path := range []string{"/", "/Trial/web", "/trial/web/", "/Trial//web/", "/Trial%2Fweb/", "/another/"} {
				response := app.do(t, client, "GET", path+"?bridge="+profiles[0].Capability().String(), nil, nil)
				_ = readHTTPBody(t, response)
				if response.StatusCode != defaultSanitizedFallbackStatus {
					t.Errorf("alias %q: %d", path, response.StatusCode)
				}
			}
			root, _ := DeriveCapability("proxy.example.com", profiles[0].SecretBytes())
			wrong := app.do(t, client, "GET", "/Trial/web/?bridge="+root.String(), nil, nil)
			_ = readHTTPBody(t, wrong)
			if wrong.StatusCode != defaultSanitizedFallbackStatus {
				t.Fatal("root capability accepted at path")
			}
			deleted := app.do(t, client, "DELETE", "/Trial/web/api/v1/session", nil, map[string]string{"Authorization": "Bearer " + token})
			_ = readHTTPBody(t, deleted)
			if deleted.StatusCode != 204 {
				t.Fatalf("delete: %d", deleted.StatusCode)
			}
		})
	}
}

func TestHTTPRecoveryAuthorizationAndRestart(t *testing.T) {
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(c *ManagerConfig) { c.Limits.MaxSessions = 1 }, nil)
	client := &http.Client{Timeout: time.Second}
	previous := createTestSession(t, app.manager, app.profiles[0])
	request := func(capability Capability, token string) *http.Response {
		return app.do(t, client, "GET", "/?bridge="+capability.String(), nil, map[string]string{"Accept": bridgeRecoveryMediaType, "Authorization": "Bearer " + token})
	}
	wrong := request(app.profiles[1].Capability(), previous.Token)
	_ = readHTTPBody(t, wrong)
	if wrong.StatusCode != defaultSanitizedFallbackStatus {
		t.Fatalf("cross-profile recovery: %d", wrong.StatusCode)
	}
	if _, err := app.manager.Get(previous.Token); err != nil {
		t.Fatal("cross-profile attempt retired another session")
	}
	for _, oldToken := range []string{previous.Token, strings.Repeat("A", 43)} {
		response := request(app.profiles[0].Capability(), oldToken)
		body := readHTTPBody(t, response)
		if response.StatusCode != 200 || response.Header.Get("Content-Type") != bridgeRecoveryMediaType || len(body) > 1024 {
			t.Fatalf("recovery: %d", response.StatusCode)
		}
		var config bridgeRecovery
		if err := json.Unmarshal(body, &config); err != nil {
			t.Fatal(err)
		}
		if config.Version != 1 || config.Carrier != CarrierHTTPS || config.Batch != DefaultLimits().CarrierBatchBytes {
			t.Fatalf("unexpected recovery policy: %#v", config)
		}
		eventually(t, time.Second, func() bool { return app.manager.Capacity().Sessions == 0 })
		created, err := app.manager.Create(config.Bootstrap, "192.0.2.1", testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}}))
		if err != nil {
			t.Fatalf("replacement at capacity one: %v", err)
		}
		created.Session.Close()
		created.Session.wait()
	}
}
