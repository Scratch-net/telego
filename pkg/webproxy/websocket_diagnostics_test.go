package webproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gobwas/ws"
)

func TestWebSocketFailureCloseSharesHTTPAllowance(t *testing.T) {
	for _, first := range []string{"http", "websocket_close"} {
		t.Run(first, func(t *testing.T) {
			reports := make(chan BridgeFailure, 8)
			app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
				config.Carrier = CarrierWebSocketLanes
			}, func(config *HTTPServerConfig) {
				config.OnBridgeFailure = func(event BridgeFailure) { reports <- event }
			})
			created := createTestSession(t, app.manager, app.profiles[0])
			post := func() {
				response := app.do(t, &http.Client{Timeout: time.Second}, "POST", bridgeDiagnosticPath, []byte(testBridgeFailureBody), map[string]string{
					"Authorization": "Bearer " + created.Token, "Content-Type": "application/octet-stream",
				})
				readHTTPBody(t, response)
				if response.StatusCode != 204 {
					t.Fatalf("diagnostic status = %d", response.StatusCode)
				}
			}
			if first == "http" {
				post()
			}
			for lane, reason := range []string{
				`{"r":"private reason","e":"none"}`,
				`{"r":"ws_lane_open","e":"ws_close","l":7,"t":25,"c":1006,"s":3}`,
				`{"r":"ws_lane_open","e":"ws_close","l":7,"t":25,"c":1006,"s":3}`,
			} {
				client, response := dialWebSocketTest(t, app.address, fmt.Sprintf("tproxy-lane-v1.%s.%d", created.Token, lane+1), "", nil)
				if response.StatusCode != http.StatusSwitchingProtocols {
					t.Fatalf("upgrade = %d", response.StatusCode)
				}
				client.write(t, ws.OpClose, true, append([]byte{0x0f, 0xa0}, reason...))
				expectWebSocketCloseCode(t, client, bridgeFailureCloseCode, time.Second)
				client.close()
			}
			post()
			if len(reports) != 1 {
				t.Fatalf("reports = %d, want one", len(reports))
			}
			report := <-reports
			if report.Delivery != first || report.BridgeID == 0 || report.User != app.profiles[0].Name() || report.Carrier != CarrierWebSocketLanes || report.LaneID != 7 || report.CloseCode != 1006 || report.OperationMS != 25 {
				t.Fatalf("unexpected failure: %+v", report)
			}
		})
	}
}

func TestWebSocketCloseDiagnostics(t *testing.T) {
	for _, kind := range []string{"peer", "transport", "client frame", "backend", "liveness"} {
		t.Run(kind, func(t *testing.T) {
			reports := make(chan WebSocketClose, 8)
			dialed := make(chan net.Conn, 1)
			app := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(config *ManagerConfig) {
				config.Carrier = CarrierWebSocketLanes
				config.BackendDialContext = func(ctx context.Context, network, address, _ string) (net.Conn, error) {
					connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
					if err == nil {
						dialed <- connection
					}
					return connection, err
				}
			}, func(config *HTTPServerConfig) {
				config.OnWebSocketClose = func(event WebSocketClose) { reports <- event }
			})
			created := createTestSession(t, app.manager, app.profiles[0])
			client, response := dialWebSocketTest(t, app.address, fmt.Sprintf("tproxy-lane-v1.%s.7", created.Token), "", nil)
			if response.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("upgrade = %d", response.StatusCode)
			}
			defer client.close()
			client.write(t, ws.OpBinary, true, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 7}, Frame{Type: FrameData, StreamID: 7, Payload: []byte("probe")}))
			found := false
			for !found {
				for _, frame := range readWebSocketBatch(t, client, time.Second) {
					found = found || frame.Type == FrameData
				}
			}
			wantReason, wantOrigin := "", ""
			switch kind {
			case "peer":
				client.write(t, ws.OpClose, true, append([]byte{3, 233}, []byte("private close reason")...))
				expectWebSocketCloseCode(t, client, ws.StatusGoingAway, time.Second)
				wantReason = "peer_close"
			case "transport":
				client.close()
				wantReason = "transport_closed"
			case "client frame":
				client.write(t, ws.OpBinary, true, testFrameBatch(t, Frame{Type: FrameClose, StreamID: 7}))
				wantReason, wantOrigin = "lane_closed", "client_frame"
			case "backend":
				select {
				case backend := <-dialed:
					_ = backend.Close()
				case <-time.After(time.Second):
					t.Fatal("backend dial was not captured")
				}
				// Acknowledge the server CLOSE frame before its lane can retire.
				for {
					frames := readWebSocketBatch(t, client, time.Second)
					closed := false
					for _, frame := range frames {
						closed = closed || frame.Type == FrameClose
					}
					if closed {
						break
					}
				}
				wantReason, wantOrigin = "lane_closed", "backend_close"
			case "liveness":
				wantReason = "liveness_timeout"
			}
			select {
			case event := <-reports:
				if event.Reason != wantReason || event.StreamOrigin != wantOrigin || event.BridgeID == 0 || event.LaneID != 7 || event.User != app.profiles[0].Name() || event.Carrier != CarrierWebSocketLanes {
					t.Fatalf("unexpected close report: %+v", event)
				}
				if kind == "peer" && (event.CloseCode != 1001 || event.PeerCloseCode != 1001) {
					t.Fatalf("peer codes: %+v", event)
				}
				if event.ReceivedBytes == 0 || event.SentBytes == 0 {
					t.Fatalf("missing traffic counts: %+v", event)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no close diagnostic")
			}
			if _, err := app.manager.Get(created.Token); err != nil {
				t.Fatalf("lane closure destroyed session: %v", err)
			}
		})
	}
}
