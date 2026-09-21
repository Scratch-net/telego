package webproxy

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const testBridgeFailureBody = `{"reason":"ws_lane_open","error":"ws_close","lane_id":7,"close_code":1006,"ready_state":3,"elapsed_ms":1234,"operation_ms":25}`

func TestBridgeDiagnosticAuthenticationAndBounds(t *testing.T) {
	reports := make(chan BridgeFailure, 8)
	app := newHTTPTestApplicationWithConfig(t, time.Second, nil, func(config *HTTPServerConfig) {
		config.OnBridgeFailure = func(failure BridgeFailure) { reports <- failure }
	})
	client := &http.Client{Timeout: time.Second}
	bootstrap, err := app.manager.IssueBootstrap(app.profiles[0].Capability(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, token, body string
		status            int
	}{
		{"unauthenticated", "", testBridgeFailureBody, 419},
		{"wrong token", strings.Repeat("a", 43), testBridgeFailureBody, 419},
		{"oversized", bootstrap, strings.Repeat("x", maxBridgeDiagnosticBytes+1), 419},
		{"unknown field", bootstrap, `{"reason":"ws_open","error":"none","secret":"never log this"}`, 400},
		{"untrusted reason", bootstrap, `{"reason":"private credential","error":"none"}`, 400},
		{"untrusted error", bootstrap, `{"reason":"ws_open","error":"private credential"}`, 400},
		{"duplicate member", bootstrap, `{"reason":"ws_open","reason":"ws_send","error":"none"}`, 400},
		{"numeric overflow", bootstrap, `{"reason":"ws_open","error":"none","lane_id":16777216}`, 400},
		{"valid", bootstrap, testBridgeFailureBody, 204},
		{"duplicate report", bootstrap, testBridgeFailureBody, 204},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := app.do(t, client, "POST", bridgeDiagnosticPath, []byte(test.body), map[string]string{
				"Authorization": "Bearer " + test.token, "Content-Type": "application/octet-stream",
			})
			readHTTPBody(t, response)
			if response.StatusCode != test.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
			}
		})
	}
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want one", len(reports))
	}
	report := <-reports
	if report.User != app.profiles[0].Name() || report.Carrier != CarrierHTTPS ||
		report.Reason != "ws_lane_open" || report.CloseCode != 1006 || report.OperationMS != 25 {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestBridgeDiagnosticAllowanceSurvivesSessionLifecycle(t *testing.T) {
	for _, firstReport := range []string{"bootstrap", "active session", "closed session"} {
		t.Run(firstReport, func(t *testing.T) {
			reports := make(chan BridgeFailure, 32)
			app := newHTTPTestApplicationWithConfig(t, time.Second, nil, func(config *HTTPServerConfig) {
				config.OnBridgeFailure = func(failure BridgeFailure) { reports <- failure }
			})
			bootstrap, err := app.manager.IssueBootstrap(app.profiles[0].Capability(), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			client := &http.Client{Timeout: time.Second}
			report := func(token string) {
				response := app.do(t, client, "POST", bridgeDiagnosticPath, []byte(testBridgeFailureBody), map[string]string{
					"Authorization": "Bearer " + token, "Content-Type": "application/octet-stream",
				})
				readHTTPBody(t, response)
				if response.StatusCode != 204 {
					t.Errorf("diagnostic status = %d", response.StatusCode)
				}
			}
			if firstReport == "bootstrap" {
				report(bootstrap)
			}
			created, err := app.manager.Create(bootstrap, "127.0.0.1", testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}}))
			if err != nil {
				t.Fatal(err)
			}
			if firstReport == "active session" {
				report(created.Token)
			}
			if err := app.manager.Close(created.Token); err != nil {
				t.Fatal(err)
			}
			created.Session.wait()
			var requests sync.WaitGroup
			for range 16 {
				requests.Go(func() { report(created.Token) })
			}
			requests.Wait()
			if len(reports) != 1 {
				t.Fatalf("reports = %d, want one", len(reports))
			}
			hash, _ := parseTokenHash(created.Token)
			app.manager.mu.Lock()
			app.manager.closedTokens[hash].expires = time.Now().Add(-time.Second)
			app.manager.mu.Unlock()
			if app.manager.authenticateBridgeDiagnostic(created.Token) != nil {
				t.Fatal("expired closed token authenticated")
			}
		})
	}
}
