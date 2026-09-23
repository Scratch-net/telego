package webproxy

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLaneDiagnosticsDoNotConsumeFailureAllowance(t *testing.T) {
	reports := make(chan BridgeFailure, 40)
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.DebugDiagnostics = true
	}, func(config *HTTPServerConfig) {
		config.OnBridgeFailure = func(failure BridgeFailure) { reports <- failure }
	})
	bootstrap, err := app.manager.IssueBootstrap(app.profiles[0].Capability(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	post := func(body string) {
		response := app.do(t, client, "POST", bridgeDiagnosticPath, []byte(body), map[string]string{
			"Authorization": "Bearer " + bootstrap, "Content-Type": "application/octet-stream",
		})
		readHTTPBody(t, response)
		if response.StatusCode != 204 {
			t.Fatalf("diagnostic status = %d", response.StatusCode)
		}
	}
	for lane := range 40 {
		body := fmt.Sprintf(`{"reason":"ws_lane_closed_transport","error":"ws_close","lane_id":%d,"close_code":1006}`, lane+1)
		post(body)
		post(body)
	}
	if len(reports) != 32 {
		t.Fatalf("lane reports = %d, want 32", len(reports))
	}
	post(testBridgeFailureBody)
	post(testBridgeFailureBody)
	if len(reports) != 33 {
		t.Fatalf("reports after bridge failure = %d, want 33", len(reports))
	}
	state := app.manager.authenticateBridgeDiagnostic(bootstrap)
	if _, allowed := state.claimLane(100, 1, time.Now()); !allowed {
		t.Fatal("browser exhausted server allowance")
	}
	suppressed, allowed := state.claimLane(100, 0, time.Now().Add(time.Minute))
	if !allowed || suppressed != 16 {
		t.Fatalf("refilled allowance = %d, %v", suppressed, allowed)
	}
	for len(reports) != 0 {
		if report := <-reports; report.BridgeID == 0 {
			t.Fatal("report omitted server-derived bridge ID")
		}
	}
}

const testBridgeFailureBody = `{"reason":"ws_lane_open","error":"ws_close","lane_id":7,"close_code":1006,"ready_state":3,"elapsed_ms":1234,"operation_ms":25}`

func TestBridgeFailureCloseValidation(t *testing.T) {
	for _, body := range []string{
		``, `null`, `{}`, strings.Repeat(" ", 124),
		`{"r":"private reason","e":"none"}`,
		`{"r":"ws_open","e":"private error"}`,
		`{"r":"ws_open","e":"none","secret":"private"}`,
		`{"r":"ws_open","r":"ws_send","e":"none"}`,
		`{"r":"ws_open","e":"none","l":16777216}`,
		`{"r":"ws_open","e":"none","t":2592000001}`,
		`{"r":"ws_open","e":"none","c":5000}`,
		`{"r":"ws_open","e":"none","s":4}`,
		`{"r":"ws_lane_closed_transport","e":"ws_close","l":7}`,
	} {
		if _, valid := parseBridgeFailureClose([]byte(body)); valid {
			t.Errorf("accepted invalid close diagnostic %q", body)
		}
	}
	failure, valid := parseBridgeFailureClose([]byte(`{"r":"ws_lane_open","e":"ws_close","l":7,"t":25,"c":1006,"s":3}`))
	if !valid || failure.Reason != "ws_lane_open" || failure.Error != "ws_close" || failure.LaneID != 7 || failure.OperationMS != 25 || failure.CloseCode != 1006 || failure.ReadyState != 3 {
		t.Fatalf("invalid parsed diagnostic: %+v, %v", failure, valid)
	}
}

func TestBridgeDiagnosticAuthenticationAndBounds(t *testing.T) {
	reports := make(chan BridgeFailure, 8)
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.DebugDiagnostics = true
	}, func(config *HTTPServerConfig) {
		config.OnBridgeFailure = func(failure BridgeFailure) { reports <- failure }
	})
	client := &http.Client{Timeout: time.Second}
	response := app.do(t, client, "GET", "/?bridge="+app.profiles[0].Capability().String(), nil, nil)
	if body := readHTTPBody(t, response); response.StatusCode != 200 || !strings.Contains(string(body), "const diagnostics=true,") {
		t.Fatal("debug manager did not enable diagnostics in the bridge page")
	}
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
			app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
				config.DebugDiagnostics = true
			}, func(config *HTTPServerConfig) {
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
