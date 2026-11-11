package webproxy

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gobwas/ws"
)

func webSocketCloseTotals(m *Manager) (map[string]uint64, uint64) {
	totals := make(map[string]uint64)
	var sum uint64
	for _, counter := range m.RuntimeStats().WebSocketCloses {
		totals[counter.Label] = counter.Total
		sum += counter.Total
	}
	return totals, sum
}

func TestWebSocketCloseStatsHaveStableReasons(t *testing.T) {
	want := []string{
		"transport_closed", "session_closed", "downlink_error", "lane_closed", "output_capacity",
		"liveness_timeout", "server_close", "uplink_error", "input_capacity", "decode_error",
		"peer_close", "encode_error", "write_error", "write_timeout",
	}
	stats := (&Manager{}).RuntimeStats().WebSocketCloses
	if len(stats) != len(want) {
		t.Fatalf("reasons = %v, want %v", stats, want)
	}
	for i, counter := range stats {
		if counter.Label != want[i] || counter.Total != 0 {
			t.Fatalf("reason %d = %+v, want %s with zero total", i, counter, want[i])
		}
	}
	for i, reason := range want {
		if got := webSocketCloseReasonFor(reason); int(got) != i {
			t.Fatalf("reason %s index = %d, want %d", reason, got, i)
		}
	}
}

// Counting does not depend on debug diagnostics.
func TestWebSocketCloseCountedOnceByReason(t *testing.T) {
	for _, kind := range []string{"peer", "transport", "client frame", "liveness"} {
		t.Run(kind, func(t *testing.T) {
			app := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(config *ManagerConfig) {
				config.Carrier = CarrierWebSocketLanes
			}, nil)
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
					found = found || (frame.Type == FrameData && bytes.Equal(frame.Payload, []byte("probe")))
				}
			}
			want := ""
			switch kind {
			case "peer":
				client.write(t, ws.OpClose, true, []byte{3, 233})
				expectWebSocketCloseCode(t, client, ws.StatusGoingAway, time.Second)
				want = "peer_close"
			case "transport":
				client.close()
				want = "transport_closed"
			case "client frame":
				client.write(t, ws.OpBinary, true, testFrameBatch(t, Frame{Type: FrameClose, StreamID: 7}))
				want = "lane_closed"
			case "liveness":
				want = "liveness_timeout"
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				if _, sum := webSocketCloseTotals(app.manager); sum > 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no WebSocket close was counted, want %s", want)
				}
				time.Sleep(time.Millisecond)
			}
			client.close()
			time.Sleep(100 * time.Millisecond)
			if totals, sum := webSocketCloseTotals(app.manager); sum != 1 || totals[want] != 1 {
				t.Fatalf("WebSocket closes = %v, want exactly one %s", totals, want)
			}
		})
	}
}

func TestHTTPWriteDeadlineCountsOnlyWriteStall(t *testing.T) {
	for _, write := range []bool{false, true} {
		manager := &Manager{}
		loop := &deadlineTestLoop{}
		connection := &deadlineTestConn{loop: loop}
		state := &httpConnectionState{manager: manager}
		if write {
			state.armWriteDeadline(connection, 5*time.Millisecond)
		} else {
			state.armDeadline(connection, 5*time.Millisecond)
		}
		deadline := time.Now().Add(3 * time.Second)
		for loop.closes.Load() == 0 {
			if time.Now().After(deadline) {
				t.Fatal("expired deadline did not close the connection")
			}
			time.Sleep(time.Millisecond)
		}
		want := uint64(0)
		if write {
			want = 1
		}
		if got := manager.RuntimeStats().HTTPWriteTimeouts; got != want {
			t.Fatalf("write=%v: HTTP write timeouts = %d, want %d", write, got, want)
		}
	}
}
