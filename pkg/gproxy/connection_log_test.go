package gproxy

import (
	"strings"
	"testing"

	"github.com/panjf2000/gnet/v2"
)

// Accepting a connection logs at Debug. Rejections at the global limit log
// at most one Info line per second.
func TestConnectionAcceptLogsAreNotPerConnectionInfo(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{MaxConnections: 1}, logger)
	logger.mu.Lock()
	logger.infos = nil
	logger.mu.Unlock()
	first := newTestMockGnetConn()
	if _, action := handler.OnOpen(first); action != gnet.None {
		t.Fatalf("first OnOpen action = %v", action)
	}
	for range 50 {
		rejected := newTestMockGnetConn()
		if _, action := handler.OnOpen(rejected); action != gnet.Close {
			t.Fatalf("saturated OnOpen action = %v", action)
		}
		handler.OnClose(rejected, nil)
	}
	logger.mu.Lock()
	infos := append([]string(nil), logger.infos...)
	logger.mu.Unlock()
	limitLines := 0
	for _, line := range infos {
		if strings.Contains(line, "new connection from") {
			t.Fatalf("accept logged at Info: %q", line)
		}
		if strings.Contains(line, "global connection limit") {
			limitLines++
		}
	}
	if limitLines < 1 || limitLines > 2 {
		t.Fatalf("global limit Info lines = %d for 50 rejections, want 1 (2 across a second boundary)", limitLines)
	}
}

func TestLogRateLimit(t *testing.T) {
	var limit logRateLimit
	if _, ok := limit.allow(10); !ok {
		t.Fatal("first line suppressed")
	}
	for range 3 {
		if _, ok := limit.allow(10); ok {
			t.Fatal("second line in the same second allowed")
		}
	}
	if suppressed, ok := limit.allow(11); !ok || suppressed != 3 {
		t.Fatalf("next second: ok=%v suppressed=%d, want true 3", ok, suppressed)
	}
}

// A flood from one IP over max-connections-per-ip logs at most one Info line
// per second.
func TestPerIPLimitLogsAreRateLimited(t *testing.T) {
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{MaxConnectionsPerIP: 1}, logger)
	logger.mu.Lock()
	logger.infos = nil
	logger.mu.Unlock()
	first := newTestMockGnetConn()
	if _, action := handler.OnOpen(first); action != gnet.None {
		t.Fatalf("first OnOpen action = %v", action)
	}
	for range 50 {
		rejected := newTestMockGnetConn()
		if _, action := handler.OnOpen(rejected); action != gnet.Close {
			t.Fatalf("over-limit OnOpen action = %v", action)
		}
		handler.OnClose(rejected, nil)
	}
	logger.mu.Lock()
	infos := append([]string(nil), logger.infos...)
	logger.mu.Unlock()
	limitLines := 0
	for _, line := range infos {
		if strings.Contains(line, "per-IP connection limit") {
			limitLines++
		}
	}
	if limitLines < 1 || limitLines > 2 {
		t.Fatalf("per-IP limit Info lines = %d for 50 rejections, want 1 (2 across a second boundary)", limitLines)
	}
}

// A wall-clock step back must not silence the log until the clock catches up.
func TestLogRateLimitSurvivesClockStepBack(t *testing.T) {
	var limit logRateLimit
	if _, ok := limit.allow(10_000); !ok {
		t.Fatal("first line suppressed")
	}
	if _, ok := limit.allow(10_000 - 3600); !ok {
		t.Fatal("line suppressed after the clock stepped back one hour")
	}
}
