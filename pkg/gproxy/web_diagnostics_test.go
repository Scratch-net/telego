package gproxy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

type webDiagnosticTestLogger struct{ testLogger }

func (l *webDiagnosticTestLogger) Warn(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warnings = append(l.warnings, fmt.Sprintf(format, args...))
}

func TestWebStreamCloseDiagnosticsAreBoundedAndScoped(t *testing.T) {
	logger := &webDiagnosticTestLogger{}
	handler := NewProxyHandler(&Config{}, logger)
	for _, internal := range []bool{false, true} {
		conn := newTestMockGnetConn()
		ctx := NewConnContext()
		ctx.secret = &Secret{Name: "desktop"}
		ctx.internalProxyAuthenticated = internal
		ctx.webCloseReason.Store(webCloseIdle)
		conn.SetContext(ctx)
		handler.activeConns.Add(1)
		handler.OnClose(conn, nil)
		handler.OnClose(conn, nil)
	}
	logger.mu.Lock()
	warnings := append([]string(nil), logger.warnings...)
	logger.mu.Unlock()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "WEB proxy stream closed") || !strings.Contains(warnings[0], "reason=idle_timeout") {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	w := &webCloseDiagnosticWindow{}
	now := time.Now()
	for range 128 {
		if _, allowed := w.claim(now); !allowed {
			t.Fatal("premature report limit")
		}
	}
	if _, allowed := w.claim(now); allowed {
		t.Fatal("report limit not enforced")
	}
	if suppressed, allowed := w.claim(now.Add(time.Minute)); !allowed || suppressed != 1 {
		t.Fatalf("refill = %d, %v", suppressed, allowed)
	}
}
