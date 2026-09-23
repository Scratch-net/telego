package gproxy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

type webDiagnosticTestLogger struct {
	testLogger
	debug bool
}

func (l *webDiagnosticTestLogger) DebugEnabled() bool { return l.debug }

func (l *webDiagnosticTestLogger) Debug(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugs = append(l.debugs, fmt.Sprintf(format, args...))
}

func TestWebStreamCloseDiagnosticsAreBoundedAndScoped(t *testing.T) {
	for _, debug := range []bool{false, true} {
		logger := &webDiagnosticTestLogger{debug: debug}
		handler := NewProxyHandler(&Config{}, logger)
		for _, internal := range []bool{false, true} {
			conn := newTestMockGnetConn()
			ctx := NewConnContext()
			ctx.secret = &Secret{Name: "desktop"}
			ctx.internalProxyAuthenticated = internal
			ctx.webDiagnostics = debug
			ctx.noteWebClose(webCloseIdle)
			if !debug && ctx.webCloseReason.Load() != 0 {
				t.Fatal("disabled diagnostics recorded a close reason")
			}
			conn.SetContext(ctx)
			handler.activeConns.Add(1)
			handler.OnClose(conn, nil)
			handler.OnClose(conn, nil)
		}
		logger.mu.Lock()
		debugs := append([]string(nil), logger.debugs...)
		warnings := len(logger.warnings)
		logger.mu.Unlock()
		var reports []string
		for _, message := range debugs {
			if strings.Contains(message, "WEB proxy stream closed") {
				reports = append(reports, message)
			}
		}
		if warnings != 0 {
			t.Fatalf("debug=%v: diagnostic reached warning level", debug)
		}
		if debug {
			if len(reports) != 1 || !strings.Contains(reports[0], "reason=idle_timeout") {
				t.Fatalf("unexpected reports: %v", reports)
			}
		} else if len(reports) != 0 || !handler.webCloseDiagnostics.start.IsZero() {
			t.Fatalf("disabled diagnostics logged or consumed allowance: %v", reports)
		}
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
