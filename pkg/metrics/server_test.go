package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestMetricsRejectsInvalidPathsWithoutDiagnostics(t *testing.T) {
	for _, path := range []string{"metrics", "GET /metrics", "/metrics/{name}", "/metrics/%65xported", "/metrics\t"} {
		t.Run(path, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("invalid metrics path panicked instead of returning an error: %v", recovered)
				}
			}()
			server, err := NewServer(Config{BindAddr: "127.0.0.1:0", Path: path}, nil)
			if server != nil {
				t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
			}
			if err == nil || server != nil {
				t.Fatal("invalid metrics path created a server")
			}
		})
	}
}

func TestMetricsHTTPBoundsWithoutDiagnostics(t *testing.T) {
	server, err := NewServer(Config{BindAddr: "127.0.0.1:0", Path: "/custom-metrics"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	if server.diagnostics != nil {
		t.Fatal("HTTP bounds enabled diagnostics")
	}
	httpServer := server.httpServer
	if httpServer.ReadHeaderTimeout != 3*time.Second || httpServer.ReadTimeout != 5*time.Second ||
		httpServer.WriteTimeout != diagnosticsRequestTimeout || httpServer.IdleTimeout != 30*time.Second ||
		httpServer.MaxHeaderBytes != 8<<10 {
		t.Fatal("ordinary metrics server omitted the existing HTTP bounds")
	}
}

func TestMetricsStartReturnsOccupiedPortError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server := &Server{httpServer: &http.Server{Addr: listener.Addr().String()}}
	t.Cleanup(func() { _ = server.httpServer.Close() })
	if err := server.Start(); err == nil {
		t.Fatal("Start hid the occupied-port error")
	} else if op, ok := errors.AsType[*net.OpError](err); !ok || op.Op != "listen" {
		t.Fatalf("Start error = %v, want a listen error", err)
	}
}
