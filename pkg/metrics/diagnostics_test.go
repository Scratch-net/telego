package metrics

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

func diagnosticsTestRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090"+path, nil)
	request.RemoteAddr = "127.0.0.1:49152"
	return request
}

func diagnosticsTestMux(t *testing.T) (*diagnostics, *http.ServeMux) {
	t.Helper()
	d := newDiagnostics()
	t.Cleanup(d.cancel)
	mux := http.NewServeMux()
	d.register(mux)
	return d, mux
}

func TestDiagnosticsPrivateBindAndReservedPaths(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9090", "[::1]:9090"} {
		if err := validateDiagnosticsConfig(Config{BindAddr: address, Diagnostics: true}); err != nil {
			t.Fatalf("private bind %s: %v", address, err)
		}
	}
	for _, address := range []string{"", ":9090", "0.0.0.0:9090", "[::]:9090", "192.0.2.1:9090", "localhost:9090", "127.0.0.1:0", "127.0.0.1:65536", "[::1%lo]:9090"} {
		if server, err := NewServer(Config{BindAddr: address, Diagnostics: true}, nil); err == nil || server != nil {
			t.Fatalf("unsafe bind %q created a server", address)
		}
		if err := validateDiagnosticsConfig(Config{BindAddr: address}); err != nil {
			t.Fatalf("disabled diagnostics changed legacy bind handling: %v", err)
		}
	}
	for _, path := range []string{"/debug/pprof", "/debug/pprof/", "/debug/pprof/heap", "/debug/%70prof/", "/%64ebug/pprof/heap", "/metrics/{name}", "GET /metrics", "metrics"} {
		if server, err := NewServer(Config{BindAddr: "127.0.0.1:9090", Path: path, Diagnostics: true}, nil); err == nil || server != nil {
			t.Fatalf("reserved or invalid path %q created a server", path)
		}
	}
}

func TestDiagnosticsDisabledAndPrivateMux(t *testing.T) {
	server, err := NewServer(Config{BindAddr: "127.0.0.1:9090"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	if server.diagnostics != nil {
		t.Fatal("diagnostics enabled by default")
	}
	for _, path := range []string{"/debug/pprof/heap", "/debug/pprof/profile", "/debug/pprof/goroutineleak"} {
		response := httptest.NewRecorder()
		server.httpServer.Handler.ServeHTTP(response, diagnosticsTestRequest(path))
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled route %s returned %d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(response, diagnosticsTestRequest("/debug/pprof/heap"))
	if response.Code != http.StatusNotFound {
		t.Fatal("diagnostics modified the default mux")
	}
}

func TestDiagnosticsAllowlistAndRequestGuards(t *testing.T) {
	_, mux := diagnosticsTestMux(t)
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/symbol", "/debug/pprof/trace", "/debug/pprof/block", "/debug/pprof/mutex", "/debug/pprof/threadcreate", "/debug/pprof/goroutineleak/extra"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, diagnosticsTestRequest(path))
		if response.Code != http.StatusNotFound {
			t.Errorf("unlisted profile %s returned %d", path, response.Code)
		}
	}
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{name: "public host", change: func(r *http.Request) { r.Host = "example.com:9090" }, status: http.StatusForbidden},
		{name: "DNS host", change: func(r *http.Request) { r.Host = "localhost:9090" }, status: http.StatusForbidden},
		{name: "public peer", change: func(r *http.Request) { r.RemoteAddr = "192.0.2.1:1234" }, status: http.StatusForbidden},
		{name: "head", change: func(r *http.Request) { r.Method = http.MethodHead }, status: http.StatusMethodNotAllowed},
		{name: "body", change: func(r *http.Request) { r.ContentLength = 1 }, status: http.StatusBadRequest},
		{name: "streaming body", change: func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, status: http.StatusBadRequest},
		{name: "long query", change: func(r *http.Request) { r.URL.RawQuery = strings.Repeat("x", 129) }, status: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := diagnosticsTestRequest("/debug/pprof/heap")
			test.change(request)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d, want %d", response.Code, test.status)
			}
		})
	}
}

func TestDiagnosticsQueryBounds(t *testing.T) {
	for _, test := range []struct {
		name, query string
		seconds     int
	}{
		{name: "profile", seconds: 10}, {name: "profile", query: "seconds=1", seconds: 1},
		{name: "profile", query: "seconds=15", seconds: 15}, {name: "goroutineleak", query: "debug=1", seconds: 10},
		{name: "heap", query: "debug=0", seconds: 10},
	} {
		if seconds, err := diagnosticsQuery(test.name, test.query); err != nil || seconds != test.seconds {
			t.Fatalf("%s?%s: seconds=%d err=%v", test.name, test.query, seconds, err)
		}
	}
	for _, test := range []struct{ name, query string }{
		{"profile", "seconds=0"}, {"profile", "seconds=16"}, {"profile", "seconds=-1"}, {"profile", "seconds=NaN"},
		{"profile", "seconds=1&seconds=2"}, {"profile", "debug=0"}, {"heap", "gc=1"},
		{"heap", "seconds=1"}, {"heap", "debug=1"}, {"goroutine", "debug=2"},
		{"goroutineleak", "debug=0"}, {"goroutineleak", "debug=2"}, {"goroutineleak", "cache=1"}, {"heap", "%zz"},
	} {
		if _, err := diagnosticsQuery(test.name, test.query); err == nil {
			t.Errorf("unsupported query %s?%s accepted", test.name, test.query)
		}
	}
}

func TestDiagnosticsProfilesAreFreshAndBinary(t *testing.T) {
	_, mux := diagnosticsTestMux(t)
	for _, name := range []string{"goroutineleak", "goroutineleak", "heap", "allocs", "goroutine", "profile?seconds=1"} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, diagnosticsTestRequest(diagnosticsPrefix+name))
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: status=%d, body=%s", name, response.Code, response.Body.String())
		}
		if name == "goroutineleak" {
			if !strings.HasPrefix(response.Body.String(), "goroutineleak profile: total ") {
				t.Fatal("leak endpoint did not return the filtered debug1 profile")
			}
			continue
		}
		reader, err := gzip.NewReader(bytes.NewReader(response.Body.Bytes()))
		if err != nil {
			t.Fatalf("%s is not a binary pprof response: %v", name, err)
		}
		payload, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil || len(payload) == 0 {
			t.Fatalf("%s returned an invalid gzip payload: %v", name, err)
		}
	}
}

func awaitDiagnosticsCollection(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for diagnosticsCollection.TryLock() {
		diagnosticsCollection.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("profile collection did not start")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDiagnosticsRejectConcurrentCollectionAndCancelCPU(t *testing.T) {
	_, mux := diagnosticsTestMux(t)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	request := diagnosticsTestRequest("/debug/pprof/profile?seconds=15").WithContext(ctx)
	first := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); mux.ServeHTTP(first, request) }()
	awaitDiagnosticsCollection(t)
	second := httptest.NewRecorder()
	mux.ServeHTTP(second, diagnosticsTestRequest("/debug/pprof/goroutineleak"))
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("concurrent profile returned %d", second.Code)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("canceled CPU profile retained its handler")
	}
	if first.Code != http.StatusServiceUnavailable {
		t.Fatalf("canceled profile returned %d", first.Code)
	}
	if err := pprof.StartCPUProfile(io.Discard); err != nil {
		t.Fatalf("CPU profiler remained active after cancellation: %v", err)
	}
	pprof.StopCPUProfile()
}

func TestDiagnosticsOutputLimit(t *testing.T) {
	buffer := &diagnosticsBuffer{ctx: t.Context()}
	if n, err := buffer.Write(make([]byte, diagnosticsMaxBytes)); n != diagnosticsMaxBytes || err != nil {
		t.Fatal("response limit rejected exact capacity")
	}
	if n, err := buffer.Write([]byte{1}); n != 0 || !errors.Is(err, errDiagnosticsTooLarge) {
		t.Fatal("oversized response was accepted")
	}
	if len(buffer.data) != diagnosticsMaxBytes || cap(buffer.data) > diagnosticsMaxBytes {
		t.Fatal("profile buffer exceeded its byte limit")
	}
}

func TestDiagnosticsShutdownCancelsActiveCPUProfile(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	server, err := NewServer(Config{BindAddr: listener.Addr().String(), Path: "/", Diagnostics: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	if server.httpServer.ReadHeaderTimeout == 0 || server.httpServer.WriteTimeout < 15*time.Second || server.httpServer.MaxHeaderBytes > 8<<10 {
		t.Fatal("diagnostics HTTP bounds are absent")
	}
	served := make(chan error, 1)
	go func() { served <- server.httpServer.Serve(listener) }()
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	result := make(chan error, 1)
	go func() {
		response, err := client.Get("http://" + listener.Addr().String() + "/debug/pprof/profile?seconds=15")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			err = response.Body.Close()
		}
		result <- err
	}()
	awaitDiagnosticsCollection(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("metrics Serve result: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, diagnosticsTestRequest("/debug/pprof/heap"))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("shutdown accepted another profile")
	}
	if err := pprof.StartCPUProfile(io.Discard); err != nil {
		t.Fatalf("shutdown retained CPU profiler: %v", err)
	}
	pprof.StopCPUProfile()
}
