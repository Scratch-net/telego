package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/webproxy"
)

func TestWebProxyRuntimeLogicalBackendStartsWithoutInternalPreface(t *testing.T) {
	config := testWebRuntimeConfig(t, "127.0.0.1:0")
	config.Backend = ""
	config.LogicalBackend = true
	config.BackendProxyProtocol = false
	config.MTProxyAddr = &net.TCPAddr{IP: net.IPv6zero, Port: 443}
	if runtime, err := newWebProxyRuntime(config, nil, nil); err == nil || runtime != nil {
		t.Fatal("logical runtime accepted a missing MTProxy core")
	}
	handler := gproxy.NewProxyHandler(&gproxy.Config{}, nil)
	runtime, err := newWebProxyRuntime(config, nil, handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Shutdown(ctx); err != nil {
			t.Errorf("logical runtime shutdown: %v", err)
		}
	})
	if err := runtime.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
}

type runtimeOwnerCapture struct {
	gnet.BuiltinEventEngine
	owner chan gnet.EventLoop
}

func (capture *runtimeOwnerCapture) OnOpen(conn gnet.Conn) ([]byte, gnet.Action) {
	capture.owner <- conn.EventLoop()
	return nil, gnet.None
}

func webRuntimeTestOwner(t *testing.T) gnet.EventLoop {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accepted.Close() })
	capture := &runtimeOwnerCapture{owner: make(chan gnet.EventLoop, 1)}
	engine, err := gnet.NewClient(capture)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	if _, err := engine.Enroll(accepted); err != nil {
		t.Fatal(err)
	}
	return <-capture.owner
}

func TestWebProxyLogicalFactoryCancellationDuringOwnerOpening(t *testing.T) {
	for _, cancelBeforeOpen := range []bool{true, false} {
		t.Run(map[bool]string{true: "cancel before owner opens", false: "successful callback cancels setup"}[cancelBeforeOpen], func(t *testing.T) {
			owner := webRuntimeTestOwner(t)
			releaseOwner := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(releaseOwner) })
			t.Cleanup(unblock)
			blocked := make(chan struct{})
			if err := owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
				close(blocked)
				<-releaseOwner
				return nil
			})); err != nil {
				t.Fatal(err)
			}
			<-blocked
			setup, cancel := context.WithCancel(t.Context())
			defer cancel()
			opened, closed := make(chan error, 1), make(chan error, 1)
			handler := gproxy.NewProxyHandler(&gproxy.Config{}, nil)
			factory := webProxyLogicalBackendFactory(handler, &net.TCPAddr{IP: net.IPv6zero, Port: 443})
			budget := webproxy.BackendBudget{Reserve: func(int, int) bool { return true }, Release: func(int, int) {}}
			backend, err := factory(webproxy.BackendOpenOptions{
				Context: setup, Owner: owner, ClientIP: "198.51.100.7",
				MaxInputBytes: 64 * 1024, MaxOutputBytes: 64 * 1024,
				MaxInputItems: 8, MaxOutputItems: 8, InputBudget: budget, OutputBudget: budget,
				Notify: func() {}, OnOpened: func(err error) { cancel(); opened <- err },
				OnClosed: func(err error) { closed <- err },
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = backend.Close() })
			if cancelBeforeOpen {
				cancel()
			}
			unblock()
			select {
			case err := <-opened:
				if cancelBeforeOpen && !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled opening = %v, want context cancellation", err)
				}
				if !cancelBeforeOpen && err != nil {
					t.Fatalf("successful opening = %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("logical opening did not finish")
			}
			if !cancelBeforeOpen {
				written := make(chan error, 1)
				if err := owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
					_, err := backend.TryWrite([]byte{1})
					written <- err
					return nil
				})); err != nil {
					t.Fatal(err)
				}
				if err := <-written; err != nil {
					t.Fatalf("setup cancellation closed an opened stream: %v", err)
				}
				_ = backend.Close()
			}
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("logical stream did not complete owner cleanup")
			}
		})
	}
}

type heldRuntimeBackend struct {
	options        webproxy.BackendOpenOptions
	closeRequested chan struct{}
	closeOnce      sync.Once
	finishOnce     sync.Once
}

func (*heldRuntimeBackend) TryRead([]byte) (int, error)  { return 0, nil }
func (*heldRuntimeBackend) TryWrite([]byte) (int, error) { return 0, nil }
func (backend *heldRuntimeBackend) Close() error {
	backend.closeOnce.Do(func() { close(backend.closeRequested) })
	return nil
}
func (backend *heldRuntimeBackend) finish() {
	backend.finishOnce.Do(func() { backend.options.OnClosed(io.EOF) })
}

func newHeldWebRuntime(t *testing.T) (*webProxyRuntime, *heldRuntimeBackend) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	runtimeConfig := testWebRuntimeConfig(t, address)
	managerConfig := webproxy.DefaultManagerConfig(runtimeConfig.Profiles, "")
	var held atomic.Pointer[heldRuntimeBackend]
	created := make(chan *heldRuntimeBackend, 1)
	managerConfig.BackendFactory = func(options webproxy.BackendOpenOptions) (webproxy.Backend, error) {
		backend := &heldRuntimeBackend{options: options, closeRequested: make(chan struct{})}
		held.Store(backend)
		options.OnOpened(nil)
		created <- backend
		return backend, nil
	}
	manager, err := webproxy.NewManager(managerConfig)
	if err != nil {
		t.Fatal(err)
	}
	server, err := webproxy.NewHTTPServer(webproxy.HTTPServerConfig{Bind: address, Hostname: runtimeConfig.Hostname, Manager: manager})
	if err != nil {
		_ = manager.Shutdown(t.Context())
		t.Fatal(err)
	}
	runtime := &webProxyRuntime{manager: manager, server: server}
	t.Cleanup(func() {
		if backend := held.Load(); backend != nil {
			backend.finish()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Shutdown(ctx); err != nil {
			t.Errorf("cleanup WEB runtime: %v", err)
		}
	})
	if err := runtime.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := manager.IssueBootstrap(runtimeConfig.Profiles[0].Capability(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	hello, err := webproxy.EncodeFrame(webproxy.Frame{Type: webproxy.FrameHello, Payload: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	response := postWebRuntimeTest(t, address, runtimeConfig.Hostname, "/api/v1/session", bootstrap, hello, false)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CREATE status = %d", response.StatusCode)
	}
	token := response.Header.Get("X-Session-Token")
	open, err := webproxy.EncodeFrame(webproxy.Frame{Type: webproxy.FrameOpen, StreamID: 1})
	if err != nil {
		t.Fatal(err)
	}
	response = postWebRuntimeTest(t, address, runtimeConfig.Hostname, "/api/v1/up", token, open, true)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("UP status = %d", response.StatusCode)
	}
	var backend *heldRuntimeBackend
	select {
	case backend = <-created:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime backend was not opened")
	}
	return runtime, backend
}

func TestWebProxyRuntimeShutdownTimeoutKeepsOwnerUntilCleanup(t *testing.T) {
	runtime, backend := newHeldWebRuntime(t)
	short, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	err := runtime.Shutdown(short)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown with held cleanup = %v, want deadline", err)
	}
	select {
	case <-backend.closeRequested:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not request backend close")
	}
	ownerRan := make(chan struct{})
	if err := backend.options.Owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		backend.finish()
		close(ownerRan)
		return nil
	})); err != nil {
		t.Fatalf("shutdown stopped the owner before cleanup: %v", err)
	}
	select {
	case <-ownerRan:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP owner did not remain alive for backend cleanup")
	}
	retry, cancelRetry := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelRetry()
	if err := runtime.Shutdown(retry); err != nil {
		t.Fatalf("shutdown retry after owner cleanup: %v", err)
	}
	if capacity := runtime.manager.Capacity(); capacity.Streams != 0 || capacity.BackendDials != 0 {
		t.Fatalf("shutdown retained backend resources: %+v", capacity)
	}
}

func TestShutdownProxyServicesWaitsForWEBBeforeStoppingDependencies(t *testing.T) {
	runtime, backend := newHeldWebRuntime(t)
	stopped := make(chan string, 2)
	done := make(chan struct{})
	go func() {
		shutdownProxyServices(runtime,
			func() { stopped <- "public and DC" },
			func() { stopped <- "Middle-End" },
			30*time.Millisecond)
		close(done)
	}()
	select {
	case <-backend.closeRequested:
	case <-time.After(5 * time.Second):
		t.Fatal("parent shutdown did not request WEB backend cleanup")
	}
	select {
	case dependency := <-stopped:
		t.Fatalf("parent stopped %s before WEB cleanup completed", dependency)
	case <-time.After(100 * time.Millisecond):
	}
	if err := backend.options.Owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		backend.finish()
		return nil
	})); err != nil {
		t.Fatalf("parent stopped the WEB owner before backend cleanup: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("parent shutdown did not finish after WEB cleanup")
	}
	if first, second := <-stopped, <-stopped; first != "public and DC" || second != "Middle-End" {
		t.Fatalf("dependency shutdown order = %q then %q", first, second)
	}
	if capacity := runtime.manager.Capacity(); capacity.Streams != 0 || capacity.BackendDials != 0 {
		t.Fatalf("parent shutdown retained WEB backend resources: %+v", capacity)
	}
}

func postWebRuntimeTest(t *testing.T, address, hostname, path, token string, body []byte, uplink bool) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+address+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = hostname
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/octet-stream")
	if uplink {
		request.Header.Set("X-Up-Seq", "1")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response
}
