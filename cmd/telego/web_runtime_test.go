package main

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/config"
	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/webproxy"
)

func testWebRuntimeConfig(t *testing.T, bind string) config.WebProxyRuntimeConfig {
	t.Helper()
	profiles, err := webproxy.DeriveProfiles("alice", "proxy.example.com", []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return config.WebProxyRuntimeConfig{
		Enabled:              true,
		BindAddr:             bind,
		Hostname:             "proxy.example.com",
		Backend:              "127.0.0.1:443",
		Profiles:             profiles[:],
		BackendProxyProtocol: true,
	}
}

func testInternalProxyAuth(t *testing.T) *gproxy.InternalProxyAuth {
	t.Helper()
	auth, err := gproxy.NewInternalProxyAuth()
	if err != nil {
		t.Fatalf("NewInternalProxyAuth: %v", err)
	}
	return auth
}

func TestNewWebProxyRuntimeDisabledHasNoRuntime(t *testing.T) {
	runtime, err := newWebProxyRuntime(config.WebProxyRuntimeConfig{}, nil, nil)
	if err != nil {
		t.Fatalf("newWebProxyRuntime: %v", err)
	}
	if runtime != nil {
		t.Fatalf("runtime = %#v, want nil", runtime)
	}
}

func TestNewWebProxyRuntimeRejectsInvalidEnabledConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.WebProxyRuntimeConfig)
	}{
		{
			name: "backend",
			mutate: func(runtimeConfig *config.WebProxyRuntimeConfig) {
				runtimeConfig.Backend = "192.0.2.1:443"
			},
		},
		{
			name: "trusted proxy",
			mutate: func(runtimeConfig *config.WebProxyRuntimeConfig) {
				runtimeConfig.TrustedProxyCIDRs = []string{"127.0.0.1/8"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtimeConfig := testWebRuntimeConfig(t, "127.0.0.1:0")
			test.mutate(&runtimeConfig)
			runtime, err := newWebProxyRuntime(runtimeConfig, testInternalProxyAuth(t), nil)
			if err == nil || runtime != nil {
				t.Fatalf("runtime = %#v, error = %v", runtime, err)
			}
		})
	}
}

func TestNewWebProxyRuntimeRequiresInternalAuthentication(t *testing.T) {
	runtime, err := newWebProxyRuntime(testWebRuntimeConfig(t, "127.0.0.1:0"), nil, nil)
	if err == nil || runtime != nil || !strings.Contains(err.Error(), "internal backend authentication is required") {
		t.Fatalf("runtime = %#v, error = %v", runtime, err)
	}
}

func TestWebProxyRuntimeStartAndShutdown(t *testing.T) {
	runtime, err := newWebProxyRuntime(testWebRuntimeConfig(t, "127.0.0.1:0"), testInternalProxyAuth(t), nil)
	if err != nil {
		t.Fatalf("newWebProxyRuntime: %v", err)
	}
	startContext, cancelStart := context.WithTimeout(context.Background(), 5*time.Second)
	if err := runtime.Start(startContext); err != nil {
		cancelStart()
		t.Fatalf("Start: %v", err)
	}
	cancelStart()

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := runtime.Shutdown(shutdownContext); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := runtime.Shutdown(shutdownContext); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

func TestWebProxyRuntimeReportsStartFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	runtime, err := newWebProxyRuntime(testWebRuntimeConfig(t, occupied.Addr().String()), testInternalProxyAuth(t), nil)
	if err != nil {
		t.Fatalf("newWebProxyRuntime: %v", err)
	}
	startContext, cancelStart := context.WithTimeout(context.Background(), 5*time.Second)
	err = runtime.Start(startContext)
	cancelStart()
	if err == nil || !strings.Contains(err.Error(), "start WEB HTTP server") {
		t.Fatalf("Start error = %v", err)
	}
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	_ = runtime.Shutdown(shutdownContext)
}

func TestBuildWebProxyLinks(t *testing.T) {
	links := buildWebProxyLinks("proxy.example.com", "dd0123456789abcdef0123456789abcdef")
	if links.Telegram != "tg://webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef" {
		t.Fatalf("Telegram link = %q", links.Telegram)
	}
	if links.HTTPS != "https://t.me/webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef" {
		t.Fatalf("HTTPS link = %q", links.HTTPS)
	}
}

func TestWebProxyBackendDialerPrependsValidatedClientIP(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	auth := testInternalProxyAuth(t)
	dialer := webProxyBackendDialer(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "unix" || address != "/run/telego.sock" {
			t.Fatalf("dial target = %q %q", network, address)
		}
		return client, nil
	}, auth)

	result := make(chan error, 1)
	go func() {
		connection, err := dialer(context.Background(), "unix", "/run/telego.sock", "198.51.100.7")
		if connection != nil {
			_ = connection.Close()
		}
		result <- err
	}()
	want := auth.AppendPreface(nil)
	want = append(want, "PROXY TCP4 198.51.100.7 127.0.0.1 0 0\r\n"...)
	header := make([]byte, len(want))
	_, err := io.ReadFull(server, header)
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if string(header) != string(want) {
		t.Fatal("backend preface or PROXY header differs")
	}
	if err := <-result; err != nil {
		t.Fatalf("dialer: %v", err)
	}
}

func TestInternalProxyHeaderIPv6AndInvalidInput(t *testing.T) {
	header, err := internalProxyHeader("2001:db8::7")
	if err != nil {
		t.Fatal(err)
	}
	if string(header) != "PROXY TCP6 2001:db8::7 ::1 0 0\r\n" {
		t.Fatalf("header = %q", header)
	}
	if _, err := internalProxyHeader("198.51.100.7 injected"); err == nil {
		t.Fatal("invalid client IP accepted")
	}
}
