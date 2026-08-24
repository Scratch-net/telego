package webproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPServerRouteSessionEndToEnd(t *testing.T) {
	application := newHTTPTestApplication(t, 500*time.Millisecond)
	client := &http.Client{Timeout: 3 * time.Second}

	bridgeResponse := application.do(t, client, "GET", "/?bridge="+application.profiles[0].Capability().String(), nil, nil)
	bridgeBody := readHTTPBody(t, bridgeResponse)
	if bridgeResponse.StatusCode != 200 || bridgeResponse.Header.Get("Content-Security-Policy") == "" ||
		bridgeResponse.Header.Get("Permissions-Policy") != PermissionsPolicy ||
		bridgeResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("bridge response = %d, headers %#v", bridgeResponse.StatusCode, bridgeResponse.Header)
	}
	bootstrap := extractBridgeBootstrap(t, bridgeBody)

	hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})
	createResponse := application.do(t, client, "POST", "/api/v1/session", hello, map[string]string{
		"Authorization": "Bearer " + bootstrap,
		"Content-Type":  "application/octet-stream",
	})
	welcome := readHTTPBody(t, createResponse)
	if createResponse.StatusCode != 200 || createResponse.Header.Get("X-Carrier-Mode") != "https" ||
		createResponse.Header.Get("X-Down-Cursor") != "0" ||
		!bytes.Equal(welcome, testFrameBatch(t, Frame{Type: FrameWelcome})) {
		t.Fatalf("create response = %d %#v %x", createResponse.StatusCode, createResponse.Header, welcome)
	}
	sessionToken := createResponse.Header.Get("X-Session-Token")
	assertCanonicalToken(t, sessionToken)

	uplink := testFrameBatch(t,
		Frame{Type: FrameOpen, StreamID: 1},
		Frame{Type: FrameData, StreamID: 1, Payload: []byte("native-gnet")},
	)
	upResponse := application.do(t, client, "POST", "/api/v1/up", uplink, map[string]string{
		"Authorization": "Bearer " + sessionToken,
		"Content-Type":  "application/octet-stream",
		"X-Up-Seq":      "1",
	})
	_ = readHTTPBody(t, upResponse)
	if upResponse.StatusCode != 204 || upResponse.Header.Get("X-Up-Ack") != "1" {
		t.Fatalf("up response = %d %#v", upResponse.StatusCode, upResponse.Header)
	}

	foundEcho := false
	cursor := "0"
	for poll := 0; poll < 3 && !foundEcho; poll++ {
		downResponse := application.do(t, client, "POST", "/api/v1/down", nil, map[string]string{
			"Authorization": "Bearer " + sessionToken,
			"X-Down-Cursor": cursor,
		})
		downBody := readHTTPBody(t, downResponse)
		if downResponse.StatusCode != 200 {
			t.Fatalf("down response = %d %#v %x", downResponse.StatusCode, downResponse.Header, downBody)
		}
		cursor = downResponse.Header.Get("X-Down-Cursor")
		frames, parseErr := ParseBatch(downBody)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		for _, frame := range frames {
			if frame.Type == FrameData && frame.StreamID == 1 && bytes.Equal(frame.Payload, []byte("native-gnet")) {
				foundEcho = true
			}
		}
	}
	if !foundEcho {
		t.Fatal("downlink omitted echo DATA")
	}

	deleteResponse := application.do(t, client, "DELETE", "/api/v1/session", nil, map[string]string{
		"Authorization": "Bearer " + sessionToken,
	})
	_ = readHTTPBody(t, deleteResponse)
	if deleteResponse.StatusCode != 204 {
		t.Fatalf("delete response = %d", deleteResponse.StatusCode)
	}
}

func TestHTTPServerAuthenticatesBeforeReadingBody(t *testing.T) {
	application := newHTTPTestApplication(t, 200*time.Millisecond)
	connection, err := net.Dial("tcp", application.address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if tcpConnection, ok := connection.(*net.TCPConn); ok {
		if err := tcpConnection.SetNoDelay(true); err != nil {
			t.Fatal(err)
		}
	}
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	unknown, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	request := "POST /api/v1/up HTTP/1.1\r\n" +
		"Host: proxy.example.com\r\n" +
		"Authorization: Bearer " + unknown + "\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Length: 2097152\r\n" +
		"X-Up-Seq: 1\r\n\r\n"
	written, err := io.WriteString(connection, request)
	if err != nil {
		t.Fatal(err)
	}
	if written != len(request) {
		t.Fatalf("request write = %d, want %d", written, len(request))
	}
	status, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		t.Fatalf("server waited for unauthenticated body: %v", err)
	}
	if status != "HTTP/1.1 419 Fallback\r\n" {
		t.Fatalf("status = %q", status)
	}
}

func TestHTTPServerLongPollDoesNotBlockEventLoopAndNewestWins(t *testing.T) {
	application := newHTTPTestApplication(t, 600*time.Millisecond)
	created := createTestSession(t, application.manager, application.profiles[0])
	client := &http.Client{Timeout: 2 * time.Second}

	type pollResult struct {
		status int
		err    error
	}
	poll := func(ctx context.Context) <-chan pollResult {
		result := make(chan pollResult, 1)
		go func() {
			request, err := http.NewRequestWithContext(ctx, "POST", "http://"+application.address+"/api/v1/down", nil)
			if err != nil {
				result <- pollResult{err: err}
				return
			}
			request.Host = "proxy.example.com"
			request.Header.Set("Authorization", "Bearer "+created.Token)
			request.Header.Set("X-Down-Cursor", "0")
			response, err := client.Do(request)
			if err != nil {
				result <- pollResult{err: err}
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			result <- pollResult{status: response.StatusCode}
		}()
		return result
	}

	firstContext, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	first := poll(firstContext)
	waitForDownPoll(t, created.Session, true)

	started := time.Now()
	fallback := application.do(t, client, "GET", "/not-a-carrier", nil, nil)
	_ = readHTTPBody(t, fallback)
	if fallback.StatusCode != 418 {
		t.Fatalf("fallback status = %d", fallback.StatusCode)
	}
	if elapsed := time.Since(started); elapsed >= 300*time.Millisecond {
		t.Fatalf("parked poll blocked the event loop for %v", elapsed)
	}

	secondContext, cancelSecond := context.WithCancel(context.Background())
	second := poll(secondContext)
	select {
	case result := <-first:
		if result.err != nil || result.status != 204 {
			t.Fatalf("superseded poll = %#v", result)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("newest poll did not supersede the older poll")
	}
	waitForDownPoll(t, created.Session, true)
	cancelSecond()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("closed poll connection did not cancel the parked operation")
	}
	waitForDownPoll(t, created.Session, false)
}

func TestHTTPServerSequentialPipelinedRequests(t *testing.T) {
	application := newHTTPTestApplication(t, 200*time.Millisecond)
	capability := application.profiles[0].Capability().String()
	request := "GET /?bridge=" + capability + " HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n"
	connection, err := net.Dial("tcp", application.address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if tcpConnection, ok := connection.(*net.TCPConn); ok {
		if err := tcpConnection.SetNoDelay(true); err != nil {
			t.Fatal(err)
		}
	}
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(connection, request+request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	for index := 0; index < 2; index++ {
		response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
		if err != nil {
			t.Fatalf("response %d: %v", index, err)
		}
		body := readHTTPBody(t, response)
		if response.StatusCode != 200 || !bytes.Contains(body, []byte("TelegramWebProxy")) {
			t.Fatalf("response %d = %d, %d bytes", index, response.StatusCode, len(body))
		}
	}
}

func TestHTTPServerLifecycleAndConfiguration(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	for name, config := range map[string]HTTPServerConfig{
		"manager":              {Bind: "127.0.0.1:1", Hostname: "proxy.example.com"},
		"bind":                 {Manager: manager, Hostname: "proxy.example.com"},
		"Unix bind":            {Manager: manager, Bind: "unix:///run/telego-web.sock", Hostname: "proxy.example.com"},
		"UDP bind":             {Manager: manager, Bind: "udp://127.0.0.1:1", Hostname: "proxy.example.com"},
		"hostname":             {Manager: manager, Bind: "127.0.0.1:1", Hostname: "Proxy.example.com"},
		"passthrough sentinel": {Manager: manager, Bind: "127.0.0.1:1", Hostname: "proxy.example.com", PassthroughStatus: 503},
		"duplicate sentinels":  {Manager: manager, Bind: "127.0.0.1:1", Hostname: "proxy.example.com", PassthroughStatus: 418, SanitizedFallbackStatus: 418},
		"loops":                {Manager: manager, Bind: "127.0.0.1:1", Hostname: "proxy.example.com", NumEventLoop: -1},
		"socket send buffer":   {Manager: manager, Bind: "127.0.0.1:1", Hostname: "proxy.example.com", SocketSendBuffer: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHTTPServer(config); err == nil {
				t.Fatal("NewHTTPServer accepted invalid configuration")
			}
		})
	}

	application := newHTTPTestApplication(t, 100*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := application.server.Start(ctx); err != ErrHTTPServerStarted {
		t.Fatalf("second Start error = %v", err)
	}
	if err := application.server.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err, open := <-application.server.Errors(); open || err != nil {
		t.Fatalf("normal error channel result = %v, open %v", err, open)
	}
	if err := application.server.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestHTTPServerReportsBindFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	manager := testManager(t, testProfiles(t), nil, nil)
	server, err := NewHTTPServer(HTTPServerConfig{
		Bind:         listener.Addr().String(),
		Hostname:     "proxy.example.com",
		Manager:      manager,
		Multicore:    false,
		ReusePort:    false,
		NumEventLoop: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	startErr := server.Start(ctx)
	if startErr == nil {
		t.Fatal("Start succeeded on an occupied address")
	}
	reported, open := <-server.Errors()
	if !open || reported == nil {
		t.Fatalf("Errors result = %v, open %v", reported, open)
	}
	if _, open = <-server.Errors(); open {
		t.Fatal("Errors channel remained open after gnet exit")
	}
}

type httpTestApplication struct {
	server   *HTTPServer
	manager  *Manager
	profiles []Profile
	address  string
}

func newHTTPTestApplication(t *testing.T, longPoll time.Duration) *httpTestApplication {
	return newHTTPTestApplicationWithConfig(t, longPoll, nil, nil)
}

func newHTTPTestApplicationWithConfig(
	t *testing.T,
	longPoll time.Duration,
	mutateManager func(*ManagerConfig),
	mutateServer func(*HTTPServerConfig),
) *httpTestApplication {
	t.Helper()
	backend := startHTTPEchoBackend(t)
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Backend = backend
		config.Timeouts.LongPoll = longPoll
		if mutateManager != nil {
			mutateManager(config)
		}
	}, nil)
	address := unusedTCPAddress(t)
	serverConfig := HTTPServerConfig{
		Bind:         address,
		Hostname:     "proxy.example.com",
		Manager:      manager,
		NumEventLoop: 1,
	}
	if mutateServer != nil {
		mutateServer(&serverConfig)
	}
	server, err := NewHTTPServer(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopContext, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		if err := server.Stop(stopContext); err != nil {
			t.Errorf("HTTP server Stop: %v", err)
		}
	})
	return &httpTestApplication{server: server, manager: manager, profiles: profiles, address: address}
}

func (a *httpTestApplication) do(
	t *testing.T,
	client *http.Client,
	method, path string,
	body []byte,
	headers map[string]string,
) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, "http://"+a.address+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "proxy.example.com"
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readHTTPBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func extractBridgeBootstrap(t *testing.T, body []byte) string {
	t.Helper()
	const prefix = `bootstrap="`
	start := bytes.Index(body, []byte(prefix))
	if start < 0 {
		t.Fatal("bridge omitted bootstrap")
	}
	start += len(prefix)
	end := bytes.IndexByte(body[start:], '"')
	if end != capabilityLength {
		t.Fatalf("bridge bootstrap length = %d", end)
	}
	return string(body[start : start+end])
}

func unusedTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func startHTTPEchoBackend(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer connection.Close()
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-stopped
		connections.Wait()
	})
	return listener.Addr().String()
}

func waitForDownPoll(t *testing.T, session *Session, active bool) {
	t.Helper()
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return session.downActive == active
	})
}

func TestCarrierResponseEncoding(t *testing.T) {
	response := newCarrierResponse(200, []responseHeader{{"X-Test", "1"}}, []byte("body"))
	encoded := string(response.encoded())
	want := "HTTP/1.1 200 OK\r\nX-Test: 1\r\nContent-Length: 4\r\n\r\nbody"
	if encoded != want {
		t.Fatalf("encoded response = %q, want %q", encoded, want)
	}
	noContent := carrierResponse{status: 204, headers: []responseHeader{{"X-Down-Cursor", strconv.Itoa(0)}}}
	if strings.Contains(string(noContent.encoded()), "Content-Length") {
		t.Fatal("204 response included Content-Length")
	}
}
