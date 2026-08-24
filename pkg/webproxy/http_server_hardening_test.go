package webproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHTTPServerFallbackClassesAndBridgeCookie(t *testing.T) {
	application := newHTTPTestApplication(t, 100*time.Millisecond)
	client := &http.Client{Timeout: 2 * time.Second}
	unknown, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	capability := application.profiles[0].Capability().String()

	for name, test := range map[string]struct {
		method  string
		path    string
		body    []byte
		headers map[string]string
	}{
		"ordinary query":                    {method: "GET", path: "/public?bridge=" + capability + "&site=1"},
		"ordinary cookie":                   {method: "GET", path: "/", headers: map[string]string{"Cookie": "site=value"}},
		"ordinary body":                     {method: "POST", path: "/submit?site=1", body: []byte("site-body"), headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Cookie": "site=value", "X-Site": "kept"}},
		"ordinary Basic":                    {method: "GET", path: "/private", headers: map[string]string{"Authorization": "Basic Zm9vOmJhcg=="}},
		"ordinary JWT":                      {method: "GET", path: "/private", headers: map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzaXRlIn0.signature"}},
		"WEB bearer without marker":         {method: "GET", path: "/private", headers: map[string]string{"Authorization": "Bearer " + unknown}},
		"carrier header without WEB bearer": {method: "GET", path: "/private", headers: map[string]string{"X-Down-Cursor": "0"}},
	} {
		t.Run(name, func(t *testing.T) {
			response := application.do(t, client, test.method, test.path, test.body, test.headers)
			_ = readHTTPBody(t, response)
			if response.StatusCode != defaultPassthroughStatus ||
				response.Header.Get(FallbackClassificationHeader) != FallbackOrdinarySite || !response.Close {
				t.Fatalf("fallback = %d, headers %#v, close %v", response.StatusCode, response.Header, response.Close)
			}
		})
	}
	for name, test := range map[string]struct {
		path    string
		headers map[string]string
	}{
		"root bridge parameter":                    {path: "/?site=1&bridge=" + capability},
		"arbitrary path reserved carrier metadata": {path: "/downloads/archive?site=1", headers: map[string]string{"Authorization": "Bearer " + unknown, "X-Down-Cursor": "0"}},
		"API cookie": {path: "/api/v1/down", headers: map[string]string{"Authorization": "Bearer " + unknown, "X-Down-Cursor": "0", "Cookie": "secret=value"}},
	} {
		t.Run(name, func(t *testing.T) {
			response := application.do(t, client, "POST", test.path, nil, test.headers)
			_ = readHTTPBody(t, response)
			if response.StatusCode != defaultSanitizedFallbackStatus ||
				response.Header.Get(FallbackClassificationHeader) != FallbackSanitizedPublic || !response.Close {
				t.Fatalf("sanitized fallback = %d, headers %#v, close %v", response.StatusCode, response.Header, response.Close)
			}
		})
	}

	bridge := application.do(t, client, "GET", "/?bridge="+capability, nil, map[string]string{"Cookie": "site=value"})
	_ = readHTTPBody(t, bridge)
	if bridge.StatusCode != 200 || bridge.Header.Get(FallbackClassificationHeader) != "" {
		t.Fatalf("cookie bridge = %d, headers %#v", bridge.StatusCode, bridge.Header)
	}
	for _, value := range []string{"GET $uri", "no request body", "Host from $http_host", "Authorization", "Cookie", "X-Up-Seq", "X-Down-Cursor", "X-Session-Token", "Forwarded", "Connection", "Upgrade"} {
		if !strings.Contains(NginxSanitizedFallback, value) {
			t.Errorf("sanitized fallback contract omitted %q", value)
		}
	}
	for _, value := range []string{"every public TLS request", "client_max_body_size", "public-site policy", "at least 2 MiB", "proxy_request_buffering on", "original method", "$request_uri including args", "buffered request body", "Host from $http_host", "Cookie", "Authorization", "Forwarded", "X-Forwarded-For", "Connection", "Upgrade", "all site request headers"} {
		if !strings.Contains(NginxPassthroughFallback, value) {
			t.Errorf("passthrough fallback contract omitted %q", value)
		}
	}
}

func TestHTTPServerLargeOrdinaryUploadFallsThroughWithoutReadingBody(t *testing.T) {
	application := newHTTPTestApplication(t, 100*time.Millisecond)
	for _, length := range []string{"2097153", "18446744073709551615"} {
		t.Run(length, func(t *testing.T) {
			connection := dialHTTPTest(t, application.address)
			defer connection.Close()
			raw := "POST /upload?site=1 HTTP/1.1\r\nHost: proxy.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: " + length + "\r\nCookie: site=value\r\nX-Site: kept\r\n\r\n"
			if _, err := io.WriteString(connection, raw); err != nil {
				t.Fatal(err)
			}
			if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: "POST"})
			if err != nil {
				t.Fatalf("server waited for %s-byte ordinary body: %v", length, err)
			}
			_ = readHTTPBody(t, response)
			if response.StatusCode != defaultPassthroughStatus ||
				response.Header.Get(FallbackClassificationHeader) != FallbackOrdinarySite || !response.Close {
				t.Fatalf("large upload fallback = %d, headers %#v, close %v", response.StatusCode, response.Header, response.Close)
			}
		})
	}
	connection := dialHTTPTest(t, application.address)
	defer connection.Close()
	carrier := "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\nContent-Type: application/octet-stream\r\nContent-Length: 2097153\r\nX-Up-Seq: 1\r\n\r\n"
	if _, err := io.WriteString(connection, carrier); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	_ = readHTTPBody(t, response)
	if response.StatusCode != defaultSanitizedFallbackStatus || response.Header.Get(FallbackClassificationHeader) != FallbackSanitizedPublic {
		t.Fatalf("oversized carrier fallback = %d, headers %#v", response.StatusCode, response.Header)
	}
}

func TestHTTPServerMatchedCarrierPressureNeverFallsThrough(t *testing.T) {
	t.Run("bridge", func(t *testing.T) {
		application := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(config *ManagerConfig) {
			config.Limits.MaxBootstraps = 1
		}, nil)
		_ = createTestSession(t, application.manager, application.profiles[0])
		response := application.do(t, &http.Client{Timeout: time.Second}, "GET", "/?bridge="+application.profiles[0].Capability().String(), nil, nil)
		_ = readHTTPBody(t, response)
		if response.StatusCode != 503 || response.Header.Get("Retry-After") != "1" || response.Header.Get(FallbackClassificationHeader) != "" {
			t.Fatalf("bridge pressure = %d, headers %#v", response.StatusCode, response.Header)
		}
	})

	t.Run("create", func(t *testing.T) {
		application := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, func(config *ManagerConfig) {
			config.Limits.MaxSessions = 1
		}, nil)
		_ = createTestSession(t, application.manager, application.profiles[0])
		bootstrap, err := application.manager.IssueBootstrap(application.profiles[0].Capability(), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})
		response := application.do(t, &http.Client{Timeout: time.Second}, "POST", "/api/v1/session", hello, map[string]string{
			"Authorization": "Bearer " + bootstrap,
			"Content-Type":  "application/octet-stream",
		})
		_ = readHTTPBody(t, response)
		if response.StatusCode != 503 || response.Header.Get("Retry-After") != "1" || response.Header.Get(FallbackClassificationHeader) != "" {
			t.Fatalf("create pressure = %d, headers %#v", response.StatusCode, response.Header)
		}
	})
}

func TestHTTPServerUpgradeFallbackClassification(t *testing.T) {
	application := newHTTPTestApplication(t, 100*time.Millisecond)
	for name, test := range map[string]struct {
		target         string
		extra          string
		status         int
		classification string
	}{
		"ordinary": {
			target: "/socket?site=1", extra: "Cookie: site=value\r\nX-Site: kept\r\n",
			status: defaultPassthroughStatus, classification: FallbackOrdinarySite,
		},
		"ordinary Basic authorization": {
			target: "/socket", extra: "Authorization: Basic Zm9vOmJhcg==\r\n",
			status: defaultPassthroughStatus, classification: FallbackOrdinarySite,
		},
		"ordinary JWT authorization": {
			target: "/socket", extra: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzaXRlIn0.signature\r\n",
			status: defaultPassthroughStatus, classification: FallbackOrdinarySite,
		},
		"ordinary canonical bearer alone": {
			target: "/socket", extra: "Authorization: Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n",
			status: defaultPassthroughStatus, classification: FallbackOrdinarySite,
		},
		"corroborated WEB bearer": {
			target: "/socket", extra: "Authorization: Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\nX-Down-Cursor: 0\r\n",
			status: defaultSanitizedFallbackStatus, classification: FallbackSanitizedPublic,
		},
		"carrier": {
			target: "/api/v1/down", extra: "Authorization: Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\nX-Down-Cursor: 0\r\n",
			status: defaultSanitizedFallbackStatus, classification: FallbackSanitizedPublic,
		},
	} {
		t.Run(name, func(t *testing.T) {
			connection := dialHTTPTest(t, application.address)
			defer connection.Close()
			raw := "GET " + test.target + " HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" + test.extra + "\r\n"
			if _, err := io.WriteString(connection, raw); err != nil {
				t.Fatal(err)
			}
			if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: "GET"})
			if err != nil {
				t.Fatal(err)
			}
			_ = readHTTPBody(t, response)
			if response.StatusCode != test.status || response.Header.Get(FallbackClassificationHeader) != test.classification {
				t.Fatalf("upgrade fallback = %d, headers %#v", response.StatusCode, response.Header)
			}
		})
	}
}

func TestHTTPServerMatchedBridgeRenderErrorNeverFallsThrough(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	address := unusedTCPAddress(t)
	server, err := NewHTTPServer(HTTPServerConfig{
		Bind:         address,
		Hostname:     "proxy.example.com",
		Manager:      manager,
		NumEventLoop: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	server.renderBridge = func(string, string, int) (BridgePage, error) {
		return BridgePage{}, errors.New("injected render failure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopContext, stopCancel := context.WithTimeout(context.Background(), time.Second)
		defer stopCancel()
		if err := server.Stop(stopContext); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	application := &httpTestApplication{server: server, manager: manager, profiles: profiles, address: address}
	response := application.do(t, &http.Client{Timeout: time.Second}, "GET", "/?bridge="+profiles[0].Capability().String(), nil, nil)
	_ = readHTTPBody(t, response)
	if response.StatusCode != 500 || response.Header.Get(FallbackClassificationHeader) != "" {
		t.Fatalf("render error = %d, headers %#v", response.StatusCode, response.Header)
	}
}

func TestHTTPServerTrustedForwardedIPIsSingleCanonicalAddress(t *testing.T) {
	trusted := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, nil, func(config *HTTPServerConfig) {
		config.TrustedProxyCIDRs = []string{"127.0.0.1/32"}
	})
	client := &http.Client{Timeout: time.Second}
	response := trusted.do(t, client, "GET", "/?bridge="+trusted.profiles[0].Capability().String(), nil, map[string]string{"X-Forwarded-For": "192.0.2.44"})
	token := extractBridgeBootstrap(t, readHTTPBody(t, response))
	hash, err := parseTokenHash(token)
	if err != nil {
		t.Fatal(err)
	}
	trusted.manager.mu.Lock()
	issuanceIP := trusted.manager.bootstraps[hash].issuanceIP
	trusted.manager.mu.Unlock()
	if response.StatusCode != 200 || issuanceIP != "192.0.2.44" {
		t.Fatalf("forwarded response = %d, issuance IP %q", response.StatusCode, issuanceIP)
	}

	for _, value := range []string{"192.0.2.1, 192.0.2.2", "192.0.002.1"} {
		response = trusted.do(t, client, "GET", "/?bridge="+trusted.profiles[0].Capability().String(), nil, map[string]string{"X-Forwarded-For": value})
		_ = readHTTPBody(t, response)
		if response.StatusCode != defaultSanitizedFallbackStatus {
			t.Fatalf("forwarded %q status = %d", value, response.StatusCode)
		}
	}

	untrusted := newHTTPTestApplication(t, 100*time.Millisecond)
	response = untrusted.do(t, client, "GET", "/?bridge="+untrusted.profiles[0].Capability().String(), nil, map[string]string{"X-Forwarded-For": "192.0.2.1"})
	_ = readHTTPBody(t, response)
	if response.StatusCode != defaultSanitizedFallbackStatus {
		t.Fatalf("untrusted forwarded status = %d", response.StatusCode)
	}
}

func TestHTTPServerFragmentedBodyAndPipelineLimit(t *testing.T) {
	t.Run("body", func(t *testing.T) {
		application := newHTTPTestApplication(t, 100*time.Millisecond)
		bootstrap, err := application.manager.IssueBootstrap(application.profiles[0].Capability(), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})
		connection := dialHTTPTest(t, application.address)
		defer connection.Close()
		header := "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + bootstrap + "\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(len(hello)) + "\r\n\r\n"
		if _, err := io.WriteString(connection, header); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Write(hello[:3]); err != nil {
			t.Fatal(err)
		}
		if err := connection.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		var one [1]byte
		if _, err := connection.Read(one[:]); err == nil {
			t.Fatal("server replied before receiving the complete body")
		}
		if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Write(hello[3:]); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: "POST"})
		if err != nil {
			t.Fatal(err)
		}
		_ = readHTTPBody(t, response)
		if response.StatusCode != 200 {
			t.Fatalf("fragmented body status = %d", response.StatusCode)
		}
	})

	t.Run("pipeline overflow", func(t *testing.T) {
		application := newHTTPTestApplication(t, 2*time.Second)
		created := createTestSession(t, application.manager, application.profiles[0])
		connection := dialHTTPTest(t, application.address)
		defer connection.Close()
		request := "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + created.Token + "\r\nX-Down-Cursor: 0\r\nContent-Length: 0\r\n\r\n"
		if _, err := io.WriteString(connection, request); err != nil {
			t.Fatal(err)
		}
		waitForDownPoll(t, created.Session, true)
		if _, err := io.WriteString(connection, strings.Repeat("X", maxPipelineBytes+1)); err != nil {
			t.Fatal(err)
		}
		expectConnectionClosed(t, connection, time.Second)
		waitForDownPoll(t, created.Session, false)
	})
}

func TestHTTPServerHeaderBodyIdleDeadlinesAndParkedPollExtension(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 140*time.Millisecond, nil, func(config *HTTPServerConfig) {
		config.HeaderTimeout = 45 * time.Millisecond
		config.BodyTimeout = 45 * time.Millisecond
		config.IdleTimeout = 55 * time.Millisecond
		config.WriteTimeout = time.Second
	})

	t.Run("fragmented header", func(t *testing.T) {
		connection := dialHTTPTest(t, application.address)
		defer connection.Close()
		if _, err := io.WriteString(connection, "GET / HTTP/1.1\r\nHo"); err != nil {
			t.Fatal(err)
		}
		expectConnectionClosed(t, connection, 500*time.Millisecond)
	})

	t.Run("fragmented body", func(t *testing.T) {
		bootstrap, err := application.manager.IssueBootstrap(application.profiles[0].Capability(), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})
		connection := dialHTTPTest(t, application.address)
		defer connection.Close()
		header := "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + bootstrap + "\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(len(hello)) + "\r\n\r\n"
		if _, err := io.WriteString(connection, header); err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Write(hello[:1]); err != nil {
			t.Fatal(err)
		}
		expectConnectionClosed(t, connection, 500*time.Millisecond)
	})

	t.Run("idle keepalive", func(t *testing.T) {
		connection := dialHTTPTest(t, application.address)
		defer connection.Close()
		request := "GET /?bridge=" + application.profiles[0].Capability().String() + " HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n"
		if _, err := io.WriteString(connection, request); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: "GET"})
		if err != nil {
			t.Fatal(err)
		}
		_ = readHTTPBody(t, response)
		expectConnectionClosed(t, connection, 500*time.Millisecond)
	})

	t.Run("parked poll", func(t *testing.T) {
		created := createTestSession(t, application.manager, application.profiles[0])
		started := time.Now()
		response := application.do(t, &http.Client{Timeout: time.Second}, "POST", "/api/v1/down", nil, map[string]string{
			"Authorization": "Bearer " + created.Token,
			"X-Down-Cursor": "0",
		})
		_ = readHTTPBody(t, response)
		if response.StatusCode != 204 || time.Since(started) < 100*time.Millisecond {
			t.Fatalf("parked poll = %d after %v", response.StatusCode, time.Since(started))
		}
	})
}

func TestHTTPServerStaleHeaderDeadlineCannotCloseNextPhase(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, 100*time.Millisecond, nil, func(config *HTTPServerConfig) {
		config.HeaderTimeout = 30 * time.Millisecond
		config.BodyTimeout = time.Second
		config.WriteTimeout = time.Second
	})
	bootstrap, err := application.manager.IssueBootstrap(application.profiles[0].Capability(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})
	connection := dialHTTPTest(t, application.address)
	defer connection.Close()
	header := "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + bootstrap + "\r\nContent-Type: application/octet-stream\r\nContent-Length: " + strconv.Itoa(len(hello)) + "\r\n\r\n"

	// Block authentication on the event loop until the header timer has fired
	// and enqueued its generation-checked runnable. Completing this request then
	// advances the phase before that stale runnable can execute.
	application.manager.mu.Lock()
	if _, err := io.WriteString(connection, header); err != nil {
		application.manager.mu.Unlock()
		t.Fatal(err)
	}
	if _, err := connection.Write(hello); err != nil {
		application.manager.mu.Unlock()
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	application.manager.mu.Unlock()

	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	_ = readHTTPBody(t, response)
	if response.StatusCode != 200 {
		t.Fatalf("stale header deadline response = %d", response.StatusCode)
	}
}

func TestHTTPServerConnectionCloseDrainsLargeDownlink(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, time.Second, nil, func(config *HTTPServerConfig) {
		config.SocketSendBuffer = 4096
	})
	created := createTestSession(t, application.manager, application.profiles[0])
	payloadSize := MaxFramePayload - FrameHeaderSize
	created.Session.mu.Lock()
	queued := created.Session.queueFrameLocked(FrameData, 1, bytes.Repeat([]byte{0x41}, payloadSize)) &&
		created.Session.queueFrameLocked(FrameData, 2, bytes.Repeat([]byte{0x42}, payloadSize))
	created.Session.mu.Unlock()
	if !queued {
		t.Fatal("failed to queue large downlink")
	}
	connection := dialHTTPTest(t, application.address)
	defer connection.Close()
	if tcp, ok := connection.(*net.TCPConn); ok {
		if err := tcp.SetReadBuffer(1024); err != nil {
			t.Fatal(err)
		}
	}
	request := "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + created.Token + "\r\nX-Down-Cursor: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	// Keep the receive window closed long enough for gnet's first writev to
	// leave data in its outbound buffer.
	time.Sleep(100 * time.Millisecond)
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	body := readHTTPBody(t, response)
	wantBytes := 2 * (FrameHeaderSize + payloadSize)
	if response.StatusCode != 200 || !response.Close || len(body) != wantBytes {
		t.Fatalf("large close response = %d, close %v, bytes %d want %d", response.StatusCode, response.Close, len(body), wantBytes)
	}
	frames, err := ParseBatch(body)
	if err != nil || len(frames) != 2 {
		t.Fatalf("large response frames = %d, %v", len(frames), err)
	}
	expectConnectionClosed(t, connection, time.Second)
	waitForDownPoll(t, created.Session, false)
}

func TestHTTPServerWriteTimeoutClosesBackpressuredDownlink(t *testing.T) {
	application := newHTTPTestApplicationWithConfig(t, time.Second, nil, func(config *HTTPServerConfig) {
		config.SocketSendBuffer = 4096
		config.WriteTimeout = 100 * time.Millisecond
		config.IdleTimeout = 2 * time.Second
	})
	created := createTestSession(t, application.manager, application.profiles[0])
	payloadSize := MaxFramePayload - FrameHeaderSize
	created.Session.mu.Lock()
	queued := created.Session.queueFrameLocked(FrameData, 1, bytes.Repeat([]byte{0x51}, payloadSize)) &&
		created.Session.queueFrameLocked(FrameData, 2, bytes.Repeat([]byte{0x52}, payloadSize))
	created.Session.mu.Unlock()
	if !queued {
		t.Fatal("failed to queue write-timeout downlink")
	}

	connection := dialHTTPTest(t, application.address)
	defer connection.Close()
	if tcp, ok := connection.(*net.TCPConn); ok {
		if err := tcp.SetReadBuffer(1024); err != nil {
			t.Fatal(err)
		}
	}
	request := "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + created.Token + "\r\nX-Down-Cursor: 0\r\nContent-Length: 0\r\n\r\n"
	started := time.Now()
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	waitForDownPoll(t, created.Session, true)
	time.Sleep(200 * time.Millisecond)
	waitForDownPoll(t, created.Session, false)
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("reading timed-out response: %v", err)
	}
	if len(received) >= 2*(FrameHeaderSize+payloadSize) {
		t.Fatalf("write timeout did not truncate the deliberately unread response: got %d bytes", len(received))
	}
	if elapsed := time.Since(started); elapsed >= application.server.config.IdleTimeout {
		t.Fatalf("connection closed at idle timeout after %v, not write timeout", elapsed)
	}
}

func dialHTTPTest(t *testing.T, address string) net.Conn {
	t.Helper()
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if tcp, ok := connection.(*net.TCPConn); ok {
		if err := tcp.SetNoDelay(true); err != nil {
			connection.Close()
			t.Fatal(err)
		}
	}
	return connection
}

func expectConnectionClosed(t *testing.T, connection net.Conn, within time.Duration) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(within)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	_, err := connection.Read(one[:])
	if err == nil {
		t.Fatal("connection remained open")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("connection did not close within %v", within)
	}
}

func TestHTTPServerRejectsInvalidTrustedProxyCIDR(t *testing.T) {
	manager := testManager(t, testProfiles(t), nil, nil)
	for _, cidr := range []string{"127.0.0.1/8", "127.0.0.1", " 127.0.0.1/32"} {
		if _, err := NewHTTPServer(HTTPServerConfig{Bind: "127.0.0.1:1", Hostname: "proxy.example.com", Manager: manager, TrustedProxyCIDRs: []string{cidr}}); err == nil {
			t.Fatalf("accepted invalid trusted proxy CIDR %q", cidr)
		}
	}
}

func TestHTTPServerRouteMethodContentTypeAndCookieMatrix(t *testing.T) {
	application := newHTTPTestApplication(t, 100*time.Millisecond)
	client := &http.Client{Timeout: time.Second}
	unknown, _, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		method  string
		path    string
		headers map[string]string
	}{
		"bridge method":         {method: "POST", path: "/?bridge=" + application.profiles[0].Capability().String()},
		"bridge authorization":  {method: "GET", path: "/?bridge=" + application.profiles[0].Capability().String(), headers: map[string]string{"Authorization": "Bearer " + unknown}},
		"create method":         {method: "GET", path: "/api/v1/session", headers: map[string]string{"Authorization": "Bearer " + unknown}},
		"create content type":   {method: "POST", path: "/api/v1/session", headers: map[string]string{"Authorization": "Bearer " + unknown, "Content-Type": "text/plain"}},
		"create carrier header": {method: "POST", path: "/api/v1/session", headers: map[string]string{"Authorization": "Bearer " + unknown, "Content-Type": "application/octet-stream", "X-Down-Cursor": "0"}},
		"up method":             {method: "DELETE", path: "/api/v1/up", headers: map[string]string{"Authorization": "Bearer " + unknown}},
		"up down cursor":        {method: "POST", path: "/api/v1/up", headers: map[string]string{"Authorization": "Bearer " + unknown, "Content-Type": "application/octet-stream", "X-Up-Seq": "1", "X-Down-Cursor": "0"}},
		"down content type":     {method: "POST", path: "/api/v1/down", headers: map[string]string{"Authorization": "Bearer " + unknown, "X-Down-Cursor": "0", "Content-Type": "application/octet-stream"}},
		"down up sequence":      {method: "POST", path: "/api/v1/down", headers: map[string]string{"Authorization": "Bearer " + unknown, "X-Down-Cursor": "0", "X-Up-Seq": "1"}},
		"API cookie":            {method: "DELETE", path: "/api/v1/session", headers: map[string]string{"Authorization": "Bearer " + unknown, "Cookie": "a=b"}},
	} {
		t.Run(name, func(t *testing.T) {
			response := application.do(t, client, test.method, test.path, nil, test.headers)
			_ = readHTTPBody(t, response)
			if response.StatusCode != defaultSanitizedFallbackStatus || response.Header.Get(FallbackClassificationHeader) != FallbackSanitizedPublic {
				t.Fatalf("response = %d, headers %#v", response.StatusCode, response.Header)
			}
		})
	}
}

func TestHTTPServerDeadlineConfigRejectsNegativeDurations(t *testing.T) {
	manager := testManager(t, testProfiles(t), nil, nil)
	for name, mutate := range map[string]func(*HTTPServerConfig){
		"header": func(config *HTTPServerConfig) { config.HeaderTimeout = -1 },
		"body":   func(config *HTTPServerConfig) { config.BodyTimeout = -1 },
		"idle":   func(config *HTTPServerConfig) { config.IdleTimeout = -1 },
		"write":  func(config *HTTPServerConfig) { config.WriteTimeout = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			config := HTTPServerConfig{Bind: "127.0.0.1:1", Hostname: "proxy.example.com", Manager: manager}
			mutate(&config)
			if _, err := NewHTTPServer(config); err == nil {
				t.Fatal("accepted negative timeout")
			}
		})
	}
}
