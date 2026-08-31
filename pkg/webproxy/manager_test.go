package webproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestManagerCapabilityTokensAndIdempotentCreate(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)

	matched, ok := manager.MatchCapability(profiles[1].Capability())
	if !ok || matched.Mode() != SecretDD || matched.Name() != profiles[1].Name() {
		t.Fatalf("matched profile = %#v, %v", matched, ok)
	}
	unknown := profiles[0].Capability()
	unknown[0] ^= 0xff
	if _, ok := manager.MatchCapability(unknown); ok {
		t.Fatal("unknown capability matched")
	}
	if _, err := manager.IssueBootstrap(unknown, "192.0.2.1"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("unknown capability error = %v", err)
	}

	bootstrap, err := manager.IssueBootstrap(profiles[0].Capability(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	assertCanonicalToken(t, bootstrap)
	hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})
	created, err := manager.Create(bootstrap, "198.51.100.5", hello)
	if err != nil {
		t.Fatal(err)
	}
	assertCanonicalToken(t, created.Token)
	wantWelcome := testFrameBatch(t, Frame{Type: FrameWelcome})
	if !bytes.Equal(created.Welcome, wantWelcome) {
		t.Fatalf("WELCOME = %x, want %x", created.Welcome, wantWelcome)
	}
	if created.Session.Profile().Mode() != SecretPlain {
		t.Fatalf("session profile mode = %s", created.Session.Profile().Mode())
	}

	retried, err := manager.Create(bootstrap, "203.0.113.9", bytes.Clone(hello))
	if err != nil {
		t.Fatal(err)
	}
	if retried.Token != created.Token || retried.Session != created.Session || !bytes.Equal(retried.Welcome, created.Welcome) {
		t.Fatal("identical create retry did not return the original result")
	}
	got, err := manager.Get(created.Token)
	if err != nil || got != created.Session {
		t.Fatalf("Get = %p, %v", got, err)
	}
	for _, invalid := range []string{"", created.Token + "=", created.Token[:42] + "+"} {
		if _, err := manager.Get(invalid); !errors.Is(err, ErrAuthentication) {
			t.Errorf("Get(%q) error = %v", invalid, err)
		}
	}

	if err := manager.Close(created.Token); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		_, getErr := manager.Get(created.Token)
		return errors.Is(getErr, ErrAuthentication)
	})
	if err := manager.Close(created.Token); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if _, err := manager.Create(bootstrap, "198.51.100.5", hello); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("closed bootstrap create error = %v", err)
	}
}

func TestBootstrapAuthenticationPrecedesBodyParsing(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	bootstrap, err := manager.IssueBootstrap(profiles[0].Capability(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := manager.AuthenticateBootstrap(bootstrap)
	if err != nil || authorization == nil {
		t.Fatalf("AuthenticateBootstrap = %p, %v", authorization, err)
	}

	var unknown string
	for {
		candidate, hash, tokenErr := newToken()
		if tokenErr != nil {
			t.Fatal(tokenErr)
		}
		manager.mu.Lock()
		used := manager.tokenHashUsedLocked(hash)
		manager.mu.Unlock()
		if !used {
			unknown = candidate
			break
		}
	}
	malformedBody := []byte{0xff}
	for name, token := range map[string]string{
		"malformed bearer": "not-base64url",
		"unknown bearer":   unknown,
	} {
		t.Run(name, func(t *testing.T) {
			gotAuthorization, authErr := manager.AuthenticateBootstrap(token)
			if gotAuthorization != nil || authErr != ErrAuthentication {
				t.Fatalf("AuthenticateBootstrap = %p, %v", gotAuthorization, authErr)
			}
			if _, createErr := manager.Create(token, "192.0.2.1", malformedBody); createErr != ErrAuthentication {
				t.Fatalf("Create error = %v; body was parsed before authentication", createErr)
			}
		})
	}
	if _, err := authorization.Create("192.0.2.1", malformedBody); !errors.Is(err, ErrProtocol) {
		t.Fatalf("authenticated malformed HELLO error = %v", err)
	}
	hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})
	if _, err := authorization.Create("192.0.2.1", hello); err != nil {
		t.Fatalf("valid create after malformed body: %v", err)
	}
	var nilAuthorization *BootstrapAuthorization
	if _, err := nilAuthorization.Create("192.0.2.1", hello); err != ErrAuthentication {
		t.Fatalf("nil authorization error = %v", err)
	}
}

func TestBootstrapAuthorizationCreateIsAtomicAndIdempotent(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	bootstrap, err := manager.IssueBootstrap(profiles[0].Capability(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := manager.AuthenticateBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})

	const callers = 32
	results := make(chan CreateResult, callers)
	errorsSeen := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Go(func() {
			result, createErr := authorization.Create("192.0.2.1", bytes.Clone(hello))
			results <- result
			errorsSeen <- createErr
		})
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	for createErr := range errorsSeen {
		if createErr != nil {
			t.Fatalf("concurrent Create: %v", createErr)
		}
	}
	var first CreateResult
	for result := range results {
		if first.Session == nil {
			first = result
			continue
		}
		if result.Token != first.Token || result.Session != first.Session || !bytes.Equal(result.Welcome, first.Welcome) {
			t.Fatal("concurrent Create returned more than one session")
		}
	}
	if capacity := manager.Capacity(); capacity.Sessions != 1 {
		t.Fatalf("concurrent Create capacity = %+v", capacity)
	}
}

func TestBootstrapExpiresBeforeBodyParsingAndCreate(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Timeouts.BootstrapLifetime = 15 * time.Millisecond
	}, nil)
	bootstrap, err := manager.IssueBootstrap(profiles[0].Capability(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := manager.AuthenticateBootstrap(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, func() bool {
		_, authErr := manager.AuthenticateBootstrap(bootstrap)
		return authErr == ErrAuthentication
	})
	if _, err := authorization.Create("192.0.2.1", []byte{0xff}); err != ErrAuthentication {
		t.Fatalf("expired authorization parsed body: %v", err)
	}
	if capacity := manager.Capacity(); capacity.Bootstraps != 0 {
		t.Fatalf("expired bootstrap remained counted: %+v", capacity)
	}
}

func TestManagerClosedTokenHistoryIsBounded(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Limits.MaxClosedTokens = 3
		config.Limits.MaxSessions = 1
	}, nil)
	tokens := make([]string, 0, 10)
	for range 10 {
		created := createTestSession(t, manager, profiles[0])
		tokens = append(tokens, created.Token)
		created.Session.Close()
		eventually(t, time.Second, func() bool { return manager.Capacity().Sessions == 0 })
		if got := manager.Capacity().ClosedTokens; got > manager.limits.MaxClosedTokens {
			t.Fatalf("closed-token count = %d", got)
		}
	}
	if got := manager.Capacity().ClosedTokens; got != 3 {
		t.Fatalf("closed-token count = %d, want 3", got)
	}
	if err := manager.Close(tokens[len(tokens)-1]); err != nil {
		t.Fatalf("newest closed token was not idempotent: %v", err)
	}
	if err := manager.Close(tokens[0]); err != ErrAuthentication {
		t.Fatalf("evicted closed token error = %v", err)
	}
}

func TestSessionManagerReferenceDefaults(t *testing.T) {
	limits := DefaultLimits()
	if limits.CarrierBatchBytes != 2*1024*1024 ||
		limits.MaxBodyBytes != 2*1024*1024 ||
		limits.MaxStreamsPerSession != 128 ||
		limits.MaxClosedStreamIDs != 4096 ||
		limits.MaxPendingPerSession != 32*1024*1024 ||
		limits.MaxPendingGlobal != 512*1024*1024 ||
		limits.MaxPendingItemsPerSession != 16*1024 ||
		limits.MaxPendingItemsGlobal != 256*1024 ||
		limits.MaxBootstraps != 512 ||
		limits.MaxSessions != 128 ||
		limits.MaxClosedTokens != 2048 ||
		limits.MaxStreams != 4096 ||
		limits.MaxBackendDialsInFlight != 256 {
		t.Fatalf("unexpected reference limits: %+v", limits)
	}
	timeouts := DefaultTimeouts()
	if timeouts.BackendDial != 5*time.Second ||
		timeouts.LongPoll != 25*time.Second ||
		timeouts.ReconnectGrace != 2*time.Minute ||
		timeouts.BootstrapLifetime != 2*time.Minute {
		t.Fatalf("unexpected reference timeouts: %+v", timeouts)
	}
}

func TestManagerRejectsInvalidConfigAndDuplicateCapabilities(t *testing.T) {
	profiles := testProfiles(t)
	tests := []struct {
		name   string
		mutate func(*ManagerConfig)
	}{
		{"no profiles", func(config *ManagerConfig) { config.Profiles = nil }},
		{"duplicate capability", func(config *ManagerConfig) { config.Profiles = []Profile{profiles[0], profiles[0]} }},
		{"non-loopback backend", func(config *ManagerConfig) { config.Backend = "192.0.2.1:443" }},
		{"hostname backend", func(config *ManagerConfig) { config.Backend = "localhost:443" }},
		{"relative Unix backend", func(config *ManagerConfig) { config.Backend = "unix://relative.sock" }},
		{"root Unix backend", func(config *ManagerConfig) { config.Backend = "/" }},
		{"unsupported carrier", func(config *ManagerConfig) { config.Carrier = "quic" }},
		{"zero limit", func(config *ManagerConfig) { config.Limits.MaxSessions = 0 }},
		{"oversized carrier", func(config *ManagerConfig) { config.Limits.CarrierBatchBytes = maxCarrierBatchBytes + 1 }},
		{"small global streams", func(config *ManagerConfig) { config.Limits.MaxStreams = config.Limits.MaxStreamsPerSession - 1 }},
		{"zero timeout", func(config *ManagerConfig) { config.Timeouts.BackendDial = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultManagerConfig(profiles, "127.0.0.1:443")
			test.mutate(&config)
			manager, err := NewManager(config)
			if manager != nil || !errors.Is(err, ErrInvalidManagerConfig) {
				t.Fatalf("NewManager = %p, %v", manager, err)
			}
		})
	}
}

func TestManagerEmptyCarrierPreservesSerializedHTTPS(t *testing.T) {
	config := DefaultManagerConfig(testProfiles(t), "127.0.0.1:443")
	config.Carrier = ""
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Shutdown(context.Background()) })
	if manager.CarrierMode() != CarrierHTTPS {
		t.Fatalf("carrier = %q", manager.CarrierMode())
	}
}

func TestManagerAcceptsAbsoluteUnixBackend(t *testing.T) {
	config := DefaultManagerConfig(testProfiles(t), "unix:///run/telego/telego.sock")
	manager, err := NewManager(config)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if manager.backendNet != "unix" || manager.backend != "/run/telego/telego.sock" {
		t.Fatalf("backend = %q %q", manager.backendNet, manager.backend)
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Shutdown(shutdownContext); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestManagerBackendDialReceivesNetworkAndClientIP(t *testing.T) {
	profiles := testProfiles(t)
	dialed := make(chan struct {
		network  string
		address  string
		clientIP string
	}, 1)
	peers := make(chan net.Conn, 1)
	config := DefaultManagerConfig(profiles, "unix:///run/telego/telego.sock")
	config.BackendDialContext = func(_ context.Context, network, address, clientIP string) (net.Conn, error) {
		client, server := net.Pipe()
		peers <- server
		dialed <- struct {
			network  string
			address  string
			clientIP string
		}{network, address, clientIP}
		return client, nil
	}
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = manager.Shutdown(shutdownContext)
	})
	created := createTestSessionWithIP(t, manager, profiles[0], "198.51.100.7")
	if _, err := created.Session.ProcessUp(1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-dialed:
		if got.network != "unix" || got.address != "/run/telego/telego.sock" || got.clientIP != "198.51.100.7" {
			t.Fatalf("dial = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("backend dial did not start")
	}
	peer := <-peers
	_ = peer.Close()
}

func TestManagerSessionLimitKeepsBootstrapRetryable(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Limits.MaxSessions = 1
		config.Limits.MaxPendingGlobal = config.Limits.MaxPendingPerSession * 2
		config.Limits.MaxPendingItemsGlobal = config.Limits.MaxPendingItemsPerSession * 2
	}, nil)
	hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})

	firstBootstrap, err := manager.IssueBootstrap(profiles[0].Capability(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.Create(firstBootstrap, "192.0.2.1", hello)
	if err != nil {
		t.Fatal(err)
	}
	secondBootstrap, err := manager.IssueBootstrap(profiles[1].Capability(), "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Create(secondBootstrap, "192.0.2.2", hello); !errors.Is(err, ErrLimit) {
		t.Fatalf("second Create error = %v", err)
	}
	first.Session.Close()
	eventually(t, time.Second, func() bool { return manager.Capacity().Sessions == 0 })
	if _, err := manager.Create(secondBootstrap, "192.0.2.2", hello); err != nil {
		t.Fatalf("retry after capacity release: %v", err)
	}
}

func TestManagerReconnectExpiryAndShutdown(t *testing.T) {
	profiles := testProfiles(t)
	dialStarted := make(chan struct{}, 1)
	dialStopped := make(chan struct{}, 1)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialStarted <- struct{}{}
		<-ctx.Done()
		dialStopped <- struct{}{}
		return nil, ctx.Err()
	}
	config := DefaultManagerConfig(profiles, "127.0.0.1:443")
	config.Timeouts.ReconnectGrace = 40 * time.Millisecond
	config.Timeouts.BootstrapLifetime = time.Second
	config.Timeouts.BackendDial = time.Second
	config.DialContext = dial
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}

	created := createTestSession(t, manager, profiles[0])
	open := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})
	if _, err := created.Session.ProcessUp(1, open); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("backend dial did not start")
	}
	eventually(t, time.Second, func() bool {
		_, getErr := manager.Get(created.Token)
		return errors.Is(getErr, ErrAuthentication)
	})
	select {
	case <-dialStopped:
	case <-time.After(time.Second):
		t.Fatal("expiry did not cancel backend dial")
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	capacity := manager.Capacity()
	if capacity.Sessions != 0 || capacity.Streams != 0 || capacity.BackendDials != 0 ||
		capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("capacity after shutdown = %+v", capacity)
	}
	if _, err := manager.IssueBootstrap(profiles[0].Capability(), "192.0.2.1"); !errors.Is(err, ErrClosed) {
		t.Fatalf("IssueBootstrap after shutdown error = %v", err)
	}
	if err := manager.Shutdown(shutdownContext); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

func testProfiles(t *testing.T) []Profile {
	t.Helper()
	base := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	derived, err := DeriveProfiles("desktop", "proxy.example.com", base)
	if err != nil {
		t.Fatal(err)
	}
	return []Profile{derived[0], derived[1]}
}

func testManager(
	t *testing.T,
	profiles []Profile,
	mutate func(*ManagerConfig),
	dial DialContextFunc,
) *Manager {
	t.Helper()
	config := DefaultManagerConfig(profiles, "127.0.0.1:443")
	config.Timeouts.LongPoll = 100 * time.Millisecond
	if mutate != nil {
		mutate(&config)
	}
	config.DialContext = dial
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := manager.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
	return manager
}

func createTestSession(t *testing.T, manager *Manager, profile Profile) CreateResult {
	return createTestSessionWithIP(t, manager, profile, "192.0.2.1")
}

func createTestSessionWithIP(t *testing.T, manager *Manager, profile Profile, clientIP string) CreateResult {
	t.Helper()
	bootstrap, err := manager.IssueBootstrap(profile.Capability(), clientIP)
	if err != nil {
		t.Fatal(err)
	}
	hello := testFrameBatch(t, Frame{Type: FrameHello, Payload: []byte{1}})
	created, err := manager.Create(bootstrap, clientIP, hello)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func testFrameBatch(t *testing.T, frames ...Frame) []byte {
	t.Helper()
	var body []byte
	var err error
	for _, frame := range frames {
		body, err = AppendFrame(body, frame)
		if err != nil {
			t.Fatal(err)
		}
	}
	return body
}

func assertCanonicalToken(t *testing.T, token string) {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 || len(token) != 43 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		t.Fatalf("token is not canonical 32-byte base64url: %q, %v", token, err)
	}
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not satisfied before timeout")
}
