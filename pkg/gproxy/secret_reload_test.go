package gproxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

func reloadTestSecret(name string, fill byte) Secret {
	key := make([]byte, 16)
	for i := range key {
		key[i] = fill
	}
	return Secret{Name: name, Key: key, Host: "example.com"}
}

// trackedTestSession authenticates a mock client the way the handshake does.
func trackedTestSession(t *testing.T, h *ProxyHandler, secret *Secret) (*testMockGnetConn, *ConnContext, bool) {
	t.Helper()
	conn := newTestMockGnetConn()
	ctx := NewConnContext()
	conn.SetContext(ctx)
	ctx.mu.Lock()
	ctx.secret = secret
	ctx.mu.Unlock()
	return conn, ctx, h.trackSecretSession(conn, ctx, secret)
}

func TestReplaceSecretsClosesOnlyRemovedSessions(t *testing.T) {
	alice := reloadTestSecret("alice", 1)
	bob := reloadTestSecret("bob", 2)
	h := NewProxyHandler(&Config{Secrets: []Secret{alice, bob}}, &testLogger{})

	list := h.currentSecrets()
	aliceConn, _, ok := trackedTestSession(t, h, &list[0])
	if !ok {
		t.Fatal("alice session was rejected")
	}
	bobConn, bobCtx, ok := trackedTestSession(t, h, &list[1])
	if !ok {
		t.Fatal("bob session was rejected")
	}

	// Same name and key in a new list: the session continues.
	if closed := h.ReplaceSecrets([]Secret{reloadTestSecret("alice", 1)}); closed != 1 {
		t.Fatalf("closed = %d, want 1", closed)
	}
	if aliceConn.IsClosed() {
		t.Fatal("unchanged secret session was closed")
	}
	if !bobConn.IsClosed() {
		t.Fatal("removed secret session stays open")
	}
	if got := connCloseReason(bobCtx.closeReason.Load()); got != closeReasonSecretRevoked {
		t.Fatalf("close reason = %s, want secret_revoked", closeReasonNames[got])
	}

	// A new key under the same name is a different secret.
	if closed := h.ReplaceSecrets([]Secret{reloadTestSecret("alice", 3)}); closed != 1 || !aliceConn.IsClosed() {
		t.Fatalf("rekeyed secret: closed = %d, session closed = %t", closed, aliceConn.IsClosed())
	}
}

func TestTrackSecretSessionRejectsSecretRemovedAfterMatch(t *testing.T) {
	h := NewProxyHandler(&Config{Secrets: []Secret{reloadTestSecret("alice", 1)}}, &testLogger{})
	matched := &h.currentSecrets()[0]
	h.ReplaceSecrets(nil)
	if _, _, ok := trackedTestSession(t, h, matched); ok {
		t.Fatal("a secret removed between match and tracking was accepted")
	}
}

func TestCloseClientForgetsSecretSession(t *testing.T) {
	h := NewProxyHandler(&Config{Secrets: []Secret{reloadTestSecret("alice", 1)}}, &testLogger{})
	conn, _, ok := trackedTestSession(t, h, &h.currentSecrets()[0])
	if !ok {
		t.Fatal("session was rejected")
	}
	h.activeConns.Add(1)
	h.OnClose(conn, nil)
	count := 0
	h.secretSessions.Range(func(any, any) bool { count++; return true })
	if count != 0 {
		t.Fatalf("%d sessions remain tracked after close", count)
	}
}

// Handshakes read and track secrets on event loops while a reload replaces
// them. Run with -race. After the last reload removes bob, every accepted bob
// session must be closed, by a sweep or by its own tracking check. Workers
// keep running after the last reload to exercise a match on the old list.
func TestReplaceSecretsConcurrentWithHandshakes(t *testing.T) {
	alice := reloadTestSecret("alice", 1)
	bob := reloadTestSecret("bob", 2)
	h := NewProxyHandler(&Config{Secrets: []Secret{alice, bob}}, &testLogger{})

	var (
		mu       sync.Mutex
		accepted []*testMockGnetConn
		wg       sync.WaitGroup
		after    atomic.Int64
		finished atomic.Bool
	)
	stop := make(chan struct{})
	for worker := range 4 {
		wg.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				if finished.Load() {
					after.Add(1)
				}
				list := h.currentSecrets()
				secret := &list[(worker+i)%len(list)]
				conn, ctx, ok := trackedTestSession(t, h, secret)
				if !ok || secret.Name == "alice" {
					// The handshake closes a rejected client, and closeClient
					// forgets it. Alice is never removed.
					h.secretSessions.Delete(ctx.id)
					continue
				}
				mu.Lock()
				accepted = append(accepted, conn)
				mu.Unlock()
			}
		})
	}
	for {
		mu.Lock()
		n := len(accepted)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	for i := range 200 {
		if i%2 == 0 {
			h.ReplaceSecrets([]Secret{alice})
		} else {
			h.ReplaceSecrets([]Secret{alice, bob})
		}
	}
	h.ReplaceSecrets([]Secret{alice})
	finished.Store(true)
	for after.Load() < 1000 {
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()

	if len(accepted) == 0 {
		t.Fatal("no bob session was accepted")
	}
	for _, conn := range accepted {
		if !conn.IsClosed() {
			t.Fatal("session of removed secret bob stays open")
		}
	}
}

// buildSeededO2ClientFrame varies the nonce so the replay cache accepts
// several clients of one secret.
func buildSeededO2ClientFrame(t *testing.T, secret []byte, seed byte) []byte {
	t.Helper()
	plain := make([]byte, obfuscated2.FrameSize)
	for i := range plain {
		plain[i] = byte(i+1) ^ seed
	}
	binary.LittleEndian.PutUint32(plain[56:60], uint32(obfuscated2.ConnectionTypePaddedIntermediate))
	binary.LittleEndian.PutUint16(plain[60:62], 2)
	hash := sha256.New()
	hash.Write(plain[8:40])
	hash.Write(secret)
	encryptor, err := obfuscated2.NewAESCTR(hash.Sum(nil), plain[40:56])
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, len(plain))
	encryptor.XORKeyStream(wire, plain)
	copy(wire[8:56], plain[8:56])
	return wire
}

// A real gnet listener and the real dd handshake: a reload that removes one
// secret closes its client and leaves the other client connected.
func TestHotReloadSecretsRealGnet(t *testing.T) {
	alice := reloadTestSecret("alice", 1)
	bob := reloadTestSecret("bob", 2)
	cfg := &Config{
		Host:             "example.com",
		HandshakeTimeout: 3 * time.Second,
		Secrets:          []Secret{alice, bob},
	}
	handler := NewProxyHandler(cfg, &testLogger{})
	dials := make(chan struct{}, 4)
	handler.directDCDial = func(ctx context.Context, _ int, _ obfuscated2.ConnectionType) (*directDCConn, error) {
		dials <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	address := runIdleProxyTestServer(t, handler)

	connect := func(secret Secret, seed byte) net.Conn {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if _, err := conn.Write(buildSeededO2ClientFrame(t, secret.Key, seed)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-dials:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not authenticate", secret.Name)
		}
		return conn
	}
	aliceConn := connect(alice, 1)
	bobConn := connect(bob, 2)

	logger := &testLogger{}
	reloader := NewHotReloader(HotReloadConfig{
		LoadConfig: func() (*Config, string, error) {
			next := *cfg
			next.Secrets = []Secret{reloadTestSecret("alice", 1)}
			return &next, "", nil
		},
		Handler: handler,
		Logger:  logger,
	})
	reloader.reload()

	if err := bobConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	if _, err := bobConn.Read(buffer[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("removed secret read = %v, want EOF", err)
	}
	if err := aliceConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := aliceConn.Read(buffer[:]); !isTimeout(err) {
		t.Fatalf("kept secret read = %v, want timeout", err)
	}

	// A new client of the removed secret no longer authenticates; without a
	// splice host it is closed.
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(buildSeededO2ClientFrame(t, bob.Key, 3)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(buffer[:]); err == nil || isTimeout(err) {
		t.Fatalf("removed secret new client read = %v, want close", err)
	}
	select {
	case <-dials:
		t.Fatal("removed secret reached the DC dial")
	default:
	}
	if !loggedFormat(logger, "secrets reloaded") {
		t.Fatal("reload did not log the secret change")
	}
}

func TestHotReloadSecretsRejectNewHost(t *testing.T) {
	alice := reloadTestSecret("alice", 1)
	cfg := &Config{Host: "example.com", Secrets: []Secret{alice}}
	handler := NewProxyHandler(cfg, &testLogger{})
	logger := &testLogger{}
	reloader := NewHotReloader(HotReloadConfig{
		LoadConfig: func() (*Config, string, error) {
			moved := reloadTestSecret("alice", 1)
			moved.Host = "other.example"
			next := *cfg
			next.Host = "other.example"
			next.Secrets = []Secret{moved}
			return &next, "", nil
		},
		Handler: handler,
		Logger:  logger,
	})
	reloader.reload()
	if got := handler.currentSecrets(); len(got) != 1 || got[0].Host != "example.com" {
		t.Fatalf("secrets = %+v, want the startup list", got)
	}
	if !loggedFormat(logger, "uses a new host") {
		t.Fatal("new host was not reported")
	}
}

func TestHotReloadInvalidConfigKeepsSecrets(t *testing.T) {
	alice := reloadTestSecret("alice", 1)
	handler := NewProxyHandler(&Config{Host: "example.com", Secrets: []Secret{alice}}, &testLogger{})
	logger := &testLogger{}
	reloader := NewHotReloader(HotReloadConfig{
		LoadConfig: func() (*Config, string, error) { return nil, "", errors.New("bad secret") },
		Handler:    handler,
		Logger:     logger,
	})
	reloader.reload()
	if got := handler.currentSecrets(); len(got) != 1 || got[0].Name != "alice" {
		t.Fatalf("secrets = %+v, want the old list", got)
	}
	if !loggedFormat(logger, "keeping the current config") {
		t.Fatal("rejected reload was not logged")
	}
}

// loggedFormat reports whether any recorded log format contains text.
func loggedFormat(l *testLogger, text string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, lines := range [][]string{l.debugs, l.infos, l.warnings, l.errors} {
		for _, line := range lines {
			if strings.Contains(line, text) {
				return true
			}
		}
	}
	return false
}

func TestUserLimiterFollowsRenamedSecret(t *testing.T) {
	limiter := NewUserIPLimiter(0, 0)
	key := reloadTestSecret("old", 1).Key
	limiter.TryAcquire(net.IPv4(192, 0, 2, 1), key, "old")
	limiter.TryAcquire(net.IPv4(192, 0, 2, 1), key, "new")
	if stats := limiter.Stats(); len(stats) != 1 || stats[0].SecretName != "new" {
		t.Fatalf("stats = %+v, want the new name", stats)
	}
}

func TestHotReloadSecretsAcceptCoverDomainHost(t *testing.T) {
	alice := reloadTestSecret("alice", 1)
	cfg := &Config{Host: "example.com", Secrets: []Secret{alice}, Domains: []TLSDomain{{Host: "d.example"}}}
	handler := NewProxyHandler(cfg, &testLogger{})
	logger := &testLogger{}
	reloader := NewHotReloader(HotReloadConfig{
		LoadConfig: func() (*Config, string, error) {
			bob := reloadTestSecret("bob", 2)
			bob.Host = "d.example"
			next := *cfg
			next.Secrets = []Secret{alice, bob}
			return &next, "", nil
		},
		Handler: handler,
		Logger:  logger,
	})
	reloader.reload()
	if got := handler.currentSecrets(); len(got) != 2 {
		t.Fatalf("secrets = %+v, want alice and bob", got)
	}
	if loggedFormat(logger, "uses a new host") {
		t.Fatal("a startup cover domain was treated as a new host")
	}
}
