package gproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// queuedIdleOwner lets a timer expire while its owner is busy, as can happen
// when a different connection is using the same real event loop.
type queuedIdleOwner struct {
	*testMockEventLoop
	queue chan gnet.Runnable
}

func (owner *queuedIdleOwner) Execute(_ context.Context, runnable gnet.Runnable) error {
	owner.queue <- runnable
	return nil
}

func newIdleTestSession(t *testing.T, timeout time.Duration) (*testMockGnetConn, *ConnContext, *queuedIdleOwner) {
	t.Helper()
	owner := &queuedIdleOwner{testMockEventLoop: &testMockEventLoop{}, queue: make(chan gnet.Runnable, 8)}
	conn := newTestMockGnetConn()
	conn.eventLoop = owner
	ctx := NewConnContext()
	ctx.SetState(StateRelaying)
	conn.SetContext(ctx)
	ctx.startAuthenticatedIdle(conn, timeout)
	t.Cleanup(ctx.Cleanup)
	return conn, ctx, owner
}

func runIdleExpiry(t *testing.T, owner *queuedIdleOwner) {
	t.Helper()
	select {
	case runnable := <-owner.queue:
		if err := runnable.Run(t.Context()); err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("idle expiry did not reach the owner loop")
	}
}

func TestAuthenticatedIdleExpiryRechecksActivityOnOwner(t *testing.T) {
	for _, direction := range []string{"client", "server"} {
		t.Run(direction, func(t *testing.T) {
			conn, ctx, owner := newIdleTestSession(t, time.Hour)
			timer := ctx.authenticatedIdle.Load()
			timer.mu.Lock()
			timer.deadline = time.Now().Add(-time.Second)
			timer.mu.Unlock()
			timer.enqueueExpiry()

			// A relay on another loop reports progress while the client owner
			// is still busy. Its queued expiry must observe the new deadline.
			if direction == "client" {
				ctx.recordClientActivity()
			} else {
				ctx.recordServerActivity()
			}
			runIdleExpiry(t, owner)
			if conn.IsClosed() {
				t.Fatal("queued idle expiry closed an active session")
			}

			// Without further progress, the owner closes the same session.
			timer.mu.Lock()
			timer.deadline = time.Now().Add(-time.Second)
			timer.mu.Unlock()
			timer.enqueueExpiry()
			runIdleExpiry(t, owner)
			if !conn.IsClosed() {
				t.Fatal("owner did not close expired session")
			}
		})
	}
}

func TestAuthenticatedIdleCleanupRetiresQueuedExpiry(t *testing.T) {
	conn, ctx, owner := newIdleTestSession(t, time.Hour)
	timer := ctx.authenticatedIdle.Load()
	timer.enqueueExpiry()
	ctx.Cleanup()
	runIdleExpiry(t, owner)
	if conn.IsClosed() {
		t.Fatal("stale idle expiry acted after cleanup")
	}
	if ctx.authenticatedIdle.Load() != nil {
		t.Fatal("cleanup retained idle timer")
	}
	timer.enqueueExpiry()
	select {
	case <-owner.queue:
		t.Fatal("retired idle timer scheduled another owner callback")
	default:
	}
}

func TestAuthenticatedIdleTimeoutHotReloadKeepsActiveSnapshot(t *testing.T) {
	handler := NewProxyHandler(&Config{IdleTimeout: time.Hour}, &testLogger{})
	_, first, _ := newIdleTestSession(t, handler.IdleTimeout())
	handler.ApplyHotConfig(&Config{IdleTimeout: 2 * time.Hour})
	_, second, _ := newIdleTestSession(t, handler.IdleTimeout())
	first.recordClientActivity()
	second.recordServerActivity()
	if got := first.authenticatedIdle.Load().timeout; got != time.Hour {
		t.Fatalf("existing idle timeout = %v, want 1h", got)
	}
	if got := second.authenticatedIdle.Load().timeout; got != 2*time.Hour {
		t.Fatalf("new idle timeout = %v, want 2h", got)
	}
	_, disabled, _ := newIdleTestSession(t, 0)
	if disabled.authenticatedIdle.Load() != nil {
		t.Fatal("disabled timeout allocated an idle timer")
	}
}

func TestAuthenticatedIdleActivityConcurrentWithCleanup(t *testing.T) {
	_, ctx, _ := newIdleTestSession(t, time.Hour)
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 1000 {
			ctx.recordClientActivity()
		}
	})
	workers.Go(func() {
		for range 1000 {
			ctx.recordServerActivity()
		}
	})
	ctx.Cleanup()
	workers.Wait()
	if ctx.authenticatedIdle.Load() != nil {
		t.Fatal("activity reinstalled a closed session's idle timer")
	}
}

func TestAuthenticatedIdleTimeoutRealGnetWhileDialing(t *testing.T) {
	secret := []byte("0123456789abcdef")
	const idleTimeout = 120 * time.Millisecond
	handler := NewProxyHandler(&Config{
		IdleTimeout:      idleTimeout,
		HandshakeTimeout: 3 * time.Second,
		Secrets:          []Secret{{Name: "idle", Key: secret}},
	}, &testLogger{})
	dialStarted := make(chan struct{})
	dialReleased := make(chan struct{})
	dialExited := make(chan struct{})
	handler.directDCDial = func(context.Context, int, obfuscated2.ConnectionType) (*directDCConn, error) {
		defer close(dialExited)
		close(dialStarted)
		<-dialReleased
		return nil, net.ErrClosed
	}
	address := runIdleProxyTestServer(t, handler)
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		close(dialReleased)
		select {
		case <-dialStarted:
			select {
			case <-dialExited:
			case <-time.After(5 * time.Second):
				t.Error("idle test DC dial did not exit")
			}
		default:
		}
	})
	started := time.Now()
	frame := buildDeterministicO2ClientFrame(t, secret, 2, obfuscated2.ConnectionTypePaddedIntermediate)
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("client did not authenticate")
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buffer [1]byte
	if _, err := conn.Read(buffer[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("idle authenticated connection read = %v, want EOF", err)
	}
	if elapsed := time.Since(started); elapsed < idleTimeout {
		t.Fatalf("authenticated connection closed too early after %v", elapsed)
	}
}

func TestAuthenticatedIdleMiddleEndPartialPacketRefreshesOnlyIdle(t *testing.T) {
	handler, _, conn, ctx, frame, _ := newMiddleEndTestHandler(
		t, 2, obfuscated2.ConnectionTypeIntermediate, nil,
	)
	handler.ApplyHotConfig(&Config{IdleTimeout: time.Hour})
	t.Cleanup(func() { closeMiddleEndTestClient(handler, conn, ctx) })
	_, _, _, requestEncryptor, err := obfuscated2.ParseClientFrameWithType(handler.config.Secrets[0].Key, frame)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadData(frame)
	if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
		t.Fatalf("authenticate Middle-End action = %v", action)
	}
	timer := ctx.authenticatedIdle.Load()
	if timer == nil {
		t.Fatal("Middle-End authentication did not start idle timer")
	}
	timer.mu.Lock()
	timer.deadline = time.Now().Add(-time.Second)
	timer.mu.Unlock()
	wire := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, validMiddleEndPacket(), requestEncryptor)
	conn.SetReadData(wire[:5])
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("consume partial packet action = %v", action)
	}
	timer.mu.Lock()
	remaining := time.Until(timer.deadline)
	timer.mu.Unlock()
	if remaining <= 0 {
		t.Fatal("consumed partial packet did not refresh idle timer")
	}
	if last := ctx.lastClientByteMs.Load(); last != 0 {
		t.Fatalf("partial packet updated silence-breaker timestamp to %d before relay", last)
	}
}

func TestAuthenticatedIdleRealGnetRelayActivityRefreshes(t *testing.T) {
	for _, direction := range []string{"uplink", "downlink"} {
		t.Run(direction, func(t *testing.T) {
			client, dc, ctx, conn := startDirectRelay(t, ModeDD, nil,
				&mockCipher{}, &mockCipher{}, &mockCipher{}, &mockCipher{}, 4*relayBatchSize)
			awaitDirectRelay(t, ctx)
			const timeout = time.Second
			armed := make(chan struct{})
			if err := conn.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
				ctx.startAuthenticatedIdle(conn, timeout)
				close(armed)
				return nil
			})); err != nil {
				t.Fatal(err)
			}
			select {
			case <-armed:
			case <-time.After(5 * time.Second):
				t.Fatal("owner did not arm idle timer")
			}
			writer, reader := client, dc
			if direction == "downlink" {
				writer, reader = dc, client
			}
			activityUntil := time.Now().Add(timeout + timeout/2)
			tick := time.NewTicker(timeout / 10)
			defer tick.Stop()
			for sequence := byte(0); time.Now().Before(activityUntil); sequence++ {
				<-tick.C
				if err := writer.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write([]byte{sequence}); err != nil {
					t.Fatalf("active %s write: %v", direction, err)
				}
				if err := reader.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				var got [1]byte
				if _, err := io.ReadFull(reader, got[:]); err != nil || got[0] != sequence {
					t.Fatalf("active %s relay = %v, %v; want %d", direction, got, err, sequence)
				}
			}
			if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var last [1]byte
			if _, err := client.Read(last[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("relay after activity stopped = %v, want idle EOF", err)
			}
		})
	}
}

func runIdleProxyTestServer(t *testing.T, handler *ProxyHandler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	var engine atomic.Pointer[gnet.Engine]
	ready := make(chan struct{})
	server := &engineCaptureHandler{ProxyHandler: handler, engPtr: &engine, ready: ready}
	result := make(chan error, 1)
	go func() {
		result <- gnet.Run(server, "tcp://"+address, gnet.WithNumEventLoop(2))
	}()
	select {
	case <-ready:
	case err := <-result:
		t.Fatalf("start idle test server: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("idle test server did not start")
	}
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := engine.Load().Stop(shutdown); err != nil {
			t.Errorf("stop idle test server: %v", err)
		}
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("idle test server: %v", err)
			}
		case <-shutdown.Done():
			t.Error("idle test server did not stop")
		}
	})
	return address
}
