package gproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

type spliceTestClient struct {
	peer  *net.TCPConn
	conn  gnet.Conn
	ctx   *ConnContext
	local net.Addr
}

type spliceTestHandler struct {
	*ProxyHandler
	opened   chan spliceTestClient
	realAddr net.Addr
}

func (handler *spliceTestHandler) OnOpen(conn gnet.Conn) ([]byte, gnet.Action) {
	_, action := handler.ProxyHandler.OnOpen(conn)
	if action != gnet.None {
		return nil, action
	}
	ctx := conn.Context().(*ConnContext)
	if handler.realAddr != nil {
		ctx.SetRealClientAddr(handler.realAddr)
	}
	action = handler.startSplice(conn, ctx)
	handler.opened <- spliceTestClient{conn: conn, ctx: ctx, local: conn.LocalAddr()}
	return nil, action
}

type spliceTestServer struct {
	handler *spliceTestHandler
	engine  *gnet.Client
}

func newSpliceTestServer(t *testing.T, config Config, dial func(context.Context, string) (net.Conn, error), realAddr net.Addr) *spliceTestServer {
	t.Helper()
	config.SpliceHost = "127.0.0.1"
	config.SplicePort = 443
	proxy := NewProxyHandler(&config, &testLogger{})
	proxy.spliceDial = dial
	upstreams, err := gnet.NewClient(&dcEventHandler{proxy: proxy}, gnet.WithSocketSendBuffer(4096))
	if err != nil {
		t.Fatal(err)
	}
	if err := upstreams.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.stopDCClient() })
	proxy.dcClient = upstreams
	handler := &spliceTestHandler{ProxyHandler: proxy, opened: make(chan spliceTestClient, 4), realAddr: realAddr}
	engine, err := gnet.NewClient(handler, gnet.WithReadBufferCap(64*1024), gnet.WithSocketSendBuffer(4096))
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	return &spliceTestServer{handler: handler, engine: engine}
}

func (server *spliceTestServer) connect(t *testing.T) spliceTestClient {
	t.Helper()
	peer, accepted := directTCPPair(t)
	if _, err := server.engine.Enroll(accepted); err != nil {
		t.Fatal(err)
	}
	select {
	case client := <-server.handler.opened:
		client.peer = peer
		return client
	case <-time.After(5 * time.Second):
		t.Fatal("splice client did not open")
		return spliceTestClient{}
	}
}

func awaitSpliceCondition(t *testing.T, description string, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", description)
		}
	}
}

func onSpliceClient(t *testing.T, client spliceTestClient, check func()) {
	t.Helper()
	done := make(chan struct{})
	if err := client.conn.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		check()
		close(done)
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("splice client owner did not run")
	}
}

func TestSpliceGnetCleanEOFDrainsBufferedTail(t *testing.T) {
	backend, socket := directTCPPair(t)
	server := newSpliceTestServer(t, Config{MaxWriteBuffer: 1024 * 1024},
		func(context.Context, string) (net.Conn, error) { return socket, nil }, nil)
	client := server.connect(t)
	if err := client.peer.SetReadBuffer(64 * 1024); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("nginx-TLS-response-"), 90000)
	written := make(chan error, 1)
	go func() {
		_, err := backend.Write(payload)
		if closeErr := backend.CloseWrite(); err == nil {
			err = closeErr
		}
		written <- err
	}()
	awaitSpliceCondition(t, "upstream EOF handoff", client.ctx.spliceDrainRequested.Load)
	var tailSize, buffered int
	onSpliceClient(t, client, func() {
		tailSize = len(client.ctx.spliceDrainTail)
		buffered = client.conn.OutboundBuffered()
	})
	if tailSize == 0 {
		t.Fatal("fixture did not retain an EOF tail under client backpressure")
	}
	if tailSize > server.handler.maxWriteBuffer || buffered > server.handler.maxWriteBuffer {
		t.Fatalf("unbounded EOF drain: tail %d, output %d", tailSize, buffered)
	}
	if err := client.peer.SetReadBuffer(256 * 1024); err != nil {
		t.Fatal(err)
	}
	if err := client.peer.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client.peer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("splice EOF delivered %d bytes, want exact %d", len(got), len(payload))
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend writer did not exit")
	}
	awaitSpliceCondition(t, "splice cleanup", func() bool { return client.ctx.State() == StateClosed })
}

func TestSpliceGnetProxyHeaderPrecedesBufferedClientBytes(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			backend, socket := directTCPPair(t)
			release := make(chan struct{})
			var released atomic.Bool
			unblock := func() {
				if released.CompareAndSwap(false, true) {
					close(release)
				}
			}
			t.Cleanup(unblock)
			realAddr := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 17), Port: 32123}
			server := newSpliceTestServer(t, Config{SpliceProxyProtocol: version},
				func(ctx context.Context, _ string) (net.Conn, error) {
					select {
					case <-release:
						return socket, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}, realAddr)
			client := server.connect(t)
			payload := bytes.Repeat([]byte{0x16, 0x03, 0x03, 0x00, 0x01, 0x00}, 2000)
			if _, err := client.peer.Write(payload); err != nil {
				t.Fatal(err)
			}
			unblock()
			want := append(buildProxyProtocolHeader(version, realAddr, client.local), payload...)
			if err := backend.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(want))
			if _, err := io.ReadFull(backend, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("splice changed the PROXY tuple or reordered buffered TLS bytes")
			}
		})
	}
}

func TestSpliceGnetStalledNginxDoesNotBlockAnotherClient(t *testing.T) {
	firstBackend, firstSocket := directTCPPair(t)
	secondBackend, secondSocket := directTCPPair(t)
	if err := firstBackend.SetReadBuffer(64 * 1024); err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int64
	server := newSpliceTestServer(t, Config{MaxWriteBuffer: 256 * 1024},
		func(context.Context, string) (net.Conn, error) {
			if dials.Add(1) == 1 {
				return firstSocket, nil
			}
			return secondSocket, nil
		}, nil)
	first := server.connect(t)
	awaitSpliceCondition(t, "first splice activation", func() bool {
		splice := first.ctx.splice.Load()
		return splice != nil && splice.active.Load()
	})
	output := first.ctx.splice.Load().upstream.Load().output
	chunk := bytes.Repeat([]byte("stalled-nginx-"), 1000)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := first.peer.SetWriteDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if _, err := first.peer.Write(chunk); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
		output.mu.Lock()
		queued, buffered, waiting := output.queued, output.buffered, output.waiting
		output.mu.Unlock()
		if queued+buffered > server.handler.maxWriteBuffer {
			t.Fatalf("stalled splice output exceeded bound: %d", queued+buffered)
		}
		if waiting > 0 && queued+buffered > 0 && relaySocketBackpressured(t, output, deadline) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture did not backpressure the stalled Nginx socket")
		}
	}
	second := server.connect(t)
	marker := []byte("another client on the same gnet loop")
	if _, err := second.peer.Write(marker); err != nil {
		t.Fatal(err)
	}
	if err := secondBackend.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(marker))
	if _, err := io.ReadFull(secondBackend, got); err != nil || !bytes.Equal(got, marker) {
		t.Fatalf("unrelated client stopped progressing: %q, %v", got, err)
	}
}

func TestSpliceGnetClientCloseCancelsDial(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	server := newSpliceTestServer(t, Config{}, func(ctx context.Context, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}, nil)
	client := server.connect(t)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("splice dial did not start")
	}
	if err := client.peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("client cancellation did not stop splice dial")
	}
	awaitSpliceCondition(t, "splice admission release", func() bool {
		return atomic.LoadInt64(&server.handler.activeConns) == 0
	})
}

func TestSpliceGnetLateDialClosesReturnedSocket(t *testing.T) {
	backend, socket := directTCPPair(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var released atomic.Bool
	unblock := func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	}
	t.Cleanup(unblock)
	server := newSpliceTestServer(t, Config{}, func(context.Context, string) (net.Conn, error) {
		close(started)
		<-release
		return socket, nil
	}, nil)
	client := server.connect(t)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("splice dial did not start")
	}
	if err := client.peer.Close(); err != nil {
		t.Fatal(err)
	}
	awaitSpliceCondition(t, "client closure before dial completion", func() bool { return client.ctx.State() == StateClosed })
	unblock()
	if err := backend.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := backend.Read(got[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("late dial socket was retained after cancellation: %v", err)
	}
}

func TestSpliceGnetClientCancellationClosesUpstream(t *testing.T) {
	backend, socket := directTCPPair(t)
	server := newSpliceTestServer(t, Config{},
		func(context.Context, string) (net.Conn, error) { return socket, nil }, nil)
	client := server.connect(t)
	awaitSpliceCondition(t, "splice activation", func() bool {
		splice := client.ctx.splice.Load()
		return splice != nil && splice.active.Load()
	})
	if err := client.peer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := backend.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := backend.Read(got[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("client close retained splice upstream: %v", err)
	}
}

func TestSpliceGnetUpstreamResetClosesClient(t *testing.T) {
	backend, socket := directTCPPair(t)
	server := newSpliceTestServer(t, Config{},
		func(context.Context, string) (net.Conn, error) { return socket, nil }, nil)
	client := server.connect(t)
	awaitSpliceCondition(t, "splice activation", func() bool {
		splice := client.ctx.splice.Load()
		return splice != nil && splice.active.Load()
	})
	if err := backend.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var got [1]byte
	if _, err := client.peer.Read(got[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("upstream reset retained splice client: %v", err)
	}
}

func TestSpliceGnetEarlyEOFKeepsBytesBeforeActivation(t *testing.T) {
	backend, socket := directTCPPair(t)
	releaseDial := make(chan struct{})
	releaseOwner := make(chan struct{})
	var dialReleased, ownerReleased atomic.Bool
	unblockDial := func() {
		if dialReleased.CompareAndSwap(false, true) {
			close(releaseDial)
		}
	}
	unblockOwner := func() {
		if ownerReleased.CompareAndSwap(false, true) {
			close(releaseOwner)
		}
	}
	server := newSpliceTestServer(t, Config{},
		func(ctx context.Context, _ string) (net.Conn, error) {
			select {
			case <-releaseDial:
				return socket, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}, nil)
	client := server.connect(t)
	t.Cleanup(unblockDial)
	t.Cleanup(unblockOwner)
	ownerBlocked := make(chan struct{})
	if err := client.conn.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		close(ownerBlocked)
		<-releaseOwner
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ownerBlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("client owner did not pause")
	}
	payload := []byte("early Nginx TLS response before client activation")
	if _, err := backend.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := backend.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	splice := client.ctx.splice.Load()
	unblockDial()
	awaitSpliceCondition(t, "early upstream EOF", splice.closed.Load)
	if splice.active.Load() {
		t.Fatal("fixture activated before the early EOF")
	}
	unblockOwner()
	if err := client.peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client.peer)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("early EOF response = %q, %v; want %q", got, err, payload)
	}
}

func TestSpliceGnetIdleTimeoutClosesBothSockets(t *testing.T) {
	backend, socket := directTCPPair(t)
	server := newSpliceTestServer(t, Config{SpliceIdleTimeout: 120 * time.Millisecond},
		func(context.Context, string) (net.Conn, error) { return socket, nil }, nil)
	client := server.connect(t)
	for _, conn := range []net.Conn{client.peer, backend} {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var got [1]byte
		if _, err := conn.Read(got[:]); !errors.Is(err, io.EOF) {
			t.Fatalf("idle splice socket read = %v, want EOF", err)
		}
	}
}
