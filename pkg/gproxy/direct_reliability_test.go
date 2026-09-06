package gproxy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// These pairs are real TCP sockets: both production event loops, enrollment,
// gnet buffers, asynchronous writes, and cipher ownership are exercised.
func directTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.AcceptTCP()
	if err != nil {
		peer.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close(); _ = accepted.Close() })
	return peer, accepted
}

type directClientTestHandler struct {
	*ProxyHandler
	waitEarlyTraffic <-chan struct{}
}

func (h *directClientTestHandler) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	ctx := c.Context().(*ConnContext)
	atomic.AddInt64(&h.activeConns, 1)
	go h.dialDC(c, ctx)
	if h.waitEarlyTraffic != nil {
		<-h.waitEarlyTraffic
	}
	return nil, gnet.None
}

type directEarlyTestHandler struct {
	*dcEventHandler
	early chan struct{}
	seen  atomic.Bool
}

func (h *directEarlyTestHandler) OnTraffic(c gnet.Conn) gnet.Action {
	action := h.dcEventHandler.OnTraffic(c)
	if h.seen.CompareAndSwap(false, true) {
		close(h.early)
	}
	return action
}

func startDirectRelay(t *testing.T, mode ProtocolMode, pending []byte, clientDecrypt, dcEncrypt, dcDecrypt, clientEncrypt cipher.Stream, limit int, earlyDC ...[]byte) (*net.TCPConn, *net.TCPConn, *ConnContext, gnet.Conn) {
	t.Helper()
	clientPeer, clientSocket := directTCPPair(t)
	dcPeer, dcSocket := directTCPPair(t)
	if err := dcSocket.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	proxy := NewProxyHandler(&Config{MaxWriteBuffer: limit}, &testLogger{})
	proxy.directDCDial = func(context.Context, int, obfuscated2.ConnectionType) (*directDCConn, error) {
		return &directDCConn{Conn: dcSocket, encryptor: dcEncrypt, decryptor: dcDecrypt}, nil
	}
	var dcHandler gnet.EventHandler = &dcEventHandler{proxy: proxy}
	var early <-chan struct{}
	if len(earlyDC) > 0 {
		signal := make(chan struct{})
		early = signal
		dcHandler = &directEarlyTestHandler{dcEventHandler: &dcEventHandler{proxy: proxy}, early: signal}
		if _, err := dcPeer.Write(earlyDC[0]); err != nil {
			t.Fatal(err)
		}
	}
	dcClient, err := gnet.NewClient(dcHandler, gnet.WithSocketSendBuffer(4096))
	if err != nil {
		t.Fatal(err)
	}
	if err := dcClient.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.stopDCClient() })
	proxy.dcClient = dcClient
	clientEngine, err := gnet.NewClient(&directClientTestHandler{ProxyHandler: proxy, waitEarlyTraffic: early}, gnet.WithReadBufferCap(256*1024), gnet.WithSocketSendBuffer(4096))
	if err != nil {
		t.Fatal(err)
	}
	if err := clientEngine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientEngine.Stop() })
	ctx := NewConnContext()
	ctx.protocolMode = mode
	ctx.decryptor = clientDecrypt
	ctx.encryptor = clientEncrypt
	ctx.pendingData = pending
	ctx.SetState(StateDialingDC)
	clientConn, err := clientEngine.EnrollContext(clientSocket, ctx)
	if err != nil {
		t.Fatal(err)
	}
	return clientPeer, dcPeer, ctx, clientConn
}

func TestDirectRelayBuffersDCDataBeforeActivation(t *testing.T) {
	plain := bytes.Repeat([]byte("early DC data"), 100)
	dcWire := make([]byte, len(plain))
	directTestCipher(t, 3).XORKeyStream(dcWire, plain)
	want := make([]byte, len(plain))
	directTestCipher(t, 4).XORKeyStream(want, plain)
	client, _, ctx, _ := startDirectRelay(t, ModeDD, nil,
		directTestCipher(t, 1), directTestCipher(t, 2), directTestCipher(t, 3), directTestCipher(t, 4), 256*1024, dcWire)
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("DC bytes arriving before activation were lost or corrupted")
	}
	if ctx.State() != StateRelaying {
		t.Fatalf("early data interrupted enrollment: %s", ctx.State())
	}
}

func TestDirectRelayStalledSocketResumesAfterDrain(t *testing.T) {
	const limit = 256 * 1024
	client, dc, ctx, _ := startDirectRelay(t, ModeDD, nil, &mockCipher{}, &mockCipher{}, &mockCipher{}, &mockCipher{}, limit)
	relay := awaitDirectRelay(t, ctx)
	if err := dc.SetReadBuffer(64 * 1024); err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte("direct-stall-"), 1000)
	var want []byte
	deadline := time.Now().Add(4 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("destination did not reach its output limit")
		}
		if _, err := client.Write(chunk); err != nil {
			t.Fatal(err)
		}
		want = append(want, chunk...)
		// Allow the receiving loop to deliver this small burst before another
		// is submitted. The test stops sending once backpressure is reached.
		time.Sleep(2 * time.Millisecond)
		relay.ToDC.mu.Lock()
		queued, buffered, waiting := relay.ToDC.queued, relay.ToDC.buffered, relay.ToDC.waiting
		relay.ToDC.mu.Unlock()
		if queued+buffered > limit {
			t.Fatalf("output grew beyond limit: queued %d buffered %d", queued, buffered)
		}
		if waiting > 0 && queued+buffered > 0 && relaySocketBackpressured(t, relay.ToDC, deadline) {
			break
		}
	}
	if err := dc.SetReadBuffer(256 * 1024); err != nil {
		t.Fatal(err)
	}
	if err := dc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if n, err := io.ReadFull(dc, got); err != nil {
		relay.ToDC.mu.Lock()
		queued, buffered, waiting := relay.ToDC.queued, relay.ToDC.buffered, relay.ToDC.waiting
		relay.ToDC.mu.Unlock()
		t.Fatalf("read %d/%d, queued %d buffered %d waiting %d state %s: %v", n, len(got), queued, buffered, waiting, ctx.State(), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("socket drain did not resume the buffered input in order")
	}
}

// Owned writes remain charged in queued until their final byte drains. Check
// the actual socket on its owner after earlier HIGH submissions, so a stalled
// task queue alone cannot satisfy these socket-backpressure fixtures.
func relaySocketBackpressured(t *testing.T, output *relayOutput, deadline time.Time) bool {
	t.Helper()
	for {
		var retained, waiting, socketBuffered int
		runLogicalOwner(t, clientOwner(output.destination), func() {
			socketBuffered = output.destination.OutboundBuffered()
			output.mu.Lock()
			retained, waiting = output.queued+output.buffered, output.waiting
			output.mu.Unlock()
		})
		if retained > output.limit {
			t.Fatalf("socket output exceeded retained limit: %d > %d", retained, output.limit)
		}
		if waiting == 0 || retained == 0 {
			return false
		}
		if socketBuffered > 0 {
			return true
		}
		if time.Now().After(deadline) {
			t.Fatal("pending relay submissions did not reach the socket owner")
		}
		// Do not inject another burst while reservations are still blocked.
		time.Sleep(time.Millisecond)
	}
}

func directTestCipher(t *testing.T, seed byte) cipher.Stream {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{seed}, aes.BlockSize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher.NewCTR(block, make([]byte, aes.BlockSize))
}

func awaitDirectRelay(t *testing.T, ctx *ConnContext) *RelayContext {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if ctx.State() == StateRelaying {
			return ctx.Relay()
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("direct relay did not activate, state %s", ctx.State())
		}
	}
}

func TestDirectRelayPendingBytesPrecedeLaterTraffic(t *testing.T) {
	for name, mode := range map[string]ProtocolMode{"dd": ModeDD, "ee": ModeEE} {
		t.Run(name, func(t *testing.T) {
			plain := bytes.Repeat([]byte("ordered cipher state"), 4000)
			clientWire := make([]byte, len(plain))
			directTestCipher(t, 1).XORKeyStream(clientWire, plain)
			want := make([]byte, len(plain))
			directTestCipher(t, 2).XORKeyStream(want, plain)
			pendingLen := 777
			client, dc, ctx, _ := startDirectRelay(t, mode, bytes.Clone(clientWire[:pendingLen]),
				directTestCipher(t, 1), directTestCipher(t, 2), directTestCipher(t, 3), directTestCipher(t, 4), 256*1024)
			if err := dc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			uplink := clientWire[pendingLen:]
			if mode == ModeEE {
				var framed []byte
				for len(uplink) > 0 {
					n := min(len(uplink), 16000)
					framed = append(framed, buildTLSApplicationData(uplink[:n])...)
					uplink = uplink[n:]
				}
				uplink = framed
			}
			if _, err := client.Write(uplink); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(want))
			if _, err := io.ReadFull(dc, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("pending bytes were reordered or cipher state diverged")
			}
			if ctx.State() != StateRelaying {
				t.Fatalf("relay closed unexpectedly: %s", ctx.State())
			}
		})
	}
}

func TestDirectRelayQueuedWritesStayBoundedAndKeepBuffers(t *testing.T) {
	const limit = 4 * relayBatchSize
	client, dc, ctx, _ := startDirectRelay(t, ModeDD, nil, &mockCipher{}, &mockCipher{}, &mockCipher{}, &mockCipher{}, limit)
	relay := awaitDirectRelay(t, ctx)
	blocked := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce atomic.Bool
	unblock := func() {
		if releaseOnce.CompareAndSwap(false, true) {
			close(release)
		}
	}
	t.Cleanup(unblock)
	if err := relay.DCConn.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		close(blocked)
		<-release
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	<-blocked
	// The DC loop cannot copy these buffers while the client loop continues
	// processing input larger than the fixed-size pool buffer.
	payload := make([]byte, limit+4096)
	for i := range payload {
		payload[i] = byte(i*31 + i/251)
	}
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		relay.ToDC.mu.Lock()
		queued, buffered, waiting := relay.ToDC.queued, relay.ToDC.buffered, relay.ToDC.waiting
		relay.ToDC.mu.Unlock()
		if queued+buffered > limit {
			t.Fatalf("output retained %d bytes above limit %d", queued+buffered, limit)
		}
		if waiting > 0 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("relay did not reach bounded backpressure")
		case <-time.After(time.Millisecond):
		}
	}
	unblock()
	if err := dc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(dc, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("in-flight pooled buffers were reused or later input failed to resume")
	}
}

func TestDirectRelayBoundsTinyPendingWrites(t *testing.T) {
	_, dc, ctx, _ := startDirectRelay(t, ModeDD, nil, &mockCipher{}, &mockCipher{}, &mockCipher{}, &mockCipher{}, 256*1024)
	relay := awaitDirectRelay(t, ctx)
	blocked := make(chan struct{})
	release := make(chan struct{})
	var released atomic.Bool
	unblock := func() {
		if released.CompareAndSwap(false, true) {
			close(release)
		}
	}
	t.Cleanup(unblock)
	if err := relay.DCConn.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		close(blocked)
		<-release
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	<-blocked
	for range relayMaxPendingWrites {
		if relay.ToDC.reserve(1, 1) != 1 {
			t.Fatal("tiny write was rejected before the item limit")
		}
		if err := relay.ToDC.write([]byte{0x5a}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if relay.ToDC.reserve(1, 1) != 0 {
		t.Fatal("queue metadata must be bounded even with remaining byte capacity")
	}
	unblock()
	if err := dc.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, relayMaxPendingWrites)
	if _, err := io.ReadFull(dc, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x5a}, relayMaxPendingWrites)) {
		t.Fatal("bounded tiny writes were not delivered")
	}
}
