package gproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	errorx "github.com/panjf2000/gnet/v2/pkg/errors"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

type logicalTestBudget struct {
	mu           sync.Mutex
	bytes, items int
	blocked      atomic.Bool
}

func (b *logicalTestBudget) callbacks() LogicalQueueBudget {
	return LogicalQueueBudget{
		Reserve: func(bytes, items int) bool {
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.blocked.Load() || b.bytes+bytes > 4<<20 || b.items+items > 1024 {
				return false
			}
			b.bytes += bytes
			b.items += items
			return true
		},
		Release: func(bytes, items int) {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.bytes -= bytes
			b.items -= items
			if b.bytes < 0 || b.items < 0 {
				panic("logical budget released twice")
			}
		},
	}
}

func (b *logicalTestBudget) assertEmpty(t *testing.T) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bytes != 0 || b.items != 0 {
		t.Errorf("retained budget after OnClosed: %d bytes, %d items", b.bytes, b.items)
	}
}

type logicalTestStream struct {
	stream        *LogicalStream
	owner         gnet.EventLoop
	input, output *logicalTestBudget
	closed        chan error
}

func logicalTestOwner(t *testing.T) gnet.EventLoop {
	t.Helper()
	_, socket := directTCPPair(t)
	engine, err := gnet.NewClient(&gnet.BuiltinEventEngine{})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	conn, err := engine.Enroll(socket)
	if err != nil {
		t.Fatal(err)
	}
	return conn.EventLoop()
}

func newLogicalTestStream(t *testing.T, handler *ProxyHandler, mutate func(*LogicalStreamOptions)) *logicalTestStream {
	t.Helper()
	x := &logicalTestStream{owner: logicalTestOwner(t), input: &logicalTestBudget{}, output: &logicalTestBudget{}, closed: make(chan error, 1)}
	opened := make(chan error, 1)
	options := LogicalStreamOptions{
		Owner: x.owner, ClientAddr: netip.MustParseAddrPort("198.51.100.9:0"),
		LocalAddr:     &net.TCPAddr{IP: net.IPv6zero, Port: 443},
		MaxInputBytes: 128 << 10, MaxInputItems: 512, MaxOutputBytes: 2 << 20, MaxOutputItems: 512,
		InputBudget: x.input.callbacks(), OutputBudget: x.output.callbacks(),
		Notify: func() {}, OnOpened: func(err error) { opened <- err }, OnClosed: func(err error) { x.closed <- err },
	}
	if mutate != nil {
		mutate(&options)
	}
	x.owner = options.Owner
	var err error
	x.stream, err = handler.OpenLogicalStream(options)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-opened:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("logical open timed out")
	}
	t.Cleanup(func() {
		_ = x.stream.Close()
		select {
		case <-x.closed:
		case <-time.After(5 * time.Second):
			t.Error("logical close did not acknowledge cleanup")
		}
		x.input.assertEmpty(t)
		x.output.assertEmpty(t)
	})
	return x
}

func runLogicalOwner(t *testing.T, owner gnet.EventLoop, run func()) {
	t.Helper()
	done := make(chan struct{})
	if err := owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error { run(); close(done); return nil })); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("logical owner did not run")
	}
}

func (x *logicalTestStream) write(t *testing.T, data []byte) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for len(data) > 0 {
		var n int
		var err error
		runLogicalOwner(t, x.owner, func() { n, err = x.stream.TryWrite(data) })
		if err != nil {
			t.Fatal(err)
		}
		data = data[n:]
		if n == 0 {
			if time.Now().After(deadline) {
				t.Fatal("logical write remained blocked")
			}
			time.Sleep(time.Millisecond)
		}
	}
}

func (x *logicalTestStream) read(t *testing.T, size int) []byte {
	t.Helper()
	out := make([]byte, size)
	offset := 0
	deadline := time.Now().Add(4 * time.Second)
	for offset < size {
		var n int
		var err error
		runLogicalOwner(t, x.owner, func() { n, err = x.stream.TryRead(out[offset:]) })
		if err != nil {
			t.Fatal(err)
		}
		offset += n
		if n == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("logical read remained blocked: %d/%d, state %s", offset, size, x.stream.ctx.State())
			}
			time.Sleep(time.Millisecond)
		}
	}
	return out
}

func (x *logicalTestStream) fakeTLSHello(t *testing.T, key []byte) {
	t.Helper()
	hello := buildTLSRecord(faketls.RecordTypeHandshake, buildValidClientHello(key, "example.com", bytes.Repeat([]byte{7}, 32)))
	x.write(t, hello)
	deadline := time.Now().Add(3 * time.Second)
	for x.stream.ctx.State() != StateReadO2Frame {
		if time.Now().After(deadline) {
			t.Fatalf("FakeTLS handshake state: %s", x.stream.ctx.State())
		}
		time.Sleep(time.Millisecond)
	}
	var size int
	runLogicalOwner(t, x.owner, func() { size = x.stream.ReadableBytes() })
	if size == 0 {
		t.Fatal("FakeTLS server handshake was not emitted")
	}
	_ = x.read(t, size)
}

func startLogicalDC(t *testing.T, handler *ProxyHandler, socket *net.TCPConn) {
	t.Helper()
	engine, err := gnet.NewClient(&dcEventHandler{proxy: handler}, gnet.WithSocketSendBuffer(4096))
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.stopDCClient() })
	handler.dcClient = engine
	handler.directDCDial = func(context.Context, int, obfuscated2.ConnectionType) (*directDCConn, error) {
		return &directDCConn{Conn: socket, encryptor: directTestCipher(t, 2), decryptor: directTestCipher(t, 3)}, nil
	}
}

func TestLogicalStreamDirectAuthenticatedDDAndEE(t *testing.T) {
	for _, mode := range []ProtocolMode{ModeDD, ModeEE} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			key := []byte("0123456789abcdef")
			handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "logical", Key: key, Host: "example.com"}}, TimeSkewTolerance: time.Minute}, &testLogger{})
			dcPeer, dcSocket := directTCPPair(t)
			startLogicalDC(t, handler, dcSocket)
			x := newLogicalTestStream(t, handler, nil)
			frame := buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate)
			_, _, responseCipher, requestCipher, err := obfuscated2.ParseClientFrameWithType(key, frame)
			if err != nil {
				t.Fatal(err)
			}
			plain := bytes.Repeat([]byte("ordered logical input"), 1000)
			wire := make([]byte, len(plain))
			requestCipher.XORKeyStream(wire, plain)
			if mode == ModeEE {
				x.fakeTLSHello(t, key)
				x.write(t, buildTLSRecord(faketls.RecordTypeApplicationData, append(bytes.Clone(frame), wire[:777]...)))
				for data := wire[777:]; len(data) > 0; {
					n := min(len(data), 16000)
					x.write(t, buildTLSRecord(faketls.RecordTypeApplicationData, data[:n]))
					data = data[n:]
				}
			} else {
				x.write(t, append(bytes.Clone(frame), wire...))
			}
			if err := dcPeer.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(plain))
			if _, err := io.ReadFull(dcPeer, got); err != nil {
				t.Fatal(err)
			}
			directTestCipher(t, 2).XORKeyStream(got, got)
			if !bytes.Equal(got, plain) {
				t.Fatal("logical uplink cipher order diverged")
			}
			response := bytes.Repeat([]byte("DC response"), 100)
			dcWire := make([]byte, len(response))
			directTestCipher(t, 3).XORKeyStream(dcWire, response)
			// A full external budget must not advance the downlink cipher.
			x.output.blocked.Store(true)
			if _, err := dcPeer.Write(dcWire); err != nil {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
			if x.stream.ReadableBytes() != 0 {
				t.Fatal("output ignored external budget")
			}
			x.output.blocked.Store(false)
			if mode == ModeEE {
				header := x.read(t, 5)
				got = x.read(t, int(binary.BigEndian.Uint16(header[3:5])))
			} else {
				got = x.read(t, len(response))
			}
			responseCipher.XORKeyStream(got, got)
			if !bytes.Equal(got, response) {
				t.Fatal("logical downlink changed across backpressure")
			}
			if real := x.stream.ctx.RealClientAddr(nil).String(); real != "198.51.100.9:0" {
				t.Fatalf("trusted identity = %s", real)
			}
		})
	}
}

func TestLogicalStreamMiddleEndUsesSharedReadyConsumer(t *testing.T) {
	for _, mode := range []ProtocolMode{ModeDD, ModeEE} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			handler, link, _, _, frame, responseCipher := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
			x := newLogicalTestStream(t, handler, nil)
			key := handler.config.Secrets[0].Key
			_, _, _, requestCipher, err := obfuscated2.ParseClientFrameWithType(key, frame)
			if err != nil {
				t.Fatal(err)
			}
			packet := validMiddleEndPacket()
			wire := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, packet, requestCipher)
			payload := append(bytes.Clone(frame), wire...)
			if mode == ModeEE {
				x.fakeTLSHello(t, key)
				payload = buildTLSRecord(faketls.RecordTypeApplicationData, payload)
			}
			x.write(t, payload)
			request, err := middleend.ParseProxyRequest(waitMiddleEndSubmission(t, link).Payload)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(request.Packet, packet) {
				t.Fatal("logical ME request differs")
			}
			var id int64
			runLogicalOwner(t, x.owner, func() { id = x.stream.ctx.middleEnd.binding.ConnectionID() })
			x.output.blocked.Store(true)
			answer := append(validMiddleEndPacket(), 1, 2, 3, 4)
			link.emit(middleend.LinkEvent{Kind: middleend.LinkEventProxyAnswer, ConnectionID: id, Packet: bytes.Clone(answer)})
			time.Sleep(20 * time.Millisecond)
			if x.stream.ReadableBytes() != 0 {
				t.Fatal("ME event ignored external output budget")
			}
			x.output.blocked.Store(false)
			var got []byte
			if mode == ModeEE {
				header := x.read(t, 5)
				got = x.read(t, int(binary.BigEndian.Uint16(header[3:5])))
			} else {
				got = x.read(t, 4+len(answer))
			}
			responseCipher.XORKeyStream(got, got)
			if binary.LittleEndian.Uint32(got[:4]) != uint32(len(answer)) || !bytes.Equal(got[4:], answer) {
				t.Fatal("ME output cipher or framing differs")
			}
		})
	}
}

func TestLogicalStreamCancelReservationAndAbortReleaseAllBudget(t *testing.T) {
	handler := NewProxyHandler(&Config{}, &testLogger{})
	x := newLogicalTestStream(t, handler, nil)
	native := newTestMockGnetConn()
	runLogicalOwner(t, x.owner, func() {
		toLogical := newRelayOutput(x.stream, native, x.stream.ctx, 1024)
		if toLogical.reserve(100, 100) != 100 {
			panic("reserve logical output")
		}
		toLogical.cancelReservation(100)
		fromLogical := newRelayOutput(native, x.stream, x.stream.ctx, 1024)
		if fromLogical.reserve(100, 100) != 100 {
			panic("reserve auxiliary input")
		}
		fromLogical.cancelReservation(100)
		_, _ = x.stream.Write([]byte("discard on abort"))
	})
	for range 100 {
		_ = x.stream.Close()
	}
}

func TestLogicalStreamCloseWaitsForDialAndPendingData(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "test", Key: key, Host: "example.com"}}, TimeSkewTolerance: time.Minute}, &testLogger{})
	entered, release := make(chan struct{}), make(chan struct{})
	handler.directDCDial = func(context.Context, int, obfuscated2.ConnectionType) (*directDCConn, error) {
		close(entered)
		<-release
		return nil, net.ErrClosed
	}
	x := newLogicalTestStream(t, handler, nil)
	x.fakeTLSHello(t, key)
	frame := buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate)
	x.write(t, buildTLSRecord(faketls.RecordTypeApplicationData, append(frame, bytes.Repeat([]byte{3}, 500)...)))
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("dial not entered")
	}
	_ = x.stream.Close()
	select {
	case <-x.closed:
		t.Fatal("OnClosed acknowledged active dial")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
}

func (x *logicalTestStream) awaitClosed(t *testing.T) {
	t.Helper()
	select {
	case err := <-x.closed:
		x.closed <- err
	case <-time.After(4 * time.Second):
		t.Fatal("logical stream did not close")
	}
}

func TestLogicalStreamHelloWaitsForOutputBudgetWithoutReplay(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "test", Key: key, Host: "example.com"}}, TimeSkewTolerance: time.Minute}, &testLogger{})
	x := newLogicalTestStream(t, handler, nil)
	x.output.blocked.Store(true)
	hello := buildTLSRecord(faketls.RecordTypeHandshake, buildValidClientHello(key, "example.com", bytes.Repeat([]byte{9}, 32)))
	x.write(t, hello)
	time.Sleep(20 * time.Millisecond)
	if x.stream.ReadableBytes() != 0 || x.stream.ctx.State() != StateReadTLSPayload {
		t.Fatal("blocked hello consumed authentication state")
	}
	x.output.blocked.Store(false)
	deadline := time.Now().Add(3 * time.Second)
	for x.stream.ctx.State() != StateReadO2Frame {
		if time.Now().After(deadline) {
			t.Fatal("hello did not resume")
		}
		time.Sleep(time.Millisecond)
	}
	if x.stream.ReadableBytes() == 0 {
		t.Fatal("resumed hello omitted response")
	}
	// The identical hello on another logical transport must use shared replay state.
	y := newLogicalTestStream(t, handler, nil)
	y.write(t, hello)
	y.awaitClosed(t)
}

func TestLogicalStreamAdmissionUsesTrustedRealIPAndReleasesSlot(t *testing.T) {
	handler := NewProxyHandler(&Config{MaxConnectionsPerIP: 1}, &testLogger{})
	x := newLogicalTestStream(t, handler, nil)
	opened, closed := make(chan error, 1), make(chan error, 1)
	options := x.stream.options
	options.OnOpened = func(err error) { opened <- err }
	options.OnClosed = func(err error) { closed <- err }
	if _, err := handler.OpenLogicalStream(options); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-opened:
		if err == nil {
			t.Fatal("same real IP bypassed admission")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("admission did not complete")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("rejected admission did not release")
	}
	_ = x.stream.Close()
	x.awaitClosed(t)
	_ = newLogicalTestStream(t, handler, nil)
}

type rejectingLogicalOwner struct {
	gnet.EventLoop
	reject atomic.Bool
}

func (owner *rejectingLogicalOwner) Execute(ctx context.Context, run gnet.Runnable) error {
	if owner.reject.Load() {
		return net.ErrClosed
	}
	return owner.EventLoop.Execute(ctx, run)
}

func TestLogicalStreamRejectedOwnerCloseCompletes(t *testing.T) {
	handler := NewProxyHandler(&Config{}, &testLogger{})
	var owner *rejectingLogicalOwner
	x := newLogicalTestStream(t, handler, func(options *LogicalStreamOptions) {
		owner = &rejectingLogicalOwner{EventLoop: options.Owner}
		options.Owner = owner
	})
	x.write(t, []byte{0x16})
	owner.reject.Store(true)
	if err := x.stream.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("rejected close = %v", err)
	}
	x.awaitClosed(t)
}

func TestLogicalStreamCloseBeforeOpenNotifiesExactlyOnce(t *testing.T) {
	handler := NewProxyHandler(&Config{}, &testLogger{})
	owner := &queuedIdleOwner{testMockEventLoop: &testMockEventLoop{}, queue: make(chan gnet.Runnable, 8)}
	budget := &logicalTestBudget{}
	var events []string
	x, err := handler.OpenLogicalStream(LogicalStreamOptions{
		Owner: owner, ClientAddr: netip.MustParseAddrPort("198.51.100.1:0"), LocalAddr: &net.TCPAddr{IP: net.IPv6zero, Port: 443},
		MaxInputBytes: 1024, MaxInputItems: 1, MaxOutputBytes: 1024, MaxOutputItems: 1,
		InputBudget: budget.callbacks(), OutputBudget: budget.callbacks(), Notify: func() {},
		OnOpened: func(err error) {
			if err == nil {
				t.Error("canceled open succeeded")
			}
			events = append(events, "opened")
		},
		OnClosed: func(error) { events = append(events, "closed") },
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		_ = x.Close()
	}
	if len(owner.queue) != 2 {
		t.Fatalf("uncoalesced close tasks: %d", len(owner.queue))
	}
	runIdleExpiry(t, owner)
	runIdleExpiry(t, owner)
	if fmt.Sprint(events) != "[opened closed]" || atomic.LoadInt64(&handler.activeConns) != 0 {
		t.Fatalf("canceled lifecycle = %v, active %d", events, handler.activeConns)
	}
	budget.assertEmpty(t)
}

func TestLogicalStreamCloseWaitsForQueuedUpstreamBuffer(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "test", Key: key}}}, &testLogger{})
	_, socket := directTCPPair(t)
	startLogicalDC(t, handler, socket)
	x := newLogicalTestStream(t, handler, nil)
	x.write(t, buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate))
	relay := awaitDirectRelay(t, x.stream.ctx)
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	t.Cleanup(finish)
	if err := relay.DCConn.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error { close(entered); <-release; return nil })); err != nil {
		t.Fatal(err)
	}
	<-entered
	x.write(t, bytes.Repeat([]byte{1}, 1024))
	deadline := time.Now().Add(3 * time.Second)
	for {
		relay.ToDC.mu.Lock()
		queued := relay.ToDC.queued
		relay.ToDC.mu.Unlock()
		if queued > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("uplink did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	_ = x.stream.Close()
	select {
	case err := <-x.closed:
		x.closed <- err
		t.Fatal("close acknowledged retained upstream write")
	case <-time.After(20 * time.Millisecond):
	}
	finish()
	x.awaitClosed(t)
}

func TestLogicalStreamBadInnerSecretPreservesSpliceTail(t *testing.T) {
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "test", Key: key}}, SpliceHost: "127.0.0.1", SplicePort: 443}, &testLogger{})
	peer, socket := directTCPPair(t)
	startLogicalDC(t, handler, socket)
	handler.spliceDial = func(context.Context, string) (net.Conn, error) { return socket, nil }
	x := newLogicalTestStream(t, handler, func(options *LogicalStreamOptions) { options.MaxOutputBytes = 128 })
	bad := buildDeterministicO2ClientFrame(t, []byte("different secret"), 2, obfuscated2.ConnectionTypeIntermediate)
	x.write(t, bad)
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(bad))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bad) {
		t.Fatal("bad inner secret did not preserve splice bytes")
	}
	x.output.blocked.Store(true)
	want := bytes.Repeat([]byte("retained EOF tail"), 20)
	if _, err := peer.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	x.output.blocked.Store(false)
	if got := x.read(t, len(want)); !bytes.Equal(got, want) {
		t.Fatal("splice tail was lost under logical output budget")
	}
	x.awaitClosed(t)
}

func TestLogicalStreamTooSmallMiddleEndOutputFailsPrecommit(t *testing.T) {
	handler, _, _, _, frame, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
	x := newLogicalTestStream(t, handler, func(options *LogicalStreamOptions) { options.MaxOutputBytes = 128 })
	x.write(t, frame)
	x.awaitClosed(t)
	if handler.middleEnd.middleEndCommits.Load() != 0 {
		t.Fatal("undersized logical output committed ME binding")
	}
}

type ownerAddressTestConn struct {
	*testMockGnetConn
	owner, violated atomic.Bool
}

func (c *ownerAddressTestConn) RemoteAddr() net.Addr {
	if !c.owner.Load() {
		c.violated.Store(true)
	}
	return c.testMockGnetConn.RemoteAddr()
}

func TestDirectActivationReadsNativeAddressOnOwner(t *testing.T) {
	handler := NewProxyHandler(&Config{}, &testLogger{})
	_, socket := directTCPPair(t)
	startLogicalDC(t, handler, socket)
	owner := &queuedIdleOwner{testMockEventLoop: &testMockEventLoop{}, queue: make(chan gnet.Runnable, 8)}
	conn := &ownerAddressTestConn{testMockGnetConn: newTestMockGnetConn()}
	conn.eventLoop = owner
	ctx := NewConnContext()
	ctx.encryptor, ctx.decryptor = &mockCipher{}, &mockCipher{}
	ctx.SetState(StateDialingDC)
	conn.SetContext(ctx)
	done := make(chan struct{})
	go func() { handler.dialDC(conn, ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("direct dial did not queue owner activation")
	}
	if conn.violated.Load() {
		t.Fatal("dial read native address outside owner")
	}
	conn.owner.Store(true)
	runIdleExpiry(t, owner)
	conn.owner.Store(false)
	ctx.SetState(StateClosed)
	if relay := ctx.Relay(); relay != nil {
		_ = relay.DCConn.Close()
	}
	ctx.Cleanup()
	if conn.violated.Load() {
		t.Fatal("native address escaped owner activation")
	}
}

func TestLogicalStreamCloseCancelsStalledSOCKSHandshake(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err == nil {
			accepted <- conn
		}
	}()
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "test", Key: key}}, Socks5Addr: listener.Addr().String()}, &testLogger{})
	x := newLogicalTestStream(t, handler, nil)
	x.write(t, buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate))
	var peer *net.TCPConn
	select {
	case peer = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS connection did not arrive")
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(peer, greeting); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(greeting, []byte{5, 1, 0}) {
		t.Fatalf("SOCKS greeting = %x", greeting)
	}
	// Never send the method selection. Closing the logical stream must cancel
	// the real SOCKS negotiation, not wait for an unrelated network timeout.
	_ = x.stream.Close()
	x.awaitClosed(t)
	if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("canceled SOCKS socket: n=%d err=%v", n, err)
	}
	if handler.handshakeFailures[handshakeFailureBackendDial].Load() != 0 {
		t.Fatal("client cancellation was counted as backend failure")
	}
}

func TestLogicalStreamOwnerStoppedRetiresAbandonedOutput(t *testing.T) {
	_, socket := directTCPPair(t)
	engine, err := gnet.NewClient(&gnet.BuiltinEventEngine{})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	stop := sync.OnceFunc(func() { _ = engine.Stop() })
	t.Cleanup(stop)
	conn, err := engine.Enroll(socket)
	if err != nil {
		t.Fatal(err)
	}
	owner := conn.EventLoop()
	handler := NewProxyHandler(&Config{}, &testLogger{})
	x := newLogicalTestStream(t, handler, func(options *LogicalStreamOptions) { options.Owner = owner })
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	if err := owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		close(entered)
		<-release
		return errorx.ErrEngineShutdown
	})); err != nil {
		t.Fatal(err)
	}
	<-entered
	output := newRelayOutput(x.stream, newTestMockGnetConn(), x.stream.ctx, 1024)
	if output.reserve(100, 100) != 100 {
		t.Fatal("output reservation failed")
	}
	var releases atomic.Int32
	if err := output.write(make([]byte, 100), func() { releases.Add(1) }); err != nil {
		t.Fatal(err)
	}
	if err := x.stream.Close(); err != nil {
		t.Fatal(err)
	}
	x.stream.tasksMu.Lock()
	queued := make([]*logicalTask, 0, len(x.stream.tasks))
	for task := range x.stream.tasks {
		queued = append(queued, task)
	}
	x.stream.tasksMu.Unlock()
	unblock()
	stop()
	x.stream.OwnerStopped()
	x.awaitClosed(t)
	for _, task := range queued {
		_ = task.Run(t.Context())
	}
	if releases.Load() != 1 {
		t.Fatalf("abandoned pooled output releases=%d", releases.Load())
	}
	x.stream.tasksMu.Lock()
	remaining := len(x.stream.tasks)
	x.stream.tasksMu.Unlock()
	if remaining != 0 {
		t.Fatalf("owner retirement retained %d tasks", remaining)
	}
	x.stream.OwnerStopped()
}

func TestLogicalStreamOwnerStoppedClosesUnactivatedDC(t *testing.T) {
	_, ownerSocket := directTCPPair(t)
	engine, err := gnet.NewClient(&gnet.BuiltinEventEngine{})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	stop := sync.OnceFunc(func() { _ = engine.Stop() })
	t.Cleanup(stop)
	ownerConn, err := engine.Enroll(ownerSocket)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{Secrets: []Secret{{Name: "test", Key: key}}}, &testLogger{})
	dcPeer, dcSocket := directTCPPair(t)
	startLogicalDC(t, handler, dcSocket)
	dial := handler.directDCDial
	dialEntered, dialRelease := make(chan struct{}), make(chan struct{})
	unblockDial := sync.OnceFunc(func() { close(dialRelease) })
	t.Cleanup(unblockDial)
	handler.directDCDial = func(ctx context.Context, id int, kind obfuscated2.ConnectionType) (*directDCConn, error) {
		close(dialEntered)
		<-dialRelease
		return dial(ctx, id, kind)
	}
	x := newLogicalTestStream(t, handler, func(options *LogicalStreamOptions) { options.Owner = ownerConn.EventLoop() })
	x.write(t, buildDeterministicO2ClientFrame(t, key, 2, obfuscated2.ConnectionTypeIntermediate))
	select {
	case <-dialEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not start")
	}
	ownerEntered, ownerRelease := make(chan struct{}), make(chan struct{})
	unblockOwner := sync.OnceFunc(func() { close(ownerRelease) })
	t.Cleanup(unblockOwner)
	if err := x.owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error { close(ownerEntered); <-ownerRelease; return errorx.ErrEngineShutdown })); err != nil {
		t.Fatal(err)
	}
	<-ownerEntered
	unblockDial()
	deadline := time.Now().Add(3 * time.Second)
	for {
		x.stream.tasksMu.Lock()
		queued := len(x.stream.tasks)
		x.stream.tasksMu.Unlock()
		if queued > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DC activation was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	unblockOwner()
	stop()
	x.stream.OwnerStopped()
	x.awaitClosed(t)
	if err := dcPeer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := dcPeer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("unactivated DC was not closed: n=%d err=%v", n, err)
	}
}
