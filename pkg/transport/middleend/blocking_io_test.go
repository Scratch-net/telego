package middleend

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBootstrapBlockingAcceptsCompleteHandshakeWithTerminalReadError(t *testing.T) {
	conn := newScriptedMEConn()
	conn.handshakeReadErr = io.EOF
	bootstrap := newTestBootstrap(t)
	link, err := BootstrapBlocking(t.Context(), conn, bootstrap)
	if err != nil {
		t.Fatalf("BootstrapBlocking: %v", err)
	}
	if !link.bootstrap.Ready() {
		t.Fatal("complete handshake did not make link ready")
	}
	if !errors.Is(link.pendingReadErr, io.EOF) {
		t.Fatalf("pending read error = %v, want EOF", link.pendingReadErr)
	}
	if _, err := link.ReadFrame(t.Context()); !errors.Is(err, io.EOF) {
		t.Fatalf("next ReadFrame error = %v, want EOF", err)
	}
	if !conn.isClosed() {
		t.Fatal("terminal read error did not close link when more bytes were required")
	}
	if !bootstrap.Ready() || bootstrap.err != nil {
		t.Fatalf("post-ready EOF retired bootstrap: stage=%d error=%v", bootstrap.stage, bootstrap.err)
	}
}

func TestBlockingClientLinkAcceptsCompletePongWithTerminalReadError(t *testing.T) {
	conn := newScriptedMEConn()
	conn.pongReadErr = io.EOF
	link, err := BootstrapBlocking(t.Context(), conn, newTestBootstrap(t))
	if err != nil {
		t.Fatalf("BootstrapBlocking: %v", err)
	}
	if err := link.Ping(t.Context(), 0x0102030405060708); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !errors.Is(link.pendingReadErr, io.EOF) {
		t.Fatalf("pending read error = %v, want EOF", link.pendingReadErr)
	}
	if _, err := link.ReadFrame(t.Context()); !errors.Is(err, io.EOF) {
		t.Fatalf("next ReadFrame error = %v, want EOF", err)
	}
}

func TestBootstrapBlockingRejectsIncompleteBytesBeforeTerminalReadError(t *testing.T) {
	conn := newScriptedMEConn()
	conn.incompleteNonce = true
	bootstrap := newTestBootstrap(t)
	_, err := BootstrapBlocking(t.Context(), conn, bootstrap)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("BootstrapBlocking error = %v, want EOF", err)
	}
	if !conn.isClosed() {
		t.Fatal("incomplete terminal stream did not close")
	}
	assertBootstrapRetiredAfterTransportFailure(t, bootstrap, io.EOF)
}

func TestBootstrapBlockingWriteNWithErrorRemainsTerminal(t *testing.T) {
	conn := newScriptedMEConn()
	conn.writeErrorAt = 1
	conn.writeError = io.EOF
	conn.writeCountBeforeError = NoncePacketSize + FullFrameOverhead
	bootstrap := newTestBootstrap(t)
	_, err := BootstrapBlocking(t.Context(), conn, bootstrap)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("BootstrapBlocking error = %v, want EOF", err)
	}
	if got := conn.firstWriteSize(); got != NoncePacketSize+FullFrameOverhead {
		t.Fatalf("first write delivered %d bytes", got)
	}
	if !conn.isClosed() {
		t.Fatal("write n>0,error did not close")
	}
	assertBootstrapRetiredAfterTransportFailure(t, bootstrap, io.EOF)
}

func TestBootstrapBlockingCancellationPermanentlyFailsCallerBootstrap(t *testing.T) {
	conn := newBlockingReadConn()
	bootstrap := newTestBootstrap(t)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := BootstrapBlocking(ctx, conn, bootstrap)
		result <- err
	}()
	<-conn.readStarted
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("BootstrapBlocking error = %v, want cancellation", err)
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("cancellation did not close connection")
	}
	assertBootstrapRetiredAfterTransportFailure(t, bootstrap, context.Canceled)
}

func TestBootstrapBlockingPreservesProtocolErrorDuringCancellation(t *testing.T) {
	conn := newScriptedMEConn()
	conn.corruptNonce = true
	ctx, cancel := context.WithCancel(t.Context())
	conn.beforeReadReturn = cancel
	_, err := BootstrapBlocking(ctx, conn, newTestBootstrap(t))
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("BootstrapBlocking error = %v, want checksum mismatch", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("protocol error was replaced by cancellation: %v", err)
	}
}

func TestBlockingCancellationClassificationStress(t *testing.T) {
	const iterations = 1024
	for range iterations {
		conn := newBlockingReadConn()
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		bootstrap := newTestBootstrap(t)
		go func() {
			_, err := BootstrapBlocking(ctx, conn, bootstrap)
			result <- err
		}()
		<-conn.readStarted
		cancel()
		err := <-result
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v", err)
		}
		if strings.Contains(err.Error(), "%!w(<nil>)") {
			t.Fatalf("cancellation wrapped nil: %v", err)
		}
	}
}

func TestBlockingDeadlineClassificationStress(t *testing.T) {
	const iterations = 512
	errorsFound := make(chan error, iterations)
	var waitGroup sync.WaitGroup
	for range iterations {
		bootstrap := newTestBootstrap(t)
		waitGroup.Go(func() {
			conn := newBlockingReadConn()
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			_, err := BootstrapBlocking(ctx, conn, bootstrap)
			errorsFound <- err
		})
	}
	waitGroup.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline error = %v", err)
		}
		if strings.Contains(err.Error(), "%!w(<nil>)") {
			t.Fatalf("deadline wrapped nil: %v", err)
		}
	}
}

func assertBootstrapRetiredAfterTransportFailure(t *testing.T, bootstrap *ClientBootstrap, target error) {
	t.Helper()
	if bootstrap.err == nil || !errors.Is(bootstrap.err, target) {
		t.Fatalf("sticky bootstrap error = %v, want %v", bootstrap.err, target)
	}
	sticky := bootstrap.err
	if bootstrap.stage != clientBootstrapFailed || bootstrap.Ready() {
		t.Fatalf("bootstrap stage=%d ready=%v, want permanently failed", bootstrap.stage, bootstrap.Ready())
	}
	if err := bootstrap.Finish(); err != sticky {
		t.Fatalf("Finish error = %v, want original sticky error %v", err, sticky)
	}
	if wire, err := bootstrap.Start(); len(wire) != 0 || err != sticky {
		t.Fatalf("Start after failure = %d bytes, %v; want sticky error %v", len(wire), err, sticky)
	}
	if consumed, update, err := bootstrap.Feed([]byte{1, 2, 3, 4}); consumed != 0 || len(update.Outbound) != 0 || len(update.Frames) != 0 || err != sticky {
		t.Fatalf("Feed after failure = consumed %d, update %+v, error %v; want sticky error %v", consumed, update, err, sticky)
	}
	if wire, err := bootstrap.Encode([]byte{1, 2, 3, 4}); len(wire) != 0 || err != sticky {
		t.Fatalf("Encode after failure = %d bytes, %v; want sticky error %v", len(wire), err, sticky)
	}
	if bootstrap.config.Secret != nil || bootstrap.config.NonceSource != nil ||
		bootstrap.config.ServerAddr.IsValid() || bootstrap.config.ClientAddr.IsValid() ||
		bootstrap.config.LocalProcessID != (ProcessID{}) || bootstrap.config.ClientTimestamp != 0 {
		t.Fatalf("bootstrap retained connection config: %+v", bootstrap.config)
	}
	if bootstrap.selector != 0 || bootstrap.clientNonce != ([16]byte{}) || bootstrap.nonceBuffer != nil {
		t.Fatal("bootstrap retained selector, client nonce, or nonce buffer")
	}
	if bootstrap.encoder != nil || bootstrap.decoder != nil || bootstrap.encrypter != nil || bootstrap.decrypter != nil {
		t.Fatal("bootstrap retained framing or cipher state")
	}
	if bootstrap.localHandshake != (HandshakePacket{}) || bootstrap.remoteProcessID != (ProcessID{}) {
		t.Fatal("bootstrap retained handshake process state")
	}
}

type scriptedRead struct {
	data []byte
	err  error
}

type scriptedMEConn struct {
	mu                    sync.Mutex
	reads                 []scriptedRead
	server                *runtimeTestServer
	writes                [][]byte
	closed                bool
	handshakeReadErr      error
	pongReadErr           error
	incompleteNonce       bool
	writeErrorAt          int
	writeError            error
	writeCountBeforeError int
	beforeReadReturn      func()
	corruptNonce          bool
}

func newScriptedMEConn() *scriptedMEConn {
	return &scriptedMEConn{}
}

func (c *scriptedMEConn) Read(destination []byte) (int, error) {
	c.mu.Lock()
	if len(c.reads) == 0 {
		if c.closed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		c.mu.Unlock()
		return 0, io.EOF
	}
	result := c.reads[0]
	c.reads[0] = scriptedRead{}
	c.reads = c.reads[1:]
	beforeReturn := c.beforeReadReturn
	c.beforeReadReturn = nil
	c.mu.Unlock()
	read := copy(destination, result.data)
	if read != len(result.data) {
		return read, io.ErrShortBuffer
	}
	if beforeReturn != nil {
		beforeReturn()
	}
	return read, result.err
}

func (c *scriptedMEConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	writeNumber := len(c.writes) + 1
	if c.writeErrorAt == writeNumber {
		written := min(c.writeCountBeforeError, len(data))
		c.writes = append(c.writes, bytes.Clone(data[:written]))
		return written, c.writeError
	}
	c.writes = append(c.writes, bytes.Clone(data))

	var err error
	switch writeNumber {
	case 1:
		c.server, err = newRuntimeTestServer(data)
		if err == nil {
			nonce := bytes.Clone(c.server.nonceWire)
			terminalErr := error(nil)
			if c.corruptNonce {
				nonce[len(nonce)-1] ^= 0xff
			}
			if c.incompleteNonce {
				nonce = nonce[:10]
				terminalErr = io.EOF
			}
			c.reads = append(c.reads, scriptedRead{data: bytes.Clone(nonce), err: terminalErr})
		}
	case 2:
		err = c.server.acceptClientHandshakeRuntime(data)
		if err == nil {
			var handshake []byte
			handshake, err = c.server.encodeHandshakeRuntime(HandshakePacket{
				Flags: HandshakeFlagCRC32C, Sender: ProcessID{IP: 0x08080808, Port: 443, PID: 71, Uptime: 12345},
				Peer: testLocalProcessID(),
			})
			if err == nil {
				c.reads = append(c.reads, scriptedRead{data: handshake, err: c.handshakeReadErr})
			}
		}
	case 3:
		var frame Frame
		frame, err = c.server.decodePayloadRuntime(data)
		if err == nil {
			var ping Ping
			ping, err = ParsePing(frame.Payload)
			if err == nil {
				var pong []byte
				pong, err = c.server.encodePayloadRuntime(Pong(ping).MarshalBinary())
				if err == nil {
					c.reads = append(c.reads, scriptedRead{data: pong, err: c.pongReadErr})
				}
			}
		}
	}
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

func (c *scriptedMEConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *scriptedMEConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *scriptedMEConn) firstWriteSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writes) == 0 {
		return 0
	}
	return len(c.writes[0])
}

func (*scriptedMEConn) LocalAddr() net.Addr              { return dummyNetAddr("local") }
func (*scriptedMEConn) RemoteAddr() net.Addr             { return dummyNetAddr("remote") }
func (*scriptedMEConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedMEConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedMEConn) SetWriteDeadline(time.Time) error { return nil }

type blockingReadConn struct {
	readStarted chan struct{}
	closed      chan struct{}
	readOnce    sync.Once
	closeOnce   sync.Once
}

func newBlockingReadConn() *blockingReadConn {
	return &blockingReadConn{readStarted: make(chan struct{}), closed: make(chan struct{})}
}

func (c *blockingReadConn) Read([]byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (*blockingReadConn) Write(data []byte) (int, error) { return len(data), nil }
func (c *blockingReadConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (*blockingReadConn) LocalAddr() net.Addr              { return dummyNetAddr("local") }
func (*blockingReadConn) RemoteAddr() net.Addr             { return dummyNetAddr("remote") }
func (*blockingReadConn) SetDeadline(time.Time) error      { return nil }
func (*blockingReadConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingReadConn) SetWriteDeadline(time.Time) error { return nil }
