package gproxy

// Test mocks for gproxy tests.
// These are test-only and don't count towards coverage.

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// testMockGnetConn implements gnet.Conn for testing.
type testMockGnetConn struct {
	mu sync.Mutex

	// Data buffers
	readBuf  []byte // Data available to read
	writeBuf []byte // Data written by handler

	// Async writes tracking
	asyncWrites [][]byte

	// Connection state
	context   any
	closed    bool
	localAddr net.Addr
	remoteIP  net.Addr
	fd        int
	eventLoop gnet.EventLoop

	// Simulated state
	outboundBuffered int

	// Callbacks
	OnWrite func([]byte)
	OnClose func()
}

// newTestMockGnetConn creates a new mock gnet connection.
func newTestMockGnetConn() *testMockGnetConn {
	return &testMockGnetConn{
		localAddr: newTestMockTCPAddr("127.0.0.1:8888"),
		remoteIP:  newTestMockTCPAddr("192.168.1.1:12345"),
		fd:        1000,
	}
}

// SetReadData sets data for reading.
func (c *testMockGnetConn) SetReadData(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readBuf = make([]byte, len(data))
	copy(c.readBuf, data)
}

// GetWrittenData returns all written data.
func (c *testMockGnetConn) GetWrittenData() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]byte, len(c.writeBuf))
	copy(result, c.writeBuf)
	return result
}

// IsClosed returns if closed.
func (c *testMockGnetConn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// SetRemoteAddr sets remote address.
func (c *testMockGnetConn) SetRemoteAddr(addr net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remoteIP = addr
}

// SetOutboundBuffered sets simulated outbound buffer.
func (c *testMockGnetConn) SetOutboundBuffered(size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outboundBuffered = size
}

// SetFD sets the file descriptor for testing.
func (c *testMockGnetConn) SetFD(fd int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fd = fd
}

// GetAsyncWrites returns async writes.
func (c *testMockGnetConn) GetAsyncWrites() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([][]byte, len(c.asyncWrites))
	copy(result, c.asyncWrites)
	return result
}

// --- gnet.Reader interface ---

func (c *testMockGnetConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.readBuf) == 0 {
		return 0, nil
	}
	n := copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *testMockGnetConn) WriteTo(w io.Writer) (int64, error) {
	c.mu.Lock()
	data := c.readBuf
	c.readBuf = nil
	c.mu.Unlock()
	written, err := w.Write(data)
	return int64(written), err
}

func (c *testMockGnetConn) Next(n int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > len(c.readBuf) {
		n = len(c.readBuf)
	}
	data := make([]byte, n)
	copy(data, c.readBuf[:n])
	c.readBuf = c.readBuf[n:]
	return data, nil
}

func (c *testMockGnetConn) Peek(n int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n < 0 || n > len(c.readBuf) {
		result := make([]byte, len(c.readBuf))
		copy(result, c.readBuf)
		return result, nil
	}
	result := make([]byte, n)
	copy(result, c.readBuf[:n])
	return result, nil
}

func (c *testMockGnetConn) Discard(n int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > len(c.readBuf) {
		n = len(c.readBuf)
	}
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *testMockGnetConn) InboundBuffered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.readBuf)
}

// --- gnet.Writer interface ---

func (c *testMockGnetConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.OnWrite != nil {
		c.OnWrite(b)
	}
	c.writeBuf = append(c.writeBuf, b...)
	n := len(b)
	c.mu.Unlock()
	return n, nil
}

func (c *testMockGnetConn) ReadFrom(r io.Reader) (int64, error) {
	buf := make([]byte, 4096)
	var total int64
	for {
		nr, err := r.Read(buf)
		if nr > 0 {
			c.mu.Lock()
			c.writeBuf = append(c.writeBuf, buf[:nr]...)
			c.mu.Unlock()
			total += int64(nr)
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func (c *testMockGnetConn) SendTo(buf []byte, addr net.Addr) (int, error) {
	return 0, io.ErrShortWrite
}

func (c *testMockGnetConn) Writev(bs [][]byte) (int, error) {
	var n int
	for _, b := range bs {
		written, err := c.Write(b)
		n += written
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func (c *testMockGnetConn) Flush() error { return nil }

func (c *testMockGnetConn) OutboundBuffered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.outboundBuffered > 0 {
		return c.outboundBuffered
	}
	return len(c.writeBuf)
}

func (c *testMockGnetConn) AsyncWrite(buf []byte, callback gnet.AsyncCallback) error {
	c.mu.Lock()
	dataCopy := make([]byte, len(buf))
	copy(dataCopy, buf)
	c.asyncWrites = append(c.asyncWrites, dataCopy)
	c.mu.Unlock()

	_, err := c.Write(buf)
	if callback != nil {
		callback(c, err)
	}
	return err
}

func (c *testMockGnetConn) AsyncWritev(bs [][]byte, callback gnet.AsyncCallback) error {
	_, err := c.Writev(bs)
	if callback != nil {
		callback(c, err)
	}
	return err
}

// --- gnet.Socket interface ---

func (c *testMockGnetConn) Fd() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fd
}

func (c *testMockGnetConn) Dup() (int, error)             { return c.Fd(), nil }
func (c *testMockGnetConn) SetReadBuffer(size int) error  { return nil }
func (c *testMockGnetConn) SetWriteBuffer(size int) error { return nil }
func (c *testMockGnetConn) SetLinger(secs int) error      { return nil }
func (c *testMockGnetConn) SetKeepAlivePeriod(d time.Duration) error {
	return nil
}
func (c *testMockGnetConn) SetKeepAlive(enabled bool, idle, intvl time.Duration, cnt int) error {
	return nil
}
func (c *testMockGnetConn) SetNoDelay(noDelay bool) error { return nil }

// --- gnet.Conn interface ---

func (c *testMockGnetConn) Context() any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.context
}

func (c *testMockGnetConn) SetContext(ctx any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.context = ctx
}

func (c *testMockGnetConn) EventLoop() gnet.EventLoop {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.eventLoop == nil {
		c.eventLoop = &testMockEventLoop{}
	}
	return c.eventLoop
}

func (c *testMockGnetConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localAddr
}

func (c *testMockGnetConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remoteIP
}

func (c *testMockGnetConn) Wake(callback gnet.AsyncCallback) error {
	if callback != nil {
		callback(c, nil)
	}
	return nil
}

func (c *testMockGnetConn) CloseWithCallback(callback gnet.AsyncCallback) error {
	err := c.Close()
	if callback != nil {
		callback(c, err)
	}
	return err
}

func (c *testMockGnetConn) Close() error {
	c.mu.Lock()
	c.closed = true
	if c.OnClose != nil {
		c.OnClose()
	}
	c.mu.Unlock()
	return nil
}

func (c *testMockGnetConn) SetDeadline(t time.Time) error      { return nil }
func (c *testMockGnetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *testMockGnetConn) SetWriteDeadline(t time.Time) error { return nil }

var _ gnet.Conn = (*testMockGnetConn)(nil)

// testMockEventLoop implements gnet.EventLoop for testing.
type testMockEventLoop struct {
	mu          sync.Mutex
	connections []gnet.Conn
}

func (e *testMockEventLoop) Register(ctx context.Context, addr net.Addr) (<-chan gnet.RegisteredResult, error) {
	ch := make(chan gnet.RegisteredResult, 1)
	close(ch)
	return ch, nil
}

func (e *testMockEventLoop) Enroll(ctx context.Context, c net.Conn) (<-chan gnet.RegisteredResult, error) {
	ch := make(chan gnet.RegisteredResult, 1)
	mockConn := newTestMockGnetConn()
	mockConn.SetRemoteAddr(c.RemoteAddr())
	e.mu.Lock()
	e.connections = append(e.connections, mockConn)
	e.mu.Unlock()
	ch <- gnet.RegisteredResult{Conn: mockConn}
	close(ch)
	return ch, nil
}

func (e *testMockEventLoop) Execute(ctx context.Context, runnable gnet.Runnable) error {
	return runnable.Run(ctx)
}

func (e *testMockEventLoop) Schedule(ctx context.Context, runnable gnet.Runnable, delay time.Duration) error {
	go func() {
		time.Sleep(delay)
		runnable.Run(ctx)
	}()
	return nil
}

func (e *testMockEventLoop) Close(c gnet.Conn) error {
	return c.Close()
}

var _ gnet.EventLoop = (*testMockEventLoop)(nil)

// testMockTCPAddr implements net.Addr for testing.
type testMockTCPAddr struct {
	network string
	addr    string
}

func (a *testMockTCPAddr) Network() string { return a.network }
func (a *testMockTCPAddr) String() string  { return a.addr }

func newTestMockTCPAddr(addr string) *testMockTCPAddr {
	return &testMockTCPAddr{network: "tcp", addr: addr}
}

// testTrafficCounters holds atomic traffic counters.
type testTrafficCounters struct {
	BytesIn  atomic.Int64
	BytesOut atomic.Int64
}

func newTestTrafficCounters() *testTrafficCounters {
	return &testTrafficCounters{}
}
