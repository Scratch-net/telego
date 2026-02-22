package tlsfront

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/example/telego/pkg/netx"
)

// Splicer handles transparent forwarding of unrecognized TLS clients
// to the mask host. This makes the proxy indistinguishable from the real server.
type Splicer struct {
	maskHost string
	maskPort int
	dialer   *netx.Dialer
	timeout  time.Duration
}

// NewSplicer creates a new splicer for the given mask host.
func NewSplicer(maskHost string, maskPort int) *Splicer {
	return &Splicer{
		maskHost: maskHost,
		maskPort: maskPort,
		dialer:   netx.NewDialer(),
		timeout:  30 * time.Second,
	}
}

// Splice forwards all traffic between the client and mask host.
// This is called when the ClientHello doesn't match our secret.
// The connection appears as a normal HTTPS connection to observers.
func (s *Splicer) Splice(ctx context.Context, client net.Conn, initialData []byte) error {
	// Connect to mask host
	addr := net.JoinHostPort(s.maskHost, fmt.Sprintf("%d", s.maskPort))
	upstream, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer upstream.Close()

	// Send any initial data (ClientHello) to upstream
	if len(initialData) > 0 {
		if _, err := upstream.Write(initialData); err != nil {
			return err
		}
	}

	// Bidirectional relay using zero-copy splice if available
	return netx.Relay(client, upstream)
}

// SpliceWithRewind handles splicing when we've partially read from the client.
// The rewindConn buffers initial reads and can replay them.
type RewindConn struct {
	net.Conn
	buf    []byte
	offset int
	mu     sync.Mutex
}

// NewRewindConn wraps a connection to allow replaying initial data.
func NewRewindConn(conn net.Conn) *RewindConn {
	return &RewindConn{Conn: conn}
}

// Read reads from buffer first, then from underlying connection.
func (c *RewindConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Read from buffer first
	if c.offset < len(c.buf) {
		n := copy(p, c.buf[c.offset:])
		c.offset += n
		return n, nil
	}

	// Read from underlying connection and buffer
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf = append(c.buf, p[:n]...)
	}
	return n, err
}

// Rewind resets the read position to replay buffered data.
func (c *RewindConn) Rewind() {
	c.mu.Lock()
	c.offset = 0
	c.mu.Unlock()
}

// GetBuffered returns all buffered data.
func (c *RewindConn) GetBuffered() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]byte, len(c.buf))
	copy(result, c.buf)
	return result
}

// StopBuffering stops buffering and returns a connection that reads
// buffered data first, then the underlying connection.
func (c *RewindConn) StopBuffering() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.buf) == 0 {
		return c.Conn
	}

	return &bufferedConn{
		Conn: c.Conn,
		buf:  c.buf,
	}
}

// bufferedConn reads from buffer first, then underlying connection.
type bufferedConn struct {
	net.Conn
	buf    []byte
	offset int
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.offset < len(c.buf) {
		n := copy(p, c.buf[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// SpliceConn performs bidirectional relay between two connections.
// Uses splice(2) on Linux for zero-copy, falls back to io.Copy otherwise.
func SpliceConn(ctx context.Context, client, upstream net.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Close connections when context is done
	go func() {
		<-ctx.Done()
		client.Close()
		upstream.Close()
	}()

	errCh := make(chan error, 2)

	// Client -> Upstream
	go func() {
		_, err := io.Copy(upstream, client)
		if tcpConn, ok := upstream.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		errCh <- err
	}()

	// Upstream -> Client
	go func() {
		_, err := io.Copy(client, upstream)
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		errCh <- err
	}()

	// Wait for both directions
	err1 := <-errCh
	err2 := <-errCh

	if err1 != nil && err1 != io.EOF {
		return err1
	}
	if err2 != nil && err2 != io.EOF {
		return err2
	}
	return nil
}
