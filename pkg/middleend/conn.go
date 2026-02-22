package middleend

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrConnClosed = errors.New("connection closed")
	ErrBadResponse = errors.New("bad ME response")
)

// MEConn represents a connection to a Middle-End server.
type MEConn struct {
	Conn      net.Conn // Exported for relay access
	encryptor cipher.Stream
	decryptor cipher.Stream

	// State
	closed  atomic.Bool
	lastUse atomic.Int64
	mu      sync.Mutex

	// Read buffer for RPC frames
	readBuf []byte
}

// newMEConn creates a new ME connection wrapper.
func newMEConn(conn net.Conn, enc, dec cipher.Stream) *MEConn {
	c := &MEConn{
		Conn:      conn,
		encryptor: enc,
		decryptor: dec,
		readBuf:   make([]byte, 64*1024),
	}
	c.lastUse.Store(time.Now().Unix())
	return c
}

// IsHealthy returns true if the connection is usable.
func (c *MEConn) IsHealthy() bool {
	if c.closed.Load() {
		return false
	}
	// Consider unhealthy if unused for 2 minutes
	lastUse := time.Unix(c.lastUse.Load(), 0)
	return time.Since(lastUse) < 2*time.Minute
}

// SendKeepalive sends a keepalive RPC to the ME server.
func (c *MEConn) SendKeepalive() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed.Load() {
		return ErrConnClosed
	}

	// Send ping RPC
	if err := c.writeRPC(RPCTypePing, nil); err != nil {
		return err
	}

	// Set read deadline for pong
	c.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.Conn.SetReadDeadline(time.Time{})

	// Read pong response
	_, _, err := c.readRPC()
	if err != nil {
		return err
	}

	c.lastUse.Store(time.Now().Unix())
	return nil
}

// Forward forwards client data to the ME server and returns the response stream.
// This is the main data path for proxied connections.
func (c *MEConn) Forward(clientData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed.Load() {
		return ErrConnClosed
	}

	// Send data as RPC
	if err := c.writeRPC(RPCTypeData, clientData); err != nil {
		return err
	}

	c.lastUse.Store(time.Now().Unix())
	return nil
}

// ReadResponse reads the next RPC response from the ME server.
func (c *MEConn) ReadResponse() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed.Load() {
		return nil, ErrConnClosed
	}

	_, data, err := c.readRPC()
	if err != nil {
		return nil, err
	}

	c.lastUse.Store(time.Now().Unix())
	return data, nil
}

// writeRPC writes an RPC frame to the connection.
// Frame format: [4 bytes length][4 bytes type][payload]
func (c *MEConn) writeRPC(rpcType uint32, payload []byte) error {
	// Build frame
	frameLen := 4 + len(payload) // type + payload
	frame := make([]byte, 4+frameLen)

	binary.LittleEndian.PutUint32(frame[0:4], uint32(frameLen))
	binary.LittleEndian.PutUint32(frame[4:8], rpcType)
	if len(payload) > 0 {
		copy(frame[8:], payload)
	}

	// Encrypt
	c.encryptor.XORKeyStream(frame, frame)

	// Write
	_, err := c.Conn.Write(frame)
	return err
}

// readRPC reads an RPC frame from the connection.
func (c *MEConn) readRPC() (uint32, []byte, error) {
	// Read length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
		return 0, nil, err
	}
	c.decryptor.XORKeyStream(lenBuf, lenBuf)
	frameLen := binary.LittleEndian.Uint32(lenBuf)

	if frameLen < 4 || frameLen > 64*1024 {
		return 0, nil, ErrBadResponse
	}

	// Read frame body
	body := make([]byte, frameLen)
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return 0, nil, err
	}
	c.decryptor.XORKeyStream(body, body)

	rpcType := binary.LittleEndian.Uint32(body[0:4])
	payload := body[4:]

	return rpcType, payload, nil
}

// Close closes the ME connection.
func (c *MEConn) Close() error {
	if c.closed.Swap(true) {
		return nil // Already closed
	}
	return c.Conn.Close()
}

// LocalAddr returns the local address.
func (c *MEConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr returns the remote address.
func (c *MEConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}
