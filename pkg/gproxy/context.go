// Package gproxy implements a gnet-based event-driven MTProxy server.
package gproxy

import (
	"crypto/cipher"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// ConnState represents the current state of a client connection.
type ConnState int32

const (
	StateReadTLSHeader  ConnState = iota // Need 5 bytes for TLS record header
	StateReadTLSPayload                  // Need header.length bytes for payload
	StateReadO2Frame                     // Need 64 bytes for obfuscated2 frame
	StateDialingDC                       // Async dial in progress
	StateRelaying                        // Bidirectional relay active
	StateSplicing                        // Forward to mask host (invalid client)
	StateClosed                          // Connection is closing
)

// String returns the state name for debugging.
func (s ConnState) String() string {
	switch s {
	case StateReadTLSHeader:
		return "ReadTLSHeader"
	case StateReadTLSPayload:
		return "ReadTLSPayload"
	case StateReadO2Frame:
		return "ReadO2Frame"
	case StateDialingDC:
		return "DialingDC"
	case StateRelaying:
		return "Relaying"
	case StateSplicing:
		return "Splicing"
	case StateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// RelayContext holds immutable relay state set once after handshake.
// Read without locking via atomic pointer.
type RelayContext struct {
	// Client ciphers (client <-> proxy)
	Encryptor cipher.Stream // encrypt data TO client
	Decryptor cipher.Stream // decrypt data FROM client

	// DC connection and ciphers (proxy <-> DC)
	DCConn    net.Conn      // TCP connection to Telegram DC
	DCEncrypt cipher.Stream // encrypt data TO DC
	DCDecrypt cipher.Stream // decrypt data FROM DC
}

// ConnContext holds per-connection state for the gnet event handler.
type ConnContext struct {
	// Atomic state - no lock needed for reads
	state atomic.Int32

	// Mutex protects handshake-phase fields only
	mu sync.Mutex

	// TLS handshake state (protected by mu)
	tlsPayloadLen int                  // Expected payload length from TLS header
	clientHello   *faketls.ClientHello // Parsed ClientHello

	// Matched secret (protected by mu during handshake, immutable after)
	secret *Secret

	// Handshake-phase cipher storage (protected by mu)
	// These are copied to RelayContext once DC connects
	encryptor cipher.Stream
	decryptor cipher.Stream
	dcID      int

	// Relay context - set once atomically when entering relay state
	// After set, read without locking
	relay atomic.Pointer[RelayContext]

	// Buffered data from handshake (protected by mu)
	pendingData []byte

	// Splice connection (protected by mu)
	spliceNetConn net.Conn

	// Timing
	connTime time.Time
}

// NewConnContext creates a new connection context.
func NewConnContext() *ConnContext {
	ctx := &ConnContext{
		connTime: time.Now(),
	}
	ctx.state.Store(int32(StateReadTLSHeader))
	return ctx
}

// State returns the current connection state (lock-free).
func (c *ConnContext) State() ConnState {
	return ConnState(c.state.Load())
}

// SetState sets the connection state (lock-free).
func (c *ConnContext) SetState(state ConnState) {
	c.state.Store(int32(state))
}

// Relay returns the relay context (lock-free, may be nil).
func (c *ConnContext) Relay() *RelayContext {
	return c.relay.Load()
}

// SetRelay sets the relay context and transitions to relay state.
func (c *ConnContext) SetRelay(r *RelayContext) {
	c.relay.Store(r)
	c.state.Store(int32(StateRelaying))
}

