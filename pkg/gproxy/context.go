// Package gproxy implements a gnet-based event-driven MTProxy server.
package gproxy

import (
	"crypto/cipher"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// ConnState represents the current state of a client connection.
type ConnState int32

const (
	StateDetectProtocol ConnState = iota // Detect ee vs dd protocol from first bytes
	StateReadProxyProto                  // Need PROXY protocol header (optional)
	StateReadTLSHeader                   // Need 5 bytes for TLS record header
	StateReadTLSPayload                  // Need header.length bytes for payload
	StateReadO2Frame                     // Need 64 bytes for obfuscated2 frame (TLS-wrapped)
	StateReadDDFrame                     // Need 64 bytes for raw obfuscated2 frame (DD mode)
	StateDialingDC                       // Async dial in progress
	StateRelaying                        // Bidirectional relay active
	StateSplicing                        // Forward to mask host (invalid client)
	StateClosed                          // Connection is closing
	StateMiddleEnd                       // Authenticated client routed through Middle-End
)

// ProtocolMode indicates the MTProxy protocol variant.
type ProtocolMode uint8

const (
	ModeEE ProtocolMode = iota // FakeTLS + Obfuscated2 (ee prefix)
	ModeDD                     // Raw Obfuscated2 (dd prefix)
)

// String returns the state name for debugging.
func (s ConnState) String() string {
	switch s {
	case StateDetectProtocol:
		return "DetectProtocol"
	case StateReadProxyProto:
		return "ReadProxyProto"
	case StateReadTLSHeader:
		return "ReadTLSHeader"
	case StateReadTLSPayload:
		return "ReadTLSPayload"
	case StateReadO2Frame:
		return "ReadO2Frame"
	case StateReadDDFrame:
		return "ReadDDFrame"
	case StateDialingDC:
		return "DialingDC"
	case StateRelaying:
		return "Relaying"
	case StateSplicing:
		return "Splicing"
	case StateClosed:
		return "Closed"
	case StateMiddleEnd:
		return "MiddleEnd"
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
	DCConn    gnet.Conn     // gnet connection to Telegram DC (enrolled in dcClient)
	DCEncrypt cipher.Stream // encrypt data TO DC
	DCDecrypt cipher.Stream // decrypt data FROM DC
}

// Global connection ID counter
var connIDCounter atomic.Uint64

// ConnContext holds per-connection state for the gnet event handler.
type ConnContext struct {
	// Connection ID for logging (immutable after creation)
	id uint64

	// Atomic state - no lock needed for reads
	state atomic.Int32
	// handshakeFailureRecorded makes explicit failure accounting one-shot.
	handshakeFailureRecorded atomic.Bool

	// Protocol mode (ee or dd) - set during detection, immutable after
	protocolMode ProtocolMode

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
	// Inner MTProto packet framing selected in the obfuscated2 handshake.
	// This must also be used for the upstream Telegram DC handshake because
	// Telego relays decrypted packet bytes without translating their framing.
	o2ConnectionType obfuscated2.ConnectionType

	// Relay context - set once atomically when entering relay state
	// After set, read without locking
	relay atomic.Pointer[RelayContext]

	// Buffered data from handshake (protected by mu)
	pendingData []byte

	// Splice connection - set once atomically when entering splice state
	// After set, read without locking
	spliceConn atomic.Pointer[net.Conn]

	// Splice flow control: signaled when client buffer has space
	// Used to avoid busy-wait sleep in relaySpliceToClientLoop
	spliceResume chan struct{}
	spliceFlowMu sync.Mutex
	// pending counts AsyncWrite submissions not processed by the event loop;
	// outbound is the latest event-loop-owned gnet buffer measurement.
	splicePendingBytes  int
	spliceOutboundBytes int

	// Splice shutdown is requested by the upstream reader goroutine after a
	// clean EOF, then owned by the client connection's event loop until every
	// queued byte has left gnet's outbound buffer.
	spliceDrainRequested atomic.Bool
	spliceDrainMu        sync.Mutex
	spliceDraining       bool
	spliceDrainID        uint64
	spliceDrainDeadline  *time.Timer
	spliceDrainWake      *time.Timer

	// Real client address from PROXY protocol (if parsed)
	// Protected by mu during handshake, immutable after
	realClientAddr net.Addr

	// The private WEB hop starts as an unauthenticated local candidate. Only a
	// matching process-local preface changes it to an authenticated internal hop.
	internalProxyCandidate     bool
	internalProxyAuthenticated bool
	trustedProxySource         net.Addr
	trustedProxyDestination    net.Addr

	// middleEnd is installed only after an exact signed-DC Bind succeeds. All
	// fields behind it except the readiness handoff are client-event-loop owned.
	middleEnd *middleEndClient

	// Connection limit tracking (protected by mu)
	ipLimitTracked   bool   // Whether this connection is tracked in per-IP limiter (set in OnOpen)
	ipLimitKey       string // Cached key for per-IP limiter release
	connLimitTracked bool   // Whether this connection is tracked in conn limiter
	connLimitKey     string // Cached key for conn limiter release
	limitTracked     bool   // Whether this connection is tracked in user IP limiter
	limitKey         string // Cached key for user IP limiter release

	// Traffic counters (pointers to user's atomic counters)
	trafficIn  *atomic.Int64
	trafficOut *atomic.Int64

	// Backpressure state for hysteresis (avoids oscillation at threshold boundaries)
	// Once throttled, stays throttled until buffer drops below resumeAt
	throttledToDC atomic.Bool // Client->DC direction is throttled

	// Relay-direction activity timestamps (Unix millis), updated from different
	// event loops so accessed atomically. Drive the client-silence wedge breaker:
	// when the server spoke more recently than the client, the client has an
	// unanswered reply. Both 0 until the first relayed payload in each direction.
	lastClientByteMs atomic.Int64 // last client->DC relayed payload
	lastServerByteMs atomic.Int64 // last DC->client relayed payload

	// One-shot splice target override (resolved "host:port") set when an
	// unauthenticated probe's SNI is on the mask safelist. Consumed by dialSplice.
	spliceOverride string // protected by mu

	// Timing
	connTime time.Time
}

// NewConnContext creates a new connection context.
func NewConnContext() *ConnContext {
	ctx := &ConnContext{
		id:       connIDCounter.Add(1),
		connTime: time.Now(),
	}
	ctx.state.Store(int32(StateDetectProtocol))
	return ctx
}

// ID returns the connection ID.
func (c *ConnContext) ID() uint64 {
	return c.id
}

// LogPrefix returns a log prefix like "#123" or "#123:user1".
func (c *ConnContext) LogPrefix() string {
	c.mu.Lock()
	name := ""
	if c.secret != nil {
		name = c.secret.Name
	}
	c.mu.Unlock()

	if name != "" {
		return fmt.Sprintf("#%d:%s", c.id, name)
	}
	return fmt.Sprintf("#%d", c.id)
}

// State returns the current connection state (lock-free).
func (c *ConnContext) State() ConnState {
	return ConnState(c.state.Load())
}

// SetState sets the connection state (lock-free).
func (c *ConnContext) SetState(state ConnState) {
	c.state.Store(int32(state))
}

// ProtocolMode returns the protocol mode (ModeEE or ModeDD).
func (c *ConnContext) ProtocolMode() ProtocolMode {
	return c.protocolMode
}

// SetProtocolMode sets the protocol mode.
func (c *ConnContext) SetProtocolMode(mode ProtocolMode) {
	c.protocolMode = mode
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

// SpliceConn returns the splice connection (lock-free, may be nil).
func (c *ConnContext) SpliceConn() net.Conn {
	if ptr := c.spliceConn.Load(); ptr != nil {
		return *ptr
	}
	return nil
}

// SetSpliceConn sets the splice connection and initializes flow control.
func (c *ConnContext) SetSpliceConn(conn net.Conn) {
	// Initialize flow control channel (buffered to allow non-blocking signal)
	c.spliceResume = make(chan struct{}, 1)
	c.spliceConn.Store(&conn)
}

// RealClientAddr returns the real client address from PROXY protocol.
// Falls back to the provided gnet connection's remote address if not set.
func (c *ConnContext) RealClientAddr(fallback net.Addr) net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.realClientAddr != nil {
		return c.realClientAddr
	}
	return fallback
}

// SetRealClientAddr sets the real client address from PROXY protocol.
func (c *ConnContext) SetRealClientAddr(addr net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.realClientAddr = addr
}

// setTrustedProxyTuple records the source and destination from the
// process-authenticated internal PROXY hop. Public PROXY headers never call
// this method and are not authoritative for Middle-End forwarding.
func (c *ConnContext) setTrustedProxyTuple(source, destination net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trustedProxySource = source
	c.trustedProxyDestination = destination
}

func (c *ConnContext) trustedProxyTuple() (net.Addr, net.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.trustedProxySource, c.trustedProxyDestination, c.internalProxyAuthenticated
}

// SetSpliceOverride records a one-shot splice target ("host:port") for an
// unauthenticated probe whose SNI is on the mask safelist.
func (c *ConnContext) SetSpliceOverride(addr string) {
	c.mu.Lock()
	c.spliceOverride = addr
	c.mu.Unlock()
}

// consumeSpliceOverride returns and clears the one-shot splice override, so a
// reused context never inherits a stale target.
func (c *ConnContext) consumeSpliceOverride() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	addr := c.spliceOverride
	c.spliceOverride = ""
	return addr
}

// DCID returns the DC ID this connection is using (0 if not yet determined).
func (c *ConnContext) DCID() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dcID
}

// o2Framing returns the MTProto packet framing selected by the client.
func (c *ConnContext) o2Framing() obfuscated2.ConnectionType {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.o2ConnectionType
}

// Cleanup zeros sensitive data in the connection context.
// Should be called when the connection is closed.
// Note: cipher.Stream internal state cannot be zeroed (opaque Go types).
func (c *ConnContext) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Zero ClientHello sensitive fields
	if c.clientHello != nil {
		Zeroize(c.clientHello.SessionID)
		ZeroizeArray32(&c.clientHello.Random)
		c.clientHello = nil
	}

	// Zero pending data (may contain partial encrypted payload)
	if c.pendingData != nil {
		Zeroize(c.pendingData)
		c.pendingData = nil
	}

	// Clear references (cipher streams can't be zeroed but break reference)
	c.encryptor = nil
	c.decryptor = nil
	c.o2ConnectionType = 0
	c.secret = nil
	c.trustedProxySource = nil
	c.trustedProxyDestination = nil
	c.middleEnd = nil
}

// SetTrafficCounters sets the traffic counter pointers for this connection.
// Must be called during handshake before entering relay state.
func (c *ConnContext) SetTrafficCounters(bytesIn, bytesOut *atomic.Int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trafficIn = bytesIn
	c.trafficOut = bytesOut
}

// TrafficIn returns the traffic-in counter (may be nil).
// Safe to call without lock because SetTrafficCounters is called during
// handshake and getters are only called during relay state (after handshake).
func (c *ConnContext) TrafficIn() *atomic.Int64 {
	return c.trafficIn
}

// TrafficOut returns the traffic-out counter (may be nil).
// Safe to call without lock because SetTrafficCounters is called during
// handshake and getters are only called during relay state (after handshake).
func (c *ConnContext) TrafficOut() *atomic.Int64 {
	return c.trafficOut
}
