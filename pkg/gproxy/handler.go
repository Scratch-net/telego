package gproxy

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/tlsfront"
)

// Buffer limit for OOM protection
const (
	// Hard limit: close connection when buffer exceeds this
	// Prevents memory exhaustion from slow clients
	defaultMaxWriteBuffer = 4 * 1024 * 1024 // 4MB
)

// ProxyHandler implements gnet.EventHandler for the MTProxy server.
type ProxyHandler struct {
	gnet.BuiltinEventEngine

	// Configuration
	config *Config

	// Hot-reloadable config: IdleTimeout stored as nanoseconds for atomic access
	idleTimeoutNs atomic.Int64

	// DC client for outgoing connections
	dcClient *gnet.Client

	// Replay cache for anti-replay protection
	replayCache *ReplayCache

	// Connection limiter (per IP+secret)
	connLimiter *ConnLimiter

	// User IP limiter/stats tracker
	userLimiter *UserIPLimiter

	// TLS fronting
	certFetcher        *tlsfront.CertFetcher
	serverHelloFetcher *tlsfront.ServerHelloFetcher // Hybrid mode: fetches real ServerHello

	// Logger
	logger Logger

	// Metrics
	activeConns int64

	// Hard limit for OOM protection (bytes per connection)
	maxWriteBuffer int

	// Cached backpressure thresholds (computed from maxWriteBuffer)
	bpSoftLimit int // Start throttling above this (maxWriteBuffer / 2)
	bpResumeAt  int // Resume full speed below this (maxWriteBuffer / 4)

	// Buffer pools with stats
	dcBufPool    *BufferPool // 64KB+ for batching writes
	relayBufPool *BufferPool // 16KB for TLS record processing

	// Desync detector
	desyncDetector *DesyncDetector

	// Pending DC contexts: keyed by fd, used to eliminate race between Enroll and SetContext
	pendingDCContexts sync.Map // int (fd) -> *DCConnContext
}

// NewProxyHandler creates a new gnet proxy handler.
func NewProxyHandler(cfg *Config, logger Logger) *ProxyHandler {
	if logger == nil {
		logger = defaultLogger{}
	}

	// Set hard limit for OOM protection
	maxWriteBuf := cfg.MaxWriteBuffer
	if maxWriteBuf <= 0 {
		maxWriteBuf = defaultMaxWriteBuffer
	}

	h := &ProxyHandler{
		config:         cfg,
		replayCache:    NewReplayCache(1000000, 10*time.Minute),
		logger:         logger,
		maxWriteBuffer: maxWriteBuf,
		bpSoftLimit:    maxWriteBuf / 2,
		bpResumeAt:     maxWriteBuf / 4,
		dcBufPool:      NewBufferPool(64*1024 + 256), // 64KB + TLS header overhead
		relayBufPool:   NewBufferPool(16 * 1024),     // 16KB TLS record
		desyncDetector: NewDesyncDetector(),
	}

	// Initialize hot-reloadable config atomically
	h.idleTimeoutNs.Store(int64(cfg.IdleTimeout))

	// Initialize connection limiter if configured
	if cfg.MaxConnectionsPerIP > 0 {
		h.connLimiter = NewConnLimiter(cfg.MaxConnectionsPerIP)
		logger.Info("Connection limiter enabled: max %d connections per IP", cfg.MaxConnectionsPerIP)
	}

	// Initialize user IP limiter/stats tracker (always created for metrics)
	h.userLimiter = NewUserIPLimiter(cfg.MaxIPsPerUser, cfg.IPBlockTimeout)
	if h.userLimiter.LimitingEnabled() {
		logger.Info("User IP limiter enabled: max %d IPs per user, block timeout %v", cfg.MaxIPsPerUser, cfg.IPBlockTimeout)
	} else {
		logger.Info("User IP stats tracking enabled (limiting disabled)")
	}

	logger.Info("OOM protection: max %dMB write buffer per connection", maxWriteBuf/1024/1024)

	return h
}

// ApplyHotConfig applies hot-reloadable configuration changes.
// Only certain fields can be changed at runtime; others require restart.
// Hot-reloadable fields:
//   - IdleTimeout: affects new connections only (existing keep their timeout)
//
// Non-hot fields (require restart):
//   - BindAddr, Secrets, MaskHost/Port, ProxyProtocol, MaxIPsPerUser
func (h *ProxyHandler) ApplyHotConfig(cfg *Config) {
	// Update idle timeout atomically - thread-safe for concurrent readers
	h.idleTimeoutNs.Store(int64(cfg.IdleTimeout))
}

// IdleTimeout returns the current idle timeout value (thread-safe).
func (h *ProxyHandler) IdleTimeout() time.Duration {
	return time.Duration(h.idleTimeoutNs.Load())
}

// UserLimiter returns the user IP limiter for metrics access.
func (h *ProxyHandler) UserLimiter() *UserIPLimiter {
	return h.userLimiter
}

// OnBoot is called when the gnet engine starts.
func (h *ProxyHandler) OnBoot(eng gnet.Engine) gnet.Action {
	h.logger.Info("gnet proxy started on %s", h.config.BindAddr)
	return gnet.None
}

// OnShutdown is called when the gnet engine shuts down.
func (h *ProxyHandler) OnShutdown(eng gnet.Engine) {
	h.logger.Info("gnet proxy shutting down")
	if h.dcClient != nil {
		h.dcClient.Stop()
	}
}

// OnOpen is called when a new connection is accepted.
func (h *ProxyHandler) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	ctx := NewConnContext()

	// Start with PROXY protocol parsing if enabled, otherwise detect protocol
	if h.config.ProxyProtocol {
		ctx.SetState(StateReadProxyProto)
	}
	// Otherwise keep default StateDetectProtocol from NewConnContext

	c.SetContext(ctx)

	conns := atomic.AddInt64(&h.activeConns, 1)
	h.logger.Debug("[#%d] new connection from %s (active: %d)", ctx.id, c.RemoteAddr(), conns)

	// Set read deadline for handshake
	c.SetReadDeadline(time.Now().Add(30 * time.Second))

	return nil, gnet.None
}

// OnClose is called when a connection is closed.
func (h *ProxyHandler) OnClose(c gnet.Conn, err error) gnet.Action {
	conns := atomic.AddInt64(&h.activeConns, -1)

	ctx, ok := c.Context().(*ConnContext)
	if !ok || ctx == nil {
		h.logger.Debug("[?] connection closed without context (active: %d)", conns)
		return gnet.None
	}

	// Mark as closed FIRST - goroutines check this before proceeding
	ctx.SetState(StateClosed)

	// Close DC connection if active
	if relay := ctx.Relay(); relay != nil && relay.DCConn != nil {
		relay.DCConn.Close()
	}

	// Close splice connection if active
	if spliceConn := ctx.SpliceConn(); spliceConn != nil {
		spliceConn.Close()
	}

	// Release connection limit slots and check if authenticated
	ctx.mu.Lock()
	authenticated := ctx.secret != nil
	if ctx.connLimitTracked && h.connLimiter != nil {
		h.connLimiter.Release(ctx.connLimitKey)
		ctx.connLimitTracked = false
	}
	if ctx.limitTracked && h.userLimiter != nil {
		h.userLimiter.Release(ctx.limitKey)
		ctx.limitTracked = false
	}
	ctx.mu.Unlock()

	// Log closure with DC info for debugging
	duration := time.Since(ctx.connTime)
	prefix := ctx.LogPrefix()
	dcID := ctx.DCID()

	// Determine if this is a real error (not just EOF/normal close)
	isRealError := err != nil && !errors.Is(err, io.EOF)

	if authenticated {
		if isRealError {
			h.logger.Warn("[%s] DC %d closed (%v): %v (active: %d)", prefix, dcID, duration.Round(time.Millisecond), err, conns)
		} else {
			h.logger.Info("[%s] DC %d closed (%v) (active: %d)", prefix, dcID, duration.Round(time.Millisecond), conns)
		}
	} else if isRealError {
		h.logger.Debug("[%s] closed (%v): %v (active: %d)", prefix, duration.Round(time.Millisecond), err, conns)
	}

	// Zero sensitive data before releasing context
	ctx.Cleanup()

	return gnet.None
}

// OnTraffic is called when data is available to read.
func (h *ProxyHandler) OnTraffic(c gnet.Conn) gnet.Action {
	ctx, ok := c.Context().(*ConnContext)
	if !ok || ctx == nil {
		return gnet.Close
	}

	// Lock-free state read
	switch ctx.State() {
	case StateDetectProtocol:
		return h.handleDetectProtocol(c, ctx)
	case StateReadProxyProto:
		return h.handleProxyProto(c, ctx)
	case StateReadTLSHeader:
		return h.handleTLSHeader(c, ctx)
	case StateReadTLSPayload:
		return h.handleTLSPayload(c, ctx)
	case StateReadO2Frame:
		return h.handleO2Frame(c, ctx)
	case StateReadDDFrame:
		return h.handleDDFrame(c, ctx)
	case StateDialingDC:
		// Still waiting for DC connection, buffer data
		return gnet.None
	case StateRelaying:
		return h.handleRelay(c, ctx)
	case StateSplicing:
		return h.handleSplice(c, ctx)
	case StateClosed:
		return gnet.Close
	}

	return gnet.Close
}

// handleProxyProto parses incoming PROXY protocol header.
func (h *ProxyHandler) handleProxyProto(c gnet.Conn, ctx *ConnContext) gnet.Action {
	data, _ := c.Peek(-1)
	if len(data) == 0 {
		return gnet.None // Need data
	}

	// Quick check: if first byte can't start a PROXY header, skip to detection immediately
	// This prevents slowloris-style attacks with tiny payloads
	// PROXY v1 starts with 'P' (0x50), v2 starts with 0x0D
	if data[0] != 'P' && data[0] != 0x0D {
		ctx.SetState(StateDetectProtocol)
		return h.handleDetectProtocol(c, ctx)
	}

	// Need minimum bytes to determine protocol type
	// v1: need 6 bytes for "PROXY " prefix
	// v2: need 12 bytes for signature
	minBytes := 6
	if data[0] == 0x0D {
		minBytes = 12
	}
	if len(data) < minBytes {
		return gnet.None // Need more data to determine
	}

	result, err := ParseProxyProtocol(data)
	if err != nil {
		h.logger.Debug("[#%d] PROXY protocol error: %v", ctx.id, err)
		return gnet.Close
	}

	if result == nil {
		// Not a PROXY protocol header, proceed to protocol detection
		ctx.SetState(StateDetectProtocol)
		return h.handleDetectProtocol(c, ctx)
	}

	// Discard the PROXY header bytes
	c.Discard(result.HeaderLen)

	// Store real client address if provided
	if result.SrcAddr != nil {
		ctx.SetRealClientAddr(result.SrcAddr)
		h.logger.Debug("[#%d] PROXY protocol: real client %s", ctx.id, result.SrcAddr)
	}

	// Proceed to protocol detection
	ctx.SetState(StateDetectProtocol)
	return h.handleDetectProtocol(c, ctx)
}

// Logger interface for proxy logging.
type Logger interface {
	Debug(format string, args ...any)
	Info(format string, args ...any)
	Warn(format string, args ...any)
	Error(format string, args ...any)
	// DebugEnabled returns true if debug logging is enabled.
	// Use to guard expensive debug log argument evaluation.
	DebugEnabled() bool
}

type defaultLogger struct{}

func (defaultLogger) Debug(format string, args ...any) {}
func (defaultLogger) Info(format string, args ...any)  {}
func (defaultLogger) Warn(format string, args ...any)  {}
func (defaultLogger) Error(format string, args ...any) {}
func (defaultLogger) DebugEnabled() bool               { return false }
