package gproxy

import (
	"errors"
	"io"
	"net"
	"strings"
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

	// Mask SNI safelist: lowercased domain -> resolved "host:port" splice target.
	// Empty when the feature is unconfigured.
	maskSafelist map[string]string

	// Client-silence wedge breaker. clientSilenceCloseMs is the threshold in
	// millis (0 = disabled). relayConns tracks active relaying connections that
	// OnTick sweeps. Both populated only when the feature is enabled.
	clientSilenceCloseMs int64
	relayConns           sync.Map // uint64 (conn id) -> *relayEntry
}

// relayEntry links an active relay's client connection to its context for the
// OnTick silence sweep.
type relayEntry struct {
	conn gnet.Conn
	ctx  *ConnContext
}

// silenceTickInterval is how often OnTick sweeps for wedged connections.
const silenceTickInterval = time.Second

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

	// Client-silence wedge breaker threshold (ms); 0 keeps it fully disabled.
	if cfg.ClientSilenceClose > 0 {
		h.clientSilenceCloseMs = cfg.ClientSilenceClose.Milliseconds()
		logger.Info("Client-silence wedge breaker enabled: close after %v of unanswered server reply", cfg.ClientSilenceClose)
	}

	// Resolve the opt-in SNI-following mask safelist (each domain -> host:443).
	// Unresolvable entries are skipped, not fatal.
	if len(cfg.MaskSNISafelist) > 0 {
		h.maskSafelist = make(map[string]string, len(cfg.MaskSNISafelist))
		for _, domain := range cfg.MaskSNISafelist {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				continue
			}
			if _, err := net.LookupHost(domain); err != nil {
				logger.Warn("mask-sni-safelist: cannot resolve %q, skipping: %v", domain, err)
				continue
			}
			h.maskSafelist[strings.ToLower(domain)] = net.JoinHostPort(domain, "443")
			logger.Info("mask-sni-safelist: fronting %q enabled", domain)
		}
	}

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

// OnTick runs periodically (only when the client-silence breaker is enabled,
// via WithTicker) on event-loop 0. It closes relaying connections stuck in the
// iOS bad_salt wedge: the last relayed payload was server->client and the client
// has not answered for the configured threshold. A healthy connection whose last
// word was its own request/ack (lastClientByteMs >= lastServerByteMs) is never
// touched, and a connection where the client has not yet spoken in relay
// (lastClientByteMs == 0) is never touched. conn.Close() is cross-loop safe: it
// enqueues the close onto the connection's own event loop.
func (h *ProxyHandler) OnTick() (time.Duration, gnet.Action) {
	if h.clientSilenceCloseMs <= 0 {
		return 0, gnet.None
	}
	now := time.Now().UnixMilli()
	h.relayConns.Range(func(k, v any) bool {
		e := v.(*relayEntry)
		lc := e.ctx.lastClientByteMs.Load()
		ls := e.ctx.lastServerByteMs.Load()
		if silenceWedged(lc, ls, now, h.clientSilenceCloseMs) {
			h.logger.Info("[#%d] closing relay: server reply unanswered %dms (iOS bad_salt wedge breaker)", e.ctx.id, now-ls)
			e.conn.Close()
			h.relayConns.Delete(k)
		}
		return true
	})
	return silenceTickInterval, gnet.None
}

// silenceWedged reports whether a relaying connection is in the iOS bad_salt
// wedge: the client has spoken at least once (lastClientMs > 0), the server's
// last payload is more recent than the client's (an unanswered reply), and that
// reply has gone unanswered past the threshold. A healthy connection whose last
// word was its own request/ack is never flagged.
func silenceWedged(lastClientMs, lastServerMs, nowMs, thresholdMs int64) bool {
	return lastClientMs > 0 &&
		lastServerMs > lastClientMs &&
		nowMs-lastServerMs > thresholdMs
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
	h.logger.Info("[#%d] new connection from %s (active: %d)", ctx.id, c.RemoteAddr(), conns)

	// Enforce per-IP connection limit before any protocol work
	if h.connLimiter != nil {
		var ip net.IP
		if tcpAddr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			ip = tcpAddr.IP
		}
		if ip != nil {
			key, ok := h.connLimiter.TryAcquireIP(ip)
			if !ok {
				h.logger.Info("[#%d] per-IP connection limit exceeded for %s (active: %d)", ctx.id, ip, conns)
				return nil, gnet.Close
			}
			ctx.ipLimitTracked = true
			ctx.ipLimitKey = key
		}
	}

	// Set read deadline for handshake
	handshakeTimeout := h.config.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = 5 * time.Second
	}
	c.SetReadDeadline(time.Now().Add(handshakeTimeout))

	// Active handshake timeout: close connection if still in pre-auth state.
	// gnet's SetReadDeadline only triggers on read attempts; silent connections
	// (no data sent) never trigger a read, so the deadline is never checked.
	time.AfterFunc(handshakeTimeout, func() {
		state := ctx.State()
		if state != StateClosed && state != StateRelaying && state != StateSplicing && state != StateDialingDC {
			h.logger.Info("[#%d] handshake timeout from %s in state %s (active: %d)",
				ctx.id, c.RemoteAddr(), state, atomic.LoadInt64(&h.activeConns))
			c.Close()
		}
	})

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

	// Drop from the silence-sweep registry if it was tracked.
	if h.clientSilenceCloseMs > 0 {
		h.relayConns.Delete(ctx.id)
	}

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
	if ctx.ipLimitTracked && h.connLimiter != nil {
		h.connLimiter.Release(ctx.ipLimitKey)
		ctx.ipLimitTracked = false
	}
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
		if ctx.ProtocolMode() == ModeDD {
			return h.handleRelayDD(c, ctx)
		}
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
