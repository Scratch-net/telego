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
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
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
	activeConns       int64
	handshakeFailures [handshakeFailureStageCount]atomic.Uint64

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

	// directDCDial is the outbound connection seam. Production initializes it
	// to dialDirectDC; tests replace it to verify handshake propagation without
	// contacting Telegram.
	directDCDial func(int, obfuscated2.ConnectionType) (*directDCConn, error)

	// middleEnd is nil for the existing direct-only construction path. A
	// non-nil frontend is injected explicitly and owns no source/runtime
	// lifecycle.
	middleEnd *middleEndFrontend

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
	h.directDCDial = h.dialDirectDC

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
	if h.middleEnd != nil {
		h.middleEnd.start()
	}
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
	if h.middleEnd != nil {
		h.middleEnd.stop()
	}
	if h.dcClient != nil {
		h.dcClient.Stop()
	}
}

// OnOpen is called when a new connection is accepted.
func (h *ProxyHandler) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	ctx := NewConnContext()

	// A local WEB connection remains only a candidate until its process-local
	// authentication preface is validated. Public PROXY acceptance remains an
	// independent operator setting.
	internalProxy := h.config.InternalProxyProtocol &&
		h.config.InternalProxyAuth != nil &&
		trustedInternalProxyPeer(c.RemoteAddr())
	ctx.internalProxyCandidate = internalProxy
	parseProxy := h.config.ProxyProtocol || ctx.internalProxyCandidate
	if parseProxy {
		ctx.SetState(StateReadProxyProto)
	}
	// Otherwise keep default StateDetectProtocol from NewConnContext

	c.SetContext(ctx)

	conns := atomic.AddInt64(&h.activeConns, 1)
	h.logger.Info("[#%d] new connection from %s (active: %d)", ctx.id, c.RemoteAddr(), conns)
	if h.config.MaxConnections > 0 && conns > int64(h.config.MaxConnections) {
		h.logger.Info("[#%d] global connection limit reached: %d > %d", ctx.id, conns, h.config.MaxConnections)
		return nil, h.failHandshake(ctx, handshakeFailureAdmission)
	}

	// Every peer consumes admission immediately. Unix WEB candidates use a
	// synthetic loopback address because Unix peer addresses contain no IP.
	admissionAddress := c.RemoteAddr()
	if ctx.internalProxyCandidate {
		if _, unixPeer := admissionAddress.(*net.UnixAddr); unixPeer {
			admissionAddress = internalUnixAdmissionAddress
		}
	}
	if !h.acquireInitialIPLimit(ctx, admissionAddress, conns) {
		return nil, h.failHandshake(ctx, handshakeFailureAdmission)
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
		if state != StateClosed && state != StateRelaying && state != StateSplicing && state != StateDialingDC && state != StateMiddleEnd {
			h.recordHandshakeFailure(ctx, handshakeStageForState(state))
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
	ctx.cancelSpliceDrain()
	if h.middleEnd != nil {
		if ctx.middleEnd != nil {
			h.closeMiddleEnd(ctx.middleEnd)
		} else {
			h.middleEnd.closeDirectFallback(ctx.id)
		}
	}

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
	case StateMiddleEnd:
		return h.handleMiddleEnd(c, ctx)
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

	if ctx.internalProxyCandidate {
		switch h.config.InternalProxyAuth.prefaceStatus(data) {
		case internalPrefaceIncomplete:
			return gnet.None
		case internalPrefaceRejected:
			if !h.acquireInitialIPLimit(ctx, c.RemoteAddr(), atomic.LoadInt64(&h.activeConns)) {
				return h.failHandshake(ctx, handshakeFailureAdmission)
			}
			h.logger.Debug("[#%d] rejected unauthenticated internal WEB preface", ctx.id)
			return h.failHandshake(ctx, handshakeFailureProxyProtocol)
		case internalPrefaceAccepted:
			c.Discard(h.config.InternalProxyAuth.prefaceLen())
			ctx.internalProxyCandidate = false
			ctx.internalProxyAuthenticated = true
			data, _ = c.Peek(-1)
			if len(data) == 0 {
				return gnet.None
			}
		case internalPrefaceNoMatch:
			ctx.internalProxyCandidate = false
			if !h.config.ProxyProtocol {
				return h.fallbackFromProxyProtocol(c, ctx)
			}
		}
	}

	frameStatus, err := inspectProxyProtocolFrame(data)
	if err != nil {
		h.logger.Debug("[#%d] PROXY protocol error: %v", ctx.id, err)
		return h.failHandshake(ctx, handshakeFailureProxyProtocol)
	}
	if frameStatus == proxyProtoIncomplete {
		return gnet.None
	}
	if frameStatus == proxyProtoNotPresent {
		if ctx.internalProxyAuthenticated {
			h.logger.Debug("[#%d] authenticated internal WEB preface without PROXY header", ctx.id)
			return h.failHandshake(ctx, handshakeFailureProxyProtocol)
		}
		return h.fallbackFromProxyProtocol(c, ctx)
	}

	result, err := ParseProxyProtocol(data)
	if err != nil {
		h.logger.Debug("[#%d] PROXY protocol error: %v", ctx.id, err)
		return h.failHandshake(ctx, handshakeFailureProxyProtocol)
	}

	if result == nil {
		return h.fallbackFromProxyProtocol(c, ctx)
	}

	// Discard the PROXY header bytes
	c.Discard(result.HeaderLen)

	// An authenticated WEB connection transfers its provisional loopback slot
	// to the validated client IP. Acquire the new slot before releasing the old
	// one so saturation cannot create an uncharged window.
	if ctx.internalProxyAuthenticated {
		if result.SrcAddr == nil || !h.transferInitialIPLimit(ctx, result.SrcAddr, atomic.LoadInt64(&h.activeConns)) {
			return h.failHandshake(ctx, handshakeFailureAdmission)
		}
		ctx.setTrustedProxyTuple(result.SrcAddr, result.DstAddr)
	}

	// Store real client address if provided.
	if result.SrcAddr != nil {
		ctx.SetRealClientAddr(result.SrcAddr)
		h.logger.Debug("[#%d] PROXY protocol: real client %s", ctx.id, result.SrcAddr)
	}
	clientAddr := result.SrcAddr
	if clientAddr == nil {
		clientAddr = c.RemoteAddr()
	}
	if !h.acquireInitialIPLimit(ctx, clientAddr, atomic.LoadInt64(&h.activeConns)) {
		return h.failHandshake(ctx, handshakeFailureAdmission)
	}

	// Proceed to protocol detection
	ctx.SetState(StateDetectProtocol)
	return h.handleDetectProtocol(c, ctx)
}

func (h *ProxyHandler) fallbackFromProxyProtocol(c gnet.Conn, ctx *ConnContext) gnet.Action {
	if !h.acquireInitialIPLimit(ctx, c.RemoteAddr(), atomic.LoadInt64(&h.activeConns)) {
		return h.failHandshake(ctx, handshakeFailureAdmission)
	}
	ctx.SetState(StateDetectProtocol)
	return h.handleDetectProtocol(c, ctx)
}

func trustedInternalProxyPeer(address net.Addr) bool {
	switch typed := address.(type) {
	case *net.TCPAddr:
		return typed.IP != nil && typed.IP.IsLoopback()
	case *net.UnixAddr:
		return true
	default:
		return false
	}
}

var internalUnixAdmissionAddress = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}

func (h *ProxyHandler) acquireInitialIPLimit(ctx *ConnContext, address net.Addr, active int64) bool {
	if h.connLimiter == nil || ctx.ipLimitTracked {
		return true
	}
	ip := limiterIP(address)
	if ip == nil {
		return true
	}
	key, ok := h.connLimiter.TryAcquireIP(ip)
	if !ok {
		h.logger.Info("[#%d] per-IP connection limit exceeded for %s (active: %d)", ctx.id, ip, active)
		return false
	}
	ctx.ipLimitTracked = true
	ctx.ipLimitKey = key
	return true
}

func (h *ProxyHandler) transferInitialIPLimit(ctx *ConnContext, address net.Addr, active int64) bool {
	if h.connLimiter == nil {
		return true
	}
	ip := limiterIP(address)
	if ip == nil {
		return false
	}
	if !ctx.ipLimitTracked {
		return h.acquireInitialIPLimit(ctx, address, active)
	}
	keyArray := h.connLimiter.hashKey(ip, nil)
	if ctx.ipLimitKey == string(keyArray[:]) {
		return true
	}
	newKey, ok := h.connLimiter.TryAcquireIP(ip)
	if !ok {
		h.logger.Info("[#%d] per-IP connection limit exceeded for %s (active: %d)", ctx.id, ip, active)
		return false
	}
	oldKey := ctx.ipLimitKey
	ctx.ipLimitKey = newKey
	h.connLimiter.Release(oldKey)
	return true
}

func limiterIP(address net.Addr) net.IP {
	if tcpAddress, ok := address.(*net.TCPAddr); ok {
		return tcpAddress.IP
	}
	if address != nil {
		if host, _, err := net.SplitHostPort(address.String()); err == nil {
			return net.ParseIP(host)
		}
	}
	return nil
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
