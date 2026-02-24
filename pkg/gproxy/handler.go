package gproxy

import (
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/tlsfront"
)

// ProxyHandler implements gnet.EventHandler for the MTProxy server.
type ProxyHandler struct {
	gnet.BuiltinEventEngine

	// Configuration
	config *Config

	// DC client for outgoing connections
	dcClient *gnet.Client

	// Our public IP (detected via STUN, used for logging)
	publicIP string

	// Replay cache for anti-replay protection
	replayCache *ReplayCache

	// TLS fronting
	certFetcher *tlsfront.CertFetcher

	// Logger
	logger Logger

	// Metrics
	activeConns int64
}

// NewProxyHandler creates a new gnet proxy handler.
func NewProxyHandler(cfg *Config, logger Logger) *ProxyHandler {
	if logger == nil {
		logger = defaultLogger{}
	}

	return &ProxyHandler{
		config:      cfg,
		replayCache: NewReplayCache(1000000, 10*time.Minute),
		logger:      logger,
	}
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
	c.SetContext(ctx)

	h.logger.Debug("new connection from %s", c.RemoteAddr())

	// Set read deadline for handshake
	c.SetReadDeadline(time.Now().Add(30 * time.Second))

	return nil, gnet.None
}

// OnClose is called when a connection is closed.
func (h *ProxyHandler) OnClose(c gnet.Conn, err error) gnet.Action {
	ctx, ok := c.Context().(*ConnContext)
	if !ok || ctx == nil {
		return gnet.None
	}

	// Close DC connection if active
	if relay := ctx.Relay(); relay != nil && relay.DCConn != nil {
		relay.DCConn.Close()
	}

	// Close splice connection if active
	ctx.mu.Lock()
	if ctx.spliceNetConn != nil {
		ctx.spliceNetConn.Close()
		ctx.spliceNetConn = nil
	}
	ctx.mu.Unlock()

	if err != nil {
		ctx.mu.Lock()
		userName := ""
		if ctx.secret != nil {
			userName = ctx.secret.Name
		}
		ctx.mu.Unlock()
		if userName != "" {
			h.logger.Debug("[%s] closed: %v", userName, err)
		} else {
			h.logger.Debug("connection closed: %v", err)
		}
	}

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
	case StateReadTLSHeader:
		return h.handleTLSHeader(c, ctx)
	case StateReadTLSPayload:
		return h.handleTLSPayload(c, ctx)
	case StateReadO2Frame:
		return h.handleO2Frame(c, ctx)
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

// Logger interface for proxy logging.
type Logger interface {
	Debug(format string, args ...any)
	Info(format string, args ...any)
	Warn(format string, args ...any)
	Error(format string, args ...any)
}

type defaultLogger struct{}

func (defaultLogger) Debug(format string, args ...any) {}
func (defaultLogger) Info(format string, args ...any)  {}
func (defaultLogger) Warn(format string, args ...any)  {}
func (defaultLogger) Error(format string, args ...any) {}
