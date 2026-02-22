// Package proxy implements the main MTProxy server.
package proxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/ants/v2"

	"github.com/example/telego/pkg/dc"
	"github.com/example/telego/pkg/middleend"
	"github.com/example/telego/pkg/netx"
	"github.com/example/telego/pkg/tlsfront"
	"github.com/example/telego/pkg/transport/faketls"
	"github.com/example/telego/pkg/transport/obfuscated2"
)

var (
	ErrProxyClosed = errors.New("proxy is closed")
)

// Proxy is the main MTProxy server.
type Proxy struct {
	// Configuration
	config Config

	// State
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closed    atomic.Bool

	// Connection handling
	workerPool *ants.PoolWithFunc

	// DC management
	dcManager *dc.Manager

	// Middle-End pool (optional)
	mePool *middleend.Pool

	// TLS fronting
	certFetcher *tlsfront.CertFetcher
	splicer     *tlsfront.Splicer

	// Anti-replay cache
	replayCache *ReplayCache

	// Logger
	logger Logger
}

// Config configures the proxy.
type Config struct {
	// Secret is the 16-byte proxy secret (ee-prefixed).
	Secret []byte
	Host   string // SNI hostname from secret

	// Network
	BindAddr    string
	Concurrency int

	// Middle-End
	MEEnabled   bool
	MEPoolSize  int
	MEServers   []string
	MEFallback  bool // Fallback to direct DC if ME fails

	// TLS Fronting
	MaskHost         string
	MaskPort         int
	FetchRealCert    bool
	SpliceUnrecognized bool
	CertRefreshHours int

	// Performance
	IPPreference  dc.IPPreference
	IdleTimeout   time.Duration
	TimeSkewTolerance time.Duration
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		Concurrency:      8192,
		MEPoolSize:       16,
		MEFallback:       true,
		MaskPort:         443,
		CertRefreshHours: 5,
		IdleTimeout:      5 * time.Minute,
		TimeSkewTolerance: 3 * time.Second,
		IPPreference:     dc.PreferIPv4,
	}
}

// New creates a new proxy.
func New(cfg Config) (*Proxy, error) {
	ctx, cancel := context.WithCancel(context.Background())

	p := &Proxy{
		config:    cfg,
		ctx:       ctx,
		cancel:    cancel,
		dcManager: dc.NewManager(cfg.Secret, cfg.IPPreference),
		replayCache: NewReplayCache(1000000, 10*time.Minute),
		logger:    defaultLogger{},
	}

	// Create worker pool
	pool, err := ants.NewPoolWithFunc(cfg.Concurrency, func(arg any) {
		p.handleConn(arg.(net.Conn))
	}, ants.WithNonblocking(true))
	if err != nil {
		cancel()
		return nil, err
	}
	p.workerPool = pool

	// Initialize ME pool if enabled
	if cfg.MEEnabled && len(cfg.MEServers) > 0 {
		publicIP, _ := middleend.DetectPublicIP()
		mePool, err := middleend.NewPool(middleend.PoolConfig{
			Size:     cfg.MEPoolSize,
			Secret:   cfg.Secret,
			PublicIP: publicIP,
			Servers:  cfg.MEServers,
		})
		if err != nil {
			p.logger.Warn("Failed to create ME pool: %v", err)
		} else {
			p.mePool = mePool
		}
	}

	// Initialize TLS fronting
	if cfg.MaskHost != "" {
		p.splicer = tlsfront.NewSplicer(cfg.MaskHost, cfg.MaskPort)
		if cfg.FetchRealCert {
			p.certFetcher = tlsfront.NewCertFetcher(cfg.CertRefreshHours)
			p.certFetcher.StartBackgroundRefresh(cfg.MaskHost, cfg.MaskPort)
		}
	}

	return p, nil
}

// Serve starts the proxy server on the given listener.
func (p *Proxy) Serve(ln net.Listener) error {
	// Tune listener if TCP
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		if err := netx.TuneListener(tcpLn); err != nil {
			p.logger.Warn("Failed to tune listener: %v", err)
		}
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if p.closed.Load() {
				return nil
			}
			p.logger.Warn("Accept error: %v", err)
			continue
		}

		// Tune connection
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			netx.TuneConn(tcpConn)
		}

		// Submit to worker pool
		if err := p.workerPool.Invoke(conn); err != nil {
			conn.Close()
			if errors.Is(err, ants.ErrPoolOverload) {
				p.logger.Debug("Pool overload, dropping connection")
			}
		}
	}
}

// handleConn processes a single client connection.
func (p *Proxy) handleConn(conn net.Conn) {
	p.wg.Add(1)
	defer p.wg.Done()
	defer conn.Close()

	// Create stream context
	ctx := p.newStreamContext(conn)
	defer ctx.cancel()

	p.logger.Debug("New connection from %s", conn.RemoteAddr())

	// Set initial deadline
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Create rewindable connection for TLS fronting fallback
	rewindConn := tlsfront.NewRewindConn(conn)

	// Step 1: FakeTLS handshake
	ftlsConn, clientHello, err := p.doFakeTLSHandshake(ctx, rewindConn)
	if err != nil {
		p.logger.Debug("FakeTLS handshake failed: %v", err)
		// Invalid ClientHello - splice to mask host
		if p.splicer != nil && p.config.SpliceUnrecognized {
			p.logger.Debug("Splicing to mask host")
			rewindConn.Rewind()
			p.splicer.Splice(ctx.ctx, rewindConn.StopBuffering(), nil)
		} else {
			p.logger.Debug("No splice configured, closing connection")
		}
		return
	}

	// Step 2: Obfuscated2 handshake
	o2Conn, dcID, err := p.doObfuscated2Handshake(ctx, ftlsConn)
	if err != nil {
		p.logger.Debug("Obfuscated2 handshake failed: %v", err)
		return
	}

	ctx.dc = dcID
	_ = clientHello // Used for logging

	// Clear deadline for relay
	conn.SetDeadline(time.Time{})

	// Step 3: Connect to Telegram (ME or Direct)
	var telegramConn net.Conn
	if p.mePool != nil && p.mePool.IsHealthy() {
		telegramConn, err = p.doMiddleEndCall(ctx)
		if err != nil && p.config.MEFallback {
			telegramConn, err = p.doDirectDCCall(ctx)
		}
	} else {
		telegramConn, err = p.doDirectDCCall(ctx)
	}

	if err != nil {
		p.logger.Debug("Failed to connect to Telegram: %v", err)
		return
	}
	defer telegramConn.Close()

	// Step 4: Relay traffic
	netx.Relay(o2Conn, telegramConn)
}

// doFakeTLSHandshake validates and processes the FakeTLS ClientHello.
func (p *Proxy) doFakeTLSHandshake(ctx *streamContext, conn *tlsfront.RewindConn) (*faketls.Conn, *faketls.ClientHello, error) {
	// Read TLS record
	rec, err := faketls.ReadRecord(conn)
	if err != nil {
		return nil, nil, err
	}
	defer faketls.ReleaseRecord(rec)

	if rec.Type != faketls.RecordTypeHandshake {
		return nil, nil, errors.New("expected TLS handshake")
	}

	// Parse and validate ClientHello
	hello, err := faketls.ParseClientHello(p.config.Secret, rec.Payload)
	if err != nil {
		// Debug: show first 20 bytes of payload
		hexDump := ""
		for i := 0; i < 20 && i < len(rec.Payload); i++ {
			hexDump += fmt.Sprintf("%02x ", rec.Payload[i])
		}
		p.logger.Debug("ParseClientHello error: %v (payload len=%d, secret len=%d, first bytes: %s)",
			err, len(rec.Payload), len(p.config.Secret), hexDump)
		return nil, nil, err
	}

	// Validate against our secret's hostname
	if err := hello.Valid(p.config.Host, p.config.TimeSkewTolerance); err != nil {
		return nil, nil, err
	}

	// Check replay
	if p.replayCache.Seen(hello.SessionID) {
		return nil, nil, errors.New("replay attack detected")
	}

	// Build and send ServerHello
	response, err := faketls.BuildServerHello(p.config.Secret, hello)
	if err != nil {
		return nil, nil, err
	}

	if _, err := conn.Write(response); err != nil {
		return nil, nil, err
	}

	return faketls.NewConn(conn.StopBuffering()), hello, nil
}

// doObfuscated2Handshake performs the obfuscated2 handshake.
func (p *Proxy) doObfuscated2Handshake(ctx *streamContext, conn net.Conn) (*obfuscated2.Conn, int, error) {
	dcID, encryptor, decryptor, err := obfuscated2.ClientHandshake(p.config.Secret, conn)
	if err != nil {
		return nil, 0, err
	}

	o2Conn := obfuscated2.NewConn(conn, encryptor, decryptor)
	return o2Conn, dcID, nil
}

// doMiddleEndCall connects via Middle-End servers.
func (p *Proxy) doMiddleEndCall(ctx *streamContext) (net.Conn, error) {
	meConn, err := p.mePool.Acquire(ctx.ctx)
	if err != nil {
		return nil, err
	}

	// ME connection is ready for data relay
	// TODO: Proper ME protocol implementation
	return meConn.Conn, nil
}

// doDirectDCCall connects directly to the Telegram DC.
func (p *Proxy) doDirectDCCall(ctx *streamContext) (net.Conn, error) {
	return p.dcManager.DialWithFallback(ctx.ctx, ctx.dc)
}

// Shutdown gracefully shuts down the proxy.
func (p *Proxy) Shutdown(timeout time.Duration) error {
	if p.closed.Swap(true) {
		return nil
	}

	p.cancel()

	// Wait for connections with timeout
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		p.logger.Warn("Shutdown timeout, forcing close")
	}

	// Cleanup
	p.workerPool.Release()
	if p.mePool != nil {
		p.mePool.Close()
	}

	return nil
}

// streamContext holds per-connection state.
type streamContext struct {
	ctx      context.Context
	cancel   context.CancelFunc
	streamID string
	dc       int
	logger   Logger
}

func (p *Proxy) newStreamContext(conn net.Conn) *streamContext {
	ctx, cancel := context.WithCancel(p.ctx)

	// Generate random stream ID
	id := make([]byte, 16)
	rand.Read(id)
	streamID := base64.RawURLEncoding.EncodeToString(id)

	return &streamContext{
		ctx:      ctx,
		cancel:   cancel,
		streamID: streamID,
		logger:   p.logger,
	}
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

// SetLogger sets the proxy logger.
func (p *Proxy) SetLogger(l Logger) {
	p.logger = l
}
