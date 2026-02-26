package gproxy

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/dc"
	"github.com/scratch-net/telego/pkg/tlsfront"
)

// Secret represents a named proxy secret.
type Secret struct {
	Name   string // User-friendly name for logging
	Key    []byte // 16-byte secret key
	Host   string // SNI hostname
	RawHex string // Original hex string for link generation
}

// Config configures the gnet proxy server.
type Config struct {
	// Secrets is the list of allowed proxy secrets.
	Secrets []Secret
	Host    string // Default SNI hostname (from first secret)

	// Network
	BindAddr string

	// TLS Fronting
	MaskHost           string // Domain to mimic (SNI validation, proxy links)
	MaskPort           int    // Default port
	FetchRealCert      bool
	SpliceUnrecognized bool
	CertRefreshHours   int

	// Certificate fetching (where to connect to get real cert)
	// Defaults to MaskHost:MaskPort if not set
	CertHost string
	CertPort int

	// Splice target (where to forward unrecognized clients)
	// Defaults to MaskHost:MaskPort if not set
	SpliceHost          string
	SplicePort          int
	SpliceProxyProtocol int // 0 = off, 1 = v1 (text), 2 = v2 (binary)

	// Performance
	IPPreference      dc.IPPreference
	IdleTimeout       time.Duration
	TimeSkewTolerance time.Duration

	// gnet-specific
	Multicore    bool // Use multiple event loops
	ReusePort    bool // Enable SO_REUSEPORT
	LockOSThread bool // Lock goroutines to OS threads
	NumEventLoop int  // Number of event loops (0 = auto)
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaskPort:          443,
		CertRefreshHours:  5,
		IdleTimeout:       5 * time.Minute,
		TimeSkewTolerance: 3 * time.Second,
		IPPreference:      dc.PreferIPv4,
		Multicore:         true,
		ReusePort:         true,
		LockOSThread:      true,
	}
}

// Run starts the proxy with graceful shutdown support.
// Returns a shutdown function that can be called to stop the server.
func Run(cfg *Config, logger Logger) (shutdown func(), errCh <-chan error) {
	ch := make(chan error, 1)

	if logger == nil {
		logger = defaultLogger{}
	}

	// Probe DC addresses at startup and sort by RTT
	dc.SetProbeLogger(logger.Info)
	dc.Init()

	// Use atomic pointer to store engine reference
	var engPtr atomic.Pointer[gnet.Engine]
	// Signal that engine is ready
	ready := make(chan struct{})

	go func() {
		handler := NewProxyHandler(cfg, logger)

		// Initialize TLS fronting if configured
		if cfg.MaskHost != "" && cfg.FetchRealCert {
			handler.certFetcher = tlsfront.NewCertFetcher(cfg.CertRefreshHours, cfg.MaskHost)

			// Fetch certificate synchronously at startup
			logger.Info("Fetching TLS certificate from %s:%d (SNI: %s)...", cfg.CertHost, cfg.CertPort, cfg.MaskHost)
			cert, err := handler.certFetcher.FetchCert(cfg.CertHost, cfg.CertPort)
			if err != nil {
				logger.Warn("Failed to fetch certificate: %v (will retry in background)", err)
			} else {
				logger.Info("Certificate fetched: %d certs in chain", len(cert.Chain))
			}

			// Start background refresh
			handler.certFetcher.StartBackgroundRefresh(cfg.CertHost, cfg.CertPort)
		}

		// Custom handler to capture engine
		wrapper := &engineCaptureHandler{
			ProxyHandler: handler,
			engPtr:       &engPtr,
			ready:        ready,
		}

		opts := []gnet.Option{
			gnet.WithMulticore(cfg.Multicore),
			gnet.WithReusePort(cfg.ReusePort),
			gnet.WithLockOSThread(cfg.LockOSThread),
		}

		if cfg.NumEventLoop > 0 {
			opts = append(opts, gnet.WithNumEventLoop(cfg.NumEventLoop))
		}

		addr := "tcp://" + cfg.BindAddr

		logger.Info("Starting gnet proxy on %s (multicore=%v, reuseport=%v)",
			cfg.BindAddr, cfg.Multicore, cfg.ReusePort)

		ch <- gnet.Run(wrapper, addr, opts...)
	}()

	shutdownFn := func() {
		// Wait for engine to be ready with a timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		select {
		case <-ready:
			if eng := engPtr.Load(); eng != nil {
				eng.Stop(ctx)
			}
		case <-ctx.Done():
			// Timeout waiting for engine, nothing to stop
		}
	}

	return shutdownFn, ch
}

// engineCaptureHandler wraps ProxyHandler to capture the engine on boot.
type engineCaptureHandler struct {
	*ProxyHandler
	engPtr *atomic.Pointer[gnet.Engine]
	ready  chan struct{}
}

func (h *engineCaptureHandler) OnBoot(eng gnet.Engine) gnet.Action {
	h.engPtr.Store(&eng)
	close(h.ready)
	return h.ProxyHandler.OnBoot(eng)
}
