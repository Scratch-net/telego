package gproxy

import (
	"context"
	"fmt"
	"os"
	"strings"
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

	// Upstream (DC connection)
	Socks5Addr string // SOCKS5 proxy for DC connections (e.g., "127.0.0.1:1080")

	// Incoming connection handling
	ProxyProtocol       bool // Accept incoming PROXY protocol headers
	MaxConnectionsPerIP int  // Per IP+secret limit, 0 = unlimited

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

// parseBindAddress parses the bind address and returns the gnet address string.
// Returns the gnet-formatted address and whether it's a Unix socket.
func parseBindAddress(addr string) (gnetAddr string, isUnix bool) {
	if strings.HasPrefix(addr, "unix://") {
		return addr, true
	}
	if strings.HasPrefix(addr, "tcp://") {
		return addr, false
	}
	// Auto-detect: paths starting with "/" are Unix sockets
	if strings.HasPrefix(addr, "/") {
		return "unix://" + addr, true
	}
	return "tcp://" + addr, false
}

// IsUnixSocket returns true if the bind address is a Unix socket.
func IsUnixSocket(addr string) bool {
	_, isUnix := parseBindAddress(addr)
	return isUnix
}

// Run starts the proxy with graceful shutdown support using gnet.
// Returns a shutdown function that can be called to stop the server.
func Run(cfg *Config, logger Logger) (shutdown func(), errCh <-chan error) {
	var cancelFunc context.CancelFunc

	ch := make(chan error, 1)

	if logger == nil {
		logger = defaultLogger{}
	}

	// Probe DC addresses at startup and sort by RTT
	dc.SetProbeLogger(logger.Info)
	if cfg.Socks5Addr != "" {
		if err := dc.SetProbeSocks5(cfg.Socks5Addr); err != nil {
			logger.Warn("Failed to set SOCKS5 for DC probing: %v", err)
		} else {
			logger.Info("DC probing via SOCKS5: %s", cfg.Socks5Addr)
		}
	}
	dc.Init()

	// Use atomic pointer to store engine reference
	var engPtr atomic.Pointer[gnet.Engine]
	// Signal that engine is ready
	ready := make(chan struct{})

	go func() {
		handler := NewProxyHandler(cfg, logger)

		// Initialize DC client for outgoing connections
		dcHandler := &dcEventHandler{proxy: handler}
		dcClient, err := gnet.NewClient(
			dcHandler,
			gnet.WithMulticore(cfg.Multicore),
			gnet.WithLockOSThread(cfg.LockOSThread),
			gnet.WithReadBufferCap(256*1024),  // 256KB read buffer
			gnet.WithWriteBufferCap(768*1024), // 768KB write buffer
		)
		if err != nil {
			ch <- fmt.Errorf("failed to create DC client: %w", err)
			return
		}
		if err := dcClient.Start(); err != nil {
			ch <- fmt.Errorf("failed to start DC client: %w", err)
			return
		}
		handler.dcClient = dcClient
		if cfg.Socks5Addr != "" {
			logger.Debug("DC client started with SOCKS5 proxy: %s", cfg.Socks5Addr)
		} else {
			logger.Debug("DC client started with %d event loops", cfg.NumEventLoop)
		}

		// Initialize TLS fronting if configured
		if cfg.MaskHost != "" && cfg.FetchRealCert {
			handler.certFetcher = tlsfront.NewCertFetcher(cfg.CertRefreshHours, cfg.MaskHost)

			// Fetch certificate synchronously at startup
			logger.Debug("Fetching TLS certificate from %s:%d (SNI: %s)...", cfg.CertHost, cfg.CertPort, cfg.MaskHost)
			cert, err := handler.certFetcher.FetchCert(cfg.CertHost, cfg.CertPort)
			if err != nil {
				logger.Warn("Failed to fetch certificate: %v (will retry in background)", err)
			} else {
				logger.Debug("Certificate fetched: %d certs in chain", len(cert.Chain))
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

		addr, isUnix := parseBindAddress(cfg.BindAddr)

		// Clean up existing socket file before binding
		if isUnix {
			socketPath := strings.TrimPrefix(addr, "unix://")
			if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
				logger.Warn("Failed to remove existing socket file %s: %v", socketPath, err)
			}
			wrapper.socketPath = socketPath
		}

		logger.Info("Starting gnet proxy on %s (multicore=%v, reuseport=%v)",
			cfg.BindAddr, cfg.Multicore, cfg.ReusePort)

		if isUnix {
			cancelFunc = runSetModeUnixSocket(logger, addr, os.FileMode(0666))
			defer cancelFunc()
		}
		ch <- gnet.Run(wrapper, addr, opts...)
	}()

	shutdownFn := func() {
		if cancelFunc != nil {
			cancelFunc()
		}
		// Wait for engine to be ready with a timeout
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		select {
		case <-ready:
			if eng := engPtr.Load(); eng != nil {
				_ = eng.Stop(ctx)
			}
		case <-ctx.Done():
			// Timeout waiting for engine, nothing to stop
		}
	}

	return shutdownFn, ch
}

// In the gnet library, there are no options for configuring Unix socket.
// And I cannot create a Unix socket file in advance with the needed permissions,
// because it is deleted in the gnet library before creating a Unix socket (this is correct behavior).
// This function starts, checks for a Unix Socket file, and changes access rights.
// The function returns the tool to abort the works of the function.
func runSetModeUnixSocket(logger Logger, addr string, mode os.FileMode) (cancelFunc context.CancelFunc) {
	const (
		errUnixSocket   = "unix socket file is not specified"
		errChmod        = "set chmod for file %q, was interrupted by an error: %s"
		unixSocketProto = "unix://"
		ticTimeout      = time.Second * 3
	)
	var (
		err  error
		ctx  context.Context
		usf  string
		done chan struct{}
	)

	ctx, cancelFunc = context.WithCancel(context.Background())
	if usf = strings.TrimPrefix(addr, unixSocketProto); usf == "" {
		logger.Error(errUnixSocket)
		return
	}
	done = make(chan struct{})
	go func(onDone chan<- struct{}) {
		var (
			tic *time.Ticker
			end bool
			inf os.FileInfo
		)

		tic = time.NewTicker(ticTimeout)
		defer tic.Stop()
		onDone <- struct{}{}
		for !end {
			select {
			case <-ctx.Done():
				end = true
				continue
			case <-tic.C:
				inf, err = os.Stat(usf)
				if err != nil {
					continue
				}
				if inf.IsDir() {
					end = true
					continue
				}
				if inf.Mode() == mode {
					continue
				}
			}
			if err = os.Chmod(usf, mode); err != nil {
				logger.Warn(errChmod, usf, err)
			}
		}
	}(done)
	<-done
	close(done)

	return
}

// engineCaptureHandler wraps ProxyHandler to capture the engine on boot.
type engineCaptureHandler struct {
	*ProxyHandler
	engPtr     *atomic.Pointer[gnet.Engine]
	ready      chan struct{}
	socketPath string // Unix socket path for chmod (empty if TCP)
}

func (h *engineCaptureHandler) OnBoot(eng gnet.Engine) gnet.Action {
	h.engPtr.Store(&eng)
	close(h.ready)

	// Set Unix socket permissions so nginx/haproxy can connect
	if h.socketPath != "" {
		if err := os.Chmod(h.socketPath, 0666); err != nil {
			h.logger.Warn("Failed to chmod socket %s: %v", h.socketPath, err)
		}
	}

	return h.ProxyHandler.OnBoot(eng)
}
