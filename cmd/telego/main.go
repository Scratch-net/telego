// Package main implements the telego CLI.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/pion/stun/v3"

	"github.com/scratch-net/telego/pkg/config"
	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/log"
	"github.com/scratch-net/telego/pkg/metrics"
)

// Build-time variables injected via ldflags.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// CLI defines the command-line interface.
var CLI struct {
	Run      RunCmd      `cmd:"" help:"Run the proxy server"`
	Generate GenerateCmd `cmd:"" help:"Generate a new secret"`
	Version  VersionCmd  `cmd:"" help:"Show version information"`
}

// RunCmd runs the proxy server.
type RunCmd struct {
	Config string `short:"c" help:"Path to config file" type:"existingfile" required:""`
	Bind   string `short:"b" help:"Address to bind to (overrides config)"`
	Link   bool   `short:"l" help:"Print Telegram proxy links on startup (detects public IP via STUN)"`
}

func (c *RunCmd) Run() error {
	// Load config file
	fileCfg, err := config.Load(c.Config)
	if err != nil {
		log.Error().Err(err).Msg("failed to load config")
		return err
	}

	cfg, err := fileCfg.ToGProxyConfig()
	if err != nil {
		log.Error().Err(err).Msg("invalid config")
		return err
	}

	// Set log level from config ([general] takes precedence)
	logLevel := fileCfg.General.LogLevel
	if logLevel == "" {
		logLevel = fileCfg.LogLevel // backwards compat
	}
	if logLevel != "" {
		log.SetLevel(logLevel)
	}

	// CLI overrides
	if c.Bind != "" {
		cfg.BindAddr = c.Bind
	}

	// Default bind address
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0:443"
	}

	// Print Telegram links if requested (skip for Unix sockets)
	if c.Link {
		if gproxy.IsUnixSocket(cfg.BindAddr) {
			log.Warn().Msg("Telegram links not available for Unix socket binding")
		} else if err := printTelegramLinks(cfg.Secrets, cfg.BindAddr); err != nil {
			log.Warn().Err(err).Msg("failed to generate Telegram links")
		}
	}

	log.Info().
		Str("bind", cfg.BindAddr).
		Int("secrets", len(cfg.Secrets)).
		Str("tls_fronting", cfg.MaskHost).
		Msg("telego proxy started")

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	logger := &zerologAdapter{}
	shutdown, handler, errCh := gproxy.RunWithHandler(&cfg, logger)

	// Start metrics server if configured
	var metricsServer *metrics.Server
	if fileCfg.Metrics.BindTo != "" {
		var err error
		metricsServer, err = metrics.NewServer(metrics.Config{
			BindAddr: fileCfg.Metrics.BindTo,
			Path:     fileCfg.Metrics.Path,
		}, handler.UserLimiter())
		if err != nil {
			log.Error().Err(err).Msg("failed to create metrics server")
		} else {
			if err := metricsServer.Start(); err != nil {
				log.Error().Err(err).Msg("failed to start metrics server")
			} else {
				log.Info().Str("addr", fileCfg.Metrics.BindTo).Msg("metrics server started")
			}
		}
	}

	// Start hot reloader for config changes
	hotReloader := gproxy.NewHotReloader(gproxy.HotReloadConfig{
		ConfigPath: c.Config,
		LoadConfig: func() (*gproxy.Config, string, error) {
			fileCfg, err := config.Load(c.Config)
			if err != nil {
				return nil, "", err
			}
			proxyCfg, err := fileCfg.ToGProxyConfig()
			if err != nil {
				return nil, "", err
			}
			logLevel := fileCfg.General.LogLevel
			if logLevel == "" {
				logLevel = fileCfg.LogLevel
			}
			return &proxyCfg, logLevel, nil
		},
		Handler:  handler,
		Logger:   logger,
		SetLogFn: log.SetLevel,
	})
	hotReloader.Start()

	select {
	case sig := <-sigCh:
		log.Info().Str("signal", sig.String()).Msg("shutting down")
		if metricsServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			metricsServer.Shutdown(shutdownCtx)
			cancel()
		}
		hotReloader.Stop()
		shutdown()
		return nil
	case err := <-errCh:
		if metricsServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			metricsServer.Shutdown(shutdownCtx)
			cancel()
		}
		hotReloader.Stop()
		return err
	}
}

// printTelegramLinks detects public IP via STUN and prints Telegram proxy links for all secrets.
func printTelegramLinks(secrets []gproxy.Secret, bindAddr string) error {
	// Get public IP via STUN
	publicIP, err := getPublicIP()
	if err != nil {
		return fmt.Errorf("STUN failed: %w", err)
	}

	// Extract port from bind address
	port := "443"
	if _, p, err := net.SplitHostPort(bindAddr); err == nil {
		port = p
	}

	for _, s := range secrets {
		// ee link (FakeTLS) - uses full secret with hostname
		eeLink := fmt.Sprintf("tg://proxy?server=%s&port=%s&secret=%s", publicIP, port, s.RawHex)

		// dd link (raw) - uses dd prefix + key only (no hostname)
		ddSecret := config.BuildDDSecret(s.Key)
		ddLink := fmt.Sprintf("tg://proxy?server=%s&port=%s&secret=%s", publicIP, port, ddSecret)

		log.Info().
			Str("name", s.Name).
			Str("ee_link", eeLink).
			Str("dd_link", ddLink).
			Msg("Telegram proxy links")
	}

	return nil
}

// getPublicIP discovers the public IP address using STUN.
func getPublicIP() (string, error) {
	// Use Google's STUN server
	conn, err := net.Dial("udp", "stun.l.google.com:19302")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	c, err := stun.NewClient(conn)
	if err != nil {
		return "", err
	}
	defer c.Close()

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var xorAddr stun.XORMappedAddress
	if err := c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			err = res.Error
			return
		}
		if getErr := xorAddr.GetFrom(res.Message); getErr != nil {
			err = getErr
		}
	}); err != nil {
		return "", err
	}

	return xorAddr.IP.String(), nil
}

// GenerateCmd generates a new secret key.
type GenerateCmd struct {
	Host string `arg:"" help:"Hostname for the secret (e.g., www.google.com)"`
}

func (c *GenerateCmd) Run() error {
	if c.Host == "" {
		return fmt.Errorf("hostname required")
	}

	keyHex, err := config.GenerateKey()
	if err != nil {
		return err
	}

	key, _ := config.ParseKey(keyHex)
	eeSecret := config.BuildFullSecret(key, c.Host)
	ddSecret := config.BuildDDSecret(key)

	log.Info().
		Str("secret", keyHex).
		Str("ee_link", "tg://proxy?server=YOUR_IP&port=443&secret="+eeSecret).
		Str("dd_link", "tg://proxy?server=YOUR_IP&port=443&secret="+ddSecret).
		Msg("generated secret (use ee for FakeTLS, dd for raw)")

	return nil
}

// VersionCmd shows version information.
type VersionCmd struct{}

func (c *VersionCmd) Run() error {
	log.Info().
		Str("version", version).
		Str("commit", commit).
		Str("date", date).
		Str("description", "Production-grade Telegram MTProxy in Go").
		Strs("features", []string{
			"Event-driven gnet architecture",
			"TLS fronting with real cert fetching",
			"Splice mode for probe resistance",
			"FakeTLS (ee) and raw (dd) protocol support",
			"Multiple secrets per user",
		}).
		Msg("telego")
	return nil
}

func main() {
	ctx := kong.Parse(&CLI,
		kong.Name("telego"),
		kong.Description("Production-grade Telegram MTProxy"),
		kong.UsageOnError(),
	)
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

// zerologAdapter adapts zerolog to proxy.Logger interface.
type zerologAdapter struct{}

func (l *zerologAdapter) Debug(format string, args ...any) {
	log.Debug().Msgf(format, args...)
}

func (l *zerologAdapter) Info(format string, args ...any) {
	log.Info().Msgf(format, args...)
}

func (l *zerologAdapter) Warn(format string, args ...any) {
	log.Warn().Msgf(format, args...)
}

func (l *zerologAdapter) Error(format string, args ...any) {
	log.Error().Msgf(format, args...)
}

func (l *zerologAdapter) DebugEnabled() bool {
	return log.Debug().Enabled()
}
