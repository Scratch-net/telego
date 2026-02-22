// Package main implements the telego CLI.
package main

import (
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

	// Set log level from config
	if fileCfg.LogLevel != "" {
		log.SetLevel(fileCfg.LogLevel)
	}

	// CLI overrides
	if c.Bind != "" {
		cfg.BindAddr = c.Bind
	}

	// Default bind address
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0:443"
	}

	// Print Telegram links if requested
	if c.Link {
		if err := printTelegramLinks(cfg.Secrets, cfg.BindAddr); err != nil {
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

	shutdown, errCh := gproxy.RunWithShutdown(&cfg, &zerologAdapter{})

	select {
	case sig := <-sigCh:
		log.Info().Str("signal", sig.String()).Msg("shutting down")
		shutdown()
		return nil
	case err := <-errCh:
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
		link := fmt.Sprintf("tg://proxy?server=%s&port=%s&secret=%s", publicIP, port, s.RawHex)
		log.Info().
			Str("name", s.Name).
			Str("link", link).
			Msg("Telegram proxy link")
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
	fullSecret := config.BuildFullSecret(key, c.Host)

	log.Info().
		Str("key", keyHex).
		Str("full_secret", fullSecret).
		Str("link", "tg://proxy?server=YOUR_IP&port=443&secret="+fullSecret).
		Msg("generated new key")

	return nil
}

// VersionCmd shows version information.
type VersionCmd struct{}

func (c *VersionCmd) Run() error {
	log.Info().
		Str("version", "v0.1.0").
		Str("description", "Production-grade Telegram MTProxy in Go").
		Strs("features", []string{
			"Event-driven gnet architecture",
			"TLS fronting with real cert fetching",
			"Splice mode for probe resistance",
			"FakeTLS (0xee prefix) support",
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
