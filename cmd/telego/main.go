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

	"github.com/example/telego/pkg/config"
	"github.com/example/telego/pkg/proxy"
)

// CLI defines the command-line interface.
var CLI struct {
	Run      RunCmd      `cmd:"" help:"Run the proxy server"`
	Generate GenerateCmd `cmd:"" help:"Generate a new secret"`
	Version  VersionCmd  `cmd:"" help:"Show version information"`
}

// RunCmd runs the proxy server.
type RunCmd struct {
	Config string `short:"c" help:"Path to config file" type:"existingfile"`
	Secret string `short:"s" help:"Proxy secret (overrides config)"`
	Bind   string `short:"b" help:"Address to bind to (default: 0.0.0.0:443)"`
}

func (c *RunCmd) Run() error {
	var cfg proxy.Config

	if c.Config != "" {
		// Load from config file
		fileCfg, err := config.Load(c.Config)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		cfg, err = fileCfg.ToProxyConfig()
		if err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}
	} else {
		cfg = proxy.DefaultConfig()
	}

	// CLI overrides
	if c.Secret != "" {
		secret, host, err := config.ParseSecret(c.Secret)
		if err != nil {
			return fmt.Errorf("invalid secret: %w", err)
		}
		cfg.Secret = secret
		cfg.Host = host
	}
	if c.Bind != "" {
		cfg.BindAddr = c.Bind
	}

	// Default bind address
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0:443"
	}

	// Validate
	if len(cfg.Secret) == 0 {
		return fmt.Errorf("secret is required")
	}

	// Create proxy
	p, err := proxy.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	// Set up logging
	p.SetLogger(&consoleLogger{})

	// Create listener
	ln, err := net.Listen("tcp", cfg.BindAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", cfg.BindAddr, err)
	}
	defer ln.Close()

	fmt.Printf("telego proxy listening on %s\n", cfg.BindAddr)
	fmt.Printf("  Host: %s\n", cfg.Host)
	fmt.Printf("  ME enabled: %v\n", cfg.MEEnabled)
	fmt.Printf("  TLS fronting: %s\n", cfg.MaskHost)

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		errCh <- p.Serve(ln)
	}()

	select {
	case sig := <-sigCh:
		fmt.Printf("\nReceived %s, shutting down...\n", sig)
		return p.Shutdown(30 * time.Second)
	case err := <-errCh:
		return err
	}
}

// GenerateCmd generates a new secret.
type GenerateCmd struct {
	Host string `arg:"" help:"Hostname for the secret (e.g., www.google.com)"`
}

func (c *GenerateCmd) Run() error {
	secret, err := config.GenerateSecret(c.Host)
	if err != nil {
		return err
	}

	fmt.Printf("Secret: %s\n", secret)
	fmt.Printf("\nUse this secret in your Telegram client.\n")
	fmt.Printf("Format: tg://proxy?server=YOUR_SERVER&port=443&secret=%s\n", secret)

	return nil
}

// VersionCmd shows version information.
type VersionCmd struct{}

func (c *VersionCmd) Run() error {
	fmt.Println("telego v0.1.0")
	fmt.Println("Production-grade Telegram MTProxy in Go")
	fmt.Println()
	fmt.Println("Features:")
	fmt.Println("  - High-performance networking with splice(2)")
	fmt.Println("  - Advanced TLS fronting with real cert fetching")
	fmt.Println("  - Middle-End connection pooling")
	fmt.Println("  - FakeTLS (0xee prefix) support")
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

// consoleLogger implements proxy.Logger for console output.
type consoleLogger struct{}

func (l *consoleLogger) Debug(format string, args ...any) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}

func (l *consoleLogger) Info(format string, args ...any) {
	fmt.Printf("[INFO] "+format+"\n", args...)
}

func (l *consoleLogger) Warn(format string, args ...any) {
	fmt.Printf("[WARN] "+format+"\n", args...)
}

func (l *consoleLogger) Error(format string, args ...any) {
	fmt.Printf("[ERROR] "+format+"\n", args...)
}
