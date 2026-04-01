// Package metrics provides Prometheus metrics via OpenTelemetry.
package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/scratch-net/telego/pkg/gproxy"
)

// Server wraps the metrics HTTP server.
type Server struct {
	httpServer *http.Server
	provider   *sdkmetric.MeterProvider
}

// StatsProvider provides user statistics for metrics.
type StatsProvider interface {
	Stats() []gproxy.UserIPStats
}

// Config configures the metrics server.
type Config struct {
	BindAddr string
	Path     string
}

// NewServer creates a new metrics server.
func NewServer(cfg Config, limiter StatsProvider) (*Server, error) {
	// Create Prometheus exporter
	exporter, err := prometheus.New()
	if err != nil {
		return nil, err
	}

	// Create meter provider
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	otel.SetMeterProvider(provider)

	meter := provider.Meter("telego")

	// Register observable instruments
	if limiter != nil {
		registerMetrics(meter, limiter)
	}

	// Create HTTP server
	mux := http.NewServeMux()
	path := cfg.Path
	if path == "" {
		path = "/metrics"
	}
	mux.Handle(path, promhttp.Handler())

	httpServer := &http.Server{
		Addr:    cfg.BindAddr,
		Handler: mux,
	}

	return &Server{
		httpServer: httpServer,
		provider:   provider,
	}, nil
}

func registerMetrics(meter metric.Meter, limiter StatsProvider) {
	// Active connections gauge
	meter.Int64ObservableGauge("telego_connections_active",
		metric.WithDescription("Active connections per user"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(s.Connections, metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Active IPs gauge (IPs with at least one connection right now)
	meter.Int64ObservableGauge("telego_ips_active",
		metric.WithDescription("IPs with active connections per user"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(int64(s.ActiveIPs), metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Tracked IPs gauge (unique IPs in LRU cache, may include disconnected)
	meter.Int64ObservableGauge("telego_ips_tracked",
		metric.WithDescription("Unique IPs tracked in LRU cache per user"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(int64(s.TrackedIPs), metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Blocked IPs gauge
	meter.Int64ObservableGauge("telego_ips_blocked",
		metric.WithDescription("Currently blocked IPs per user"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(int64(s.BlockedIPs), metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Blocked total counter
	meter.Int64ObservableCounter("telego_blocked_total",
		metric.WithDescription("Total IP block events per user"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(s.BlockedTotal, metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Traffic in counter
	meter.Int64ObservableCounter("telego_traffic_in_bytes_total",
		metric.WithDescription("Total bytes received from clients per user"),
		metric.WithUnit("By"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(s.BytesIn, metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)

	// Traffic out counter
	meter.Int64ObservableCounter("telego_traffic_out_bytes_total",
		metric.WithDescription("Total bytes sent to clients per user"),
		metric.WithUnit("By"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			for _, s := range limiter.Stats() {
				name := s.SecretName
				if name == "" {
					name = "unknown"
				}
				o.Observe(s.BytesOut, metric.WithAttributes(attribute.String("user", name)))
			}
			return nil
		}),
	)
}

// Start starts the metrics HTTP server in a goroutine.
// Errors during ListenAndServe are silently ignored because metrics are optional.
// The caller should verify the server is accessible if metrics are required.
func (s *Server) Start() error {
	go func() {
		_ = s.httpServer.ListenAndServe()
		// Errors ignored: metrics are optional, and ErrServerClosed is expected on shutdown
	}()
	return nil
}

// Shutdown gracefully shuts down the metrics server.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.httpServer.Shutdown(ctx); err != nil {
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.provider.Shutdown(shutdownCtx)
}
