// Package metrics provides Prometheus metrics via OpenTelemetry.
package metrics

import (
	"context"
	"math"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/webproxy"
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

// ProxyStatsProvider supplies cumulative MTProxy handshake diagnostics.
type ProxyStatsProvider interface {
	HandshakeFailureStats() []gproxy.HandshakeFailureStat
}

// WebStatsProvider supplies WEB lifecycle and capacity diagnostics.
type WebStatsProvider interface {
	RuntimeStats() webproxy.RuntimeStats
}

// Config configures the metrics server.
type Config struct {
	BindAddr   string
	Path       string
	ProxyStats ProxyStatsProvider
	WebStats   WebStatsProvider
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
	if cfg.ProxyStats != nil {
		registerProxyMetrics(meter, cfg.ProxyStats)
	}
	if cfg.WebStats != nil {
		registerWebMetrics(meter, cfg.WebStats)
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

func registerProxyMetrics(meter metric.Meter, provider ProxyStatsProvider) {
	meter.Int64ObservableCounter("telego_handshake_failures_total",
		metric.WithDescription("MTProxy handshake failures by processing stage"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			for _, stat := range provider.HandshakeFailureStats() {
				observer.Observe(metricValue(stat.Total), metric.WithAttributes(attribute.String("stage", stat.Stage)))
			}
			return nil
		}),
	)
}

func registerWebMetrics(meter metric.Meter, provider WebStatsProvider) {
	meter.Int64ObservableGauge("telego_web_websocket_connections_active",
		metric.WithDescription("Active WEB WebSocket carrier connections"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(provider.RuntimeStats().WebSocketsActive)
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_web_sessions_active",
		metric.WithDescription("Active WEB relay sessions"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(int64(provider.RuntimeStats().Capacity.Sessions))
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_web_streams_active",
		metric.WithDescription("Active WEB backend streams"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(int64(provider.RuntimeStats().Capacity.Streams))
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_web_backend_dials_active",
		metric.WithDescription("WEB backend dials in progress"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(int64(provider.RuntimeStats().Capacity.BackendDials))
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_web_pending_bytes",
		metric.WithDescription("Bytes charged to WEB pending queues"),
		metric.WithUnit("By"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(provider.RuntimeStats().Capacity.PendingBytes)
			return nil
		}),
	)
	meter.Int64ObservableGauge("telego_web_pending_items",
		metric.WithDescription("Items charged to WEB pending queues"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(provider.RuntimeStats().Capacity.PendingItems)
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_web_sessions_created_total",
		metric.WithDescription("WEB relay sessions created"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			observer.Observe(metricValue(provider.RuntimeStats().SessionsCreated))
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_web_sessions_closed_total",
		metric.WithDescription("WEB relay sessions closed by reason"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			for _, counter := range provider.RuntimeStats().SessionsClosed {
				observer.Observe(metricValue(counter.Total), metric.WithAttributes(attribute.String("reason", counter.Label)))
			}
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_web_carrier_retries_total",
		metric.WithDescription("Authenticated WEB carrier retries and replays"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			for _, counter := range provider.RuntimeStats().CarrierRetries {
				observer.Observe(metricValue(counter.Total), metric.WithAttributes(attribute.String("operation", counter.Label)))
			}
			return nil
		}),
	)
	meter.Int64ObservableCounter("telego_web_backpressure_total",
		metric.WithDescription("WEB carrier requests delayed by resource backpressure"),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) error {
			for _, counter := range provider.RuntimeStats().Backpressure {
				observer.Observe(metricValue(counter.Total), metric.WithAttributes(attribute.String("operation", counter.Label)))
			}
			return nil
		}),
	)
}

func metricValue(value uint64) int64 {
	return int64(min(value, uint64(math.MaxInt64)))
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
