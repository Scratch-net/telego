// Package middleend implements connection pooling to Telegram's Middle-End servers.
// ME servers (port 8888) provide better performance and reliability than direct DC connections.
package middleend

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrPoolClosed   = errors.New("connection pool is closed")
	ErrPoolExhausted = errors.New("connection pool exhausted")
	ErrNoHealthyConn = errors.New("no healthy connections available")
)

// Pool manages a pool of connections to Middle-End servers.
// It provides:
// - Connection reuse with health checks
// - Warm standby connections
// - Automatic reconnection
// - Backpressure via bounded channel
type Pool struct {
	// Configuration
	size        int
	warmStandby int
	secret      []byte // proxy-secret from Telegram
	publicIP    string // Our public IP for ME handshake

	// Connection management
	conns    chan *MEConn
	mu       sync.RWMutex
	closed   atomic.Bool
	wg       sync.WaitGroup

	// Health monitoring
	healthInterval time.Duration
	lastHealthy    atomic.Int64

	// ME server addresses
	servers []string
	serverIdx atomic.Int32

	// Dialer
	dialer *Dialer
}

// PoolConfig configures the connection pool.
type PoolConfig struct {
	Size           int           // Total pool size (default: 16)
	WarmStandby    int           // Pre-initialized connections (default: 8)
	Secret         []byte        // Proxy secret from Telegram
	PublicIP       string        // Our public IP
	Servers        []string      // ME server addresses (host:8888)
	HealthInterval time.Duration // Health check interval (default: 30s)
}

// NewPool creates a new ME connection pool.
func NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.Size <= 0 {
		cfg.Size = 16
	}
	if cfg.WarmStandby <= 0 {
		cfg.WarmStandby = 8
	}
	if cfg.WarmStandby > cfg.Size {
		cfg.WarmStandby = cfg.Size
	}
	if cfg.HealthInterval <= 0 {
		cfg.HealthInterval = 30 * time.Second
	}
	if len(cfg.Servers) == 0 {
		return nil, errors.New("no ME servers configured")
	}

	p := &Pool{
		size:           cfg.Size,
		warmStandby:    cfg.WarmStandby,
		secret:         cfg.Secret,
		publicIP:       cfg.PublicIP,
		servers:        cfg.Servers,
		conns:          make(chan *MEConn, cfg.Size),
		healthInterval: cfg.HealthInterval,
		dialer:         NewDialer(),
	}

	// Pre-warm connections
	for i := 0; i < cfg.WarmStandby; i++ {
		conn, err := p.createConn()
		if err != nil {
			// Log but don't fail - we'll create connections on demand
			continue
		}
		p.conns <- conn
	}

	// Start health checker
	p.wg.Add(1)
	go p.healthChecker()

	return p, nil
}

// Acquire gets a connection from the pool.
// Creates a new connection if pool is empty.
func (p *Pool) Acquire(ctx context.Context) (*MEConn, error) {
	if p.closed.Load() {
		return nil, ErrPoolClosed
	}

	// Try to get from pool first (non-blocking)
	select {
	case conn := <-p.conns:
		if conn.IsHealthy() {
			return conn, nil
		}
		// Unhealthy connection, close and create new
		conn.Close()
	default:
		// Pool empty
	}

	// Create new connection
	return p.createConnWithContext(ctx)
}

// Release returns a connection to the pool.
// Closes the connection if pool is full or connection is unhealthy.
func (p *Pool) Release(conn *MEConn) {
	if p.closed.Load() || !conn.IsHealthy() {
		conn.Close()
		return
	}

	// Try to return to pool (non-blocking)
	select {
	case p.conns <- conn:
		// Returned to pool
	default:
		// Pool full, close connection
		conn.Close()
	}
}

// createConn creates a new ME connection.
func (p *Pool) createConn() (*MEConn, error) {
	return p.createConnWithContext(context.Background())
}

// createConnWithContext creates a new ME connection with context.
func (p *Pool) createConnWithContext(ctx context.Context) (*MEConn, error) {
	// Round-robin server selection
	idx := int(p.serverIdx.Add(1)) % len(p.servers)
	server := p.servers[idx]

	return p.dialer.DialME(ctx, server, p.secret, p.publicIP)
}

// healthChecker periodically checks connection health.
func (p *Pool) healthChecker() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.healthInterval)
	defer ticker.Stop()

	for {
		if p.closed.Load() {
			return
		}

		select {
		case <-ticker.C:
			p.checkHealth()
		}
	}
}

// checkHealth checks and replaces unhealthy connections.
func (p *Pool) checkHealth() {
	// Drain and check all connections
	var healthy []*MEConn

	for {
		select {
		case conn := <-p.conns:
			if conn.IsHealthy() {
				// Send keepalive
				if err := conn.SendKeepalive(); err != nil {
					conn.Close()
					continue
				}
				healthy = append(healthy, conn)
			} else {
				conn.Close()
			}
		default:
			// Pool drained
			goto refill
		}
	}

refill:
	// Return healthy connections
	for _, conn := range healthy {
		select {
		case p.conns <- conn:
		default:
			conn.Close()
		}
	}

	// Refill to warm standby level
	current := len(p.conns)
	for i := current; i < p.warmStandby; i++ {
		conn, err := p.createConn()
		if err != nil {
			continue
		}
		select {
		case p.conns <- conn:
		default:
			conn.Close()
		}
	}

	if len(healthy) > 0 {
		p.lastHealthy.Store(time.Now().Unix())
	}
}

// IsHealthy returns true if the pool has healthy connections.
func (p *Pool) IsHealthy() bool {
	lastHealthy := time.Unix(p.lastHealthy.Load(), 0)
	return time.Since(lastHealthy) < 2*p.healthInterval
}

// Close shuts down the pool and all connections.
func (p *Pool) Close() error {
	if p.closed.Swap(true) {
		return nil // Already closed
	}

	// Close all pooled connections
	close(p.conns)
	for conn := range p.conns {
		conn.Close()
	}

	// Wait for health checker
	p.wg.Wait()

	return nil
}

// Stats returns pool statistics.
type PoolStats struct {
	Size        int
	Available   int
	LastHealthy time.Time
}

func (p *Pool) Stats() PoolStats {
	return PoolStats{
		Size:        p.size,
		Available:   len(p.conns),
		LastHealthy: time.Unix(p.lastHealthy.Load(), 0),
	}
}
