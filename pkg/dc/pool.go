package dc

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/telego/pkg/netx"
	"github.com/example/telego/pkg/transport/obfuscated2"
)

var (
	ErrNoAddresses = errors.New("no addresses available for DC")
	ErrAllFailed   = errors.New("all DC addresses failed")
)

// IPPreference controls which IP version to prefer.
type IPPreference int

const (
	PreferIPv4 IPPreference = iota
	PreferIPv6
	OnlyIPv4
	OnlyIPv6
)

// Pool manages connections to a specific datacenter.
type Pool struct {
	dc         int
	addrs      []Addr
	preference IPPreference
	dialer     *netx.Dialer
	secret     []byte

	// Connection stats for latency-based routing
	latencies sync.Map // addr -> *latencyStats
}

type latencyStats struct {
	avg     atomic.Int64 // microseconds
	samples atomic.Int32
	failed  atomic.Int32
}

// NewPool creates a new DC connection pool.
func NewPool(dc int, secret []byte, pref IPPreference) *Pool {
	addrs := DCAddresses(dc)
	if pref == OnlyIPv4 {
		addrs = DCAddressesIPv4(dc)
	} else if pref == OnlyIPv6 {
		addrs = DCAddressesIPv6(dc)
	}

	return &Pool{
		dc:         dc,
		addrs:      addrs,
		preference: pref,
		dialer:     netx.NewDialer(),
		secret:     secret,
	}
}

// Dial connects to the DC and returns an obfuscated2 connection.
func (p *Pool) Dial(ctx context.Context) (*obfuscated2.Conn, error) {
	if len(p.addrs) == 0 {
		return nil, ErrNoAddresses
	}

	// Sort addresses by latency
	addrs := p.sortedAddrs()

	var lastErr error
	for _, addr := range addrs {
		conn, err := p.dialAddr(ctx, addr)
		if err != nil {
			lastErr = err
			p.recordFailure(addr)
			continue
		}
		return conn, nil
	}

	return nil, lastErr
}

// dialAddr connects to a specific address.
func (p *Pool) dialAddr(ctx context.Context, addr Addr) (*obfuscated2.Conn, error) {
	start := time.Now()

	// Dial TCP connection
	conn, err := p.dialer.DialContext(ctx, addr.Network, addr.Address)
	if err != nil {
		return nil, err
	}

	// Perform obfuscated2 handshake
	o2Conn, err := obfuscated2.ServerHandshake(conn, p.dc)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Record latency
	p.recordLatency(addr, time.Since(start))

	return o2Conn, nil
}

// sortedAddrs returns addresses sorted by latency.
func (p *Pool) sortedAddrs() []Addr {
	type addrLatency struct {
		addr    Addr
		latency int64
	}

	sorted := make([]addrLatency, len(p.addrs))
	for i, addr := range p.addrs {
		lat := int64(0)
		if stats, ok := p.latencies.Load(addr.Address); ok {
			s := stats.(*latencyStats)
			lat = s.avg.Load()
			// Penalize failed addresses
			if s.failed.Load() > 0 {
				lat += 1000000 // +1s penalty
			}
		}
		sorted[i] = addrLatency{addr: addr, latency: lat}
	}

	// Simple bubble sort (small N)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].latency < sorted[i].latency {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Apply IP preference
	result := make([]Addr, 0, len(sorted))
	switch p.preference {
	case PreferIPv4:
		// IPv4 first
		for _, al := range sorted {
			if !al.addr.IsIPv6() {
				result = append(result, al.addr)
			}
		}
		for _, al := range sorted {
			if al.addr.IsIPv6() {
				result = append(result, al.addr)
			}
		}
	case PreferIPv6:
		// IPv6 first
		for _, al := range sorted {
			if al.addr.IsIPv6() {
				result = append(result, al.addr)
			}
		}
		for _, al := range sorted {
			if !al.addr.IsIPv6() {
				result = append(result, al.addr)
			}
		}
	default:
		for _, al := range sorted {
			result = append(result, al.addr)
		}
	}

	return result
}

// recordLatency records a successful connection latency.
func (p *Pool) recordLatency(addr Addr, d time.Duration) {
	stats, _ := p.latencies.LoadOrStore(addr.Address, &latencyStats{})
	s := stats.(*latencyStats)

	// Exponential moving average
	lat := d.Microseconds()
	samples := s.samples.Add(1)
	if samples == 1 {
		s.avg.Store(lat)
	} else {
		// avg = 0.8 * avg + 0.2 * new
		oldAvg := s.avg.Load()
		newAvg := (oldAvg*8 + lat*2) / 10
		s.avg.Store(newAvg)
	}

	// Clear failure count on success
	s.failed.Store(0)
}

// recordFailure records a connection failure.
func (p *Pool) recordFailure(addr Addr) {
	stats, _ := p.latencies.LoadOrStore(addr.Address, &latencyStats{})
	s := stats.(*latencyStats)
	s.failed.Add(1)
}

// Manager manages pools for all DCs.
type Manager struct {
	pools      map[int]*Pool
	mu         sync.RWMutex
	secret     []byte
	preference IPPreference
}

// NewManager creates a new DC manager.
func NewManager(secret []byte, pref IPPreference) *Manager {
	return &Manager{
		pools:      make(map[int]*Pool),
		secret:     secret,
		preference: pref,
	}
}

// GetPool returns or creates a pool for the given DC.
func (m *Manager) GetPool(dc int) *Pool {
	m.mu.RLock()
	pool, ok := m.pools[dc]
	m.mu.RUnlock()
	if ok {
		return pool
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check
	if pool, ok := m.pools[dc]; ok {
		return pool
	}

	pool = NewPool(dc, m.secret, m.preference)
	m.pools[dc] = pool
	return pool
}

// Dial connects to the specified DC.
func (m *Manager) Dial(ctx context.Context, dc int) (*obfuscated2.Conn, error) {
	return m.GetPool(dc).Dial(ctx)
}

// DialWithFallback tries the specified DC, falls back to DC 2 on failure.
func (m *Manager) DialWithFallback(ctx context.Context, dc int) (*obfuscated2.Conn, error) {
	conn, err := m.Dial(ctx, dc)
	if err == nil {
		return conn, nil
	}

	// Fallback to DC 2
	if dc != 2 {
		return m.Dial(ctx, 2)
	}
	return nil, err
}

// DialTCP dials a raw TCP connection to the DC.
func DialTCP(ctx context.Context, addr Addr) (netx.Conn, error) {
	dialer := netx.NewDialer()
	return dialer.DialContext(ctx, addr.Network, addr.Address)
}

// net.Conn wrapper that tracks the DC
type DCConn struct {
	net.Conn
	DC int
}
