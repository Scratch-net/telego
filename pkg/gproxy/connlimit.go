package gproxy

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/zeebo/blake3"
)

const (
	// Number of shards to reduce lock contention
	// Power of 2 for fast modulo via bitwise AND
	limiterShards    = 64
	limiterShardMask = limiterShards - 1

	// Key size: 8 bytes is enough for uniqueness (birthday paradox threshold ~4B entries)
	limiterKeySize = 8
)

// Pool of blake3 hashers to avoid allocation per TryAcquire
var hasherPool = sync.Pool{
	New: func() any { return blake3.New() },
}

// ConnLimiter limits concurrent connections per IP+secret combination.
// Uses sharded maps and atomic counters for minimal contention.
type ConnLimiter struct {
	maxConns int
	shards   [limiterShards]limiterShard
}

type limiterShard struct {
	mu    sync.Mutex
	conns map[[limiterKeySize]byte]*int64 // key -> atomic count pointer
}

// NewConnLimiter creates a new connection limiter.
// maxConns <= 0 disables limiting.
func NewConnLimiter(maxConns int) *ConnLimiter {
	l := &ConnLimiter{maxConns: maxConns}
	for i := range l.shards {
		l.shards[i].conns = make(map[[limiterKeySize]byte]*int64)
	}
	return l
}

// TryAcquire attempts to acquire a connection slot for the given IP+secret.
// Returns the key (for Release) and success status.
// If maxConns is 0, always succeeds (limiting disabled).
func (l *ConnLimiter) TryAcquire(ip net.IP, secret []byte) (key string, ok bool) {
	if l.maxConns <= 0 {
		return "", true
	}

	// Compute key: blake3(ip || secret), truncated to limiterKeySize bytes
	// Blake3 is ~3x faster than SHA256 and highly optimized
	var keyArr [limiterKeySize]byte
	h := hasherPool.Get().(*blake3.Hasher)
	h.Reset()
	h.Write(ip)
	h.Write(secret)
	hash := h.Sum(nil)
	copy(keyArr[:], hash[:limiterKeySize])
	hasherPool.Put(h)

	// Select shard based on first byte of key
	shardIdx := int(keyArr[0]) & limiterShardMask
	s := &l.shards[shardIdx]

	s.mu.Lock()
	defer s.mu.Unlock()

	counter, exists := s.conns[keyArr]
	if !exists {
		// First connection for this key
		var initial int64 = 1
		s.conns[keyArr] = &initial
		return string(keyArr[:]), true
	}

	// Check limit before incrementing
	current := atomic.LoadInt64(counter)
	if current >= int64(l.maxConns) {
		return "", false
	}

	// Increment counter
	atomic.AddInt64(counter, 1)
	return string(keyArr[:]), true
}

// Release releases a connection slot.
// key must be the value returned by TryAcquire.
func (l *ConnLimiter) Release(key string) {
	if l.maxConns <= 0 || len(key) != limiterKeySize {
		return
	}

	var keyArr [limiterKeySize]byte
	copy(keyArr[:], key)

	shardIdx := int(keyArr[0]) & limiterShardMask
	s := &l.shards[shardIdx]

	s.mu.Lock()
	defer s.mu.Unlock()

	counter, exists := s.conns[keyArr]
	if !exists {
		return
	}

	newVal := atomic.AddInt64(counter, -1)
	if newVal <= 0 {
		// Remove entry when count reaches 0 to prevent memory leak
		delete(s.conns, keyArr)
	}
}

// ActiveConnections returns the total number of active connections being tracked.
// This is O(n) and should only be used for metrics, not in hot path.
func (l *ConnLimiter) ActiveConnections() int64 {
	var total int64
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		for _, counter := range s.conns {
			total += atomic.LoadInt64(counter)
		}
		s.mu.Unlock()
	}
	return total
}
