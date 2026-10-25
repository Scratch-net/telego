package gproxy

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/zeebo/xxh3"
)

const (
	// Number of shards to reduce lock contention
	// Power of 2 for fast modulo via bitwise AND
	limiterShards    = 64
	limiterShardMask = limiterShards - 1

	// Internal connection keys use the full XXH3-128 digest.
	limiterKeySize = 16
)

// Pool of XXH3 hashers to avoid allocation per TryAcquire
var hasherPool = sync.Pool{
	New: func() any { return xxh3.New128() },
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

	// Compute the process-local XXH3-128 key for ip || secret.
	keyArr := l.hashKey(ip, secret)
	return l.tryAcquire(keyArr)
}

// TryAcquireIP attempts to acquire a connection slot for the given IP only.
// Used in OnOpen to limit total connections per IP before authentication.
func (l *ConnLimiter) TryAcquireIP(ip net.IP) (key string, ok bool) {
	if l.maxConns <= 0 {
		return "", true
	}

	keyArr := l.hashKey(ip, nil)
	return l.tryAcquire(keyArr)
}

func (l *ConnLimiter) hashKey(ip net.IP, secret []byte) [limiterKeySize]byte {
	h := hasherPool.Get().(*xxh3.Hasher128)
	h.Reset()
	h.Write(ip)
	if len(secret) > 0 {
		h.Write(secret)
	}
	keyArr := h.Sum128().Bytes()
	hasherPool.Put(h)
	return keyArr
}

func (l *ConnLimiter) tryAcquire(keyArr [limiterKeySize]byte) (key string, ok bool) {
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
