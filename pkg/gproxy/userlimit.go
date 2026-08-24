package gproxy

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	// Number of shards to reduce lock contention (power of 2)
	userLimiterShards    = 64
	userLimiterShardMask = userLimiterShards - 1

	// Secret key size (16 bytes)
	secretKeySize = 16

	// Max IPs to track per user when limiting is disabled (for stats only)
	statsOnlyMaxIPs = 10000
)

// UserIPLimiter tracks per-user statistics and optionally limits unique IPs per user.
// Uses sharded maps and LRU caches for minimal contention.
type UserIPLimiter struct {
	maxIPsPerUser   int
	blockTimeout    time.Duration
	limitingEnabled bool
	shards          [userLimiterShards]userLimiterShard
}

type userLimiterShard struct {
	mu    sync.Mutex
	users map[[secretKeySize]byte]*userIPState
}

// userIPState tracks IP state for a single user.
type userIPState struct {
	// Secret name for metrics labeling
	secretName string

	// Active IPs with connection count (LRU)
	activeIPs *lru.Cache[string, *int64]

	// Blocked IPs (expirable LRU with TTL) - nil when limiting disabled
	blockedIPs *expirable.LRU[string, struct{}]

	// Traffic counters (read via atomic, updated in hot path)
	bytesIn  atomic.Int64
	bytesOut atomic.Int64

	// Block event counter
	blockedTotal atomic.Int64

	// Whether this user state has limiting enabled
	limitingEnabled bool
	blockTimeout    time.Duration
}

// UserIPStats contains statistics for a single user.
type UserIPStats struct {
	SecretName    string
	TrackedIPs    int      // Unique IPs in LRU cache (may include disconnected)
	ActiveIPs     int      // IPs with active connections right now
	BlockedIPs    int
	TrackedIPList []string // List of tracked IP addresses
	BlockedIPList []string // List of currently blocked IP addresses
	Connections   int64
	BytesIn       int64
	BytesOut      int64
	BlockedTotal  int64
}

// NewUserIPLimiter creates a new user IP limiter/stats tracker.
// If maxIPsPerUser <= 0, limiting is disabled but stats are still tracked.
func NewUserIPLimiter(maxIPsPerUser int, blockTimeout time.Duration) *UserIPLimiter {
	l := &UserIPLimiter{
		maxIPsPerUser:   maxIPsPerUser,
		blockTimeout:    blockTimeout,
		limitingEnabled: maxIPsPerUser > 0,
	}

	for i := range l.shards {
		l.shards[i].users = make(map[[secretKeySize]byte]*userIPState)
	}

	return l
}

// LimitingEnabled returns whether IP limiting is active.
func (l *UserIPLimiter) LimitingEnabled() bool {
	if l == nil {
		return false
	}
	return l.limitingEnabled
}

// getShardIdx returns shard index for a secret key.
func getShardIdx(secret []byte) int {
	if len(secret) == 0 {
		return 0
	}
	return int(secret[0]) & userLimiterShardMask
}

// getOrCreateUserState gets or creates user state for a secret.
// Caller must hold shard lock.
func (l *UserIPLimiter) getOrCreateUserState(shard *userLimiterShard, secretKey [secretKeySize]byte, secretName string) *userIPState {
	state, exists := shard.users[secretKey]
	if exists {
		return state
	}

	// Create new user state
	state = &userIPState{
		secretName:      secretName,
		limitingEnabled: l.limitingEnabled,
		blockTimeout:    l.blockTimeout,
	}

	if l.limitingEnabled {
		// Limiting mode: use configured max with eviction callback
		activeIPs, _ := lru.NewWithEvict[string, *int64](l.maxIPsPerUser, func(ip string, countPtr *int64) {
			// Only block IPs that still have active connections when evicted.
			// IPs that had legitimately disconnected (count=0) should not be blocked -
			// they're just being removed to make room for new IPs.
			if state.blockedIPs != nil && atomic.LoadInt64(countPtr) > 0 {
				state.blockedIPs.Add(ip, struct{}{})
				state.blockedTotal.Add(1)
			}
		})
		state.activeIPs = activeIPs

		// Create blocked IPs expirable LRU
		state.blockedIPs = expirable.NewLRU[string, struct{}](
			l.maxIPsPerUser*10, // Allow tracking more blocked IPs
			nil,
			l.blockTimeout,
		)
	} else {
		// Stats-only mode: large LRU for tracking, no blocking
		activeIPs, _ := lru.New[string, *int64](statsOnlyMaxIPs)
		state.activeIPs = activeIPs
		// blockedIPs stays nil - no blocking in stats-only mode
	}

	shard.users[secretKey] = state
	return state
}

// TryAcquire attempts to acquire a connection slot for the given IP+secret.
// Returns the key (for Release) and success status.
// secretName is used for metrics labeling.
// When limiting is disabled, always succeeds but still tracks stats.
func (l *UserIPLimiter) TryAcquire(ip net.IP, secret []byte, secretName string) (key string, ok bool) {
	if l == nil || len(secret) < secretKeySize {
		return "", true // Disabled or invalid secret
	}

	var secretKey [secretKeySize]byte
	copy(secretKey[:], secret[:secretKeySize])

	ipStr := ip.String()

	shardIdx := getShardIdx(secret)
	shard := &l.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	state := l.getOrCreateUserState(shard, secretKey, secretName)

	// Check if IP is blocked (only when limiting is enabled)
	if state.limitingEnabled && state.blockedIPs != nil {
		if _, blocked := state.blockedIPs.Peek(ipStr); blocked {
			// Refresh TTL by re-adding
			state.blockedIPs.Add(ipStr, struct{}{})
			return "", false
		}
	}

	// Check if IP is already active
	if countPtr, exists := state.activeIPs.Get(ipStr); exists {
		// Increment connection count
		atomic.AddInt64(countPtr, 1)
		// Build key: secret + IP
		return string(secretKey[:]) + ipStr, true
	}

	// New IP - add to active (may trigger eviction of oldest when limiting)
	var count int64 = 1
	state.activeIPs.Add(ipStr, &count)

	return string(secretKey[:]) + ipStr, true
}

// Release releases a connection slot.
func (l *UserIPLimiter) Release(key string) {
	if l == nil || len(key) <= secretKeySize {
		return
	}

	var secretKey [secretKeySize]byte
	copy(secretKey[:], key[:secretKeySize])
	ipStr := key[secretKeySize:]

	shardIdx := getShardIdx(secretKey[:])
	shard := &l.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	state, exists := shard.users[secretKey]
	if !exists {
		return
	}

	// Use Peek instead of Get to avoid moving the IP to front of LRU.
	// Releasing a connection shouldn't affect eviction order.
	countPtr, exists := state.activeIPs.Peek(ipStr)
	if !exists {
		return
	}

	// Decrement connection count.
	// Keep IP in LRU even at 0 connections - preserves LRU ordering.
	// Will be evicted naturally when other IPs need the slot.
	atomic.AddInt64(countPtr, -1)
}

// TrafficCounters returns pointers to traffic counters for a user.
// Used to store in ConnContext for hot-path traffic counting.
func (l *UserIPLimiter) TrafficCounters(secret []byte) (bytesIn, bytesOut *atomic.Int64) {
	if l == nil || len(secret) < secretKeySize {
		return nil, nil
	}

	var secretKey [secretKeySize]byte
	copy(secretKey[:], secret[:secretKeySize])

	shardIdx := getShardIdx(secret)
	shard := &l.shards[shardIdx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	state, exists := shard.users[secretKey]
	if !exists {
		return nil, nil
	}

	return &state.bytesIn, &state.bytesOut
}

// Stats returns statistics for all users.
func (l *UserIPLimiter) Stats() []UserIPStats {
	if l == nil {
		return nil
	}

	var stats []UserIPStats

	for i := range l.shards {
		shard := &l.shards[i]
		shard.mu.Lock()

		for _, state := range shard.users {
			var totalConns int64
			var activeIPs int
			trackedKeys := state.activeIPs.Keys()
			for _, ip := range trackedKeys {
				if countPtr, ok := state.activeIPs.Peek(ip); ok {
					count := atomic.LoadInt64(countPtr)
					totalConns += count
					if count > 0 {
						activeIPs++
					}
				}
			}

			var blockedKeys []string
			if state.blockedIPs != nil {
				blockedKeys = state.blockedIPs.Keys()
			}

			stats = append(stats, UserIPStats{
				SecretName:    state.secretName,
				TrackedIPs:    state.activeIPs.Len(),
				ActiveIPs:     activeIPs,
				BlockedIPs:    len(blockedKeys),
				TrackedIPList: trackedKeys,
				BlockedIPList: blockedKeys,
				Connections:   totalConns,
				BytesIn:       state.bytesIn.Load(),
				BytesOut:      state.bytesOut.Load(),
				BlockedTotal:  state.blockedTotal.Load(),
			})
		}

		shard.mu.Unlock()
	}

	return stats
}

// Close stops any background goroutines.
func (l *UserIPLimiter) Close() {
	// expirable.LRU runs its own cleanup goroutine
	// Purge all to stop cleanup timers
	if l == nil {
		return
	}

	for i := range l.shards {
		shard := &l.shards[i]
		shard.mu.Lock()
		for _, state := range shard.users {
			if state.blockedIPs != nil {
				state.blockedIPs.Purge()
			}
		}
		shard.mu.Unlock()
	}
}
