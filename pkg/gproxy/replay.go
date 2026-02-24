package gproxy

import (
	"sync"
	"time"
)

// Number of shards for striped locking - must be power of 2
const numShards = 32

// ReplayCache detects replay attacks by tracking seen session IDs.
// Uses striped locking (32 shards) to reduce contention under high load.
type ReplayCache struct {
	shards      [numShards]replayShard
	maxSize     int
	maxPerShard int
	ttl         time.Duration
}

// replayShard is a single shard of the replay cache.
type replayShard struct {
	seen map[string]time.Time
	mu   sync.RWMutex
}

// NewReplayCache creates a new replay cache.
func NewReplayCache(maxSize int, ttl time.Duration) *ReplayCache {
	c := &ReplayCache{
		maxSize:     maxSize,
		maxPerShard: maxSize / numShards,
		ttl:         ttl,
	}

	// Initialize shards
	for i := range c.shards {
		c.shards[i].seen = make(map[string]time.Time)
	}

	// Start cleanup goroutine
	go c.cleanup()

	return c
}

// getShard returns the shard for a given key using FNV-1a hash.
func (c *ReplayCache) getShard(key string) *replayShard {
	// FNV-1a hash - fast and good distribution
	h := uint32(2166136261)
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return &c.shards[h&(numShards-1)]
}

// Seen checks if the session ID was seen before.
// Returns true if this is a replay, false if new.
func (c *ReplayCache) Seen(sessionID []byte) bool {
	key := string(sessionID)
	shard := c.getShard(key)

	// Fast path: check if exists with read lock only
	shard.mu.RLock()
	_, exists := shard.seen[key]
	shard.mu.RUnlock()

	if exists {
		return true
	}

	// Slow path: add with write lock
	shard.mu.Lock()
	// Double-check after acquiring write lock
	if _, exists := shard.seen[key]; exists {
		shard.mu.Unlock()
		return true
	}
	shard.seen[key] = time.Now()
	shard.mu.Unlock()

	return false
}

// cleanup periodically removes expired entries from all shards.
func (c *ReplayCache) cleanup() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		for i := range c.shards {
			shard := &c.shards[i]
			shard.mu.Lock()

			// Remove expired entries
			for key, seen := range shard.seen {
				if now.Sub(seen) > c.ttl {
					delete(shard.seen, key)
				}
			}

			// If shard too large, remove some entries
			if len(shard.seen) > c.maxPerShard {
				count := 0
				target := len(shard.seen) / 2
				for key := range shard.seen {
					delete(shard.seen, key)
					count++
					if count >= target {
						break
					}
				}
			}

			shard.mu.Unlock()
		}
	}
}
