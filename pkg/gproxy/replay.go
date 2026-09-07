package gproxy

import (
	"sync"
	"time"
)

// Number of shards for striped locking - must be power of 2
const numShards = 64

// replayShard wraps a TTL set with a mutex for atomic check-and-add.
type replayShard struct {
	mu    sync.Mutex
	cache *ttlSet
}

// ReplayCache detects replay attacks by tracking seen session IDs.
// Uses sharded TTL sets for:
//   - Proper LRU eviction (oldest entries removed first)
//   - TTL expiration checked during access, without background workers
//   - Reduced lock contention (64 shards)
type ReplayCache struct {
	shards      [numShards]replayShard
	maxPerShard int
	ttl         time.Duration
}

// NewReplayCache creates a new replay cache.
// maxSize is the total capacity across all shards.
// ttl is how long entries are kept. Nonpositive ttl disables expiration.
func NewReplayCache(maxSize int, ttl time.Duration) *ReplayCache {
	maxPerShard := max(maxSize/numShards, 1)

	c := &ReplayCache{
		maxPerShard: maxPerShard,
		ttl:         ttl,
	}

	// Initialize shards without starting cleanup workers.
	for i := range c.shards {
		c.shards[i].cache = newTTLSet(maxPerShard, ttl)
	}

	return c
}

// getShardIdx returns the shard index for a given key using FNV-1a hash.
func (c *ReplayCache) getShardIdx(key string) int {
	// FNV-1a hash - fast and good distribution
	h := uint32(2166136261)
	for i := range len(key) {
		h ^= uint32(key[i])
		h *= 16777619
	}
	return int(h & (numShards - 1))
}

// Seen checks if the session ID was seen before and adds it if not.
// Returns true if this is a replay attack, false if new.
// This operation is atomic (check-and-add).
func (c *ReplayCache) Seen(sessionID []byte) bool {
	key := string(sessionID)
	shard := &c.shards[c.getShardIdx(key)]

	// Atomic check-and-add with shard lock
	shard.mu.Lock()
	exists := shard.cache.contains(key)
	if !exists {
		shard.cache.add(key)
	}
	shard.mu.Unlock()

	return exists
}

// Len returns the total number of entries across all shards.
func (c *ReplayCache) Len() int {
	total := 0
	for i := range c.shards {
		c.shards[i].mu.Lock()
		total += c.shards[i].cache.len()
		c.shards[i].mu.Unlock()
	}
	return total
}
