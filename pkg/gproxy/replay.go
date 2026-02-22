package gproxy

import (
	"sync"
	"time"
)

// ReplayCache detects replay attacks by tracking seen session IDs.
// Uses a simple map with periodic cleanup for simplicity.
type ReplayCache struct {
	seen    map[string]time.Time
	mu      sync.RWMutex
	maxSize int
	ttl     time.Duration
}

// NewReplayCache creates a new replay cache.
func NewReplayCache(maxSize int, ttl time.Duration) *ReplayCache {
	c := &ReplayCache{
		seen:    make(map[string]time.Time),
		maxSize: maxSize,
		ttl:     ttl,
	}

	// Start cleanup goroutine
	go c.cleanup()

	return c
}

// Seen checks if the session ID was seen before.
// Returns true if this is a replay, false if new.
func (c *ReplayCache) Seen(sessionID []byte) bool {
	key := string(sessionID)

	c.mu.RLock()
	_, exists := c.seen[key]
	c.mu.RUnlock()

	if exists {
		return true
	}

	// Add to cache
	c.mu.Lock()
	c.seen[key] = time.Now()
	c.mu.Unlock()

	return false
}

// cleanup periodically removes expired entries.
func (c *ReplayCache) cleanup() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, seen := range c.seen {
			if now.Sub(seen) > c.ttl {
				delete(c.seen, key)
			}
		}

		// If still too large, remove oldest entries
		if len(c.seen) > c.maxSize {
			count := 0
			for key := range c.seen {
				delete(c.seen, key)
				count++
				if count >= len(c.seen)/2 {
					break
				}
			}
		}
		c.mu.Unlock()
	}
}
