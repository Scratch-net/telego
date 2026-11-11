package gproxy

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
)

// ttlSet is a bounded set with no background work. Its owner must serialize
// access. Only add updates recency and expiration. For the fixed TTL,
// expiration order matches LRU order. An addUntil entry can expire later, so
// prune stops at it and contains checks each entry's own deadline.
// Nonpositive TTL disables expiration.
type ttlSet struct {
	entries *simplelru.LRU[string, time.Time]
	ttl     time.Duration
}

func newTTLSet(capacity int, ttl time.Duration) *ttlSet {
	entries, _ := simplelru.NewLRU[string, time.Time](max(capacity, 1), nil)
	return &ttlSet{entries: entries, ttl: ttl}
}

func (s *ttlSet) contains(key string) bool {
	now := time.Now()
	s.prune(now)
	deadline, ok := s.entries.Peek(key)
	if ok && !deadline.IsZero() && !now.Before(deadline) {
		s.entries.Remove(key)
		return false
	}
	return ok
}

// add reports whether a live entry was evicted to make room. Expired
// entries are pruned first, so an eviction removes one before its TTL.
func (s *ttlSet) add(key string) bool {
	now := time.Now()
	s.prune(now)
	var deadline time.Time
	if s.ttl > 0 {
		deadline = now.Add(s.ttl)
	}
	return s.entries.Add(key, deadline)
}

// addUntil adds key until the later of its TTL and until.
func (s *ttlSet) addUntil(key string, until time.Time) bool {
	now := time.Now()
	s.prune(now)
	var deadline time.Time
	if s.ttl > 0 {
		deadline = now.Add(s.ttl)
		if until.After(deadline) {
			deadline = until
		}
	}
	return s.entries.Add(key, deadline)
}

func (s *ttlSet) keys() []string {
	s.prune(time.Now())
	return s.entries.Keys()
}

func (s *ttlSet) len() int {
	s.prune(time.Now())
	return s.entries.Len()
}

func (s *ttlSet) purge() {
	s.entries.Purge()
}

func (s *ttlSet) prune(now time.Time) {
	if s.ttl <= 0 {
		return
	}
	for {
		_, deadline, ok := s.entries.GetOldest()
		if !ok || now.Before(deadline) {
			return
		}
		s.entries.RemoveOldest()
	}
}
