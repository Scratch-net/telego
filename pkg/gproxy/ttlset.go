package gproxy

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
)

// ttlSet is a bounded set with no background work. Its owner must serialize
// access. Only add updates recency and expiration, so expiration order matches
// LRU order for the fixed TTL. Nonpositive TTL disables expiration.
type ttlSet struct {
	entries *simplelru.LRU[string, time.Time]
	ttl     time.Duration
}

func newTTLSet(capacity int, ttl time.Duration) *ttlSet {
	entries, _ := simplelru.NewLRU[string, time.Time](max(capacity, 1), nil)
	return &ttlSet{entries: entries, ttl: ttl}
}

func (s *ttlSet) contains(key string) bool {
	s.prune(time.Now())
	return s.entries.Contains(key)
}

func (s *ttlSet) add(key string) {
	now := time.Now()
	s.prune(now)
	var deadline time.Time
	if s.ttl > 0 {
		deadline = now.Add(s.ttl)
	}
	s.entries.Add(key, deadline)
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
