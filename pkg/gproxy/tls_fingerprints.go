package gproxy

import (
	"cmp"
	"slices"
	"sync"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

const (
	// tlsFingerprintSlots bounds the fingerprints counted per kind. When all
	// slots are in use, a new fingerprint replaces the least counted one
	// (Space-Saving), so a frequent new client still gets a slot.
	tlsFingerprintSlots = 64
	// tlsFingerprintTop is the number of fingerprints exported per kind. The
	// rest are exported together as tlsFingerprintOther.
	tlsFingerprintTop   = 16
	tlsFingerprintOther = "other"
)

type tlsFingerprintKind uint8

const (
	tlsFingerprintAuthenticated tlsFingerprintKind = iota
	tlsFingerprintMaskFallback
	tlsFingerprintKindCount
)

var tlsFingerprintKindNames = [...]string{
	"authenticated",
	"mask_fallback",
}

// TLSFingerprintStat is the number of ClientHellos with one JA4 fingerprint
// since start. JA4 is tlsFingerprintOther for the sum of the fingerprints
// outside the top of their kind.
type TLSFingerprintStat struct {
	Kind  string
	JA4   string
	Count uint64
}

type tlsFingerprintSlot struct {
	fingerprint faketls.JA4
	count       uint64
}

// tlsFingerprintTable is a bounded top-N of JA4 fingerprints. A count can
// be too high by at most the count of the slot it replaced; total is exact.
type tlsFingerprintTable struct {
	mu    sync.Mutex
	total uint64
	used  int
	slots [tlsFingerprintSlots]tlsFingerprintSlot
}

func (t *tlsFingerprintTable) add(fingerprint faketls.JA4) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.total++
	for i := range t.used {
		if t.slots[i].fingerprint == fingerprint {
			t.slots[i].count++
			return
		}
	}
	if t.used < len(t.slots) {
		t.slots[t.used] = tlsFingerprintSlot{fingerprint, 1}
		t.used++
		return
	}
	least := 0
	for i := 1; i < len(t.slots); i++ {
		if t.slots[i].count < t.slots[least].count {
			least = i
		}
	}
	t.slots[least] = tlsFingerprintSlot{fingerprint, t.slots[least].count + 1}
}

// appendStats appends the top fingerprints by count, then the sum of the
// others. It appends nothing before the first fingerprint.
func (t *tlsFingerprintTable) appendStats(stats []TLSFingerprintStat, kind string) []TLSFingerprintStat {
	t.mu.Lock()
	total := t.total
	slots := slices.Clone(t.slots[:t.used])
	t.mu.Unlock()
	if total == 0 {
		return stats
	}
	slices.SortFunc(slots, func(a, b tlsFingerprintSlot) int {
		if c := cmp.Compare(b.count, a.count); c != 0 {
			return c
		}
		return slices.Compare(a.fingerprint[:], b.fingerprint[:])
	})
	other := total
	for _, slot := range slots[:min(len(slots), tlsFingerprintTop)] {
		stats = append(stats, TLSFingerprintStat{Kind: kind, JA4: slot.fingerprint.String(), Count: slot.count})
		other -= slot.count
	}
	return append(stats, TLSFingerprintStat{Kind: kind, JA4: tlsFingerprintOther, Count: other})
}

// recordTLSFingerprint counts the JA4 of a ClientHello handshake payload.
// A hello whose JA4 cannot be computed is not counted.
func (h *ProxyHandler) recordTLSFingerprint(kind tlsFingerprintKind, payload []byte) {
	if fingerprint, ok := faketls.ComputeJA4(payload); ok {
		h.tlsFingerprints[kind].add(fingerprint)
	}
}

// TLSFingerprintStats returns, for each kind, the most frequent JA4
// fingerprints and the sum of the others. It contains no client addresses.
func (h *ProxyHandler) TLSFingerprintStats() []TLSFingerprintStat {
	stats := make([]TLSFingerprintStat, 0, int(tlsFingerprintKindCount)*(tlsFingerprintTop+1))
	for kind := range tlsFingerprintKindCount {
		stats = h.tlsFingerprints[kind].appendStats(stats, tlsFingerprintKindNames[kind])
	}
	return stats
}
