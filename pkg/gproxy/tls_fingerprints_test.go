package gproxy

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

func testFingerprint(i int) faketls.JA4 {
	var fp faketls.JA4
	copy(fp[:], fmt.Sprintf("t13d%04dh2_000000000000_%012d", i%10000, i))
	return fp
}

// Many distinct fingerprints export at most the top plus "other", and the
// counts always add up to the number of hellos.
func TestTLSFingerprintCardinalityBound(t *testing.T) {
	var table tlsFingerprintTable
	total := 0
	for i := range 1000 {
		for range i%7 + 1 {
			table.add(testFingerprint(i))
			total++
		}
	}
	stats := table.appendStats(nil, "mask_fallback")
	if len(stats) != tlsFingerprintTop+1 {
		t.Fatalf("exported %d series, want %d", len(stats), tlsFingerprintTop+1)
	}
	if table.used != tlsFingerprintSlots {
		t.Fatalf("used slots = %d", table.used)
	}
	var sum uint64
	for i, stat := range stats {
		sum += stat.Count
		if stat.Kind != "mask_fallback" {
			t.Fatalf("kind = %q", stat.Kind)
		}
		if i < tlsFingerprintTop && (stat.JA4 == tlsFingerprintOther || len(stat.JA4) != faketls.JA4Len) {
			t.Fatalf("stat %d = %+v", i, stat)
		}
		if i > 0 && i < tlsFingerprintTop && stat.Count > stats[i-1].Count {
			t.Fatal("top is not sorted by count")
		}
	}
	if stats[tlsFingerprintTop].JA4 != tlsFingerprintOther || sum != uint64(total) {
		t.Fatalf("other = %+v, sum = %d, want %d", stats[tlsFingerprintTop], sum, total)
	}
}

// A frequent fingerprint that arrives after the table is full still gets
// a slot and reaches the top.
func TestTLSFingerprintNewHeavyHitter(t *testing.T) {
	var table tlsFingerprintTable
	for i := range 10 * tlsFingerprintSlots {
		table.add(testFingerprint(i))
	}
	late := testFingerprint(99999)
	for range 100 {
		table.add(late)
	}
	stats := table.appendStats(nil, "authenticated")
	if stats[0].JA4 != late.String() || stats[0].Count < 100 {
		t.Fatalf("top = %+v", stats[0])
	}
}

func TestTLSFingerprintFewExact(t *testing.T) {
	var table tlsFingerprintTable
	if stats := table.appendStats(nil, "authenticated"); len(stats) != 0 {
		t.Fatalf("empty table exported %+v", stats)
	}
	table.add(testFingerprint(1))
	table.add(testFingerprint(2))
	table.add(testFingerprint(2))
	got := table.appendStats(nil, "authenticated")
	want := []TLSFingerprintStat{
		{"authenticated", testFingerprint(2).String(), 2},
		{"authenticated", testFingerprint(1).String(), 1},
		{"authenticated", "other", 0},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("stats = %+v", got)
	}
}

func TestTLSFingerprintConcurrent(t *testing.T) {
	var table tlsFingerprintTable
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 1000 {
				table.add(testFingerprint(worker*1000 + i%100))
			}
			_ = table.appendStats(nil, "authenticated")
		})
	}
	wg.Wait()
	var sum uint64
	for _, stat := range table.appendStats(nil, "authenticated") {
		sum += stat.Count
	}
	if sum != 8000 {
		t.Fatalf("sum = %d", sum)
	}
}

// Handshakes count the JA4 of authenticated hellos and of mask fallbacks.
// The labels contain only the kind and the fingerprint.
func TestHandshakeRecordsTLSFingerprints(t *testing.T) {
	cfg := coverDomainConfig()
	cfg.SpliceHost = ""
	handler := NewProxyHandler(cfg, &testLogger{})

	authenticated := buildValidClientHello(maskKey, "mask.example", nil)
	runClientHello(handler, authenticated)
	runClientHello(handler, buildValidClientHello([]byte("unknown-secret!!"), "mask.example", nil))
	runClientHello(handler, authenticated) // replay

	want, ok := faketls.ComputeJA4(authenticated)
	if !ok {
		t.Fatal("no JA4 for the test hello")
	}
	counts := map[string]uint64{}
	for _, stat := range handler.TLSFingerprintStats() {
		if stat.JA4 != tlsFingerprintOther && stat.JA4 != want.String() {
			t.Fatalf("unexpected fingerprint %+v", stat)
		}
		if strings.Contains(stat.JA4, "127.0.0.1") {
			t.Fatal("client address in labels")
		}
		counts[stat.Kind+" "+stat.JA4] += stat.Count
	}
	if counts["authenticated "+want.String()] != 1 || counts["mask_fallback "+want.String()] != 2 {
		t.Fatalf("counts = %v", counts)
	}
}

func TestTLSFingerprintAddDoesNotAllocate(t *testing.T) {
	var table tlsFingerprintTable
	fp := testFingerprint(1)
	if allocs := testing.AllocsPerRun(100, func() { table.add(fp) }); allocs != 0 {
		t.Fatalf("add allocates %.0f times", allocs)
	}
}

// BenchmarkRecordTLSFingerprint measures the handshake cost: JA4 of a
// Chrome-like hello plus one table update.
func BenchmarkRecordTLSFingerprint(b *testing.B) {
	handler := NewProxyHandler(&Config{}, &testLogger{})
	payload := buildValidClientHello([]byte("0123456789abcdef"), "www.google.com", make([]byte, 32))
	b.ReportAllocs()
	for b.Loop() {
		handler.recordTLSFingerprint(tlsFingerprintAuthenticated, payload)
	}
}
