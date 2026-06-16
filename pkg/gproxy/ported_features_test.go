package gproxy

import "testing"

func TestSilenceWedged(t *testing.T) {
	const threshold = 10_000 // ms
	const now = 1_000_000

	tests := []struct {
		name       string
		lastClient int64
		lastServer int64
		wantClose  bool
	}{
		{"never spoke in relay (lc=0)", 0, now - 20_000, false},
		{"server reply unanswered past threshold", now - 30_000, now - 20_000, true},
		{"server reply unanswered within threshold", now - 30_000, now - 5_000, false},
		{"client answered most recently (healthy)", now - 1_000, now - 5_000, false},
		{"client ping was last word (idle healthy)", now - 100, now - 100_000, false},
		{"equal timestamps (no unanswered reply)", now - 5_000, now - 5_000, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := silenceWedged(tc.lastClient, tc.lastServer, now, threshold)
			if got != tc.wantClose {
				t.Fatalf("silenceWedged(lc=%d, ls=%d) = %v, want %v",
					tc.lastClient, tc.lastServer, got, tc.wantClose)
			}
		})
	}
}

func TestSpliceOverrideOneShot(t *testing.T) {
	ctx := NewConnContext()

	if got := ctx.consumeSpliceOverride(); got != "" {
		t.Fatalf("fresh context override = %q, want empty", got)
	}

	ctx.SetSpliceOverride("example.com:443")
	if got := ctx.consumeSpliceOverride(); got != "example.com:443" {
		t.Fatalf("override = %q, want example.com:443", got)
	}
	// Must be consumed (cleared) so a reused context never inherits it.
	if got := ctx.consumeSpliceOverride(); got != "" {
		t.Fatalf("override not cleared after consume, got %q", got)
	}
}
