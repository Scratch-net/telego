package main

import "testing"

func TestMiddleEndDirectFallbackFDMinimum(t *testing.T) {
	for _, test := range []struct {
		name           string
		maxConnections int
		want           uint64
	}{
		{name: "negative", maxConnections: -1, want: 0},
		{name: "disabled", maxConnections: 0, want: 0},
		{name: "production default", maxConnections: 10_000, want: 20_000},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := middleEndDirectFallbackFDMinimum(test.maxConnections); got != test.want {
				t.Fatalf("middleEndDirectFallbackFDMinimum(%d) = %d, want %d", test.maxConnections, got, test.want)
			}
		})
	}
}
