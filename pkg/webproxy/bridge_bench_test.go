package webproxy

import (
	"strings"
	"testing"
)

func BenchmarkRenderBridgeWebSocket(b *testing.B) {
	token := strings.Repeat("A", 43)
	if _, err := parseToken(token); err != nil {
		b.Skip("benchmark token format changed")
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := renderBridgeAtPath("proxy.example.com", token, maxCarrierBatchBytes, CarrierWebSocket, 128, false, ""); err != nil {
			b.Fatal(err)
		}
	}
}
