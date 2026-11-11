package webproxy

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func BenchmarkCarrierResponseEncodedHeader(b *testing.B) {
	response := newCarrierResponse(200, []responseHeader{
		{"Cache-Control", "no-store"},
		{"X-Down-Cursor", strconv.Itoa(12345)},
		{"Content-Type", "application/octet-stream"},
	}, make([]byte, 1024))
	b.ReportAllocs()
	for b.Loop() {
		if len(response.encodedHeader()) == 0 {
			b.Fatal("empty header")
		}
	}
}

func TestHeaderCompletionMatchesJoinedSearch(t *testing.T) {
	input := []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\nX\r\n\r\n")
	reference := func(prefix, next []byte) int {
		boundary := min(3, len(prefix))
		joined := append(append([]byte(nil), prefix[len(prefix)-boundary:]...), next...)
		if end := strings.Index(string(joined), "\r\n\r\n"); end >= 0 && end+4-boundary > 0 {
			return end + 4 - boundary
		}
		return 0
	}
	for split := range len(input) + 1 {
		for end := split; end <= len(input); end++ {
			prefix, next := input[:split], input[split:end]
			if bytes.Contains(prefix, []byte("\r\n\r\n")) {
				continue
			}
			if got, want := headerCompletion(prefix, next), reference(prefix, next); got != want {
				t.Fatalf("headerCompletion(%q, %q) = %d, want %d", prefix, next, got, want)
			}
		}
	}
}

func BenchmarkHeaderCompletion(b *testing.B) {
	prefix := []byte("POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\n")
	next := []byte("Authorization: Bearer 0123456789abcdef0123456789abcdef\r\nX-Down-Cursor: 7\r\nContent-Length: 0\r\n\r\n")
	b.ReportAllocs()
	for b.Loop() {
		if headerCompletion(prefix, next) != len(next) {
			b.Fatal("header end not found")
		}
	}
}
