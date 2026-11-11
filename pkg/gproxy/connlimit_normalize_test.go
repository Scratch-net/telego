package gproxy

import (
	"net"
	"testing"
)

// A dual-stack listener reports IPv4 clients as 16-byte v4-mapped addresses,
// while WEB streams and PROXY v2 headers give 4-byte addresses. Both forms
// must share one bucket.
func TestConnLimiterNormalizesIPv4MappedAddresses(t *testing.T) {
	limiter := NewConnLimiter(1)
	mapped := net.ParseIP("192.0.2.7")
	plain := mapped.To4()
	if len(mapped) != net.IPv6len || len(plain) != net.IPv4len {
		t.Fatal("fixture lengths")
	}
	if _, ok := limiter.TryAcquireIP(mapped); !ok {
		t.Fatal("first acquire failed")
	}
	if _, ok := limiter.TryAcquireIP(plain); ok {
		t.Fatal("4-byte form of the same IPv4 address used a second bucket")
	}
	secret := []byte("0123456789abcdef")
	if _, ok := limiter.TryAcquire(plain, secret); !ok {
		t.Fatal("first secret acquire failed")
	}
	if _, ok := limiter.TryAcquire(mapped, secret); ok {
		t.Fatal("v4-mapped form of the same IPv4 address used a second secret bucket")
	}
}
