package gproxy

import (
	"net"
	"net/netip"
	"testing"
)

// With trusted CIDRs, only listed TCP peers (and Unix peers) may send a
// PROXY header. Other peers are direct clients. An empty list keeps the old
// behavior: any peer may send one.
func TestProxyProtocolTrustedSources(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for _, test := range []struct {
		name    string
		trusted []netip.Prefix
		peer    net.Addr
		want    ConnState
	}{
		{"no list accepts any peer", nil, &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4000}, StateReadProxyProto},
		{"listed peer", trusted, &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3).To4(), Port: 4000}, StateReadProxyProto},
		{"unlisted peer is direct", trusted, &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4000}, StateDetectProtocol},
		{"v4-mapped listed peer", trusted, &net.TCPAddr{IP: net.ParseIP("::ffff:10.1.2.3"), Port: 4000}, StateReadProxyProto},
		{"unix peer", trusted, &net.UnixAddr{Name: "@", Net: "unix"}, StateReadProxyProto},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := NewProxyHandler(&Config{ProxyProtocol: true, TrustedProxyPrefixes: test.trusted}, &testLogger{})
			connection := newTestMockGnetConn()
			connection.SetRemoteAddr(test.peer)
			handler.OnOpen(connection)
			ctx := connection.Context().(*ConnContext)
			if got := ctx.State(); got != test.want {
				t.Fatalf("state = %v, want %v", got, test.want)
			}
			handler.OnClose(connection, nil)
		})
	}
}

// An internal WEB candidate that sends no internal preface falls through to
// public PROXY parsing. That path must apply trusted-proxy-cidrs too.
func TestInternalCandidateHonoursTrustedProxyPrefixes(t *testing.T) {
	auth, err := NewInternalProxyAuth()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.InternalProxyProtocol = true
	cfg.InternalProxyAuth = auth
	cfg.ProxyProtocol = true
	cfg.TrustedProxyPrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	handler := NewProxyHandler(&cfg, &testLogger{})
	c := newTestMockGnetConn()
	c.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000})
	handler.OnOpen(c)
	ctx := c.Context().(*ConnContext)
	c.SetReadData([]byte("PROXY TCP4 198.51.100.77 127.0.0.1 1234 443\r\n\x16\x03\x01\x00\x10"))
	handler.handleProxyProto(c, ctx)
	if got := ctx.RealClientAddr(nil); got != nil {
		t.Fatalf("untrusted loopback peer spoofed client address: %v", got)
	}
	handler.OnClose(c, nil)
}
