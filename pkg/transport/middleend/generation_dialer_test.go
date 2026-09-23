package middleend

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

// Only LocalAddr and Close are valid: route selection must send no datagrams.
type generationDialerRouteConn struct {
	net.Conn
	local  netip.AddrPort
	closed bool
}

func (c *generationDialerRouteConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.local)
}

func (c *generationDialerRouteConn) Close() error {
	c.closed = true
	return nil
}

func TestProductionGenerationDialerNATBeforeTCP(t *testing.T) {
	discoveryFailure := errors.New("STUN unavailable")
	tests := []struct {
		name       string
		endpoint   string
		local      string
		publicIP   string
		family     AddressFamily
		static     bool
		probeError error
		want       []string
	}{
		{"private IPv4", "149.154.167.50:8888", "172.18.0.2:40000", "8.8.8.8", AddressFamilyIPv4, false, nil, []string{"udp4", "resolve", "tcp4"}},
		{"private IPv6", "[2001:4860::1]:8888", "[fd00::2]:40000", "2001:4860::2", AddressFamilyIPv6, false, nil, []string{"udp6", "resolve", "tcp6"}},
		{"public IPv4", "149.154.167.50:8888", "8.8.8.8:40000", "8.8.8.8", AddressFamilyIPv4, false, nil, []string{"udp4", "tcp4"}},
		{"public IPv6", "[2001:4860::1]:8888", "[2001:4860::2]:40000", "2001:4860::2", AddressFamilyIPv6, false, nil, []string{"udp6", "tcp6"}},
		{"static NAT", "149.154.167.50:8888", "172.18.0.2:40000", "8.8.8.8", AddressFamilyIPv4, true, nil, []string{"udp4", "tcp4"}},
		{"discovery failure", "149.154.167.50:8888", "172.18.0.2:40000", "8.8.8.8", AddressFamilyIPv4, false, discoveryFailure, []string{"udp4", "resolve"}},
		{"discovery canceled", "149.154.167.50:8888", "172.18.0.2:40000", "8.8.8.8", AddressFamilyIPv4, false, context.Canceled, []string{"udp4", "resolve"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls []string
				route := &generationDialerRouteConn{local: netip.MustParseAddrPort(tc.local)}
				config := natResolverTestConfig()
				config.ProbeTimeout = 5 * time.Second
				if tc.static {
					config.PublicIP = netip.MustParseAddr(tc.publicIP)
				}
				resolver, err := newNATResolver(config, time.Now,
					func(ctx context.Context, family AddressFamily, _ []string, _ int) (natProbeResult, error) {
						calls = append(calls, "resolve")
						if family != tc.family {
							t.Errorf("discovery family = %v, want %v", family, tc.family)
						}
						if !route.closed {
							t.Error("route socket is still open during discovery")
						}
						// Discovery must not consume the TCP connection timeout.
						time.Sleep(2 * time.Second)
						return natProbeResult{address: netip.MustParseAddr(tc.publicIP), respondingServers: 2, agreeingServers: 2}, tc.probeError
					})
				if err != nil {
					t.Fatal(err)
				}
				cleanupNATResolver(t, resolver)
				tcpStopped := errors.New("TCP dial reached")
				dialer := productionGenerationDialer{
					nat: resolver,
					dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						calls = append(calls, network)
						if address != tc.endpoint {
							t.Errorf("dial address = %s, want %s", address, tc.endpoint)
						}
						if network == "udp4" || network == "udp6" {
							return route, nil
						}
						if ctx.Err() != nil {
							t.Errorf("TCP dial context already expired: %v", ctx.Err())
						}
						return nil, tcpStopped
					},
				}
				conn, _, _, err := dialer.Dial(t.Context(), netip.MustParseAddrPort(tc.endpoint), time.Second)
				if conn != nil {
					conn.Close()
					t.Fatal("unexpected TCP connection")
				}
				wantErr := tcpStopped
				if tc.probeError != nil {
					wantErr = tc.probeError
				}
				if !errors.Is(err, wantErr) {
					t.Errorf("Dial error = %v, want %v", err, wantErr)
				}
				if !slices.Equal(calls, tc.want) {
					t.Errorf("startup order = %v, want %v", calls, tc.want)
				}
				if !route.closed {
					t.Error("route socket was not closed")
				}
			})
		})
	}
}

func TestProductionGenerationDialerWithoutNATResolver(t *testing.T) {
	tcpStopped := errors.New("TCP dial reached")
	dialer := productionGenerationDialer{
		dialContext: func(_ context.Context, network, _ string) (net.Conn, error) {
			if network != "tcp4" {
				t.Errorf("dial network = %s, want tcp4", network)
			}
			return nil, tcpStopped
		},
	}
	_, _, _, err := dialer.Dial(t.Context(), netip.MustParseAddrPort("149.154.167.50:8888"), time.Second)
	if !errors.Is(err, tcpStopped) {
		t.Fatalf("Dial error = %v, want %v", err, tcpStopped)
	}
}

func TestProductionGenerationDialerSOCKS5BypassesDirectNAT(t *testing.T) {
	proxyStopped := errors.New("proxy dial reached")
	dialer := productionGenerationDialer{
		nat: new(NATResolver),
		socks5: &SOCKS5Dialer{
			proxyAddress: "127.0.0.1:1080",
			dialTCP: func(_ context.Context, _, address string) (*net.TCPConn, error) {
				if address != "127.0.0.1:1080" {
					t.Errorf("proxy address = %s", address)
				}
				return nil, proxyStopped
			},
		},
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Error("SOCKS5 attempted direct dialing or NAT discovery")
			return nil, errors.New("unexpected direct dial")
		},
	}
	_, _, _, err := dialer.Dial(t.Context(), netip.MustParseAddrPort("149.154.167.50:8888"), time.Second)
	if !errors.Is(err, proxyStopped) {
		t.Fatalf("Dial error = %v, want %v", err, proxyStopped)
	}
}
