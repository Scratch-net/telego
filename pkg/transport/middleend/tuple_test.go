package middleend

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSOCKS5AddressTupleAuthority(t *testing.T) {
	server := netip.MustParseAddrPort("149.154.167.50:443")
	tests := []struct {
		name  string
		bound SOCKS5Address
		want  netip.AddrPort
	}{
		{
			name:  "public IPv4",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("93.184.216.34"), Port: 32000},
			want:  netip.MustParseAddrPort("93.184.216.34:32000"),
		},
		{
			name:  "unspecified",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.IPv4Unspecified(), Port: 32000},
		},
		{
			name:  "loopback",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("127.0.0.1"), Port: 32000},
		},
		{
			name:  "private",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("10.0.0.1"), Port: 32000},
		},
		{
			name:  "shared",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("100.64.1.2"), Port: 32000},
		},
		{
			name:  "domain",
			bound: SOCKS5Address{Type: SOCKS5AddressDomain, Name: "proxy.invalid", Port: 32000},
		},
		{
			name:  "mixed family",
			bound: SOCKS5Address{Type: SOCKS5AddressIPv6, IP: netip.MustParseAddr("2606:4700:4700::1111"), Port: 32000},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotServer, gotClient, err := SOCKS5AddressTuple(server, test.bound)
			if test.want.IsValid() {
				if err != nil {
					t.Fatalf("SOCKS5AddressTuple: %v", err)
				}
				if gotServer != server || gotClient != test.want {
					t.Fatalf("tuple = %s/%s, want %s/%s", gotServer, gotClient, server, test.want)
				}
				return
			}
			if !errors.Is(err, ErrTupleNotAuthoritative) {
				t.Fatalf("error = %v, want %v", err, ErrTupleNotAuthoritative)
			}
		})
	}
}

func TestDirectAddressTupleRejectsLocalAndMismatchedEndpoints(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := listener.AcceptTCP()
		accepted <- conn
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer client.Close()
	server := <-accepted
	if server != nil {
		defer server.Close()
	}

	selected := listener.Addr().(*net.TCPAddr).AddrPort()
	if _, _, err := DirectAddressTuple(client, selected); !errors.Is(err, ErrTupleNotAuthoritative) {
		t.Fatalf("loopback tuple error = %v", err)
	}
	if _, _, err := DirectAddressTuple(client, netip.MustParseAddrPort("8.8.8.8:443")); !errors.Is(err, ErrTupleNotAuthoritative) {
		t.Fatalf("mismatch tuple error = %v", err)
	}
}

func TestClientProcessIDIPv4AndIPv6(t *testing.T) {
	uptime := time.Unix(1700000000, 0)
	ipv4, err := ClientProcessID(netip.MustParseAddrPort("1.2.3.4:32000"), 65537, uptime)
	if err != nil {
		t.Fatalf("ClientProcessID IPv4: %v", err)
	}
	if ipv4 != (ProcessID{IP: 0x01020304, PID: 1, Uptime: 1700000000}) {
		t.Fatalf("IPv4 process ID = %+v", ipv4)
	}
	ipv6, err := ClientProcessID(netip.MustParseAddrPort("[2606:4700:4700::1111]:32000"), 42, uptime)
	if err != nil {
		t.Fatalf("ClientProcessID IPv6: %v", err)
	}
	if ipv6.IP != 0 || ipv6.Port != 0 || ipv6.PID != 42 {
		t.Fatalf("IPv6 process ID = %+v", ipv6)
	}
	if _, err := ClientProcessID(netip.MustParseAddrPort("1.2.3.4:32000"), 65536, uptime); !errors.Is(err, ErrBootstrapState) {
		t.Fatalf("truncated zero PID error = %v", err)
	}
}

func TestSelectEndpointDeterministicSignedDC(t *testing.T) {
	snapshot := ArtifactSnapshot{
		defaultDC: -203,
		endpoints: map[DCID][]netip.AddrPort{
			-203: {
				netip.MustParseAddrPort("149.154.167.50:443"),
				netip.MustParseAddrPort("149.154.167.51:443"),
				netip.MustParseAddrPort("[2001:67c:4e8:f004::a]:443"),
			},
			4: {netip.MustParseAddrPort("149.154.167.91:443")},
		},
	}
	dc, endpoint, err := SelectEndpoint(snapshot, nil, AddressFamilyAny, 0)
	if err != nil {
		t.Fatalf("SelectEndpoint default: %v", err)
	}
	if dc != -203 || endpoint != netip.MustParseAddrPort("149.154.167.50:443") {
		t.Fatalf("default selection = %d/%s", dc, endpoint)
	}
	dc, endpoint, err = SelectEndpoint(snapshot, new(DCID(4)), AddressFamilyIPv4, 0)
	if err != nil {
		t.Fatalf("SelectEndpoint explicit: %v", err)
	}
	if dc != 4 || endpoint != netip.MustParseAddrPort("149.154.167.91:443") {
		t.Fatalf("explicit selection = %d/%s", dc, endpoint)
	}
	_, endpoint, err = SelectEndpoint(snapshot, nil, AddressFamilyIPv6, 0)
	if err != nil || !endpoint.Addr().Is6() {
		t.Fatalf("IPv6 selection = %s, %v", endpoint, err)
	}
	if _, _, err := SelectEndpoint(snapshot, nil, AddressFamilyIPv6, 1); !errors.Is(err, ErrEndpointSelection) {
		t.Fatalf("unavailable index error = %v", err)
	}
}
