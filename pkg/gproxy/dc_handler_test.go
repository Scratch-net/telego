package gproxy

import (
	"net"
	"testing"

	"github.com/scratch-net/telego/pkg/dc"
)

// TestBuildProxyProtocolV1_IPv4 tests building v1 header for IPv4.
func TestBuildProxyProtocolV1_IPv4(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	header := buildProxyProtocolV1(src, dst)

	expected := "PROXY TCP4 192.168.1.100 10.0.0.1 12345 443\r\n"
	if string(header) != expected {
		t.Errorf("buildProxyProtocolV1 IPv4:\ngot:  %q\nwant: %q", string(header), expected)
	}
}

// TestBuildProxyProtocolV1_IPv6 tests building v1 header for IPv6.
func TestBuildProxyProtocolV1_IPv6(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}

	header := buildProxyProtocolV1(src, dst)

	expected := "PROXY TCP6 2001:db8::1 2001:db8::2 54321 443\r\n"
	if string(header) != expected {
		t.Errorf("buildProxyProtocolV1 IPv6:\ngot:  %q\nwant: %q", string(header), expected)
	}
}

// TestBuildProxyProtocolV2_IPv4 tests building v2 binary header for IPv4.
func TestBuildProxyProtocolV2_IPv4(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	header := buildProxyProtocolV2(src, dst)

	// Verify header structure
	if len(header) != 28 { // 16 bytes header + 12 bytes IPv4 addresses
		t.Errorf("IPv4 header length: got %d, want 28", len(header))
	}

	// Verify signature (first 12 bytes)
	if string(header[:12]) != string(proxyProtocolV2Sig) {
		t.Error("v2 signature mismatch")
	}

	// Verify version and command (byte 12)
	if header[12] != 0x21 { // version 2, PROXY command
		t.Errorf("ver_cmd: got 0x%02x, want 0x21", header[12])
	}

	// Verify family (byte 13)
	if header[13] != 0x11 { // AF_INET + STREAM
		t.Errorf("family: got 0x%02x, want 0x11", header[13])
	}

	// Verify address length (bytes 14-15)
	addrLen := int(header[14])<<8 | int(header[15])
	if addrLen != 12 {
		t.Errorf("addr_len: got %d, want 12", addrLen)
	}

	// Verify source IP (bytes 16-19)
	srcIP := net.IP(header[16:20])
	if !srcIP.Equal(net.ParseIP("192.168.1.100").To4()) {
		t.Errorf("srcIP: got %s, want 192.168.1.100", srcIP)
	}

	// Verify destination IP (bytes 20-23)
	dstIP := net.IP(header[20:24])
	if !dstIP.Equal(net.ParseIP("10.0.0.1").To4()) {
		t.Errorf("dstIP: got %s, want 10.0.0.1", dstIP)
	}

	// Verify source port (bytes 24-25)
	srcPort := int(header[24])<<8 | int(header[25])
	if srcPort != 12345 {
		t.Errorf("srcPort: got %d, want 12345", srcPort)
	}

	// Verify destination port (bytes 26-27)
	dstPort := int(header[26])<<8 | int(header[27])
	if dstPort != 443 {
		t.Errorf("dstPort: got %d, want 443", dstPort)
	}
}

// TestBuildProxyProtocolV2_IPv6 tests building v2 binary header for IPv6.
func TestBuildProxyProtocolV2_IPv6(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}

	header := buildProxyProtocolV2(src, dst)

	// Verify header structure
	if len(header) != 52 { // 16 bytes header + 36 bytes IPv6 addresses
		t.Errorf("IPv6 header length: got %d, want 52", len(header))
	}

	// Verify family (byte 13)
	if header[13] != 0x21 { // AF_INET6 + STREAM
		t.Errorf("family: got 0x%02x, want 0x21", header[13])
	}

	// Verify address length (bytes 14-15)
	addrLen := int(header[14])<<8 | int(header[15])
	if addrLen != 36 {
		t.Errorf("addr_len: got %d, want 36", addrLen)
	}
}

// TestBuildProxyProtocolHeader_Version tests version selection.
func TestBuildProxyProtocolHeader_Version(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	// Version 1 should return text format
	v1 := buildProxyProtocolHeader(1, src, dst)
	if v1[0] != 'P' {
		t.Error("v1 should start with 'P'")
	}

	// Version 2 should return binary format
	v2 := buildProxyProtocolHeader(2, src, dst)
	if v2[0] != 0x0D {
		t.Error("v2 should start with 0x0D")
	}
}

// TestBuildProxyProtocolHeader_NonTCPAddr tests handling of non-TCP addresses.
func TestBuildProxyProtocolHeader_NonTCPAddr(t *testing.T) {
	// Using UDP address (shouldn't happen but test defensive code)
	src := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	header := buildProxyProtocolHeader(1, src, dst)
	if header != nil {
		t.Error("should return nil for non-TCP source address")
	}

	header = buildProxyProtocolHeader(1, dst, src)
	if header != nil {
		t.Error("should return nil for non-TCP destination address")
	}
}

// TestFilterAddrs_IPv4Only tests filtering to IPv4 addresses only.
func TestFilterAddrs_IPv4Only(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp6", Address: "[2001:db8::1]:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
		{Network: "tcp6", Address: "[2001:db8::2]:443"},
	}

	filtered := filterAddrs(addrs, false) // wantIPv6=false means IPv4

	if len(filtered) != 2 {
		t.Errorf("expected 2 IPv4 addresses, got %d", len(filtered))
	}

	for _, a := range filtered {
		if a.IsIPv6() {
			t.Errorf("unexpected IPv6 address: %s", a.Address)
		}
	}
}

// TestFilterAddrs_IPv6Only tests filtering to IPv6 addresses only.
func TestFilterAddrs_IPv6Only(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp6", Address: "[2001:db8::1]:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
		{Network: "tcp6", Address: "[2001:db8::2]:443"},
	}

	filtered := filterAddrs(addrs, true) // wantIPv6=true

	if len(filtered) != 2 {
		t.Errorf("expected 2 IPv6 addresses, got %d", len(filtered))
	}

	for _, a := range filtered {
		if !a.IsIPv6() {
			t.Errorf("unexpected IPv4 address: %s", a.Address)
		}
	}
}

// TestFilterAddrs_Empty tests filtering an empty list.
func TestFilterAddrs_Empty(t *testing.T) {
	filtered := filterAddrs([]dc.Addr{}, true)
	if len(filtered) != 0 {
		t.Errorf("expected empty result, got %d", len(filtered))
	}
}

// TestFilterAddrs_NoMatch tests filtering when no addresses match.
func TestFilterAddrs_NoMatch(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
	}

	// Filter for IPv6 when all are IPv4
	filtered := filterAddrs(addrs, true)
	if len(filtered) != 0 {
		t.Errorf("expected no addresses, got %d", len(filtered))
	}
}

// TestSortAddrsByPreference_PreferIPv4 tests sorting with IPv4 preference.
func TestSortAddrsByPreference_PreferIPv4(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp6", Address: "[2001:db8::1]:443"},
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp6", Address: "[2001:db8::2]:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
	}

	sorted := sortAddrsByPreference(addrs, false) // preferIPv6=false means prefer IPv4

	if len(sorted) != 4 {
		t.Fatalf("expected 4 addresses, got %d", len(sorted))
	}

	// First two should be IPv4
	if sorted[0].IsIPv6() || sorted[1].IsIPv6() {
		t.Error("IPv4 addresses should come first")
	}

	// Last two should be IPv6
	if !sorted[2].IsIPv6() || !sorted[3].IsIPv6() {
		t.Error("IPv6 addresses should come last")
	}

	// Verify relative order within each group is preserved
	if sorted[0].Address != "1.1.1.1:443" {
		t.Errorf("first IPv4 should be 1.1.1.1:443, got %s", sorted[0].Address)
	}
	if sorted[1].Address != "2.2.2.2:443" {
		t.Errorf("second IPv4 should be 2.2.2.2:443, got %s", sorted[1].Address)
	}
}

// TestSortAddrsByPreference_PreferIPv6 tests sorting with IPv6 preference.
func TestSortAddrsByPreference_PreferIPv6(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp6", Address: "[2001:db8::1]:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
		{Network: "tcp6", Address: "[2001:db8::2]:443"},
	}

	sorted := sortAddrsByPreference(addrs, true) // preferIPv6=true

	if len(sorted) != 4 {
		t.Fatalf("expected 4 addresses, got %d", len(sorted))
	}

	// First two should be IPv6
	if !sorted[0].IsIPv6() || !sorted[1].IsIPv6() {
		t.Error("IPv6 addresses should come first")
	}

	// Last two should be IPv4
	if sorted[2].IsIPv6() || sorted[3].IsIPv6() {
		t.Error("IPv4 addresses should come last")
	}
}

// TestSortAddrsByPreference_AllSameFamily tests sorting when all addresses are same family.
func TestSortAddrsByPreference_AllSameFamily(t *testing.T) {
	addrs := []dc.Addr{
		{Network: "tcp4", Address: "1.1.1.1:443"},
		{Network: "tcp4", Address: "2.2.2.2:443"},
		{Network: "tcp4", Address: "3.3.3.3:443"},
	}

	sorted := sortAddrsByPreference(addrs, true) // prefer IPv6, but all are IPv4

	if len(sorted) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(sorted))
	}

	// Order should be preserved
	for i, a := range sorted {
		if a.Address != addrs[i].Address {
			t.Errorf("order not preserved at index %d", i)
		}
	}
}

// TestSortAddrsByPreference_Empty tests sorting an empty list.
func TestSortAddrsByPreference_Empty(t *testing.T) {
	sorted := sortAddrsByPreference([]dc.Addr{}, true)
	if len(sorted) != 0 {
		t.Errorf("expected empty result, got %d", len(sorted))
	}
}

// TestGetFd_NonSyscallConn tests getFd with a connection that doesn't support SyscallConn.
func TestGetFd_NonSyscallConn(t *testing.T) {
	// net.Pipe() returns connections that don't support SyscallConn
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	fd := getFd(client)
	if fd != -1 {
		t.Errorf("getFd should return -1 for net.Pipe connection, got %d", fd)
	}
}

// BenchmarkBuildProxyProtocolV1 benchmarks v1 header building.
func BenchmarkBuildProxyProtocolV1(b *testing.B) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	b.ResetTimer()
	for b.Loop() {
		buildProxyProtocolV1(src, dst)
	}
}

// BenchmarkBuildProxyProtocolV2 benchmarks v2 header building.
func BenchmarkBuildProxyProtocolV2(b *testing.B) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	b.ResetTimer()
	for b.Loop() {
		buildProxyProtocolV2(src, dst)
	}
}

// BenchmarkFilterAddrs benchmarks address filtering.
func BenchmarkFilterAddrs(b *testing.B) {
	addrs := make([]dc.Addr, 10)
	for i := range addrs {
		if i%2 == 0 {
			addrs[i] = dc.Addr{Network: "tcp4", Address: "1.1.1.1:443"}
		} else {
			addrs[i] = dc.Addr{Network: "tcp6", Address: "[2001:db8::1]:443"}
		}
	}

	b.ResetTimer()
	for b.Loop() {
		filterAddrs(addrs, false)
	}
}

// BenchmarkSortAddrsByPreference benchmarks address sorting.
func BenchmarkSortAddrsByPreference(b *testing.B) {
	addrs := make([]dc.Addr, 10)
	for i := range addrs {
		if i%2 == 0 {
			addrs[i] = dc.Addr{Network: "tcp4", Address: "1.1.1.1:443"}
		} else {
			addrs[i] = dc.Addr{Network: "tcp6", Address: "[2001:db8::1]:443"}
		}
	}

	b.ResetTimer()
	for b.Loop() {
		sortAddrsByPreference(addrs, false)
	}
}
