package gproxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestParseProxyProtocol_V1_TCP4(t *testing.T) {
	data := []byte("PROXY TCP4 192.168.1.1 192.168.1.2 12345 443\r\n")

	result, err := ParseProxyProtocol(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if result.HeaderLen != len(data) {
		t.Errorf("HeaderLen: got %d, want %d", result.HeaderLen, len(data))
	}

	srcAddr, ok := result.SrcAddr.(*net.TCPAddr)
	if !ok {
		t.Fatal("SrcAddr should be *net.TCPAddr")
	}
	if srcAddr.IP.String() != "192.168.1.1" {
		t.Errorf("SrcAddr IP: got %s, want 192.168.1.1", srcAddr.IP)
	}
	if srcAddr.Port != 12345 {
		t.Errorf("SrcAddr Port: got %d, want 12345", srcAddr.Port)
	}

	dstAddr, ok := result.DstAddr.(*net.TCPAddr)
	if !ok {
		t.Fatal("DstAddr should be *net.TCPAddr")
	}
	if dstAddr.IP.String() != "192.168.1.2" {
		t.Errorf("DstAddr IP: got %s, want 192.168.1.2", dstAddr.IP)
	}
	if dstAddr.Port != 443 {
		t.Errorf("DstAddr Port: got %d, want 443", dstAddr.Port)
	}
}

func TestParseProxyProtocol_V1_TCP6(t *testing.T) {
	data := []byte("PROXY TCP6 2001:db8::1 2001:db8::2 12345 443\r\n")

	result, err := ParseProxyProtocol(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}

	srcAddr := result.SrcAddr.(*net.TCPAddr)
	if srcAddr.IP.String() != "2001:db8::1" {
		t.Errorf("SrcAddr IP: got %s, want 2001:db8::1", srcAddr.IP)
	}
}

func TestParseProxyProtocol_V1_Unknown(t *testing.T) {
	data := []byte("PROXY UNKNOWN\r\n")

	result, err := ParseProxyProtocol(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if !result.IsLocal {
		t.Error("UNKNOWN should set IsLocal=true")
	}
	if result.SrcAddr != nil {
		t.Error("UNKNOWN should have nil SrcAddr")
	}
}

func TestParseProxyProtocol_V1_Incomplete(t *testing.T) {
	// No CRLF yet
	data := []byte("PROXY TCP4 192.168.1.1 192.168.1.2 12345 443")

	_, err := ParseProxyProtocol(data)
	if err == nil {
		t.Fatal("expected error for incomplete header")
	}
}

func TestParseProxyProtocol_V1_TooLong(t *testing.T) {
	// Max v1 header is 107 bytes
	data := make([]byte, 110)
	copy(data, "PROXY TCP4 ")
	for i := 11; i < 110; i++ {
		data[i] = 'x'
	}

	_, err := ParseProxyProtocol(data)
	if err == nil {
		t.Fatal("expected error for too long header")
	}
}

func TestParseProxyProtocol_V1_InvalidPort(t *testing.T) {
	data := []byte("PROXY TCP4 192.168.1.1 192.168.1.2 99999 443\r\n")

	_, err := ParseProxyProtocol(data)
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
}

func TestParseProxyProtocol_V1_InvalidIP(t *testing.T) {
	data := []byte("PROXY TCP4 invalid 192.168.1.2 12345 443\r\n")

	_, err := ParseProxyProtocol(data)
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestParseProxyProtocolV1RejectsAddressFamilyMismatch(t *testing.T) {
	for _, header := range []string{
		"PROXY TCP4 2001:db8::1 192.0.2.2 12345 443\r\n",
		"PROXY TCP4 192.0.2.1 2001:db8::2 12345 443\r\n",
		"PROXY TCP6 192.0.2.1 2001:db8::2 12345 443\r\n",
		"PROXY TCP6 2001:db8::1 192.0.2.2 12345 443\r\n",
	} {
		if _, err := ParseProxyProtocol([]byte(header)); err == nil {
			t.Fatalf("address-family mismatch accepted: %q", header)
		}
	}
}

func TestParseProxyProtocol_V2_IPv4(t *testing.T) {
	// Build v2 header manually
	data := make([]byte, 28) // 16 header + 12 addresses

	// Signature
	copy(data[0:12], proxyProtoV2Sig)

	// Version (2) and command (PROXY=1)
	data[12] = 0x21

	// Family (AF_INET=1) and protocol (STREAM=1)
	data[13] = 0x11

	// Address length (12 bytes for IPv4)
	binary.BigEndian.PutUint16(data[14:16], 12)

	// Source IP: 192.168.1.100
	data[16] = 192
	data[17] = 168
	data[18] = 1
	data[19] = 100

	// Dest IP: 10.0.0.1
	data[20] = 10
	data[21] = 0
	data[22] = 0
	data[23] = 1

	// Source port: 54321
	binary.BigEndian.PutUint16(data[24:26], 54321)

	// Dest port: 443
	binary.BigEndian.PutUint16(data[26:28], 443)

	result, err := ParseProxyProtocol(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if result.HeaderLen != 28 {
		t.Errorf("HeaderLen: got %d, want 28", result.HeaderLen)
	}

	srcAddr := result.SrcAddr.(*net.TCPAddr)
	if srcAddr.IP.String() != "192.168.1.100" {
		t.Errorf("SrcAddr IP: got %s, want 192.168.1.100", srcAddr.IP)
	}
	if srcAddr.Port != 54321 {
		t.Errorf("SrcAddr Port: got %d, want 54321", srcAddr.Port)
	}
}

func TestParseProxyProtocolV2ProxyRequiresIPStream(t *testing.T) {
	base := make([]byte, 28)
	copy(base[:12], proxyProtoV2Sig)
	base[12] = 0x21
	binary.BigEndian.PutUint16(base[14:16], 12)
	copy(base[16:20], net.ParseIP("192.0.2.1").To4())
	copy(base[20:24], net.ParseIP("198.51.100.1").To4())
	binary.BigEndian.PutUint16(base[24:26], 12345)
	binary.BigEndian.PutUint16(base[26:28], 443)

	for _, test := range []struct {
		name     string
		famProto byte
	}{
		{name: "IPv4 DGRAM", famProto: 0x12},
		{name: "IPv4 unspecified transport", famProto: 0x10},
		{name: "unspecified family STREAM", famProto: 0x01},
		{name: "UNIX STREAM with IPv4 address block", famProto: 0x31},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := bytes.Clone(base)
			wire[13] = test.famProto
			if _, err := ParseProxyProtocol(wire); err == nil {
				t.Fatal("invalid PROXY family/transport was accepted")
			}
		})
	}

	local := make([]byte, 16)
	copy(local[:12], proxyProtoV2Sig)
	local[12] = 0x20
	local[13] = 0x12
	result, err := ParseProxyProtocol(local)
	if err != nil || result == nil || !result.IsLocal {
		t.Fatalf("LOCAL DGRAM compatibility = %+v, %v", result, err)
	}
}

func TestParseProxyProtocol_V2_IPv6(t *testing.T) {
	// Build v2 header for IPv6
	data := make([]byte, 52) // 16 header + 36 addresses

	copy(data[0:12], proxyProtoV2Sig)
	data[12] = 0x21 // version 2, PROXY command
	data[13] = 0x21 // AF_INET6, STREAM

	binary.BigEndian.PutUint16(data[14:16], 36)

	// Source IP: 2001:db8::1
	srcIP := net.ParseIP("2001:db8::1")
	copy(data[16:32], srcIP.To16())

	// Dest IP: 2001:db8::2
	dstIP := net.ParseIP("2001:db8::2")
	copy(data[32:48], dstIP.To16())

	// Ports
	binary.BigEndian.PutUint16(data[48:50], 12345)
	binary.BigEndian.PutUint16(data[50:52], 443)

	result, err := ParseProxyProtocol(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srcAddr := result.SrcAddr.(*net.TCPAddr)
	if srcAddr.IP.String() != "2001:db8::1" {
		t.Errorf("SrcAddr IP: got %s, want 2001:db8::1", srcAddr.IP)
	}
}

func TestParseProxyProtocol_V2_Local(t *testing.T) {
	data := make([]byte, 16)
	copy(data[0:12], proxyProtoV2Sig)
	data[12] = 0x20 // version 2, LOCAL command
	data[13] = 0x00 // AF_UNSPEC
	binary.BigEndian.PutUint16(data[14:16], 0)

	result, err := ParseProxyProtocol(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsLocal {
		t.Error("LOCAL command should set IsLocal=true")
	}
}

func TestParseProxyProtocol_V2_Incomplete(t *testing.T) {
	// Just the signature, no rest
	data := make([]byte, 14)
	copy(data[0:12], proxyProtoV2Sig)

	_, err := ParseProxyProtocol(data)
	if err == nil {
		t.Fatal("expected error for incomplete v2 header")
	}
}

func TestParseProxyProtocol_V2_InvalidVersion(t *testing.T) {
	data := make([]byte, 16)
	copy(data[0:12], proxyProtoV2Sig)
	data[12] = 0x11 // version 1 (invalid for v2 format)

	_, err := ParseProxyProtocol(data)
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
}

func TestParseProxyProtocol_NotProxy(t *testing.T) {
	// TLS ClientHello starts with 0x16
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00}

	result, err := ParseProxyProtocol(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("TLS data should return nil result")
	}
}

func TestParseProxyProtocol_TooShort(t *testing.T) {
	data := []byte{0x16, 0x03}

	result, err := ParseProxyProtocol(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("short data should return nil result")
	}
}

func TestParseProxyProtocol_V2_BufferNotAliased(t *testing.T) {
	// Verify that modifying input buffer doesn't affect result
	data := make([]byte, 28)
	copy(data[0:12], proxyProtoV2Sig)
	data[12] = 0x21
	data[13] = 0x11
	binary.BigEndian.PutUint16(data[14:16], 12)
	data[16] = 192
	data[17] = 168
	data[18] = 1
	data[19] = 100
	data[20] = 10
	data[21] = 0
	data[22] = 0
	data[23] = 1
	binary.BigEndian.PutUint16(data[24:26], 54321)
	binary.BigEndian.PutUint16(data[26:28], 443)

	result, _ := ParseProxyProtocol(data)
	originalIP := result.SrcAddr.(*net.TCPAddr).IP.String()

	// Modify the input buffer
	data[16] = 10
	data[17] = 10
	data[18] = 10
	data[19] = 10

	// Result should be unchanged
	if result.SrcAddr.(*net.TCPAddr).IP.String() != originalIP {
		t.Error("modifying input buffer should not affect result")
	}
}

func TestParseProxyProtocol_WithTrailingData(t *testing.T) {
	// PROXY header followed by TLS data
	proxyHeader := []byte("PROXY TCP4 192.168.1.1 192.168.1.2 12345 443\r\n")
	tlsData := []byte{0x16, 0x03, 0x01, 0x00, 0x05}
	data := append(proxyHeader, tlsData...)

	result, err := ParseProxyProtocol(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// HeaderLen should only include PROXY header
	if result.HeaderLen != len(proxyHeader) {
		t.Errorf("HeaderLen: got %d, want %d", result.HeaderLen, len(proxyHeader))
	}
}

func BenchmarkParseProxyProtocol_V1(b *testing.B) {
	data := []byte("PROXY TCP4 192.168.1.1 192.168.1.2 12345 443\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseProxyProtocol(data)
	}
}

func BenchmarkParseProxyProtocol_V2(b *testing.B) {
	data := make([]byte, 28)
	copy(data[0:12], proxyProtoV2Sig)
	data[12] = 0x21
	data[13] = 0x11
	binary.BigEndian.PutUint16(data[14:16], 12)
	copy(data[16:20], net.ParseIP("192.168.1.1").To4())
	copy(data[20:24], net.ParseIP("192.168.1.2").To4())
	binary.BigEndian.PutUint16(data[24:26], 12345)
	binary.BigEndian.PutUint16(data[26:28], 443)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseProxyProtocol(data)
	}
}

func BenchmarkParseProxyProtocol_NotProxy(b *testing.B) {
	// TLS data - should quickly return nil
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseProxyProtocol(data)
	}
}
