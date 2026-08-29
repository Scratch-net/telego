package gproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// proxyProtocolV2Sig is the 12-byte signature for PROXY protocol v2.
// Reused from dc_handler.go for consistency.
var proxyProtoV2Sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

var proxyProtoV1Prefix = []byte("PROXY ")

const (
	maxProxyProtoV1Header = 107
	maxProxyProtoV2Header = 16 + int(^uint16(0))
)

// ProxyProtoResult holds the parsed PROXY protocol header result.
type ProxyProtoResult struct {
	SrcAddr   net.Addr // Source (client) address
	DstAddr   net.Addr // Destination (server) address
	HeaderLen int      // Total bytes consumed by header
	IsLocal   bool     // True if LOCAL command (health check)
}

// ParseProxyProtocol attempts to parse a PROXY protocol v1 or v2 header.
// Returns nil if the data doesn't start with a valid PROXY protocol header.
// Returns error if header is malformed or incomplete.
func ParseProxyProtocol(data []byte) (*ProxyProtoResult, error) {
	if len(data) < 8 {
		return nil, nil // Not enough data to determine
	}

	// Check for v2 signature (12 bytes)
	if len(data) >= 12 && bytes.Equal(data[:12], proxyProtoV2Sig) {
		return parseProxyProtoV2(data)
	}

	// Check for v1 "PROXY " prefix
	if bytes.HasPrefix(data, []byte("PROXY ")) {
		return parseProxyProtoV1(data)
	}

	// Not a PROXY protocol header
	return nil, nil
}

type proxyProtoFrameStatus uint8

const (
	proxyProtoNotPresent proxyProtoFrameStatus = iota
	proxyProtoIncomplete
	proxyProtoComplete
)

// inspectProxyProtocolFrame determines whether the buffered prefix can still
// be a PROXY header and whether the complete bounded header is available.
func inspectProxyProtocolFrame(data []byte) (proxyProtoFrameStatus, error) {
	if len(data) == 0 {
		return proxyProtoIncomplete, nil
	}

	switch data[0] {
	case proxyProtoV1Prefix[0]:
		compared := min(len(data), len(proxyProtoV1Prefix))
		if !bytes.Equal(data[:compared], proxyProtoV1Prefix[:compared]) {
			return proxyProtoNotPresent, nil
		}
		if len(data) < len(proxyProtoV1Prefix) {
			return proxyProtoIncomplete, nil
		}
		if end := bytes.Index(data, []byte("\r\n")); end >= 0 {
			if end+2 > maxProxyProtoV1Header {
				return proxyProtoNotPresent, fmt.Errorf("proxy protocol v1: header too long")
			}
			return proxyProtoComplete, nil
		}
		if len(data) >= maxProxyProtoV1Header {
			return proxyProtoNotPresent, fmt.Errorf("proxy protocol v1: header too long")
		}
		return proxyProtoIncomplete, nil

	case proxyProtoV2Sig[0]:
		compared := min(len(data), len(proxyProtoV2Sig))
		if !bytes.Equal(data[:compared], proxyProtoV2Sig[:compared]) {
			return proxyProtoNotPresent, nil
		}
		if len(data) < 16 {
			return proxyProtoIncomplete, nil
		}
		total := 16 + int(binary.BigEndian.Uint16(data[14:16]))
		if total > maxProxyProtoV2Header {
			return proxyProtoNotPresent, fmt.Errorf("proxy protocol v2: header too long")
		}
		if len(data) < total {
			return proxyProtoIncomplete, nil
		}
		return proxyProtoComplete, nil
	default:
		return proxyProtoNotPresent, nil
	}
}

// parseProxyProtoV1 parses a PROXY protocol v1 (text) header.
// Format: "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n"
func parseProxyProtoV1(data []byte) (*ProxyProtoResult, error) {
	// Find the end of line
	idx := bytes.Index(data, []byte("\r\n"))
	if idx == -1 {
		if len(data) >= maxProxyProtoV1Header {
			return nil, fmt.Errorf("proxy protocol v1: header too long")
		}
		return nil, fmt.Errorf("proxy protocol v1: incomplete header")
	}
	if idx+2 > maxProxyProtoV1Header {
		return nil, fmt.Errorf("proxy protocol v1: header too long")
	}

	parts := bytes.Fields(data[:idx])

	if len(parts) < 2 {
		return nil, fmt.Errorf("proxy protocol v1: invalid header")
	}

	proto := string(parts[1])

	// Handle UNKNOWN protocol (LOCAL equivalent)
	if proto == "UNKNOWN" {
		return &ProxyProtoResult{
			HeaderLen: idx + 2,
			IsLocal:   true,
		}, nil
	}

	if len(parts) != 6 {
		return nil, fmt.Errorf("proxy protocol v1: expected 6 fields, got %d", len(parts))
	}

	if proto != "TCP4" && proto != "TCP6" {
		return nil, fmt.Errorf("proxy protocol v1: unsupported protocol %s", proto)
	}

	srcIP := net.ParseIP(string(parts[2]))
	dstIP := net.ParseIP(string(parts[3]))
	if srcIP == nil || dstIP == nil {
		return nil, fmt.Errorf("proxy protocol v1: invalid IP address")
	}
	if proto == "TCP4" {
		if srcIP.To4() == nil || dstIP.To4() == nil {
			return nil, fmt.Errorf("proxy protocol v1: TCP4 address family mismatch")
		}
	} else {
		if srcIP.To4() != nil || dstIP.To4() != nil {
			return nil, fmt.Errorf("proxy protocol v1: TCP6 address family mismatch")
		}
		if srcIP.To16() == nil || dstIP.To16() == nil {
			return nil, fmt.Errorf("proxy protocol v1: invalid TCP6 address")
		}
	}

	srcPort, err := strconv.Atoi(string(parts[4]))
	if err != nil || srcPort < 0 || srcPort > 65535 {
		return nil, fmt.Errorf("proxy protocol v1: invalid source port")
	}

	dstPort, err := strconv.Atoi(string(parts[5]))
	if err != nil || dstPort < 0 || dstPort > 65535 {
		return nil, fmt.Errorf("proxy protocol v1: invalid destination port")
	}

	return &ProxyProtoResult{
		SrcAddr:   &net.TCPAddr{IP: srcIP, Port: srcPort},
		DstAddr:   &net.TCPAddr{IP: dstIP, Port: dstPort},
		HeaderLen: idx + 2,
	}, nil
}

// parseProxyProtoV2 parses a PROXY protocol v2 (binary) header.
func parseProxyProtoV2(data []byte) (*ProxyProtoResult, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("proxy protocol v2: incomplete header")
	}

	// Byte 12: version and command
	verCmd := data[12]
	version := (verCmd >> 4) & 0x0F
	command := verCmd & 0x0F

	if version != 2 {
		return nil, fmt.Errorf("proxy protocol v2: unsupported version %d", version)
	}

	// Byte 13: address family and protocol
	famProto := data[13]

	// Bytes 14-15: address length (big endian)
	addrLen := binary.BigEndian.Uint16(data[14:16])

	totalLen := 16 + int(addrLen)
	if len(data) < totalLen {
		return nil, fmt.Errorf("proxy protocol v2: incomplete address data")
	}

	result := &ProxyProtoResult{
		HeaderLen: totalLen,
	}

	// Command: 0 = LOCAL, 1 = PROXY
	if command == 0 {
		result.IsLocal = true
		return result, nil
	}

	if command != 1 {
		return nil, fmt.Errorf("proxy protocol v2: unsupported command %d", command)
	}

	// A PROXY command is authoritative for a TCP connection only when the
	// transport nibble is STREAM. Do not materialize DGRAM metadata as TCP
	// addresses, especially on the authenticated internal ingress.
	family := (famProto >> 4) & 0x0F
	protocol := famProto & 0x0F
	if protocol != 1 {
		return nil, fmt.Errorf("proxy protocol v2: unsupported transport protocol %d", protocol)
	}

	// Parse addresses based on family.
	addrData := data[16:totalLen]

	switch family {
	case 1: // AF_INET (IPv4)
		if len(addrData) < 12 {
			return nil, fmt.Errorf("proxy protocol v2: IPv4 address data too short")
		}
		// Copy IPs to avoid referencing the input buffer (which may be reused)
		srcIP := make(net.IP, 4)
		dstIP := make(net.IP, 4)
		copy(srcIP, addrData[0:4])
		copy(dstIP, addrData[4:8])
		srcPort := binary.BigEndian.Uint16(addrData[8:10])
		dstPort := binary.BigEndian.Uint16(addrData[10:12])

		result.SrcAddr = &net.TCPAddr{IP: srcIP, Port: int(srcPort)}
		result.DstAddr = &net.TCPAddr{IP: dstIP, Port: int(dstPort)}

	case 2: // AF_INET6 (IPv6)
		if len(addrData) < 36 {
			return nil, fmt.Errorf("proxy protocol v2: IPv6 address data too short")
		}
		// Copy IPs to avoid referencing the input buffer (which may be reused)
		srcIP := make(net.IP, 16)
		dstIP := make(net.IP, 16)
		copy(srcIP, addrData[0:16])
		copy(dstIP, addrData[16:32])
		srcPort := binary.BigEndian.Uint16(addrData[32:34])
		dstPort := binary.BigEndian.Uint16(addrData[34:36])

		result.SrcAddr = &net.TCPAddr{IP: srcIP, Port: int(srcPort)}
		result.DstAddr = &net.TCPAddr{IP: dstIP, Port: int(dstPort)}

	default:
		return nil, fmt.Errorf("proxy protocol v2: unsupported address family %d", family)
	}

	return result, nil
}
