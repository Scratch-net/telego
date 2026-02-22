package middleend

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// STUN servers for public IP detection
var defaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
}

var (
	ErrNoPublicIP = errors.New("could not determine public IP")
)

// STUN message constants
const (
	stunMagicCookie = 0x2112A442
	stunBindingRequest = 0x0001
	stunBindingResponse = 0x0101
	stunXORMappedAddress = 0x0020
	stunMappedAddress = 0x0001
)

// DetectPublicIP uses STUN to detect our public IP address.
// This is needed for ME handshake which includes the proxy's IP.
func DetectPublicIP() (string, error) {
	return DetectPublicIPWithServers(defaultSTUNServers)
}

// DetectPublicIPWithServers tries multiple STUN servers.
func DetectPublicIPWithServers(servers []string) (string, error) {
	for _, server := range servers {
		ip, err := stunQuery(server)
		if err == nil {
			return ip, nil
		}
	}
	return "", ErrNoPublicIP
}

// stunQuery performs a STUN binding request.
func stunQuery(server string) (string, error) {
	conn, err := net.DialTimeout("udp", server, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Build STUN Binding Request
	request := buildSTUNRequest()

	// Send request
	if _, err := conn.Write(request); err != nil {
		return "", err
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return "", err
	}

	// Parse response
	return parseSTUNResponse(response[:n])
}

// buildSTUNRequest creates a STUN Binding Request message.
func buildSTUNRequest() []byte {
	msg := make([]byte, 20)

	// Message type: Binding Request
	binary.BigEndian.PutUint16(msg[0:2], stunBindingRequest)

	// Message length: 0 (no attributes)
	binary.BigEndian.PutUint16(msg[2:4], 0)

	// Magic cookie
	binary.BigEndian.PutUint32(msg[4:8], stunMagicCookie)

	// Transaction ID (random 12 bytes)
	// Using deterministic for simplicity - real impl should use crypto/rand
	copy(msg[8:20], []byte("telego-stun!"))

	return msg
}

// parseSTUNResponse extracts the mapped address from STUN response.
func parseSTUNResponse(data []byte) (string, error) {
	if len(data) < 20 {
		return "", errors.New("response too short")
	}

	// Check message type
	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != stunBindingResponse {
		return "", errors.New("not a binding response")
	}

	// Check magic cookie
	cookie := binary.BigEndian.Uint32(data[4:8])
	if cookie != stunMagicCookie {
		return "", errors.New("invalid magic cookie")
	}

	// Parse attributes
	msgLen := binary.BigEndian.Uint16(data[2:4])
	offset := 20

	for offset < 20+int(msgLen) && offset+4 <= len(data) {
		attrType := binary.BigEndian.Uint16(data[offset:])
		attrLen := binary.BigEndian.Uint16(data[offset+2:])
		offset += 4

		if offset+int(attrLen) > len(data) {
			break
		}

		switch attrType {
		case stunXORMappedAddress:
			return parseXORMappedAddress(data[offset:offset+int(attrLen)], data[4:8])
		case stunMappedAddress:
			return parseMappedAddress(data[offset : offset+int(attrLen)])
		}

		// Align to 4 bytes
		offset += int(attrLen)
		if attrLen%4 != 0 {
			offset += 4 - int(attrLen%4)
		}
	}

	return "", errors.New("no mapped address in response")
}

// parseXORMappedAddress extracts IP from XOR-MAPPED-ADDRESS attribute.
func parseXORMappedAddress(data, magicCookie []byte) (string, error) {
	if len(data) < 8 {
		return "", errors.New("attribute too short")
	}

	// Skip reserved byte, get family
	family := data[1]

	// XOR port with magic cookie
	// port := binary.BigEndian.Uint16(data[2:4]) ^ binary.BigEndian.Uint16(magicCookie[0:2])

	if family == 0x01 { // IPv4
		if len(data) < 8 {
			return "", errors.New("IPv4 address too short")
		}
		ip := make([]byte, 4)
		for i := 0; i < 4; i++ {
			ip[i] = data[4+i] ^ magicCookie[i]
		}
		return net.IP(ip).String(), nil
	} else if family == 0x02 { // IPv6
		if len(data) < 20 {
			return "", errors.New("IPv6 address too short")
		}
		// For IPv6, XOR with magic cookie + transaction ID
		// Simplified - just return error for now
		return "", errors.New("IPv6 not supported yet")
	}

	return "", errors.New("unknown address family")
}

// parseMappedAddress extracts IP from MAPPED-ADDRESS attribute.
func parseMappedAddress(data []byte) (string, error) {
	if len(data) < 8 {
		return "", errors.New("attribute too short")
	}

	family := data[1]

	if family == 0x01 { // IPv4
		ip := net.IP(data[4:8])
		return ip.String(), nil
	}

	return "", errors.New("unsupported address family")
}
