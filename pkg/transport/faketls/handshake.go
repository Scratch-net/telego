package faketls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"
)

const (
	// ClientHello structure offsets
	clientHelloRandomOffset    = 6
	clientHelloSessionIDOffset = 38
	randomLen                  = 32

	// Tolerance for client time skew
	DefaultTimeSkewTolerance = 3 * time.Second
)

var (
	ErrBadDigest      = errors.New("invalid ClientHello digest")
	ErrBadTimestamp   = errors.New("timestamp out of range")
	ErrBadHost        = errors.New("SNI hostname mismatch")
	ErrReplayAttack   = errors.New("replay attack detected")
	ErrInvalidPayload = errors.New("invalid ClientHello payload")
)

// ClientHello represents a parsed TLS ClientHello.
type ClientHello struct {
	Time      time.Time
	Random    [32]byte
	SessionID []byte
	Host      string
}

// ParseClientHello parses and validates a FakeTLS ClientHello.
// The secret is the 16-byte proxy secret.
func ParseClientHello(secret []byte, payload []byte) (*ClientHello, error) {
	if len(payload) < clientHelloSessionIDOffset+1 {
		return nil, ErrInvalidPayload
	}

	hello := &ClientHello{}

	// Extract random bytes
	copy(hello.Random[:], payload[clientHelloRandomOffset:clientHelloRandomOffset+randomLen])

	// Extract session ID
	sessionIDLen := int(payload[clientHelloSessionIDOffset])
	if len(payload) < clientHelloSessionIDOffset+1+sessionIDLen {
		return nil, ErrInvalidPayload
	}
	hello.SessionID = make([]byte, sessionIDLen)
	copy(hello.SessionID, payload[clientHelloSessionIDOffset+1:])

	// Compute expected digest: HMAC-SHA256(secret, payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	expectedRandom := mac.Sum(nil)

	// XOR with transmitted random to get verification data
	for i := 0; i < randomLen; i++ {
		expectedRandom[i] ^= hello.Random[i]
	}

	// First 28 bytes should be zero after XOR
	emptyRandom := make([]byte, randomLen-4)
	if subtle.ConstantTimeCompare(emptyRandom, expectedRandom[:randomLen-4]) != 1 {
		return nil, ErrBadDigest
	}

	// Last 4 bytes contain timestamp (little-endian)
	timestamp := binary.LittleEndian.Uint32(expectedRandom[randomLen-4:])
	hello.Time = time.Unix(int64(timestamp), 0)

	// Extract SNI hostname from extensions
	hello.Host = extractSNI(payload)

	return hello, nil
}

// Valid checks if the ClientHello is valid for the given host and time tolerance.
func (h *ClientHello) Valid(expectedHost string, tolerance time.Duration) error {
	// Check SNI
	if h.Host != expectedHost {
		return ErrBadHost
	}

	// Check timestamp
	now := time.Now()
	if h.Time.Before(now.Add(-tolerance)) || h.Time.After(now.Add(tolerance)) {
		return ErrBadTimestamp
	}

	return nil
}

// extractSNI extracts the SNI hostname from ClientHello extensions.
func extractSNI(payload []byte) string {
	// Skip to extensions: after session_id, cipher_suites, compression_methods
	offset := clientHelloSessionIDOffset
	if offset >= len(payload) {
		return ""
	}

	// Skip session ID
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(payload) {
		return ""
	}

	// Skip cipher suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2 + cipherSuitesLen
	if offset+1 > len(payload) {
		return ""
	}

	// Skip compression methods
	compressionLen := int(payload[offset])
	offset += 1 + compressionLen
	if offset+2 > len(payload) {
		return ""
	}

	// Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2
	extensionsEnd := offset + extensionsLen

	// Parse extensions
	for offset+4 <= extensionsEnd && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset:])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2:]))
		offset += 4

		if extType == 0 { // SNI extension
			if offset+5 > len(payload) {
				return ""
			}
			// Skip SNI list length (2) and name type (1)
			nameLen := int(binary.BigEndian.Uint16(payload[offset+3:]))
			if offset+5+nameLen > len(payload) {
				return ""
			}
			return string(payload[offset+5 : offset+5+nameLen])
		}

		offset += extLen
	}

	return ""
}

// BuildServerHello creates a ServerHello response for FakeTLS.
func BuildServerHello(secret []byte, clientHello *ClientHello) ([]byte, error) {
	// ServerHello base structure (simplified)
	// Real implementation would include full ServerHello + ChangeCipherSpec + random padding
	buf := &bytes.Buffer{}

	// Generate random padding (1024 + 0-3072 random bytes)
	paddingLen := 1024 + (time.Now().UnixNano() % 3072)
	serverData := make([]byte, paddingLen)
	rand.Read(serverData)

	// Compute MAC for response
	mac := hmac.New(sha256.New, secret)
	mac.Write(clientHello.Random[:])
	mac.Write(serverData)
	macSum := mac.Sum(nil)

	// Build ServerHello record
	serverHello := buildServerHelloMessage(macSum)
	changeCipherSpec := []byte{0x01} // ChangeCipherSpec message

	// Write ServerHello as TLS handshake record
	WriteRecord(buf, RecordTypeHandshake, serverHello)

	// Write ChangeCipherSpec
	WriteRecord(buf, RecordTypeChangeCipherSpec, changeCipherSpec)

	// Write encrypted application data (random padding)
	WriteRecord(buf, RecordTypeApplicationData, serverData)

	return buf.Bytes(), nil
}

// buildServerHelloMessage creates the ServerHello handshake message.
func buildServerHelloMessage(serverRandom []byte) []byte {
	// Simplified ServerHello structure:
	// [0]     Handshake type (0x02 = ServerHello)
	// [1:4]   Length (3 bytes)
	// [4:6]   Version (TLS 1.2)
	// [6:38]  Server random (32 bytes) - contains our MAC
	// [38]    Session ID length
	// ...     Rest of ServerHello

	msg := make([]byte, 74) // Minimal ServerHello

	msg[0] = 0x02 // ServerHello
	// Length will be filled after

	// Version
	msg[4] = 0x03
	msg[5] = 0x03

	// Server random (MAC)
	copy(msg[6:38], serverRandom)

	// Session ID length = 0
	msg[38] = 0

	// Cipher suite (TLS_AES_128_GCM_SHA256)
	msg[39] = 0x13
	msg[40] = 0x01

	// Compression method (null)
	msg[41] = 0x00

	// Extensions length = 0 (minimal)
	msg[42] = 0x00
	msg[43] = 0x00

	// Set length (3 bytes, big-endian)
	length := len(msg) - 4
	msg[1] = byte(length >> 16)
	msg[2] = byte(length >> 8)
	msg[3] = byte(length)

	return msg
}
