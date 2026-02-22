package faketls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	// ClientHello structure offsets (within handshake message, after 4-byte header)
	clientHelloRandomOffset    = 6  // After: type(1) + length(3) + version(2)
	clientHelloSessionIDOffset = 38 // After random (32 bytes)
	randomLen                  = 32

	// Handshake types
	handshakeTypeClient = 0x01

	// Tolerance for client time skew
	DefaultTimeSkewTolerance = 3 * time.Second
)

var (
	ErrBadDigest      = errors.New("invalid ClientHello digest")
	ErrBadTimestamp   = errors.New("timestamp out of range")
	ErrBadHost        = errors.New("SNI hostname mismatch")
	ErrReplayAttack   = errors.New("replay attack detected")
	ErrInvalidPayload = errors.New("invalid ClientHello payload")

	// Zero bytes for replacing random during HMAC computation
	emptyRandom = make([]byte, randomLen)
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
// The payload is the TLS handshake record payload (not including record header).
func ParseClientHello(secret []byte, payload []byte) (*ClientHello, error) {
	if len(payload) < clientHelloSessionIDOffset+1 {
		return nil, fmt.Errorf("%w: too short (%d bytes)", ErrInvalidPayload, len(payload))
	}

	// Verify handshake type
	if payload[0] != handshakeTypeClient {
		return nil, fmt.Errorf("%w: bad handshake type 0x%02x", ErrInvalidPayload, payload[0])
	}

	// Verify handshake length
	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if len(payload)-4 != handshakeLen {
		return nil, fmt.Errorf("%w: length mismatch (header=%d, actual=%d)",
			ErrInvalidPayload, handshakeLen, len(payload)-4)
	}

	hello := &ClientHello{}

	// Extract random bytes (before zeroing)
	copy(hello.Random[:], payload[clientHelloRandomOffset:clientHelloRandomOffset+randomLen])

	// Create a copy of payload with zeroed random for HMAC computation
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)
	copy(payloadCopy[clientHelloRandomOffset:], emptyRandom)

	// Build full TLS record for HMAC computation:
	// [type(1)][version(2)][length(2)][payload]
	// mtg uses TLS 1.0 version (0x0301) for the record header
	record := make([]byte, 5+len(payloadCopy))
	record[0] = RecordTypeHandshake // 0x16
	record[1] = 0x03                // TLS 1.0 major
	record[2] = 0x01                // TLS 1.0 minor
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payloadCopy)))
	copy(record[5:], payloadCopy)

	// Compute HMAC-SHA256 over the entire record
	mac := hmac.New(sha256.New, secret)
	mac.Write(record)
	computedRandom := mac.Sum(nil)

	// XOR with transmitted random to get verification data
	for i := 0; i < randomLen; i++ {
		computedRandom[i] ^= hello.Random[i]
	}

	// First 28 bytes should be zero after XOR
	if subtle.ConstantTimeCompare(emptyRandom[:randomLen-4], computedRandom[:randomLen-4]) != 1 {
		return nil, ErrBadDigest
	}

	// Last 4 bytes contain timestamp (little-endian)
	timestamp := binary.LittleEndian.Uint32(computedRandom[randomLen-4:])
	hello.Time = time.Unix(int64(timestamp), 0)

	// Extract session ID
	sessionIDLen := int(payload[clientHelloSessionIDOffset])
	if len(payload) < clientHelloSessionIDOffset+1+sessionIDLen {
		return nil, ErrInvalidPayload
	}
	hello.SessionID = make([]byte, sessionIDLen)
	copy(hello.SessionID, payload[clientHelloSessionIDOffset+1:])

	// Extract SNI hostname from extensions
	hello.Host = extractSNI(payload)

	return hello, nil
}

// Valid checks if the ClientHello is valid for the given host and time tolerance.
func (h *ClientHello) Valid(expectedHost string, tolerance time.Duration) error {
	// Check SNI (allow empty - some clients don't send it)
	if h.Host != "" && h.Host != expectedHost {
		return ErrBadHost
	}

	// Check timestamp
	now := time.Now()
	diff := now.Sub(h.Time)
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
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

	// Parse extensions looking for SNI (type 0x0000)
	for offset+4 <= extensionsEnd && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset:])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2:]))
		offset += 4

		if extType == 0 { // SNI extension
			// SNI extension format:
			// [list_length(2)][name_type(1)][name_length(2)][name]
			if offset+5 > len(payload) {
				return ""
			}
			// Skip list length, check name type
			nameType := payload[offset+2]
			if nameType != 0 { // 0 = hostname
				return ""
			}
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
	buf := &bytes.Buffer{}

	// Generate random padding (1024 + 0-3072 random bytes)
	paddingLen := 1024 + (time.Now().UnixNano() % 3072)
	randomData := make([]byte, paddingLen)
	rand.Read(randomData)

	// Build ServerHello handshake message
	serverHello := buildServerHelloMessage()

	// Build the TLS record that will be sent (with zeroed random for MAC)
	serverHelloCopy := make([]byte, len(serverHello))
	copy(serverHelloCopy, serverHello)
	copy(serverHelloCopy[6:6+randomLen], emptyRandom)

	// Build full TLS record for MAC computation (matching ClientHello pattern)
	record := make([]byte, 5+len(serverHelloCopy))
	record[0] = RecordTypeHandshake // 0x16
	record[1] = 0x03                // TLS 1.0 major (match ClientHello)
	record[2] = 0x01                // TLS 1.0 minor
	binary.BigEndian.PutUint16(record[3:5], uint16(len(serverHelloCopy)))
	copy(record[5:], serverHelloCopy)

	// Compute MAC for response
	// server_random = HMAC-SHA256(secret, client_random || serverHello_record_with_zeroed_random)
	mac := hmac.New(sha256.New, secret)
	mac.Write(clientHello.Random[:])
	mac.Write(record)
	serverRandom := mac.Sum(nil)

	fmt.Printf("[DEBUG BuildServerHello] clientRandom=%02x..., serverRandom=%02x...\n",
		clientHello.Random[:8], serverRandom[:8])

	// Place computed random into ServerHello
	copy(serverHello[6:6+randomLen], serverRandom)

	// Write ServerHello as TLS handshake record (use TLS 1.0 version for record header)
	writeRecordWithVersion(buf, RecordTypeHandshake, VersionTLS10, serverHello)

	// Write ChangeCipherSpec
	writeRecordWithVersion(buf, RecordTypeChangeCipherSpec, VersionTLS10, []byte{0x01})

	// Write encrypted application data (random padding)
	writeRecordWithVersion(buf, RecordTypeApplicationData, VersionTLS12, randomData)

	return buf.Bytes(), nil
}

// writeRecordWithVersion writes a TLS record with the specified version.
func writeRecordWithVersion(w *bytes.Buffer, recordType byte, version uint16, payload []byte) {
	header := [RecordHeaderSize]byte{
		recordType,
		byte(version >> 8),
		byte(version),
		byte(len(payload) >> 8),
		byte(len(payload)),
	}
	w.Write(header[:])
	w.Write(payload)
}

// buildServerHelloMessage creates the ServerHello handshake message.
func buildServerHelloMessage() []byte {
	// ServerHello structure:
	// [0]     Handshake type (0x02 = ServerHello)
	// [1:4]   Length (3 bytes, big-endian)
	// [4:6]   Version (TLS 1.2 = 0x0303)
	// [6:38]  Server random (32 bytes)
	// [38]    Session ID length (0)
	// [39:41] Cipher suite (TLS_AES_128_GCM_SHA256 = 0x1301)
	// [41]    Compression method (null = 0x00)
	// [42:44] Extensions length
	// [44+]   Extensions

	// TLS 1.3 extensions for ServerHello
	extensions := []byte{
		0x00, 0x2b, // Extension: Supported Versions
		0x00, 0x02, // Length: 2 bytes
		0x03, 0x04, // TLS 1.3

		0x00, 0x33, // Extension: Key Share
		0x00, 0x24, // Length: 36 bytes
		0x00, 0x1d, // x25519 curve
		0x00, 0x20, // 32 bytes of key share
	}
	// Add 32 random bytes for key share
	keyShare := make([]byte, 32)
	rand.Read(keyShare)
	extensions = append(extensions, keyShare...)

	// Total message length
	msgLen := 2 + 32 + 1 + 2 + 1 + 2 + len(extensions) // version + random + session_id_len + cipher + compression + ext_len + extensions

	msg := make([]byte, 4+msgLen)
	msg[0] = 0x02 // ServerHello
	msg[1] = byte(msgLen >> 16)
	msg[2] = byte(msgLen >> 8)
	msg[3] = byte(msgLen)

	// Version (TLS 1.2 in ServerHello, real version in extension)
	msg[4] = 0x03
	msg[5] = 0x03

	// Random will be filled later (32 bytes at offset 6)

	// Session ID length = 0
	msg[38] = 0x00

	// Cipher suite
	msg[39] = 0x13
	msg[40] = 0x01

	// Compression method
	msg[41] = 0x00

	// Extensions length
	binary.BigEndian.PutUint16(msg[42:44], uint16(len(extensions)))

	// Extensions
	copy(msg[44:], extensions)

	return msg
}
