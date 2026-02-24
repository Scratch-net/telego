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
	Time        time.Time
	Random      [32]byte
	SessionID   []byte
	Host        string
	CipherSuite uint16
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
	for i := range randomLen {
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

	// Extract cipher suite (first one from the list)
	hello.CipherSuite = extractCipherSuite(payload, sessionIDLen)

	// Extract SNI hostname from extensions
	hello.Host = extractSNI(payload)

	return hello, nil
}

// extractCipherSuite extracts the first cipher suite from ClientHello.
func extractCipherSuite(payload []byte, sessionIDLen int) uint16 {
	// Cipher suites start after: handshake_header(4) + version(2) + random(32) + session_id_len(1) + session_id
	offset := 4 + 2 + 32 + 1 + sessionIDLen
	if offset+4 > len(payload) {
		return 0
	}
	// Skip cipher suites length (2 bytes), read first cipher suite
	return binary.BigEndian.Uint16(payload[offset+2 : offset+4])
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

// WelcomePacketRandomOffset is the offset of server random in the welcome packet.
// This is: record_header(5) + handshake_type(1) + handshake_length(3) + version(2) = 11
const WelcomePacketRandomOffset = 11

// ServerHelloOptions configures ServerHello generation.
type ServerHelloOptions struct {
	// CertChain is the raw certificate chain from the mask host.
	// If non-nil, it will be included in the encrypted portion to make
	// DPI see real certificate bytes.
	CertChain [][]byte
}

// BuildServerHello creates a ServerHello response for FakeTLS.
// Based on mtg v2 welcome.go implementation.
func BuildServerHello(secret []byte, clientHello *ClientHello) ([]byte, error) {
	return BuildServerHelloWithOptions(secret, clientHello, nil)
}

// BuildServerHelloWithOptions creates a ServerHello response with configurable options.
func BuildServerHelloWithOptions(secret []byte, clientHello *ClientHello, opts *ServerHelloOptions) ([]byte, error) {
	buf := &bytes.Buffer{}

	// Build ServerHello handshake message (with zeroed random initially)
	serverHello := buildServerHelloMessage(clientHello)

	// Write ServerHello as TLS record (TLS 1.2 version per mtg)
	writeRecordTLS12(buf, RecordTypeHandshake, serverHello)

	// Write ChangeCipherSpec (TLS 1.2 version per mtg)
	writeRecordTLS12(buf, RecordTypeChangeCipherSpec, []byte{0x01})

	// Build the encrypted portion content
	var encryptedData []byte
	if opts != nil && len(opts.CertChain) > 0 {
		// Include real certificate bytes for DPI evasion
		// Format: fake "encrypted" handshake with real cert data
		encryptedData = buildEncryptedHandshakeWithCert(opts.CertChain)
	} else {
		// Random padding (1024 + random 0-3091 bytes, per mtg)
		paddingLen := 1024 + int(time.Now().UnixNano()%3092)
		encryptedData = make([]byte, paddingLen)
		rand.Read(encryptedData)
	}

	// Write ApplicationData records (split into max 16KB chunks per TLS spec)
	writeApplicationDataChunked(buf, encryptedData)

	// Get the complete packet
	packet := buf.Bytes()

	// Compute MAC over: client_random || entire_packet (with zeroed server_random)
	// Per mtg: mac.Write(clientHello.Random[:]); mac.Write(packet)
	mac := hmac.New(sha256.New, secret)
	mac.Write(clientHello.Random[:])
	mac.Write(packet)
	serverRandom := mac.Sum(nil)

	// Place computed random into the packet at offset 11
	copy(packet[WelcomePacketRandomOffset:], serverRandom)

	return packet, nil
}

// buildEncryptedHandshakeWithCert creates fake encrypted handshake bytes
// that include the real certificate data. This makes DPI see valid cert bytes.
func buildEncryptedHandshakeWithCert(certChain [][]byte) []byte {
	buf := &bytes.Buffer{}

	// Build Certificate message structure (will appear as encrypted data)
	// TLS 1.3 Certificate message format:
	// - certificate_request_context length (1 byte) = 0
	// - certificate_list length (3 bytes)
	// - for each cert:
	//   - cert_data length (3 bytes)
	//   - cert_data
	//   - extensions length (2 bytes) = 0

	// Calculate total cert list length
	certListLen := 0
	for _, cert := range certChain {
		certListLen += 3 + len(cert) + 2 // length(3) + cert + extensions(2)
	}

	// Certificate message
	certMsg := &bytes.Buffer{}
	certMsg.WriteByte(0) // certificate_request_context length = 0

	// Certificate list length (3 bytes)
	certMsg.WriteByte(byte(certListLen >> 16))
	certMsg.WriteByte(byte(certListLen >> 8))
	certMsg.WriteByte(byte(certListLen))

	// Write each certificate
	for _, cert := range certChain {
		// Cert length (3 bytes)
		certMsg.WriteByte(byte(len(cert) >> 16))
		certMsg.WriteByte(byte(len(cert) >> 8))
		certMsg.WriteByte(byte(len(cert)))
		certMsg.Write(cert)
		// Extensions length (2 bytes) = 0
		certMsg.WriteByte(0)
		certMsg.WriteByte(0)
	}

	// Add handshake header for Certificate (type 0x0b)
	certBody := certMsg.Bytes()
	buf.WriteByte(0x0b) // Certificate handshake type
	buf.WriteByte(byte(len(certBody) >> 16))
	buf.WriteByte(byte(len(certBody) >> 8))
	buf.WriteByte(byte(len(certBody)))
	buf.Write(certBody)

	// Add random padding to match expected size (similar to random-only path)
	// Include some fake CertificateVerify and Finished-like data
	paddingLen := 256 + int(time.Now().UnixNano()%512)
	padding := make([]byte, paddingLen)
	rand.Read(padding)
	buf.Write(padding)

	return buf.Bytes()
}

// writeApplicationDataChunked writes data as ApplicationData records,
// splitting into chunks if needed (max ~16KB per TLS record).
func writeApplicationDataChunked(buf *bytes.Buffer, data []byte) {
	const maxChunk = 16000 // Leave room for headers

	for len(data) > 0 {
		chunkLen := min(len(data), maxChunk)
		writeRecordTLS12(buf, RecordTypeApplicationData, data[:chunkLen])
		data = data[chunkLen:]
	}
}

// writeRecordTLS12 writes a TLS record with TLS 1.2 version (0x0303).
func writeRecordTLS12(w *bytes.Buffer, recordType byte, payload []byte) {
	header := [RecordHeaderSize]byte{
		recordType,
		0x03, // TLS 1.2 major
		0x03, // TLS 1.2 minor
		byte(len(payload) >> 8),
		byte(len(payload)),
	}
	w.Write(header[:])
	w.Write(payload)
}

// serverHelloSuffix contains compression method + extensions header.
// Per mtg: compression(1) + extensions_length(2) + supported_versions(6) + key_share_header(8)
var serverHelloSuffix = []byte{
	0x00,       // no compression
	0x00, 0x2e, // 46 bytes of extensions
	0x00, 0x2b, // Extension: Supported Versions
	0x00, 0x02, // 2 bytes
	0x03, 0x04, // TLS 1.3
	0x00, 0x33, // Extension: Key Share
	0x00, 0x24, // 36 bytes
	0x00, 0x1d, // x25519 curve
	0x00, 0x20, // 32 bytes of key
}

// buildServerHelloMessage creates the ServerHello handshake message.
// Per mtg welcome.go generateServerHello function.
func buildServerHelloMessage(clientHello *ClientHello) []byte {
	buf := &bytes.Buffer{}

	// Version (TLS 1.2)
	buf.WriteByte(0x03)
	buf.WriteByte(0x03)

	// Random (32 bytes of zeros - will be filled in later by MAC)
	buf.Write(emptyRandom)

	// Session ID (copy from client)
	buf.WriteByte(byte(len(clientHello.SessionID)))
	buf.Write(clientHello.SessionID)

	// Cipher suite (copy from client, or use default)
	cipherSuite := clientHello.CipherSuite
	if cipherSuite == 0 {
		cipherSuite = 0x1301 // TLS_AES_128_GCM_SHA256
	}
	buf.WriteByte(byte(cipherSuite >> 8))
	buf.WriteByte(byte(cipherSuite))

	// Suffix (compression + extensions header)
	buf.Write(serverHelloSuffix)

	// Generate x25519 key share (32 bytes)
	keyShare := make([]byte, 32)
	rand.Read(keyShare)
	buf.Write(keyShare)

	// Build final message with handshake header
	body := buf.Bytes()
	msg := make([]byte, 4+len(body))
	msg[0] = 0x02 // ServerHello handshake type
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)

	return msg
}
