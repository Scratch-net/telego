package faketls

import (
	"bytes"
	"crypto/ecdh"
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
	ALPN        []string // ALPN protocols offered by client
	OffersPQ    bool     // client offered the X25519MLKEM768 (0x11ec) key_share group
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

	// Extract ALPN protocols from extensions
	hello.ALPN = extractALPN(payload)

	// Note whether the client offered the hybrid post-quantum key_share group
	// (X25519MLKEM768, 0x11ec). Used to echo a matching group in the synthetic
	// ServerHello so we don't emit a passive group-downgrade tell.
	hello.OffersPQ = clientOffersPQKeyShare(payload)

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

// bootTimeThreshold is the maximum timestamp considered as "boot time" (uptime).
// Some embedded clients send uptime instead of Unix timestamp.
// ~2.7 years in seconds - timestamps below this are likely uptime, not Unix time.
const bootTimeThreshold = 60 * 60 * 24 * 1000

// Valid checks if the ClientHello is valid for the given host and time tolerance.
func (h *ClientHello) Valid(expectedHost string, tolerance time.Duration) error {
	// Check SNI (allow empty - some clients don't send it)
	if h.Host != "" && h.Host != expectedHost {
		return ErrBadHost
	}

	// Check timestamp
	timestamp := h.Time.Unix()

	// Boot time quirk: some clients send uptime instead of Unix time
	// Accept small timestamps (< ~2.7 years) as valid boot time
	if timestamp > 0 && timestamp < bootTimeThreshold {
		return nil
	}

	// Normal Unix timestamp validation. correctedNow applies any startup clock
	// correction so a skewed server clock doesn't reject every client.
	now := correctedNow()
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

// extractALPN extracts ALPN protocols from ClientHello extensions.
func extractALPN(payload []byte) []string {
	// Skip to extensions (same as extractSNI)
	offset := clientHelloSessionIDOffset
	if offset >= len(payload) {
		return nil
	}

	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(payload) {
		return nil
	}

	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2 + cipherSuitesLen
	if offset+1 > len(payload) {
		return nil
	}

	compressionLen := int(payload[offset])
	offset += 1 + compressionLen
	if offset+2 > len(payload) {
		return nil
	}

	extensionsLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2
	extensionsEnd := offset + extensionsLen

	// Parse extensions looking for ALPN (type 0x0010)
	for offset+4 <= extensionsEnd && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset:])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2:]))
		offset += 4

		if extType == 0x0010 && extLen >= 2 { // ALPN extension
			// ALPN format: [list_length(2)][proto_len(1)][proto]...
			if offset+2 > len(payload) {
				return nil
			}
			listLen := int(binary.BigEndian.Uint16(payload[offset:]))
			pos := offset + 2
			listEnd := pos + listLen
			if listEnd > len(payload) || listEnd > offset+extLen {
				return nil
			}

			var protocols []string
			for pos < listEnd {
				protoLen := int(payload[pos])
				pos++
				if pos+protoLen > listEnd {
					break
				}
				protocols = append(protocols, string(payload[pos:pos+protoLen]))
				pos += protoLen
			}
			return protocols
		}

		offset += extLen
	}

	return nil
}

// ExtractSNI returns the SNI hostname from a ClientHello handshake payload
// (the bytes after the 5-byte TLS record header), or "" if absent. Exported so
// the splice path can read the claimed SNI of an unauthenticated probe.
func ExtractSNI(payload []byte) string {
	return extractSNI(payload)
}

// pqNamedGroup is the TLS named group for the hybrid X25519MLKEM768 key exchange.
const pqNamedGroup = 0x11ec

// clientOffersPQKeyShare reports whether the ClientHello carries a key_share
// entry for X25519MLKEM768 (named group 0x11ec). It walks the same extension
// layout as extractSNI/extractALPN and never panics on malformed input.
func clientOffersPQKeyShare(payload []byte) bool {
	offset := clientHelloSessionIDOffset
	if offset >= len(payload) {
		return false
	}

	// Skip session ID
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(payload) {
		return false
	}

	// Skip cipher suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2 + cipherSuitesLen
	if offset+1 > len(payload) {
		return false
	}

	// Skip compression methods
	compressionLen := int(payload[offset])
	offset += 1 + compressionLen
	if offset+2 > len(payload) {
		return false
	}

	// Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset:]))
	offset += 2
	extensionsEnd := offset + extensionsLen

	// Parse extensions looking for key_share (type 0x0033)
	for offset+4 <= extensionsEnd && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset:])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2:]))
		offset += 4

		if extType == 0x0033 { // key_share
			// key_share: 2-byte client_shares list length, then entries of
			// [group(2)][key_len(2)][key].
			if offset+2 > len(payload) {
				return false
			}
			kp := offset + 2
			ksEnd := min(offset+extLen, len(payload))
			for kp+4 <= ksEnd {
				group := binary.BigEndian.Uint16(payload[kp:])
				if group == pqNamedGroup {
					return true
				}
				keyLen := int(binary.BigEndian.Uint16(payload[kp+2:]))
				kp += 4 + keyLen
			}
			return false
		}

		offset += extLen
	}

	return false
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

	// RealServerHello is a captured ServerHello response from a real TLS server.
	// If non-nil, this will be used as the base response instead of generating
	// a synthetic one. The random field will be patched with the computed HMAC.
	// This provides authentic TLS fingerprints to defeat DPI.
	RealServerHello []byte

	// RealServerHelloRandomOffset is the offset within RealServerHello where
	// the 32-byte random field starts. Required when RealServerHello is set.
	RealServerHelloRandomOffset int

	// FakeCertSize, when > 0, sets the exact payload length of the fake
	// "encrypted certificate" ApplicationData record instead of the default
	// random 1024+rand padding. Matching the mask backend's real first-flight
	// cert-record size removes the accept-vs-mask cert-record-length tell.
	// Clamped to [minFakeCertSize, maxFakeCertSize].
	FakeCertSize int
}

// Fake-cert (ApplicationData) record size clamp bounds (sane TLS record sizes).
const (
	minFakeCertSize = 256
	maxFakeCertSize = 16384
)

// fakeCertPadding returns the fake-cert ApplicationData payload. When size > 0
// it produces exactly that many random bytes (clamped); otherwise it falls back
// to the legacy 1024 + rand(0..3091) padding.
func fakeCertPadding(size int) []byte {
	if size > 0 {
		size = min(max(size, minFakeCertSize), maxFakeCertSize)
	} else {
		size = 1024 + int(time.Now().UnixNano()%3092)
	}
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// BuildServerHello creates a ServerHello response for FakeTLS.
// Based on mtg v2 welcome.go implementation.
func BuildServerHello(secret []byte, clientHello *ClientHello) ([]byte, error) {
	return BuildServerHelloWithOptions(secret, clientHello, nil)
}

// BuildServerHelloWithOptions creates a ServerHello response with configurable options.
func BuildServerHelloWithOptions(secret []byte, clientHello *ClientHello, opts *ServerHelloOptions) ([]byte, error) {
	// HYBRID MODE: Use real ServerHello from mask host if provided
	if opts != nil && len(opts.RealServerHello) > 0 {
		return buildHybridServerHello(secret, clientHello, opts)
	}

	// LEGACY MODE: Generate synthetic ServerHello
	return buildSyntheticServerHello(secret, clientHello, opts)
}

// buildHybridServerHello uses a real ServerHello record from a mask host,
// then appends synthetic ChangeCipherSpec + ApplicationData.
// This gives authentic TLS fingerprint on the ServerHello while maintaining
// the packet structure the Telegram client expects.
func buildHybridServerHello(secret []byte, clientHello *ClientHello, opts *ServerHelloOptions) ([]byte, error) {
	if opts.RealServerHelloRandomOffset < 11 || opts.RealServerHelloRandomOffset+32 > len(opts.RealServerHello) {
		return nil, fmt.Errorf("invalid RealServerHelloRandomOffset: %d (response len: %d)",
			opts.RealServerHelloRandomOffset, len(opts.RealServerHello))
	}

	buf := &bytes.Buffer{}

	// Write the real ServerHello record (with zeroed random for now)
	serverHelloRecord := make([]byte, len(opts.RealServerHello))
	copy(serverHelloRecord, opts.RealServerHello)
	randomOffset := opts.RealServerHelloRandomOffset
	for i := range 32 {
		serverHelloRecord[randomOffset+i] = 0
	}
	buf.Write(serverHelloRecord)

	// Append synthetic ChangeCipherSpec + ApplicationData (same as legacy)
	writeRecordTLS12(buf, RecordTypeChangeCipherSpec, []byte{0x01})

	encryptedData := fakeCertPadding(opts.FakeCertSize)
	writeApplicationDataChunked(buf, encryptedData)

	// Compute HMAC over the entire packet
	packet := buf.Bytes()
	mac := hmac.New(sha256.New, secret)
	mac.Write(clientHello.Random[:])
	mac.Write(packet)
	serverRandom := mac.Sum(nil)

	// Patch the random field
	copy(packet[randomOffset:], serverRandom)

	return packet, nil
}

// buildSyntheticServerHello generates a ServerHello from scratch (legacy mode).
func buildSyntheticServerHello(secret []byte, clientHello *ClientHello, opts *ServerHelloOptions) ([]byte, error) {
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
		fakeCertSize := 0
		if opts != nil {
			fakeCertSize = opts.FakeCertSize
		}
		encryptedData = fakeCertPadding(fakeCertSize)
	}

	// Write ApplicationData records (split into max 16KB chunks per TLS spec)
	writeApplicationDataChunked(buf, encryptedData)

	// Get the complete packet
	packet := buf.Bytes()

	// Compute MAC over: client_random || entire_packet (with zeroed server_random)
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
// splitting into chunks with jittered sizes to evade DPI fingerprinting.
// Uses ±3% variance on chunk sizes (similar to telemt).
func writeApplicationDataChunked(buf *bytes.Buffer, data []byte) {
	const baseChunk = 16000 // Base chunk size
	const jitterPercent = 3 // ±3% variance

	for len(data) > 0 {
		// Apply jitter: baseChunk ± 3%
		jitterRange := baseChunk * jitterPercent / 100 // ~480 bytes
		var jitterBytes [2]byte
		rand.Read(jitterBytes[:])
		jitter := int(jitterBytes[0])%(2*jitterRange+1) - jitterRange // -480 to +480

		targetChunk := max(baseChunk+jitter, 1000) // Minimum reasonable size

		chunkLen := min(len(data), targetChunk)
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

// generateX25519Key generates a valid X25519 public key.
// Uses crypto/ecdh to ensure the key is a valid curve point (quadratic residue),
// which is harder for DPI to detect as fake.
func generateX25519Key() []byte {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		// Fallback to random bytes if key generation fails (shouldn't happen)
		fallback := make([]byte, 32)
		rand.Read(fallback)
		return fallback
	}
	return key.PublicKey().Bytes()
}

// buildServerHelloMessage creates the ServerHello handshake message.
// Generates proper X25519 keys and optionally includes ALPN.
func buildServerHelloMessage(clientHello *ClientHello) []byte {
	buf := &bytes.Buffer{}

	// Version (TLS 1.2 in header, TLS 1.3 in extension)
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

	// Compression method
	buf.WriteByte(0x00)

	// Build extensions
	extBuf := &bytes.Buffer{}

	// Extension: Supported Versions (TLS 1.3)
	extBuf.Write([]byte{0x00, 0x2b}) // type
	extBuf.Write([]byte{0x00, 0x02}) // length
	extBuf.Write([]byte{0x03, 0x04}) // TLS 1.3

	// Extension: Key Share. Echo the client's offered group: when the client
	// offered the hybrid post-quantum group X25519MLKEM768 (0x11ec), answer with
	// a correctly-sized 0x11ec share, else classical x25519 (0x001d). Always
	// answering x25519 to a PQ-offering client is a passive group-downgrade tell.
	// The PQ share is high-entropy bytes, not a real ML-KEM encapsulation:
	// FakeTLS clients validate only record framing + the server-random HMAC, and
	// we are not a TLS terminator, so a valid ciphertext buys nothing.
	if clientHello.OffersPQ {
		// X25519MLKEM768 server share: ML-KEM-768 ciphertext (1088) || X25519 (32) = 1120.
		const pqKeyLen = 1120
		pqKey := make([]byte, pqKeyLen)
		rand.Read(pqKey)
		extBuf.Write([]byte{0x00, 0x33})                                 // type: key_share
		extLen := 2 + 2 + pqKeyLen                                       // group(2)+key_len(2)+key
		extBuf.Write([]byte{byte(extLen >> 8), byte(extLen)})            // ext length
		extBuf.Write([]byte{0x11, 0xec})                                 // group: X25519MLKEM768
		extBuf.Write([]byte{byte(pqKeyLen >> 8), byte(pqKeyLen & 0xff)}) // key length: 1120
		extBuf.Write(pqKey)
	} else {
		x25519Key := generateX25519Key()
		extBuf.Write([]byte{0x00, 0x33}) // type
		extBuf.Write([]byte{0x00, 0x24}) // length: 36 bytes
		extBuf.Write([]byte{0x00, 0x1d}) // curve: x25519
		extBuf.Write([]byte{0x00, 0x20}) // key length: 32
		extBuf.Write(x25519Key)
	}

	// Extension: ALPN (if client offered any)
	// Safe to include - client only validates record headers, not ServerHello content
	if len(clientHello.ALPN) > 0 {
		// Select first protocol (typically "h2" or "http/1.1")
		selectedProto := clientHello.ALPN[0]
		protoBytes := []byte(selectedProto)

		// ALPN extension format:
		// type(2) + ext_len(2) + list_len(2) + proto_len(1) + proto
		extBuf.Write([]byte{0x00, 0x10}) // type: ALPN
		listLen := 1 + len(protoBytes)
		extLen := 2 + listLen
		extBuf.WriteByte(byte(extLen >> 8))
		extBuf.WriteByte(byte(extLen))
		extBuf.WriteByte(byte(listLen >> 8))
		extBuf.WriteByte(byte(listLen))
		extBuf.WriteByte(byte(len(protoBytes)))
		extBuf.Write(protoBytes)
	}

	// Write extensions length + data
	extensions := extBuf.Bytes()
	buf.WriteByte(byte(len(extensions) >> 8))
	buf.WriteByte(byte(len(extensions)))
	buf.Write(extensions)

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
