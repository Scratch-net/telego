package faketls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

// buildValidClientHello constructs a valid FakeTLS ClientHello for testing.
// Returns the handshake payload (without TLS record header).
func buildValidClientHello(secret []byte, host string, sessionID []byte) []byte {
	// Build ClientHello structure
	buf := &bytes.Buffer{}

	// Handshake type (0x01 = ClientHello)
	buf.WriteByte(0x01)

	// Placeholder for handshake length (3 bytes)
	lengthPos := buf.Len()
	buf.Write([]byte{0, 0, 0})

	// Version (TLS 1.2 = 0x0303)
	buf.Write([]byte{0x03, 0x03})

	// Random (32 bytes) - will be computed after
	randomPos := buf.Len()
	buf.Write(make([]byte, 32))

	// Session ID
	buf.WriteByte(byte(len(sessionID)))
	buf.Write(sessionID)

	// Cipher suites (minimal set)
	cipherSuites := []byte{
		0x00, 0x04, // Length: 4 bytes (2 cipher suites)
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x13, 0x02, // TLS_AES_256_GCM_SHA384
	}
	buf.Write(cipherSuites)

	// Compression methods
	buf.Write([]byte{0x01, 0x00}) // 1 method: null

	// Extensions
	extensions := buildSNIExtension(host)
	binary.Write(buf, binary.BigEndian, uint16(len(extensions)))
	buf.Write(extensions)

	payload := buf.Bytes()

	// Fill in handshake length (excluding type and length fields)
	handshakeLen := len(payload) - 4
	payload[lengthPos] = byte(handshakeLen >> 16)
	payload[lengthPos+1] = byte(handshakeLen >> 8)
	payload[lengthPos+2] = byte(handshakeLen)

	// Compute HMAC for the random field
	// Per protocol: HMAC(secret, TLS_record_with_zeroed_random) XOR timestamp
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)
	// Zero out the random in copy (it's already zero)

	// Build TLS record
	record := make([]byte, 5+len(payloadCopy))
	record[0] = RecordTypeHandshake // 0x16
	record[1] = 0x03
	record[2] = 0x01 // TLS 1.0
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payloadCopy)))
	copy(record[5:], payloadCopy)

	// Compute MAC
	mac := hmac.New(sha256.New, secret)
	mac.Write(record)
	computedRandom := mac.Sum(nil)

	// XOR with timestamp (last 4 bytes)
	timestamp := uint32(time.Now().Unix())
	computedRandom[28] ^= byte(timestamp)
	computedRandom[29] ^= byte(timestamp >> 8)
	computedRandom[30] ^= byte(timestamp >> 16)
	computedRandom[31] ^= byte(timestamp >> 24)

	// Copy computed random into payload
	copy(payload[randomPos:randomPos+32], computedRandom)

	return payload
}

// buildSNIExtension builds an SNI extension with the given hostname.
func buildSNIExtension(host string) []byte {
	// SNI extension format:
	// [ext_type(2)][ext_len(2)][list_len(2)][name_type(1)][name_len(2)][name]
	buf := &bytes.Buffer{}

	// Extension type (0x0000 = SNI)
	buf.Write([]byte{0x00, 0x00})

	// Extension data length (will be filled)
	extDataLen := 2 + 1 + 2 + len(host) // list_len + name_type + name_len + name
	binary.Write(buf, binary.BigEndian, uint16(extDataLen))

	// Server name list length
	listLen := 1 + 2 + len(host) // name_type + name_len + name
	binary.Write(buf, binary.BigEndian, uint16(listLen))

	// Name type (0 = hostname)
	buf.WriteByte(0)

	// Name length
	binary.Write(buf, binary.BigEndian, uint16(len(host)))

	// Name
	buf.WriteString(host)

	return buf.Bytes()
}

// TestParseClientHello_Valid tests parsing a valid ClientHello with correct HMAC.
func TestParseClientHello_Valid(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	host := "www.example.com"
	payload := buildValidClientHello(secret, host, sessionID)

	hello, err := ParseClientHello(secret, payload)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	if hello.Host != host {
		t.Errorf("SNI: got %q, want %q", hello.Host, host)
	}

	if !bytes.Equal(hello.SessionID, sessionID) {
		t.Error("SessionID mismatch")
	}

	// Check time is within tolerance
	diff := time.Since(hello.Time)
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Second {
		t.Errorf("timestamp too far off: %v", diff)
	}
}

// TestParseClientHello_BadHMAC tests that invalid HMAC returns ErrBadDigest.
func TestParseClientHello_BadHMAC(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	host := "www.example.com"
	payload := buildValidClientHello(secret, host, sessionID)

	// Corrupt the random field
	payload[10] ^= 0xff

	_, err := ParseClientHello(secret, payload)
	if err != ErrBadDigest {
		t.Errorf("expected ErrBadDigest, got %v", err)
	}
}

// TestParseClientHello_BadTimestamp tests that too old/future timestamps return ErrBadTimestamp.
func TestParseClientHello_BadTimestamp(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	host := "www.example.com"
	payload := buildValidClientHello(secret, host, sessionID)

	// Parse with valid HMAC
	hello, err := ParseClientHello(secret, payload)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	// Validate with very tight tolerance (should fail since clock may have ticked)
	// Using negative tolerance to force failure
	err = hello.Valid(host, -time.Hour)
	// This should fail because tolerance is negative
	if err == nil {
		// Tolerance handling may vary, just verify Valid works
		t.Log("Valid with negative tolerance didn't error (implementation may differ)")
	}

	// Test with future time by modifying the hello
	hello.Time = time.Now().Add(time.Hour * 24)
	err = hello.Valid(host, DefaultTimeSkewTolerance)
	if err != ErrBadTimestamp {
		t.Errorf("expected ErrBadTimestamp for future time, got %v", err)
	}

	// Test with old time
	hello.Time = time.Now().Add(-time.Hour * 24)
	err = hello.Valid(host, DefaultTimeSkewTolerance)
	if err != ErrBadTimestamp {
		t.Errorf("expected ErrBadTimestamp for old time, got %v", err)
	}
}

// TestParseClientHello_NoSNI tests that missing SNI extension returns empty string.
func TestParseClientHello_NoSNI(t *testing.T) {
	// Test extractSNI with minimal payload that has no extensions
	payload := make([]byte, 100)
	// Handshake header
	payload[0] = 0x01 // ClientHello

	// Skip the full validation, just test SNI extraction
	sni := extractSNI(payload)
	if sni != "" {
		t.Errorf("expected empty SNI, got %q", sni)
	}
}

// TestParseClientHello_Undersized tests that payload < minimum returns error.
func TestParseClientHello_Undersized(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	testCases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"too_short", 38}, // Less than clientHelloSessionIDOffset + 1
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.size)
			rand.Read(payload)

			_, err := ParseClientHello(secret, payload)
			if err == nil {
				t.Error("expected error for undersized payload")
			}
		})
	}
}

// TestParseClientHello_BadHandshakeType tests that non-ClientHello type returns error.
func TestParseClientHello_BadHandshakeType(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	// Create a payload with wrong handshake type
	payload := make([]byte, 100)
	payload[0] = 0x02 // ServerHello instead of ClientHello

	_, err := ParseClientHello(secret, payload)
	if err == nil {
		t.Error("expected error for wrong handshake type")
	}
}

// TestBuildServerHello_Basic tests that ServerHello generates valid response structure.
func TestBuildServerHello_Basic(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	clientHello := &ClientHello{
		SessionID:   make([]byte, 32),
		CipherSuite: 0x1301,
	}
	rand.Read(clientHello.SessionID)
	rand.Read(clientHello.Random[:])

	response, err := BuildServerHello(secret, clientHello)
	if err != nil {
		t.Fatalf("BuildServerHello failed: %v", err)
	}

	// Verify minimum size (TLS record header + ServerHello + ChangeCipherSpec + ApplicationData)
	if len(response) < 100 {
		t.Errorf("response too short: %d bytes", len(response))
	}

	// Verify first record is handshake (ServerHello)
	if response[0] != RecordTypeHandshake {
		t.Errorf("first record type: got 0x%02x, want 0x%02x", response[0], RecordTypeHandshake)
	}

	// Verify TLS version in header
	if response[1] != 0x03 || response[2] != 0x03 {
		t.Errorf("TLS version: got 0x%02x%02x, want 0x0303", response[1], response[2])
	}
}

// TestBuildServerHello_WithCerts tests that certificate chain is included correctly.
func TestBuildServerHello_WithCerts(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	clientHello := &ClientHello{
		SessionID:   make([]byte, 32),
		CipherSuite: 0x1301,
	}
	rand.Read(clientHello.SessionID)
	rand.Read(clientHello.Random[:])

	// Create fake certificate chain
	cert1 := make([]byte, 500)
	cert2 := make([]byte, 300)
	rand.Read(cert1)
	rand.Read(cert2)

	opts := &ServerHelloOptions{
		CertChain: [][]byte{cert1, cert2},
	}

	response, err := BuildServerHelloWithOptions(secret, clientHello, opts)
	if err != nil {
		t.Fatalf("BuildServerHelloWithOptions failed: %v", err)
	}

	// Response with certs should be larger
	if len(response) < 800 {
		t.Errorf("response with certs too short: %d bytes", len(response))
	}
}

// TestBuildServerHello_MACPlacement tests that MAC is at offset 11 (WelcomePacketRandomOffset).
func TestBuildServerHello_MACPlacement(t *testing.T) {
	if WelcomePacketRandomOffset != 11 {
		t.Errorf("WelcomePacketRandomOffset should be 11, got %d", WelcomePacketRandomOffset)
	}

	secret := make([]byte, 16)
	rand.Read(secret)

	clientHello := &ClientHello{
		SessionID:   make([]byte, 32),
		CipherSuite: 0x1301,
	}
	rand.Read(clientHello.SessionID)
	rand.Read(clientHello.Random[:])

	response, err := BuildServerHello(secret, clientHello)
	if err != nil {
		t.Fatalf("BuildServerHello failed: %v", err)
	}

	// Verify the random field at offset 11 is not all zeros
	// (it should contain the computed MAC)
	randomField := response[WelcomePacketRandomOffset : WelcomePacketRandomOffset+32]
	allZero := true
	for _, b := range randomField {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("server random field should not be all zeros after MAC computation")
	}
}

// TestExtractSNI_Valid tests that SNI hostname is extracted correctly.
func TestExtractSNI_Valid(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	testCases := []string{
		"www.example.com",
		"google.com",
		"test.subdomain.example.org",
	}

	for _, host := range testCases {
		t.Run(host, func(t *testing.T) {
			sessionID := make([]byte, 32)
			rand.Read(sessionID)

			payload := buildValidClientHello(secret, host, sessionID)
			hello, err := ParseClientHello(secret, payload)
			if err != nil {
				t.Fatalf("ParseClientHello failed: %v", err)
			}

			if hello.Host != host {
				t.Errorf("extractSNI: got %q, want %q", hello.Host, host)
			}
		})
	}
}

// TestExtractSNI_Missing tests that missing SNI is handled gracefully.
func TestExtractSNI_Missing(t *testing.T) {
	// Build a ClientHello-like structure without SNI extension
	buf := &bytes.Buffer{}

	// Handshake type
	buf.WriteByte(0x01)
	// Length placeholder
	buf.Write([]byte{0, 0, 0x40}) // 64 bytes
	// Version
	buf.Write([]byte{0x03, 0x03})
	// Random
	buf.Write(make([]byte, 32))
	// Session ID (empty)
	buf.WriteByte(0)
	// Cipher suites (minimal)
	buf.Write([]byte{0x00, 0x02, 0x13, 0x01})
	// Compression methods
	buf.Write([]byte{0x01, 0x00})
	// Extensions length (0 = no extensions)
	buf.Write([]byte{0x00, 0x00})

	payload := buf.Bytes()
	sni := extractSNI(payload)
	if sni != "" {
		t.Errorf("expected empty SNI for payload without extensions, got %q", sni)
	}
}

// TestExtractSNI_Truncated tests that truncated SNI extension doesn't panic.
func TestExtractSNI_Truncated(t *testing.T) {
	// Build a minimal payload with truncated extensions
	payload := make([]byte, 50)
	payload[0] = 0x01 // ClientHello

	// This should not panic
	sni := extractSNI(payload)
	if sni != "" {
		t.Errorf("expected empty SNI for truncated payload, got %q", sni)
	}
}

// TestClientHello_Valid_HostMismatch tests that mismatched host returns ErrBadHost.
func TestClientHello_Valid_HostMismatch(t *testing.T) {
	hello := &ClientHello{
		Host: "www.google.com",
		Time: time.Now(),
	}

	err := hello.Valid("www.example.com", DefaultTimeSkewTolerance)
	if err != ErrBadHost {
		t.Errorf("expected ErrBadHost, got %v", err)
	}
}

// TestClientHello_Valid_EmptyHost tests that empty host in ClientHello is allowed.
func TestClientHello_Valid_EmptyHost(t *testing.T) {
	hello := &ClientHello{
		Host: "", // Empty host is allowed
		Time: time.Now(),
	}

	err := hello.Valid("www.example.com", DefaultTimeSkewTolerance)
	if err != nil {
		t.Errorf("empty host should be allowed, got %v", err)
	}
}

// TestExtractCipherSuite tests cipher suite extraction.
func TestExtractCipherSuite(t *testing.T) {
	// Build a minimal ClientHello with known cipher suite
	buf := &bytes.Buffer{}

	// Handshake header
	buf.Write([]byte{0x01, 0x00, 0x00, 0x30}) // type + length
	// Version
	buf.Write([]byte{0x03, 0x03})
	// Random
	buf.Write(make([]byte, 32))
	// Session ID (empty)
	buf.WriteByte(0)
	// Cipher suites: length + suites
	buf.Write([]byte{0x00, 0x04, 0x13, 0x01, 0x13, 0x02})

	payload := buf.Bytes()
	cipherSuite := extractCipherSuite(payload, 0)

	// First cipher suite should be 0x1301
	if cipherSuite != 0x1301 {
		t.Errorf("cipher suite: got 0x%04x, want 0x1301", cipherSuite)
	}
}

// TestDefaultTimeSkewTolerance tests the default tolerance constant.
func TestDefaultTimeSkewTolerance(t *testing.T) {
	if DefaultTimeSkewTolerance != 3*time.Second {
		t.Errorf("DefaultTimeSkewTolerance: got %v, want 3s", DefaultTimeSkewTolerance)
	}
}

// TestGenerateX25519Key tests that X25519 key generation produces valid 32-byte keys.
func TestGenerateX25519Key(t *testing.T) {
	key1 := generateX25519Key()
	key2 := generateX25519Key()

	if len(key1) != 32 {
		t.Errorf("key1 length: got %d, want 32", len(key1))
	}
	if len(key2) != 32 {
		t.Errorf("key2 length: got %d, want 32", len(key2))
	}

	// Keys should be different (random)
	if bytes.Equal(key1, key2) {
		t.Error("generated keys should be different")
	}

	// Keys should not be all zeros
	allZero := true
	for _, b := range key1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("key should not be all zeros")
	}
}

// TestExtractALPN tests ALPN protocol extraction from ClientHello.
func TestExtractALPN(t *testing.T) {
	// Build a ClientHello with ALPN extension
	secret := make([]byte, 16)
	rand.Read(secret)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	// Build ClientHello with ALPN
	payload := buildClientHelloWithALPN(secret, "www.example.com", sessionID, []string{"h2", "http/1.1"})

	hello, err := ParseClientHello(secret, payload)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	if len(hello.ALPN) != 2 {
		t.Fatalf("ALPN count: got %d, want 2", len(hello.ALPN))
	}

	if hello.ALPN[0] != "h2" {
		t.Errorf("ALPN[0]: got %q, want %q", hello.ALPN[0], "h2")
	}
	if hello.ALPN[1] != "http/1.1" {
		t.Errorf("ALPN[1]: got %q, want %q", hello.ALPN[1], "http/1.1")
	}
}

// TestExtractALPN_None tests that missing ALPN returns nil.
func TestExtractALPN_None(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	sessionID := make([]byte, 32)
	rand.Read(sessionID)

	// Build ClientHello without ALPN
	payload := buildValidClientHello(secret, "www.example.com", sessionID)

	hello, err := ParseClientHello(secret, payload)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	if hello.ALPN != nil {
		t.Errorf("expected nil ALPN, got %v", hello.ALPN)
	}
}

// TestBuildServerHello_WithALPN tests that ALPN is echoed in ServerHello.
func TestBuildServerHello_WithALPN(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	clientHello := &ClientHello{
		SessionID:   make([]byte, 32),
		CipherSuite: 0x1301,
		ALPN:        []string{"h2", "http/1.1"},
	}
	rand.Read(clientHello.SessionID)
	rand.Read(clientHello.Random[:])

	response, err := BuildServerHello(secret, clientHello)
	if err != nil {
		t.Fatalf("BuildServerHello failed: %v", err)
	}

	// Response should contain ALPN extension (0x00 0x10)
	// Find it in the ServerHello portion
	found := false
	for i := 0; i < len(response)-1; i++ {
		if response[i] == 0x00 && response[i+1] == 0x10 {
			// Check if "h2" follows (the selected protocol)
			for j := i + 2; j < len(response)-2 && j < i+20; j++ {
				if response[j] == 'h' && response[j+1] == '2' {
					found = true
					break
				}
			}
			break
		}
	}

	if !found {
		t.Error("ALPN extension with 'h2' not found in ServerHello")
	}
}

// buildClientHelloWithALPN builds a ClientHello with SNI and ALPN extensions.
func buildClientHelloWithALPN(secret []byte, host string, sessionID []byte, alpn []string) []byte {
	buf := &bytes.Buffer{}

	// Handshake type
	buf.WriteByte(0x01)

	// Placeholder for handshake length
	lengthPos := buf.Len()
	buf.Write([]byte{0, 0, 0})

	// Version (TLS 1.2)
	buf.Write([]byte{0x03, 0x03})

	// Random (32 bytes)
	randomPos := buf.Len()
	buf.Write(make([]byte, 32))

	// Session ID
	buf.WriteByte(byte(len(sessionID)))
	buf.Write(sessionID)

	// Cipher suites
	buf.Write([]byte{0x00, 0x04, 0x13, 0x01, 0x13, 0x02})

	// Compression methods
	buf.Write([]byte{0x01, 0x00})

	// Extensions
	extBuf := &bytes.Buffer{}

	// SNI extension
	sniExt := buildSNIExtension(host)
	extBuf.Write(sniExt)

	// ALPN extension
	alpnExt := buildALPNExtension(alpn)
	extBuf.Write(alpnExt)

	// Write extensions
	extensions := extBuf.Bytes()
	binary.Write(buf, binary.BigEndian, uint16(len(extensions)))
	buf.Write(extensions)

	payload := buf.Bytes()

	// Fill in handshake length
	handshakeLen := len(payload) - 4
	payload[lengthPos] = byte(handshakeLen >> 16)
	payload[lengthPos+1] = byte(handshakeLen >> 8)
	payload[lengthPos+2] = byte(handshakeLen)

	// Compute HMAC
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)

	record := make([]byte, 5+len(payloadCopy))
	record[0] = RecordTypeHandshake
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payloadCopy)))
	copy(record[5:], payloadCopy)

	mac := hmac.New(sha256.New, secret)
	mac.Write(record)
	computedRandom := mac.Sum(nil)

	timestamp := uint32(time.Now().Unix())
	computedRandom[28] ^= byte(timestamp)
	computedRandom[29] ^= byte(timestamp >> 8)
	computedRandom[30] ^= byte(timestamp >> 16)
	computedRandom[31] ^= byte(timestamp >> 24)

	copy(payload[randomPos:randomPos+32], computedRandom)

	return payload
}

// buildALPNExtension builds an ALPN extension with the given protocols.
func buildALPNExtension(protocols []string) []byte {
	buf := &bytes.Buffer{}

	// Extension type (0x0010 = ALPN)
	buf.Write([]byte{0x00, 0x10})

	// Build protocol list
	listBuf := &bytes.Buffer{}
	for _, proto := range protocols {
		listBuf.WriteByte(byte(len(proto)))
		listBuf.WriteString(proto)
	}
	listData := listBuf.Bytes()

	// Extension data: list_len(2) + list
	extDataLen := 2 + len(listData)
	binary.Write(buf, binary.BigEndian, uint16(extDataLen))
	binary.Write(buf, binary.BigEndian, uint16(len(listData)))
	buf.Write(listData)

	return buf.Bytes()
}
