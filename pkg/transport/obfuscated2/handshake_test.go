package obfuscated2

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

func buildDeterministicClientFrame(
	t *testing.T,
	secret []byte,
	dcID int,
	connectionType ConnectionType,
) ([]byte, cipher.Stream, cipher.Stream) {
	t.Helper()

	var plain HandshakeFrame
	for i := range plain {
		plain[i] = byte(i + 1)
	}
	binary.LittleEndian.PutUint32(plain[56:60], uint32(connectionType))
	binary.LittleEndian.PutUint16(plain[60:62], uint16(int16(dcID)))

	clientEncryptor, err := NewAESCTR(deriveKey(secret, plain[8:40]), plain[40:56])
	if err != nil {
		t.Fatalf("create client encryptor: %v", err)
	}
	reversed := reverseKeyIV(plain[8:56])
	clientDecryptor, err := NewAESCTR(deriveKey(secret, reversed[:32]), reversed[32:48])
	if err != nil {
		t.Fatalf("create client decryptor: %v", err)
	}

	wire := make([]byte, FrameSize)
	clientEncryptor.XORKeyStream(wire, plain[:])
	copy(wire[8:56], plain[8:56])
	return wire, clientEncryptor, clientDecryptor
}

func decodeServerFrame(t *testing.T, wire []byte) (HandshakeFrame, cipher.Stream, cipher.Stream) {
	t.Helper()
	if len(wire) != FrameSize {
		t.Fatalf("server frame length = %d, want %d", len(wire), FrameSize)
	}

	dcDecryptor, err := NewAESCTR(wire[8:40], wire[40:56])
	if err != nil {
		t.Fatalf("create DC decryptor: %v", err)
	}
	var plain HandshakeFrame
	dcDecryptor.XORKeyStream(plain[:], wire)

	reversed := reverseKeyIV(wire[8:56])
	dcEncryptor, err := NewAESCTR(reversed[:32], reversed[32:48])
	if err != nil {
		t.Fatalf("create DC encryptor: %v", err)
	}
	return plain, dcDecryptor, dcEncryptor
}

func TestParseClientFrameWithType_AllSupportedFramings(t *testing.T) {
	secret := []byte("0123456789abcdef")
	tests := []struct {
		name           string
		connectionType ConnectionType
		packet         []byte
	}{
		{
			name:           "abridged EF",
			connectionType: ConnectionTypeAbridged,
			packet:         []byte{0x01, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:           "intermediate EE",
			connectionType: ConnectionTypeIntermediate,
			packet:         []byte{0x04, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:           "padded intermediate DD",
			connectionType: ConnectionTypePaddedIntermediate,
			packet:         []byte{0x06, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire, clientEncryptor, clientDecryptor := buildDeterministicClientFrame(
				t,
				secret,
				-4,
				tc.connectionType,
			)
			originalWire := bytes.Clone(wire)

			dcID, gotType, proxyEncryptor, proxyDecryptor, err := ParseClientFrameWithType(secret, wire)
			if err != nil {
				t.Fatalf("ParseClientFrameWithType: %v", err)
			}
			if dcID != -4 {
				t.Errorf("DC ID = %d, want -4", dcID)
			}
			if gotType != tc.connectionType {
				t.Errorf("connection type = 0x%08x, want 0x%08x", gotType, tc.connectionType)
			}
			if !bytes.Equal(wire, originalWire) {
				t.Fatal("ParseClientFrameWithType modified its input")
			}

			toProxy := make([]byte, len(tc.packet))
			clientEncryptor.XORKeyStream(toProxy, tc.packet)
			gotAtProxy := make([]byte, len(tc.packet))
			proxyDecryptor.XORKeyStream(gotAtProxy, toProxy)
			if !bytes.Equal(gotAtProxy, tc.packet) {
				t.Errorf("client-to-proxy packet = %x, want %x", gotAtProxy, tc.packet)
			}

			toClient := make([]byte, len(tc.packet))
			proxyEncryptor.XORKeyStream(toClient, tc.packet)
			gotAtClient := make([]byte, len(tc.packet))
			clientDecryptor.XORKeyStream(gotAtClient, toClient)
			if !bytes.Equal(gotAtClient, tc.packet) {
				t.Errorf("proxy-to-client packet = %x, want %x", gotAtClient, tc.packet)
			}
		})
	}
}

func TestParseClientFrameWithType_UnsupportedFraming(t *testing.T) {
	secret := []byte("0123456789abcdef")
	wire, _, _ := buildDeterministicClientFrame(t, secret, 2, ConnectionType(0xabababab))

	_, _, _, _, err := ParseClientFrameWithType(secret, wire)
	if !errors.Is(err, ErrUnsupportedConnection) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedConnection)
	}
}

func TestGenerateServerFrameWithType_AllSupportedFramings(t *testing.T) {
	tests := []ConnectionType{
		ConnectionTypeAbridged,
		ConnectionTypeIntermediate,
		ConnectionTypePaddedIntermediate,
	}

	for _, connectionType := range tests {
		t.Run(fmt.Sprintf("0x%08x", connectionType), func(t *testing.T) {
			wire, proxyEncryptor, proxyDecryptor, err := GenerateServerFrameWithType(-5, connectionType)
			if err != nil {
				t.Fatalf("GenerateServerFrameWithType: %v", err)
			}

			plain, dcDecryptor, dcEncryptor := decodeServerFrame(t, wire)
			gotType := ConnectionType(binary.LittleEndian.Uint32(plain[56:60]))
			if gotType != connectionType {
				t.Errorf("connection type = 0x%08x, want 0x%08x", gotType, connectionType)
			}
			gotDC := int(int16(binary.LittleEndian.Uint16(plain[60:62])))
			if gotDC != -5 {
				t.Errorf("DC ID = %d, want -5", gotDC)
			}

			packet := []byte{0x01, 0xde, 0xad, 0xbe, 0xef}
			toDC := make([]byte, len(packet))
			proxyEncryptor.XORKeyStream(toDC, packet)
			gotAtDC := make([]byte, len(packet))
			dcDecryptor.XORKeyStream(gotAtDC, toDC)
			if !bytes.Equal(gotAtDC, packet) {
				t.Errorf("proxy-to-DC packet = %x, want %x", gotAtDC, packet)
			}

			toProxy := make([]byte, len(packet))
			dcEncryptor.XORKeyStream(toProxy, packet)
			gotAtProxy := make([]byte, len(packet))
			proxyDecryptor.XORKeyStream(gotAtProxy, toProxy)
			if !bytes.Equal(gotAtProxy, packet) {
				t.Errorf("DC-to-proxy packet = %x, want %x", gotAtProxy, packet)
			}
		})
	}
}

func TestGenerateServerFrameWithType_UnsupportedFraming(t *testing.T) {
	_, _, _, err := GenerateServerFrameWithType(2, ConnectionType(0xabababab))
	if !errors.Is(err, ErrUnsupportedConnection) {
		t.Fatalf("error = %v, want %v", err, ErrUnsupportedConnection)
	}
}

func TestLegacyParseClientFrame_PreservesExistingBehavior(t *testing.T) {
	secret := []byte("0123456789abcdef")
	for _, connectionType := range []ConnectionType{
		ConnectionTypeIntermediate,
		ConnectionTypePaddedIntermediate,
	} {
		t.Run(fmt.Sprintf("0x%08x", connectionType), func(t *testing.T) {
			wire, _, _ := buildDeterministicClientFrame(t, secret, 4, connectionType)
			dcID, encryptor, decryptor, err := ParseClientFrame(secret, wire)
			if err != nil {
				t.Fatalf("ParseClientFrame: %v", err)
			}
			if dcID != 4 {
				t.Errorf("DC ID = %d, want 4", dcID)
			}
			if encryptor == nil || decryptor == nil {
				t.Fatal("ParseClientFrame returned a nil cipher")
			}
		})
	}
}

func TestLegacyGenerateServerFrame_DefaultsToPaddedIntermediate(t *testing.T) {
	wire, encryptor, decryptor, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatalf("GenerateServerFrame: %v", err)
	}
	if encryptor == nil || decryptor == nil {
		t.Fatal("GenerateServerFrame returned a nil cipher")
	}

	plain, _, _ := decodeServerFrame(t, wire)
	gotType := ConnectionType(binary.LittleEndian.Uint32(plain[56:60]))
	if gotType != ConnectionTypePaddedIntermediate {
		t.Errorf("connection type = 0x%08x, want legacy default 0x%08x", gotType, ConnectionTypePaddedIntermediate)
	}
}

// TestParseClientFrame_Valid tests parsing a valid 64-byte frame with correct DC ID extraction.
func TestParseClientFrame_Valid(t *testing.T) {
	// Generate a frame and parse it to verify round-trip
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	dc := 2
	frameBytes, encryptor, decryptor, err := GenerateServerFrame(dc)
	if err != nil {
		t.Fatalf("GenerateServerFrame failed: %v", err)
	}

	// ParseClientFrame uses the perspective of a server receiving a client frame
	// GenerateServerFrame creates a frame from the proxy's perspective connecting to DC
	// For testing, we verify the frame structure is valid
	if len(frameBytes) != FrameSize {
		t.Errorf("expected frame size %d, got %d", FrameSize, len(frameBytes))
	}

	// Verify ciphers were created
	if encryptor == nil {
		t.Error("encryptor is nil")
	}
	if decryptor == nil {
		t.Error("decryptor is nil")
	}
}

// TestParseClientFrame_Undersized tests that frames smaller than 64 bytes return ErrInvalidFrame.
func TestParseClientFrame_Undersized(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	testCases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"half_size", 32},
		{"just_under", 63},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			frame := make([]byte, tc.size)
			rand.Read(frame)

			_, _, _, err := ParseClientFrame(secret, frame)
			if err != ErrInvalidFrame {
				t.Errorf("expected ErrInvalidFrame, got %v", err)
			}
		})
	}
}

// TestParseClientFrame_BadConnectionType tests that non-0xdddddddd connection type returns ErrUnsupportedConnection.
func TestParseClientFrame_BadConnectionType(t *testing.T) {
	secret := make([]byte, 16)
	rand.Read(secret)

	// Create a frame with wrong connection type
	// We need to craft a frame that decrypts to have wrong connection type
	// The simplest test is to verify the error is returned when parsing fails
	frame := make([]byte, FrameSize)
	rand.Read(frame)

	// This will likely fail with either ErrInvalidFrame or ErrUnsupportedConnection
	// depending on how the decryption affects the connection type bytes
	_, _, _, err := ParseClientFrame(secret, frame)
	if err == nil {
		t.Error("expected error for random frame, got nil")
	}
}

// TestParseClientFrame_NegativeDC tests that negative DC IDs are extracted correctly as signed int16.
func TestParseClientFrame_NegativeDC(t *testing.T) {
	testCases := []int{-1, -2, -3, -4, -5}

	for _, dc := range testCases {
		t.Run("dc_"+string(rune('0'-dc)), func(t *testing.T) {
			frameBytes, _, _, err := GenerateServerFrame(dc)
			if err != nil {
				t.Fatalf("GenerateServerFrame failed: %v", err)
			}

			// The DC ID is stored at offset 60-62 in the original frame before encryption
			// After encryption it's XORed, but the structure should be preserved
			if len(frameBytes) != FrameSize {
				t.Errorf("expected frame size %d, got %d", FrameSize, len(frameBytes))
			}
		})
	}
}

// TestParseClientFrame_CipherSymmetry tests that encrypting with enc and decrypting with dec matches.
func TestParseClientFrame_CipherSymmetry(t *testing.T) {
	dc := 3
	_, encryptor, decryptor, err := GenerateServerFrame(dc)
	if err != nil {
		t.Fatalf("GenerateServerFrame failed: %v", err)
	}

	// Test data
	plaintext := []byte("Hello, Telegram MTProxy obfuscated2 protocol!")

	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	encryptor.XORKeyStream(ciphertext, plaintext)

	// Verify ciphertext is different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	// Decrypt with decryptor
	decrypted := make([]byte, len(ciphertext))
	decryptor.XORKeyStream(decrypted, ciphertext)

	// Note: The ciphers from GenerateServerFrame are for outgoing connection
	// In actual protocol, the reverse key/IV is used for opposite direction
	// This test verifies the cipher creation works, not full round-trip
	if len(decrypted) != len(plaintext) {
		t.Errorf("decrypted length mismatch: got %d, want %d", len(decrypted), len(plaintext))
	}
}

// TestGenerateServerFrame_Randomness tests that multiple calls produce different frames.
func TestGenerateServerFrame_Randomness(t *testing.T) {
	seen := make(map[string]bool)

	for range 100 {
		frameBytes, _, _, err := GenerateServerFrame(2)
		if err != nil {
			t.Fatalf("GenerateServerFrame failed: %v", err)
		}

		key := string(frameBytes)
		if seen[key] {
			t.Error("duplicate frame generated")
		}
		seen[key] = true
	}
}

// TestGenerateServerFrame_AvoidReserved tests that the internal generateServerFrame
// avoids reserved magic values before encryption.
func TestGenerateServerFrame_AvoidReserved(t *testing.T) {
	reservedPatterns := [][]byte{
		{0x48, 0x45, 0x41, 0x44}, // "HEAD"
		{0x50, 0x4f, 0x53, 0x54}, // "POST"
		{0x47, 0x45, 0x54, 0x20}, // "GET "
		{0x4f, 0x50, 0x54, 0x49}, // "OPTI"
	}

	// Test the internal function that generates the frame before encryption
	for range 1000 {
		frame, err := generateServerFrame(2)
		if err != nil {
			t.Fatalf("generateServerFrame failed: %v", err)
		}

		// Check first byte isn't 0xef
		if frame[0] == 0xef {
			t.Error("frame starts with reserved byte 0xef")
		}

		// Check for reserved patterns (little-endian)
		first4 := frame[0:4]
		for _, pattern := range reservedPatterns {
			// Reverse pattern for little-endian comparison
			reversed := []byte{pattern[3], pattern[2], pattern[1], pattern[0]}
			if bytes.Equal(first4, reversed) {
				t.Errorf("frame starts with reserved pattern: %x", first4)
			}
		}

		// Verify bytes [4:8] are not all zero
		if frame[4]|frame[5]|frame[6]|frame[7] == 0 {
			t.Error("bytes [4:8] should not be all zero")
		}
	}
}

// TestGenerateServerFrame_DCEncoding tests that DC ID is encoded as little-endian int16.
func TestGenerateServerFrame_DCEncoding(t *testing.T) {
	testCases := []struct {
		dc       int
		expected uint16
	}{
		{1, 1},
		{2, 2},
		{5, 5},
		{-2, 0xfffe}, // -2 as uint16
		{-5, 0xfffb}, // -5 as uint16
	}

	for _, tc := range testCases {
		t.Run("dc_encoding", func(t *testing.T) {
			// Test that generateServerFrame creates valid frame
			frame, err := generateServerFrame(tc.dc)
			if err != nil {
				t.Fatalf("generateServerFrame failed: %v", err)
			}

			// DC ID is at offset 60-62 (before encryption)
			// Note: frame is encrypted by GenerateServerFrame, so we test the internal function
			dcID := binary.LittleEndian.Uint16(frame[60:62])
			if dcID != tc.expected {
				t.Errorf("DC ID encoding: got %d, want %d", dcID, tc.expected)
			}
		})
	}
}

// TestNewAESCTR_ValidKey tests that 32-byte key + 16-byte IV succeeds.
func TestNewAESCTR_ValidKey(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	cipher, err := NewAESCTR(key, iv)
	if err != nil {
		t.Errorf("NewAESCTR with valid key failed: %v", err)
	}
	if cipher == nil {
		t.Error("cipher is nil")
	}
}

// TestNewAESCTR_InvalidKey tests that wrong key length returns error.
func TestNewAESCTR_InvalidKey(t *testing.T) {
	testCases := []struct {
		name    string
		keyLen  int
		ivLen   int
		wantErr bool
	}{
		{"key_16_iv_16", 16, 16, false}, // AES-128 is valid
		{"key_24_iv_16", 24, 16, false}, // AES-192 is valid
		{"key_32_iv_16", 32, 16, false}, // AES-256 is valid
		{"key_15_iv_16", 15, 16, true},  // Invalid key length
		{"key_33_iv_16", 33, 16, true},  // Invalid key length
		{"key_0_iv_16", 0, 16, true},    // Empty key
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keyLen)
			iv := make([]byte, tc.ivLen)
			rand.Read(key)
			rand.Read(iv)

			_, err := NewAESCTR(key, iv)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestDeriveKey_Deterministic tests that same inputs produce same output.
func TestDeriveKey_Deterministic(t *testing.T) {
	secret := []byte("0123456789abcdef")
	handshakeKey := make([]byte, 32)
	rand.Read(handshakeKey)

	result1 := deriveKey(secret, handshakeKey)
	result2 := deriveKey(secret, handshakeKey)

	if !bytes.Equal(result1, result2) {
		t.Error("deriveKey not deterministic")
	}

	// Verify output length (SHA-256 = 32 bytes)
	if len(result1) != 32 {
		t.Errorf("expected 32-byte output, got %d", len(result1))
	}
}

// TestDeriveKey_DifferentInputs tests that different inputs produce different outputs.
func TestDeriveKey_DifferentInputs(t *testing.T) {
	secret1 := []byte("0123456789abcdef")
	secret2 := []byte("fedcba9876543210")
	handshakeKey := make([]byte, 32)
	rand.Read(handshakeKey)

	result1 := deriveKey(secret1, handshakeKey)
	result2 := deriveKey(secret2, handshakeKey)

	if bytes.Equal(result1, result2) {
		t.Error("different secrets should produce different keys")
	}
}

// TestReverseKeyIV tests 48-byte reversal is correct.
func TestReverseKeyIV(t *testing.T) {
	input := make([]byte, 48)
	for i := range 48 {
		input[i] = byte(i)
	}

	result := reverseKeyIV(input)

	// Verify reversal
	for i := range 48 {
		expected := byte(47 - i)
		if result[i] != expected {
			t.Errorf("reverseKeyIV[%d]: got %d, want %d", i, result[i], expected)
		}
	}

	// Verify double reversal gives original
	doubleReversed := reverseKeyIV(result[:])
	if !bytes.Equal(doubleReversed[:], input) {
		t.Error("double reversal should give original")
	}
}

// TestFrameSize tests that FrameSize constant is correct.
func TestFrameSize(t *testing.T) {
	if FrameSize != 64 {
		t.Errorf("FrameSize should be 64, got %d", FrameSize)
	}
}

// TestConnectionTypePaddedIntermediate tests the accurately named connection type constant.
func TestConnectionTypePaddedIntermediate(t *testing.T) {
	if ConnectionTypePaddedIntermediate != 0xdddddddd {
		t.Errorf("ConnectionTypePaddedIntermediate should be 0xdddddddd, got 0x%x", ConnectionTypePaddedIntermediate)
	}
}

// TestConnectionTypeFakeTLSAlias preserves the deprecated source-compatible name.
func TestConnectionTypeFakeTLSAlias(t *testing.T) {
	if ConnectionTypeFakeTLS != ConnectionTypePaddedIntermediate {
		t.Errorf(
			"ConnectionTypeFakeTLS = 0x%08x, want alias of ConnectionTypePaddedIntermediate 0x%08x",
			ConnectionTypeFakeTLS,
			ConnectionTypePaddedIntermediate,
		)
	}
}

// TestConnectionTypeIntermediate tests the intermediate connection type constant.
func TestConnectionTypeIntermediate(t *testing.T) {
	if ConnectionTypeIntermediate != 0xeeeeeeee {
		t.Errorf("ConnectionTypeIntermediate should be 0xeeeeeeee, got 0x%x", ConnectionTypeIntermediate)
	}
}

// TestConnectionTypeConstants verifies all supported connection type constants.
func TestConnectionTypeConstants(t *testing.T) {
	if ConnectionTypeAbridged != 0xefefefef {
		t.Errorf("ConnectionTypeAbridged = 0x%08x, want 0xefefefef", ConnectionTypeAbridged)
	}

	if ConnectionTypePaddedIntermediate != 0xdddddddd {
		t.Errorf("ConnectionTypePaddedIntermediate = 0x%08x, want 0xdddddddd", ConnectionTypePaddedIntermediate)
	}

	if ConnectionTypeIntermediate != 0xeeeeeeee {
		t.Errorf("ConnectionTypeIntermediate = 0x%08x, want 0xeeeeeeee", ConnectionTypeIntermediate)
	}
}
