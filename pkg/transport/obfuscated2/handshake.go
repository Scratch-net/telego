package obfuscated2

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
)

const (
	// FrameSize is the size of the obfuscated2 handshake frame.
	FrameSize = 64

	// ConnectionTypeAbridged is the abridged MTProto transport marker.
	ConnectionTypeAbridged = 0xefefefef

	// ConnectionTypePaddedIntermediate is the padded-intermediate MTProto
	// transport marker.
	ConnectionTypePaddedIntermediate = 0xdddddddd

	// ConnectionTypeFakeTLS is retained for source compatibility.
	//
	// Deprecated: use ConnectionTypePaddedIntermediate. FakeTLS is an outer
	// transport and is independent of the inner MTProto packet framing.
	ConnectionTypeFakeTLS = ConnectionTypePaddedIntermediate

	// Connection type for Intermediate mode (0xeeeeeeee) - without random padding
	ConnectionTypeIntermediate = 0xeeeeeeee
)

// ConnectionType identifies the MTProto packet framing carried inside an
// obfuscated2 connection.
type ConnectionType uint32

var (
	ErrInvalidFrame          = errors.New("invalid handshake frame")
	ErrUnsupportedConnection = errors.New("unsupported connection type")
)

// Reserved magic values that must be avoided in handshake frames.
var reservedMagic = []uint32{
	0x44414548, // "HEAD"
	0x54534f50, // "POST"
	0x20544547, // "GET "
	0x4954504f, // "OPTI"
	0xeeeeeeee, // Reserved
}

// HandshakeFrame represents the 64-byte obfuscated2 handshake.
//
// Layout:
//
//	[0:8]   - Random noise
//	[8:40]  - AES-256 key (32 bytes)
//	[40:56] - AES-256 IV (16 bytes)
//	[56:60] - MTProto packet framing connection type
//	[60:62] - DC ID (little-endian int16)
//	[62:64] - Random noise
type HandshakeFrame [FrameSize]byte

// generateServerFrame creates a padded-intermediate handshake frame for
// connecting to Telegram. It preserves the legacy default used by
// GenerateServerFrame.
func generateServerFrame(dc int) (HandshakeFrame, error) {
	return generateServerFrameWithType(dc, ConnectionTypePaddedIntermediate)
}

// generateServerFrameWithType creates a valid handshake frame for connecting
// to Telegram using the requested MTProto packet framing.
func generateServerFrameWithType(dc int, connectionType ConnectionType) (HandshakeFrame, error) {
	var frame HandshakeFrame
	if !connectionType.valid() {
		return frame, ErrUnsupportedConnection
	}

	for {
		if _, err := rand.Read(frame[:]); err != nil {
			return frame, err
		}

		// Check reserved first byte
		if frame[0] == 0xef {
			continue
		}

		// Check reserved magic at offset 0
		magic := binary.LittleEndian.Uint32(frame[0:4])
		reserved := slices.Contains(reservedMagic, magic)
		if reserved {
			continue
		}

		// Ensure bytes [4:8] are not all zero
		if frame[4]|frame[5]|frame[6]|frame[7] == 0 {
			continue
		}

		break
	}

	// Set connection type
	binary.LittleEndian.PutUint32(frame[56:60], uint32(connectionType))

	// Set DC ID (little-endian int16) - can be negative for media DCs
	binary.LittleEndian.PutUint16(frame[60:62], uint16(int16(dc)))

	return frame, nil
}

func (c ConnectionType) valid() bool {
	return c == ConnectionTypeAbridged ||
		c == ConnectionTypePaddedIntermediate ||
		c == ConnectionTypeIntermediate
}

// deriveKey derives an AES key from the secret and handshake data.
func deriveKey(secret, handshakeKey []byte) []byte {
	h := sha256.New()
	h.Write(handshakeKey)
	h.Write(secret)
	return h.Sum(nil)
}

// reverseKeyIV reverses a 48-byte key+IV block into a stack-allocated array.
func reverseKeyIV(b []byte) [48]byte {
	var result [48]byte
	for i := range 48 {
		result[47-i] = b[i]
	}
	return result
}

// ParseClientFrame parses a client's handshake frame from a byte slice.
// This is the buffer-based version for use with gnet.
// The secret is the 16-byte proxy secret.
func ParseClientFrame(secret, frame []byte) (int, cipher.Stream, cipher.Stream, error) {
	dcID, _, encryptor, decryptor, err := ParseClientFrameWithType(secret, frame)
	return dcID, encryptor, decryptor, err
}

// ParseClientFrameWithType parses a client's handshake frame and returns the
// MTProto packet framing selected by the client. Callers that relay decrypted
// bytes without translating packet framing must use the same connection type
// for their upstream Telegram connection.
func ParseClientFrameWithType(secret, frame []byte) (int, ConnectionType, cipher.Stream, cipher.Stream, error) {
	if len(frame) < FrameSize {
		return 0, 0, nil, nil, ErrInvalidFrame
	}

	// Work with a stack-allocated copy to avoid modifying the original
	var frameCopy [FrameSize]byte
	copy(frameCopy[:], frame[:FrameSize])

	// CRITICAL: Save original key+IV BEFORE decryption (mtg creates both ciphers before decrypting)
	// Derive decryption key using SHA256(key + secret) and IV directly
	decKey := deriveKey(secret, frameCopy[8:40])
	var decIV [16]byte
	copy(decIV[:], frameCopy[40:56])

	// Derive encryption key BEFORE decryption using original frame bytes
	// Per mtg: reverse the entire key+IV block (48 bytes), then extract key and IV
	invertedKeyIV := reverseKeyIV(frameCopy[8:56]) // Use ORIGINAL bytes before decryption!
	encKeyData := invertedKeyIV[:32]
	encIVData := invertedKeyIV[32:48]
	encKey := deriveKey(secret, encKeyData)

	// Create both ciphers BEFORE decryption (matching mtg behavior)
	decryptor, err := NewAESCTR(decKey, decIV[:])
	if err != nil {
		return 0, 0, nil, nil, err
	}
	encryptor, err := NewAESCTR(encKey, encIVData)
	if err != nil {
		return 0, 0, nil, nil, err
	}

	// NOW decrypt the frame in place
	decryptor.XORKeyStream(frameCopy[:], frameCopy[:])

	// Validate the abridged, intermediate, or padded-intermediate connection type.
	connectionType := ConnectionType(binary.LittleEndian.Uint32(frameCopy[56:60]))
	if !connectionType.valid() {
		return 0, 0, nil, nil, ErrUnsupportedConnection
	}

	// Extract DC ID (little-endian int16)
	dcID := int(int16(binary.LittleEndian.Uint16(frameCopy[60:62])))

	return dcID, connectionType, encryptor, decryptor, nil
}

// GenerateServerFrame creates a valid handshake frame for connecting to Telegram.
// Returns the frame bytes and the encryption/decryption ciphers.
// This is the buffer-based version of ServerHandshake for use with gnet.
func GenerateServerFrame(dc int) ([]byte, cipher.Stream, cipher.Stream, error) {
	return GenerateServerFrameWithType(dc, ConnectionTypePaddedIntermediate)
}

// GenerateServerFrameWithType creates a valid handshake frame for connecting
// to Telegram using the requested MTProto packet framing. It returns the frame
// bytes and the encryption/decryption ciphers for the connection.
func GenerateServerFrameWithType(dc int, connectionType ConnectionType) ([]byte, cipher.Stream, cipher.Stream, error) {
	frame, err := generateServerFrameWithType(dc, connectionType)
	if err != nil {
		return nil, nil, nil, err
	}

	// Save original key and IV before encryption
	origKey := make([]byte, 32)
	origIV := make([]byte, 16)
	copy(origKey, frame[8:40])
	copy(origIV, frame[40:56])

	// Create encryptor from original key+IV
	encryptor, err := NewAESCTR(origKey, origIV)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create decryptor from INVERTED 48-byte key+IV block
	invertedKeyIV := reverseKeyIV(frame[8:56])
	decKey := invertedKeyIV[:32]
	decIV := invertedKeyIV[32:48]
	decryptor, err := NewAESCTR(decKey, decIV)
	if err != nil {
		return nil, nil, nil, err
	}

	// Encrypt the ENTIRE frame
	encryptor.XORKeyStream(frame[:], frame[:])

	// Restore original (unencrypted) key+IV into the encrypted frame
	// Telegram needs these to derive the same ciphers
	copy(frame[8:40], origKey)
	copy(frame[40:56], origIV)

	return frame[:], encryptor, decryptor, nil
}
