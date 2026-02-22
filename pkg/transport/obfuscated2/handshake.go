package obfuscated2

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	// FrameSize is the size of the obfuscated2 handshake frame.
	FrameSize = 64

	// Connection type for FakeTLS (0xdddddddd)
	ConnectionTypeFakeTLS = 0xdddddddd
)

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
	0xdddddddd, // Our marker (but not at offset 0)
}

// HandshakeFrame represents the 64-byte obfuscated2 handshake.
//
// Layout:
//
//	[0:8]   - Random noise
//	[8:40]  - AES-256 key (32 bytes)
//	[40:56] - AES-256 IV (16 bytes)
//	[56:60] - Connection type (0xdddddddd for FakeTLS)
//	[60:62] - DC ID (little-endian int16)
//	[62:64] - Random noise
type HandshakeFrame [FrameSize]byte

// ClientHandshake parses a client's handshake frame and returns the DC ID and ciphers.
// The secret is the 16-byte proxy secret.
func ClientHandshake(secret []byte, reader io.Reader) (int, cipher.Stream, cipher.Stream, error) {
	var frame HandshakeFrame
	if _, err := io.ReadFull(reader, frame[:]); err != nil {
		return 0, nil, nil, err
	}

	// Derive decryption key using SHA256(secret + frame[8:40])
	// and decryption IV from frame[40:56]
	decKey := deriveKey(secret, frame[8:40])
	decIV := make([]byte, 16)
	copy(decIV, frame[40:56])

	decryptor, err := NewAESCTR(decKey, decIV)
	if err != nil {
		return 0, nil, nil, err
	}

	// Decrypt the frame in place
	decryptor.XORKeyStream(frame[:], frame[:])

	// Validate connection type
	connType := binary.LittleEndian.Uint32(frame[56:60])
	if connType != ConnectionTypeFakeTLS {
		return 0, nil, nil, ErrUnsupportedConnection
	}

	// Extract DC ID (little-endian int16)
	dcID := int(int16(binary.LittleEndian.Uint16(frame[60:62])))

	// Derive encryption key for responses
	// Reverse key and IV for the other direction
	encKey := reverseBytes(decKey)
	encIV := reverseBytes(decIV)

	encryptor, err := NewAESCTR(encKey, encIV)
	if err != nil {
		return 0, nil, nil, err
	}

	// Reset decryptor since we already decrypted the handshake
	decryptor, _ = NewAESCTR(decKey, decIV)
	// Skip past the frame we already decrypted
	skip := make([]byte, FrameSize)
	decryptor.XORKeyStream(skip, skip)

	return dcID, encryptor, decryptor, nil
}

// ServerHandshake generates a handshake frame to send to Telegram servers.
// Returns the connection with encryption applied.
func ServerHandshake(conn net.Conn, dc int) (*Conn, error) {
	frame := generateServerFrame(dc)

	// Extract key and IV before encryption
	encKey := make([]byte, 32)
	encIV := make([]byte, 16)
	copy(encKey, frame[8:40])
	copy(encIV, frame[40:56])

	// Reverse for decryption (server's perspective)
	decKey := reverseBytes(encKey)
	decIV := reverseBytes(encIV)

	encryptor, err := NewAESCTR(encKey, encIV)
	if err != nil {
		return nil, err
	}
	decryptor, err := NewAESCTR(decKey, decIV)
	if err != nil {
		return nil, err
	}

	// Encrypt the frame
	encryptor.XORKeyStream(frame[:], frame[:])

	// Send handshake
	if _, err := conn.Write(frame[:]); err != nil {
		return nil, err
	}

	// Reset encryptor for actual data
	encryptor, _ = NewAESCTR(encKey, encIV)
	skip := make([]byte, FrameSize)
	encryptor.XORKeyStream(skip, skip)

	return NewConn(conn, encryptor, decryptor), nil
}

// generateServerFrame creates a valid handshake frame for connecting to Telegram.
func generateServerFrame(dc int) HandshakeFrame {
	var frame HandshakeFrame

	for {
		rand.Read(frame[:])

		// Check reserved first byte
		if frame[0] == 0xef {
			continue
		}

		// Check reserved magic at offset 0
		magic := binary.LittleEndian.Uint32(frame[0:4])
		reserved := false
		for _, r := range reservedMagic {
			if magic == r {
				reserved = true
				break
			}
		}
		if reserved {
			continue
		}

		// Ensure IV bytes [4:8] are not all zero
		if frame[4]|frame[5]|frame[6]|frame[7] == 0 {
			continue
		}

		break
	}

	// Set connection type
	binary.LittleEndian.PutUint32(frame[56:60], ConnectionTypeFakeTLS)

	// Set DC ID
	binary.LittleEndian.PutUint16(frame[60:62], uint16(int16(dc)))

	return frame
}

// deriveKey derives an AES key from the secret and handshake data.
func deriveKey(secret, handshakeKey []byte) []byte {
	h := sha256.New()
	h.Write(handshakeKey)
	h.Write(secret)
	return h.Sum(nil)
}

// reverseBytes returns a reversed copy of the byte slice.
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := range b {
		result[len(b)-1-i] = b[i]
	}
	return result
}
