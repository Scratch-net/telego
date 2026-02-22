package middleend

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	// ME handshake frame size
	MEFrameSize = 64

	// ME connection type marker
	MEConnectionType = 0xefefefef
)

var (
	ErrMEHandshakeFailed = errors.New("ME handshake failed")
)

// MEHandshake performs the Middle-End handshake.
// The ME handshake includes the proxy's public IP in the key derivation.
func MEHandshake(conn net.Conn, proxySecret, publicIP []byte) (*MEConn, error) {
	frame := generateMEFrame(publicIP)

	// Extract key material before encryption
	encKey := deriveKey(proxySecret, frame[8:40], publicIP)
	encIV := make([]byte, 16)
	copy(encIV, frame[40:56])

	// Reverse for decryption direction
	decKey := reverseBytes(encKey)
	decIV := reverseBytes(encIV)

	// Create ciphers
	encryptor, err := newAESCTR(encKey, encIV)
	if err != nil {
		return nil, err
	}
	decryptor, err := newAESCTR(decKey, decIV)
	if err != nil {
		return nil, err
	}

	// Encrypt frame
	encryptor.XORKeyStream(frame[:], frame[:])

	// Send handshake
	if _, err := conn.Write(frame[:]); err != nil {
		return nil, err
	}

	// Reset encryptor for data
	encryptor, _ = newAESCTR(encKey, encIV)
	skip := make([]byte, MEFrameSize)
	encryptor.XORKeyStream(skip, skip)

	return newMEConn(conn, encryptor, decryptor), nil
}

// generateMEFrame creates a valid ME handshake frame.
func generateMEFrame(publicIP []byte) [MEFrameSize]byte {
	var frame [MEFrameSize]byte

	for {
		rand.Read(frame[:])

		// Check reserved first byte
		if frame[0] == 0xef {
			continue
		}

		// Check reserved magic at offset 0
		magic := binary.LittleEndian.Uint32(frame[0:4])
		if isReservedMagic(magic) {
			continue
		}

		// Ensure IV bytes [4:8] are not all zero
		if frame[4]|frame[5]|frame[6]|frame[7] == 0 {
			continue
		}

		break
	}

	// Set ME connection type
	binary.LittleEndian.PutUint32(frame[56:60], MEConnectionType)

	// Embed public IP hash in frame (helps ME route correctly)
	if len(publicIP) > 0 {
		h := sha256.Sum256(publicIP)
		copy(frame[60:64], h[:4])
	}

	return frame
}

// deriveKey derives the encryption key for ME connection.
// Unlike regular obfuscated2, this includes the proxy's public IP.
func deriveKey(secret, frameKey, publicIP []byte) []byte {
	h := sha256.New()
	h.Write(frameKey)
	h.Write(secret)
	if len(publicIP) > 0 {
		h.Write(publicIP)
	}
	return h.Sum(nil)
}

// reverseBytes returns a reversed copy of the slice.
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := range b {
		result[len(b)-1-i] = b[i]
	}
	return result
}

// isReservedMagic checks if the magic value is reserved.
func isReservedMagic(magic uint32) bool {
	reserved := []uint32{
		0x44414548, // "HEAD"
		0x54534f50, // "POST"
		0x20544547, // "GET "
		0x4954504f, // "OPTI"
		0xeeeeeeee, // FakeTLS marker
		0xefefefef, // ME marker
	}
	for _, r := range reserved {
		if magic == r {
			return true
		}
	}
	return false
}

// newAESCTR creates an AES-CTR cipher stream.
func newAESCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

// ParseMEResponse parses an ME server response.
func ParseMEResponse(r io.Reader) (uint32, []byte, error) {
	// Read length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return 0, nil, err
	}
	length := binary.LittleEndian.Uint32(lenBuf)

	if length < 4 || length > 1024*1024 {
		return 0, nil, ErrMEHandshakeFailed
	}

	// Read body
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}

	rpcType := binary.LittleEndian.Uint32(body[0:4])
	return rpcType, body[4:], nil
}
