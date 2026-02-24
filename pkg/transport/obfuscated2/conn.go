// Package obfuscated2 implements the Telegram obfuscated2 protocol.
package obfuscated2

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
	"sync"
)

// Conn wraps a connection with obfuscated2 encryption.
type Conn struct {
	net.Conn
	encryptor cipher.Stream
	decryptor cipher.Stream
	writeMu   sync.Mutex
}

// bufferPool provides reusable write buffers - 128KB for better throughput.
var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 128*1024)
		return &buf
	},
}

// NewConn creates an obfuscated2 connection with the given ciphers.
func NewConn(conn net.Conn, encryptor, decryptor cipher.Stream) *Conn {
	return &Conn{
		Conn:      conn,
		encryptor: encryptor,
		decryptor: decryptor,
	}
}

// Read decrypts data from the underlying connection.
// Note: underlying conn (faketls.Conn) already has buffering, so we read directly.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.decryptor.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// Write encrypts and writes data to the underlying connection.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Get buffer from pool, encrypt into it, write
	poolBuf := bufferPool.Get().(*[]byte)
	buf := *poolBuf
	defer bufferPool.Put(poolBuf)

	// Handle data larger than buffer in chunks
	total := 0
	for len(p) > 0 {
		n := min(len(p), len(buf))

		// Copy and encrypt
		copy(buf[:n], p[:n])
		c.encryptor.XORKeyStream(buf[:n], buf[:n])

		written, err := c.Conn.Write(buf[:n])
		total += written
		if err != nil {
			return total, err
		}

		p = p[n:]
	}

	return total, nil
}

// CloseRead closes the read side of the connection.
func (c *Conn) CloseRead() error {
	if closer, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return nil
}

// CloseWrite closes the write side of the connection.
func (c *Conn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

// NewAESCTR creates an AES-CTR cipher stream from key and iv.
func NewAESCTR(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

// Unwrap returns the underlying connection for FD access.
func (c *Conn) Unwrap() net.Conn {
	return c.Conn
}
