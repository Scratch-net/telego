// Package obfuscated2 implements the Telegram obfuscated2 protocol.
// This is an optimized implementation that avoids per-operation allocations.
package obfuscated2

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"net"
	"sync"
)

// Conn wraps a connection with obfuscated2 encryption.
// Unlike mtg, this uses a fixed buffer to avoid allocations on Write.
type Conn struct {
	net.Conn
	encryptor cipher.Stream
	decryptor cipher.Stream

	// Write buffer to avoid allocations
	writeBuf []byte
	writeMu  sync.Mutex
}

// bufferPool provides reusable write buffers.
var bufferPool = sync.Pool{
	New: func() any {
		// 64KB buffer covers most MTProto messages
		buf := make([]byte, 64*1024)
		return &buf
	},
}

// NewConn creates an obfuscated2 connection with the given ciphers.
func NewConn(conn net.Conn, encryptor, decryptor cipher.Stream) *Conn {
	return &Conn{
		Conn:      conn,
		encryptor: encryptor,
		decryptor: decryptor,
		writeBuf:  make([]byte, 64*1024),
	}
}

// Read decrypts data from the underlying connection.
func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		// Decrypt in-place
		c.decryptor.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// Write encrypts and writes data to the underlying connection.
// This uses a pre-allocated buffer to avoid allocations in the hot path.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := len(p)
	written := 0

	for len(p) > 0 {
		// Use internal buffer or pool buffer for large writes
		chunk := len(p)
		var buf []byte

		if chunk <= len(c.writeBuf) {
			buf = c.writeBuf[:chunk]
		} else {
			// Large write, get from pool
			poolBuf := bufferPool.Get().(*[]byte)
			defer bufferPool.Put(poolBuf)
			if chunk > len(*poolBuf) {
				chunk = len(*poolBuf)
			}
			buf = (*poolBuf)[:chunk]
		}

		// Copy and encrypt
		copy(buf, p[:chunk])
		c.encryptor.XORKeyStream(buf, buf)

		// Write encrypted data
		n, err := c.Conn.Write(buf)
		if err != nil {
			return written + n, err
		}
		if n != chunk {
			return written + n, io.ErrShortWrite
		}

		p = p[chunk:]
		written += n
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
