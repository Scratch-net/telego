package faketls

import (
	"bytes"
	"io"
	"net"
	"sync"
)

// Conn wraps a connection with TLS record framing.
// Unlike mtg's random chunking, this uses optimal fixed-size chunks.
type Conn struct {
	net.Conn
	readBuf bytes.Buffer
	readMu  sync.Mutex
	writeMu sync.Mutex
}

// NewConn creates a new FakeTLS connection wrapper.
func NewConn(conn net.Conn) *Conn {
	return &Conn{Conn: conn}
}

// Read reads and unwraps TLS application data records.
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Return buffered data first
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}

	// Read next record
	for {
		rec, err := ReadRecord(c.Conn)
		if err != nil {
			return 0, err
		}
		defer ReleaseRecord(rec)

		switch rec.Type {
		case RecordTypeApplicationData:
			// Buffer payload and return what fits
			c.readBuf.Write(rec.Payload)
			return c.readBuf.Read(p)

		case RecordTypeChangeCipherSpec:
			// Skip change cipher spec records
			continue

		default:
			return 0, ErrInvalidRecordType
		}
	}
}

// Write writes data as TLS application data records.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := WriteApplicationData(c.Conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
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

// WriteTLSRecord writes a raw TLS record (for handshake).
func (c *Conn) WriteTLSRecord(recordType byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return WriteRecord(c.Conn, recordType, payload)
}

// ReadTLSRecord reads a raw TLS record (for handshake).
func (c *Conn) ReadTLSRecord() (*Record, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return ReadRecord(c.Conn)
}

// WrappedReader returns a reader that decrypts TLS records.
// Useful for pipelining with obfuscated2.
type WrappedReader struct {
	conn    *Conn
	readBuf bytes.Buffer
}

// NewWrappedReader creates a reader that unwraps TLS records.
func NewWrappedReader(conn *Conn) io.Reader {
	return &WrappedReader{conn: conn}
}

func (r *WrappedReader) Read(p []byte) (int, error) {
	if r.readBuf.Len() > 0 {
		return r.readBuf.Read(p)
	}

	rec, err := ReadRecord(r.conn.Conn)
	if err != nil {
		return 0, err
	}
	defer ReleaseRecord(rec)

	if rec.Type != RecordTypeApplicationData {
		return 0, ErrInvalidRecordType
	}

	r.readBuf.Write(rec.Payload)
	return r.readBuf.Read(p)
}
