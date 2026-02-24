package faketls

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"sync"
)

// Conn wraps a connection with TLS record framing.
type Conn struct {
	net.Conn
	// Buffered reader to reduce syscalls - 64KB buffer
	bufReader *bufio.Reader
	// Buffered writer to reduce syscalls - 64KB buffer
	bufWriter *bufio.Writer
	// Read buffer - stores leftover data from previous record
	readBuf    []byte
	readBufPos int
	readBufLen int
	readMu     sync.Mutex
	writeMu    sync.Mutex
}

// NewConn creates a new FakeTLS connection wrapper.
func NewConn(conn net.Conn) *Conn {
	return &Conn{
		Conn:      conn,
		bufReader: bufio.NewReaderSize(conn, 64*1024),
		bufWriter: bufio.NewWriterSize(conn, 64*1024),
		readBuf:   make([]byte, MaxRecordPayload),
	}
}

// Read reads and unwraps TLS application data records.
// Optimized to read directly into output buffer without intermediate copies.
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Return buffered data first
	if c.readBufLen > c.readBufPos {
		n := copy(p, c.readBuf[c.readBufPos:c.readBufLen])
		c.readBufPos += n
		if c.readBufPos == c.readBufLen {
			c.readBufPos = 0
			c.readBufLen = 0
		}
		return n, nil
	}

	totalRead := 0

	// Read records until buffer is full or no more data available
	for totalRead < len(p) {
		// After first record, only continue if more data is ready
		if totalRead > 0 && c.bufReader.Buffered() < RecordHeaderSize {
			break
		}

		// Read record header directly
		recordType, payloadLen, err := c.readRecordHeader()
		if err != nil {
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, err
		}

		switch recordType {
		case RecordTypeApplicationData, RecordTypeHandshake:
			remaining := len(p) - totalRead

			if payloadLen <= remaining {
				// Read directly into output buffer - no intermediate copy
				if _, err := io.ReadFull(c.bufReader, p[totalRead:totalRead+payloadLen]); err != nil {
					if totalRead > 0 {
						return totalRead, nil
					}
					return 0, fmt.Errorf("read payload: %w", err)
				}
				totalRead += payloadLen
			} else {
				// Read what fits into output, rest into overflow buffer
				if remaining > 0 {
					if _, err := io.ReadFull(c.bufReader, p[totalRead:totalRead+remaining]); err != nil {
						if totalRead > 0 {
							return totalRead, nil
						}
						return 0, fmt.Errorf("read payload: %w", err)
					}
					totalRead += remaining
				}
				excess := payloadLen - remaining
				if _, err := io.ReadFull(c.bufReader, c.readBuf[:excess]); err != nil {
					return totalRead, fmt.Errorf("read excess: %w", err)
				}
				c.readBufPos = 0
				c.readBufLen = excess
				return totalRead, nil
			}

		case RecordTypeChangeCipherSpec:
			// Skip CCS records - discard payload
			if _, err := io.CopyN(io.Discard, c.bufReader, int64(payloadLen)); err != nil {
				if totalRead > 0 {
					return totalRead, nil
				}
				return 0, err
			}
			continue

		default:
			// Skip unknown record types
			if _, err := io.CopyN(io.Discard, c.bufReader, int64(payloadLen)); err != nil {
				if totalRead > 0 {
					return totalRead, nil
				}
				return 0, err
			}
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, fmt.Errorf("%w: got 0x%02x", ErrInvalidRecordType, recordType)
		}
	}

	return totalRead, nil
}

// readRecordHeader reads just the TLS record header (5 bytes).
// Uses stack allocation instead of pool - benchmark shows 60x faster.
func (c *Conn) readRecordHeader() (recordType byte, payloadLen int, err error) {
	var header [RecordHeaderSize]byte

	if _, err := io.ReadFull(c.bufReader, header[:]); err != nil {
		return 0, 0, fmt.Errorf("read header: %w", err)
	}

	recordType = header[0]
	payloadLen = int(uint16(header[3])<<8 | uint16(header[4]))

	if payloadLen > MaxRecordPayload {
		return 0, 0, fmt.Errorf("%w: length=%d", ErrRecordTooLarge, payloadLen)
	}

	return recordType, payloadLen, nil
}

// Write writes data as TLS application data records.
func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := WriteApplicationData(c.bufWriter, p); err != nil {
		return 0, err
	}
	// Must flush to ensure data is sent immediately
	if err := c.bufWriter.Flush(); err != nil {
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
	return ReadRecord(c.bufReader)
}

// Unwrap returns the underlying connection for FD access.
func (c *Conn) Unwrap() net.Conn {
	return c.Conn
}
