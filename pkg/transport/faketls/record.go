// Package faketls implements TLS record framing for the FakeTLS protocol.
// This is optimized to use fixed-size chunks instead of mtg's random sizing.
package faketls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// TLS record types
const (
	RecordTypeChangeCipherSpec = 0x14
	RecordTypeHandshake        = 0x16
	RecordTypeApplicationData  = 0x17
)

// TLS versions
const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
)

// Record size limits
const (
	RecordHeaderSize = 5

	// MaxRecordPayload is the maximum TLS record payload we accept.
	// RFC 8446 §5.2 allows up to 16384 + 256 bytes for TLS 1.3 ciphertext.
	// iOS Telegram clients may send records up to this size for media uploads.
	// Using strict 16384 limit breaks iOS uploads (media/file sending fails).
	MaxRecordPayload = 16384 + 256 // 16640 bytes

	// OptimalChunkSize for writes - use standard TLS fragment size
	OptimalChunkSize = 16384
)

var (
	ErrRecordTooLarge    = errors.New("TLS record too large")
	ErrInvalidRecordType = errors.New("invalid TLS record type")
)

// Record represents a TLS record.
type Record struct {
	Type    byte
	Version uint16
	Payload []byte
}

// recordPool provides reusable record buffers.
var recordPool = sync.Pool{
	New: func() any {
		return &Record{
			Payload: make([]byte, 0, MaxRecordPayload),
		}
	},
}

// headerPool provides reusable 5-byte header buffers.
var headerPool = sync.Pool{
	New: func() any {
		buf := make([]byte, RecordHeaderSize)
		return &buf
	},
}

// AcquireRecord gets a record from the pool.
func AcquireRecord() *Record {
	r := recordPool.Get().(*Record)
	r.Payload = r.Payload[:0]
	return r
}

// ReleaseRecord returns a record to the pool.
func ReleaseRecord(r *Record) {
	if r != nil && cap(r.Payload) <= MaxRecordPayload*2 {
		recordPool.Put(r)
	}
}

// ReadRecord reads a TLS record from the reader.
func ReadRecord(r io.Reader) (*Record, error) {
	rec := AcquireRecord()

	// Read header (5 bytes: type + version + length) - use pooled buffer
	headerPtr := headerPool.Get().(*[]byte)
	header := *headerPtr
	n, err := io.ReadFull(r, header)
	if err != nil {
		headerPool.Put(headerPtr)
		ReleaseRecord(rec)
		return nil, fmt.Errorf("read header: %w (read %d bytes)", err, n)
	}

	rec.Type = header[0]
	rec.Version = binary.BigEndian.Uint16(header[1:3])
	length := int(binary.BigEndian.Uint16(header[3:5]))
	headerPool.Put(headerPtr)

	if length > MaxRecordPayload {
		ReleaseRecord(rec)
		return nil, fmt.Errorf("%w: length=%d", ErrRecordTooLarge, length)
	}

	// Read payload
	if cap(rec.Payload) < length {
		rec.Payload = make([]byte, length)
	} else {
		rec.Payload = rec.Payload[:length]
	}

	n, err = io.ReadFull(r, rec.Payload)
	if err != nil {
		ReleaseRecord(rec)
		return nil, fmt.Errorf("read payload: %w (expected %d, read %d)", err, length, n)
	}

	return rec, nil
}

// writeRecordPool provides buffers for WriteRecord to avoid allocations
var writeRecordPool = sync.Pool{
	New: func() any {
		// Most handshake records are small, but ServerHello can be ~2KB with certs
		buf := make([]byte, 4*1024)
		return &buf
	},
}

// WriteRecord writes a TLS record to the writer.
func WriteRecord(w io.Writer, recordType byte, payload []byte) error {
	totalLen := RecordHeaderSize + len(payload)

	// Get buffer from pool or allocate if payload is large
	var buf []byte
	var bufPtr *[]byte
	if totalLen <= 4*1024 {
		bufPtr = writeRecordPool.Get().(*[]byte)
		buf = (*bufPtr)[:totalLen]
	} else {
		buf = make([]byte, totalLen)
	}

	// Write header
	buf[0] = recordType
	binary.BigEndian.PutUint16(buf[1:3], VersionTLS12)
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(payload)))

	// Copy payload
	copy(buf[RecordHeaderSize:], payload)

	// Write and return buffer to pool
	_, err := w.Write(buf)
	if bufPtr != nil {
		writeRecordPool.Put(bufPtr)
	}
	return err
}

// Dump writes the record to a buffer.
func (r *Record) Dump(buf *bytes.Buffer) {
	header := [RecordHeaderSize]byte{
		r.Type,
		byte(r.Version >> 8),
		byte(r.Version),
		byte(len(r.Payload) >> 8),
		byte(len(r.Payload)),
	}
	buf.Write(header[:])
	buf.Write(r.Payload)
}

// writeBufferPool for coalescing writes.
var writeBufferPool = sync.Pool{
	New: func() any {
		// Large enough for multiple records (128KB + headers)
		return bytes.NewBuffer(make([]byte, 0, 140*1024))
	},
}

// WriteApplicationData writes data as TLS application data records.
// Unlike mtg which uses random chunk sizes, this uses optimal fixed sizes.
func WriteApplicationData(w io.Writer, data []byte) error {
	buf := writeBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer writeBufferPool.Put(buf)

	for len(data) > 0 {
		// Use optimal chunk size instead of random (mtg is slow here)
		chunk := min(OptimalChunkSize, len(data))

		// Write record header
		header := [RecordHeaderSize]byte{
			RecordTypeApplicationData,
			0x03, // TLS 1.2 major
			0x03, // TLS 1.2 minor
			byte(chunk >> 8),
			byte(chunk),
		}
		buf.Write(header[:])
		buf.Write(data[:chunk])

		data = data[chunk:]
	}

	// Single syscall for all records
	_, err := w.Write(buf.Bytes())
	return err
}

// WrapApplicationData wraps payload bytes in a TLS ApplicationData record.
// Returns the complete record including the 5-byte header.
// This is the buffer-based version for use with gnet's AsyncWrite.
func WrapApplicationData(payload []byte) []byte {
	buf := make([]byte, RecordHeaderSize+len(payload))
	buf[0] = RecordTypeApplicationData
	buf[1] = 0x03 // TLS 1.2 major
	buf[2] = 0x03 // TLS 1.2 minor
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(payload)))
	copy(buf[RecordHeaderSize:], payload)
	return buf
}

// WrapApplicationDataChunked wraps payload bytes into multiple TLS ApplicationData records
// if the payload exceeds MaxRecordPayload (16KB). Returns the complete records.
func WrapApplicationDataChunked(payload []byte) []byte {
	if len(payload) <= MaxRecordPayload {
		return WrapApplicationData(payload)
	}

	// Calculate total size needed
	numRecords := (len(payload) + MaxRecordPayload - 1) / MaxRecordPayload
	totalSize := len(payload) + numRecords*RecordHeaderSize

	// Allocate once and write directly - avoids intermediate allocations
	buf := make([]byte, totalSize)
	WrapApplicationDataTo(buf, payload)
	return buf
}

// WrapApplicationDataTo wraps payload into TLS ApplicationData records,
// writing to the provided destination buffer. Returns the number of bytes written.
// dst must be large enough: len(payload) + ((len(payload) + MaxRecordPayload - 1) / MaxRecordPayload) * RecordHeaderSize
func WrapApplicationDataTo(dst, payload []byte) int {
	written := 0
	for len(payload) > 0 {
		chunk := min(MaxRecordPayload, len(payload))

		// Write TLS record header
		dst[written] = RecordTypeApplicationData
		dst[written+1] = 0x03 // TLS 1.2 major
		dst[written+2] = 0x03 // TLS 1.2 minor
		binary.BigEndian.PutUint16(dst[written+3:written+5], uint16(chunk))
		written += RecordHeaderSize

		// Copy payload chunk
		copy(dst[written:], payload[:chunk])
		written += chunk

		payload = payload[chunk:]
	}
	return written
}
