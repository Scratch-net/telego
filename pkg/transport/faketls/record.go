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
	MaxRecordPayload = 16384 // TLS max record size

	// OptimalChunkSize for writes - larger chunks = fewer syscalls
	// Unlike mtg which uses random sizes (slow), we use fixed optimal size
	OptimalChunkSize = 8192
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

	// Read header (5 bytes: type + version + length)
	header := make([]byte, RecordHeaderSize)
	n, err := io.ReadFull(r, header)
	if err != nil {
		ReleaseRecord(rec)
		return nil, fmt.Errorf("read header: %w (read %d bytes)", err, n)
	}

	rec.Type = header[0]
	rec.Version = binary.BigEndian.Uint16(header[1:3])
	length := int(binary.BigEndian.Uint16(header[3:5]))

	// Debug: log what we read
	fmt.Printf("[DEBUG ReadRecord] header=%02x %02x %02x %02x %02x → type=0x%02x version=0x%04x length=%d\n",
		header[0], header[1], header[2], header[3], header[4], rec.Type, rec.Version, length)

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

// WriteRecord writes a TLS record to the writer.
func WriteRecord(w io.Writer, recordType byte, payload []byte) error {
	header := make([]byte, RecordHeaderSize)
	header[0] = recordType
	binary.BigEndian.PutUint16(header[1:3], VersionTLS12)
	binary.BigEndian.PutUint16(header[3:5], uint16(len(payload)))

	// Write header and payload together to minimize syscalls
	buf := make([]byte, RecordHeaderSize+len(payload))
	copy(buf, header)
	copy(buf[RecordHeaderSize:], payload)

	_, err := w.Write(buf)
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
		// Large enough for multiple records
		return bytes.NewBuffer(make([]byte, 0, 32*1024))
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
		chunk := OptimalChunkSize
		if chunk > len(data) {
			chunk = len(data)
		}

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
