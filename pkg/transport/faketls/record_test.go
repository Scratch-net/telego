package faketls

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

// TestReadRecord_Valid tests parsing a complete valid TLS record.
func TestReadRecord_Valid(t *testing.T) {
	payload := []byte("Hello, TLS record!")

	// Build a valid TLS record
	buf := &bytes.Buffer{}
	buf.WriteByte(RecordTypeApplicationData) // Type
	buf.Write([]byte{0x03, 0x03})            // Version (TLS 1.2)
	binary.Write(buf, binary.BigEndian, uint16(len(payload)))
	buf.Write(payload)

	record, err := ReadRecord(buf)
	if err != nil {
		t.Fatalf("ReadRecord failed: %v", err)
	}
	defer ReleaseRecord(record)

	if record.Type != RecordTypeApplicationData {
		t.Errorf("Type: got 0x%02x, want 0x%02x", record.Type, RecordTypeApplicationData)
	}

	if record.Version != VersionTLS12 {
		t.Errorf("Version: got 0x%04x, want 0x%04x", record.Version, VersionTLS12)
	}

	if !bytes.Equal(record.Payload, payload) {
		t.Errorf("Payload mismatch")
	}
}

// TestReadRecord_TooLarge tests that payload > 16384 returns ErrRecordTooLarge.
func TestReadRecord_TooLarge(t *testing.T) {
	// Build a record with oversized length in header
	buf := &bytes.Buffer{}
	buf.WriteByte(RecordTypeApplicationData)
	buf.Write([]byte{0x03, 0x03}) // Version

	// Length > MaxRecordPayload
	binary.Write(buf, binary.BigEndian, uint16(MaxRecordPayload+1))

	// We don't need the actual payload; ReadRecord should fail on length check
	buf.Write(make([]byte, 100)) // Just some data

	_, err := ReadRecord(buf)
	if err == nil {
		t.Error("expected ErrRecordTooLarge, got nil")
	}
	// The error should contain or be ErrRecordTooLarge
	if !bytes.Contains([]byte(err.Error()), []byte("too large")) {
		t.Errorf("expected error about record too large, got: %v", err)
	}
}

// TestReadRecord_Partial tests that incomplete read is handled.
func TestReadRecord_Partial(t *testing.T) {
	// Only header, no payload
	buf := &bytes.Buffer{}
	buf.WriteByte(RecordTypeApplicationData)
	buf.Write([]byte{0x03, 0x03})
	binary.Write(buf, binary.BigEndian, uint16(100)) // Expect 100 bytes

	// No payload written - should fail
	_, err := ReadRecord(buf)
	if err == nil {
		t.Error("expected error for incomplete record")
	}
}

// TestReadRecord_HeaderOnly tests reading with only partial header.
func TestReadRecord_HeaderOnly(t *testing.T) {
	testCases := []struct {
		name   string
		header []byte
	}{
		{"empty", []byte{}},
		{"one_byte", []byte{0x17}},
		{"three_bytes", []byte{0x17, 0x03, 0x03}},
		{"four_bytes", []byte{0x17, 0x03, 0x03, 0x00}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf := bytes.NewReader(tc.header)
			_, err := ReadRecord(buf)
			if err == nil {
				t.Error("expected error for incomplete header")
			}
		})
	}
}

// TestWriteRecord_Basic tests correct header format.
func TestWriteRecord_Basic(t *testing.T) {
	payload := []byte("Test payload")

	buf := &bytes.Buffer{}
	err := WriteRecord(buf, RecordTypeApplicationData, payload)
	if err != nil {
		t.Fatalf("WriteRecord failed: %v", err)
	}

	written := buf.Bytes()

	// Verify header
	if written[0] != RecordTypeApplicationData {
		t.Errorf("Type: got 0x%02x, want 0x%02x", written[0], RecordTypeApplicationData)
	}

	if written[1] != 0x03 || written[2] != 0x03 {
		t.Errorf("Version: got 0x%02x%02x, want 0x0303", written[1], written[2])
	}

	length := binary.BigEndian.Uint16(written[3:5])
	if int(length) != len(payload) {
		t.Errorf("Length: got %d, want %d", length, len(payload))
	}

	// Verify payload
	if !bytes.Equal(written[5:], payload) {
		t.Error("Payload mismatch")
	}
}

// TestWrapApplicationData_Single tests single record wrapping.
func TestWrapApplicationData_Single(t *testing.T) {
	payload := []byte("Small payload")

	wrapped := WrapApplicationData(payload)

	// Should be header + payload
	expectedLen := RecordHeaderSize + len(payload)
	if len(wrapped) != expectedLen {
		t.Errorf("Length: got %d, want %d", len(wrapped), expectedLen)
	}

	// Verify header
	if wrapped[0] != RecordTypeApplicationData {
		t.Errorf("Type: got 0x%02x, want 0x%02x", wrapped[0], RecordTypeApplicationData)
	}

	// Verify payload
	if !bytes.Equal(wrapped[RecordHeaderSize:], payload) {
		t.Error("Payload mismatch")
	}
}

// TestWrapApplicationDataChunked_Boundary tests chunking at exactly 16384 bytes.
func TestWrapApplicationDataChunked_Boundary(t *testing.T) {
	testCases := []struct {
		name           string
		payloadSize    int
		expectedChunks int
	}{
		{"under_limit", MaxRecordPayload - 1, 1},
		{"at_limit", MaxRecordPayload, 1},
		{"over_limit", MaxRecordPayload + 1, 2},
		{"double_limit", MaxRecordPayload * 2, 2},
		{"double_plus", MaxRecordPayload*2 + 1, 3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := make([]byte, tc.payloadSize)
			rand.Read(payload)

			wrapped := WrapApplicationDataChunked(payload)

			// Count records by parsing
			reader := bytes.NewReader(wrapped)
			chunks := 0
			totalPayload := 0

			for {
				header := make([]byte, RecordHeaderSize)
				_, err := io.ReadFull(reader, header)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Failed to read header: %v", err)
				}

				length := int(binary.BigEndian.Uint16(header[3:5]))
				totalPayload += length

				// Skip payload
				_, err = io.CopyN(io.Discard, reader, int64(length))
				if err != nil {
					t.Fatalf("Failed to skip payload: %v", err)
				}

				chunks++
			}

			if chunks != tc.expectedChunks {
				t.Errorf("Chunks: got %d, want %d", chunks, tc.expectedChunks)
			}

			if totalPayload != tc.payloadSize {
				t.Errorf("Total payload: got %d, want %d", totalPayload, tc.payloadSize)
			}
		})
	}
}

// TestWrapApplicationDataChunked_Large tests chunking with 100KB payload.
func TestWrapApplicationDataChunked_Large(t *testing.T) {
	payloadSize := 100 * 1024 // 100KB
	payload := make([]byte, payloadSize)
	rand.Read(payload)

	wrapped := WrapApplicationDataChunked(payload)

	// Expected chunks: ceil(100KB / 16KB) = 7
	expectedChunks := (payloadSize + MaxRecordPayload - 1) / MaxRecordPayload
	expectedSize := payloadSize + expectedChunks*RecordHeaderSize

	if len(wrapped) != expectedSize {
		t.Errorf("Wrapped size: got %d, want %d", len(wrapped), expectedSize)
	}

	// Verify we can reconstruct the original
	reader := bytes.NewReader(wrapped)
	var reconstructed []byte

	for {
		header := make([]byte, RecordHeaderSize)
		_, err := io.ReadFull(reader, header)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read header: %v", err)
		}

		length := int(binary.BigEndian.Uint16(header[3:5]))
		chunk := make([]byte, length)
		_, err = io.ReadFull(reader, chunk)
		if err != nil {
			t.Fatalf("Failed to read chunk: %v", err)
		}

		reconstructed = append(reconstructed, chunk...)
	}

	if !bytes.Equal(reconstructed, payload) {
		t.Error("Reconstructed payload doesn't match original")
	}
}

// TestWrapApplicationDataTo tests writing to provided buffer.
func TestWrapApplicationDataTo(t *testing.T) {
	payload := []byte("Test payload for WrapApplicationDataTo")

	// Calculate required buffer size
	numRecords := (len(payload) + MaxRecordPayload - 1) / MaxRecordPayload
	requiredSize := len(payload) + numRecords*RecordHeaderSize

	dst := make([]byte, requiredSize+100) // Extra space
	written := WrapApplicationDataTo(dst, payload)

	if written != len(payload)+RecordHeaderSize {
		t.Errorf("Written: got %d, want %d", written, len(payload)+RecordHeaderSize)
	}

	// Verify content matches WrapApplicationData
	expected := WrapApplicationData(payload)
	if !bytes.Equal(dst[:written], expected) {
		t.Error("WrapApplicationDataTo doesn't match WrapApplicationData")
	}
}

// TestWrapApplicationDataTo_Chunked tests writing chunked data to buffer.
func TestWrapApplicationDataTo_Chunked(t *testing.T) {
	payloadSize := MaxRecordPayload + 100
	payload := make([]byte, payloadSize)
	rand.Read(payload)

	numRecords := (payloadSize + MaxRecordPayload - 1) / MaxRecordPayload
	requiredSize := payloadSize + numRecords*RecordHeaderSize

	dst := make([]byte, requiredSize)
	written := WrapApplicationDataTo(dst, payload)

	if written != requiredSize {
		t.Errorf("Written: got %d, want %d", written, requiredSize)
	}

	// Verify against WrapApplicationDataChunked
	expected := WrapApplicationDataChunked(payload)
	if !bytes.Equal(dst[:written], expected) {
		t.Error("WrapApplicationDataTo doesn't match WrapApplicationDataChunked")
	}
}

// TestRecordPool tests record pool acquire/release.
func TestRecordPool(t *testing.T) {
	// Acquire multiple records
	records := make([]*Record, 10)
	for i := range records {
		records[i] = AcquireRecord()
		if records[i] == nil {
			t.Error("AcquireRecord returned nil")
		}
	}

	// Release them
	for _, r := range records {
		ReleaseRecord(r)
	}

	// Should not panic
	ReleaseRecord(nil)
}

// TestRecord_Dump tests record serialization.
func TestRecord_Dump(t *testing.T) {
	record := &Record{
		Type:    RecordTypeHandshake,
		Version: VersionTLS12,
		Payload: []byte("Handshake data"),
	}

	buf := &bytes.Buffer{}
	record.Dump(buf)

	dumped := buf.Bytes()

	// Verify header
	if dumped[0] != RecordTypeHandshake {
		t.Errorf("Type: got 0x%02x, want 0x%02x", dumped[0], RecordTypeHandshake)
	}

	version := binary.BigEndian.Uint16(dumped[1:3])
	if version != VersionTLS12 {
		t.Errorf("Version: got 0x%04x, want 0x%04x", version, VersionTLS12)
	}

	length := binary.BigEndian.Uint16(dumped[3:5])
	if int(length) != len(record.Payload) {
		t.Errorf("Length: got %d, want %d", length, len(record.Payload))
	}

	if !bytes.Equal(dumped[5:], record.Payload) {
		t.Error("Payload mismatch")
	}
}

// TestWriteApplicationData tests batched record writing.
func TestWriteApplicationData(t *testing.T) {
	payload := make([]byte, 50000) // ~3 records
	rand.Read(payload)

	buf := &bytes.Buffer{}
	err := WriteApplicationData(buf, payload)
	if err != nil {
		t.Fatalf("WriteApplicationData failed: %v", err)
	}

	// Parse and verify
	reader := bytes.NewReader(buf.Bytes())
	var reconstructed []byte

	for {
		header := make([]byte, RecordHeaderSize)
		_, err := io.ReadFull(reader, header)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Failed to read header: %v", err)
		}

		if header[0] != RecordTypeApplicationData {
			t.Errorf("Record type: got 0x%02x, want 0x%02x", header[0], RecordTypeApplicationData)
		}

		length := int(binary.BigEndian.Uint16(header[3:5]))
		if length > OptimalChunkSize {
			t.Errorf("Chunk size %d exceeds optimal %d", length, OptimalChunkSize)
		}

		chunk := make([]byte, length)
		_, err = io.ReadFull(reader, chunk)
		if err != nil {
			t.Fatalf("Failed to read chunk: %v", err)
		}

		reconstructed = append(reconstructed, chunk...)
	}

	if !bytes.Equal(reconstructed, payload) {
		t.Error("Reconstructed payload doesn't match original")
	}
}

// TestConstants tests record constants.
func TestConstants(t *testing.T) {
	if RecordHeaderSize != 5 {
		t.Errorf("RecordHeaderSize: got %d, want 5", RecordHeaderSize)
	}

	if MaxRecordPayload != 16640 {
		t.Errorf("MaxRecordPayload: got %d, want 16640", MaxRecordPayload)
	}

	if OptimalChunkSize != 16384 {
		t.Errorf("OptimalChunkSize: got %d, want 16384", OptimalChunkSize)
	}

	if RecordTypeHandshake != 0x16 {
		t.Errorf("RecordTypeHandshake: got 0x%02x, want 0x16", RecordTypeHandshake)
	}

	if RecordTypeApplicationData != 0x17 {
		t.Errorf("RecordTypeApplicationData: got 0x%02x, want 0x17", RecordTypeApplicationData)
	}

	if RecordTypeChangeCipherSpec != 0x14 {
		t.Errorf("RecordTypeChangeCipherSpec: got 0x%02x, want 0x14", RecordTypeChangeCipherSpec)
	}

	if VersionTLS10 != 0x0301 {
		t.Errorf("VersionTLS10: got 0x%04x, want 0x0301", VersionTLS10)
	}

	if VersionTLS11 != 0x0302 {
		t.Errorf("VersionTLS11: got 0x%04x, want 0x0302", VersionTLS11)
	}

	if VersionTLS12 != 0x0303 {
		t.Errorf("VersionTLS12: got 0x%04x, want 0x0303", VersionTLS12)
	}
}

// TestEmptyPayload tests handling of empty payloads.
func TestEmptyPayload(t *testing.T) {
	payload := []byte{}

	wrapped := WrapApplicationData(payload)
	if len(wrapped) != RecordHeaderSize {
		t.Errorf("Empty payload wrapped size: got %d, want %d", len(wrapped), RecordHeaderSize)
	}

	wrapped = WrapApplicationDataChunked(payload)
	if len(wrapped) != RecordHeaderSize {
		t.Errorf("Empty payload chunked size: got %d, want %d", len(wrapped), RecordHeaderSize)
	}
}
