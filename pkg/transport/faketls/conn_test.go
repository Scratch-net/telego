package faketls

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestNewConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client)
	if conn == nil {
		t.Fatal("NewConn returned nil")
	}
	if conn.Conn != client {
		t.Error("Conn should wrap original connection")
	}
	if conn.bufReader == nil {
		t.Error("bufReader should be initialized")
	}
	if conn.bufWriter == nil {
		t.Error("bufWriter should be initialized")
	}
}

func TestConn_WriteRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientConn := NewConn(client)
	serverConn := NewConn(server)

	// Write some data from client
	testData := []byte("Hello, FakeTLS!")
	done := make(chan error, 1)

	go func() {
		_, err := clientConn.Write(testData)
		done <- err
	}()

	// Read on server side
	buf := make([]byte, 1024)
	n, err := serverConn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if !bytes.Equal(buf[:n], testData) {
		t.Errorf("Read data mismatch: got %q, want %q", buf[:n], testData)
	}
}

func TestConn_WriteReadLargeData(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	clientConn := NewConn(client)
	serverConn := NewConn(server)

	// Write large data that spans multiple records
	testData := bytes.Repeat([]byte("X"), MaxRecordPayload+1000)
	done := make(chan error, 1)

	go func() {
		_, err := clientConn.Write(testData)
		done <- err
	}()

	// Read all data on server side
	buf := make([]byte, len(testData)+1024)
	total := 0
	for total < len(testData) {
		n, err := serverConn.Read(buf[total:])
		if err != nil && err != io.EOF {
			t.Fatalf("Read failed: %v", err)
		}
		if n == 0 {
			break
		}
		total += n
	}

	if err := <-done; err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if total != len(testData) {
		t.Errorf("Read length mismatch: got %d, want %d", total, len(testData))
	}

	if !bytes.Equal(buf[:total], testData) {
		t.Error("Large data mismatch")
	}
}

func TestConn_CloseRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client)

	// net.Pipe doesn't support half-close, so CloseRead should return nil
	err := conn.CloseRead()
	if err != nil {
		t.Errorf("CloseRead should return nil for connections without half-close support: %v", err)
	}
}

func TestConn_CloseWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client)

	// net.Pipe doesn't support half-close, so CloseWrite should return nil
	err := conn.CloseWrite()
	if err != nil {
		t.Errorf("CloseWrite should return nil for connections without half-close support: %v", err)
	}
}

func TestConn_Unwrap(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client)
	unwrapped := conn.Unwrap()

	if unwrapped != client {
		t.Error("Unwrap should return the original connection")
	}
}

func TestConn_WriteTLSRecord(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client)

	done := make(chan error, 1)
	go func() {
		err := conn.WriteTLSRecord(RecordTypeApplicationData, []byte("test data"))
		done <- err
	}()

	// Read the raw record on server side
	buf := make([]byte, 1024)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("WriteTLSRecord failed: %v", err)
	}

	// Verify it's a valid TLS record
	if n < RecordHeaderSize {
		t.Fatalf("Response too short: %d bytes", n)
	}

	// Check record type
	if buf[0] != RecordTypeApplicationData {
		t.Errorf("Wrong record type: got 0x%02x, want 0x%02x", buf[0], RecordTypeApplicationData)
	}
}

func TestConn_ReadTLSRecord(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client)

	// Build a TLS record to send
	testPayload := []byte("test record")
	record := buildTestRecord(RecordTypeApplicationData, testPayload)

	done := make(chan error, 1)
	go func() {
		_, err := server.Write(record)
		done <- err
	}()

	// Read the record
	rec, err := conn.ReadTLSRecord()
	if err != nil {
		t.Fatalf("ReadTLSRecord failed: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if rec.Type != RecordTypeApplicationData {
		t.Errorf("Wrong record type: got 0x%02x, want 0x%02x", rec.Type, RecordTypeApplicationData)
	}

	if !bytes.Equal(rec.Payload, testPayload) {
		t.Errorf("Payload mismatch: got %q, want %q", rec.Payload, testPayload)
	}

	ReleaseRecord(rec)
}

// buildTestRecord creates a raw TLS record for testing
func buildTestRecord(recordType byte, payload []byte) []byte {
	length := len(payload)
	record := make([]byte, RecordHeaderSize+length)
	record[0] = recordType
	record[1] = 0x03 // TLS 1.2 major
	record[2] = 0x03 // TLS 1.2 minor
	record[3] = byte(length >> 8)
	record[4] = byte(length)
	copy(record[RecordHeaderSize:], payload)
	return record
}

func TestConn_Read_ChangeCipherSpec(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client)

	// Send a CCS record followed by application data
	ccsRecord := buildTestRecord(RecordTypeChangeCipherSpec, []byte{0x01})
	appRecord := buildTestRecord(RecordTypeApplicationData, []byte("after ccs"))
	allRecords := append(ccsRecord, appRecord...)

	go func() {
		server.Write(allRecords)
	}()

	// Read should skip the CCS record and return the app data
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if !bytes.Equal(buf[:n], []byte("after ccs")) {
		t.Errorf("Read mismatch: got %q, want %q", buf[:n], "after ccs")
	}
}

func TestConn_ReadRecordTooLarge(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client)

	// Build a record with invalid length (too large)
	record := []byte{
		RecordTypeApplicationData,
		0x03, 0x03, // TLS 1.2
		0xFF, 0xFF, // Length = 65535 (too large)
	}

	go func() {
		server.Write(record)
	}()

	// Read should fail with record too large
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected error for oversized record")
	}
}

// BenchmarkConn_Write benchmarks writing through the FakeTLS wrapper
func BenchmarkConn_Write(b *testing.B) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client)

	// Consume data on server side
	go func() {
		buf := make([]byte, 64*1024)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()

	data := make([]byte, 1024)
	b.ResetTimer()

	for b.Loop() {
		conn.Write(data)
	}
}

// BenchmarkConn_Read benchmarks reading through the FakeTLS wrapper
func BenchmarkConn_Read(b *testing.B) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	conn := NewConn(client)

	// Send data on server side
	testData := make([]byte, 1024)
	go func() {
		serverConn := NewConn(server)
		for {
			if _, err := serverConn.Write(testData); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 4096)
	b.ResetTimer()

	for b.Loop() {
		conn.Read(buf)
	}
}
