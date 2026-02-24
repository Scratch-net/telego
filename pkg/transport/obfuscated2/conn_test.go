package obfuscated2

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
)

// TestNewConn tests connection creation.
func TestNewConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, enc, dec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	conn := NewConn(client, enc, dec)
	if conn == nil {
		t.Fatal("NewConn returned nil")
	}

	// Verify underlying connection
	if conn.Conn != client {
		t.Error("underlying connection mismatch")
	}
}

// TestConn_ReadWrite tests basic read/write operations.
func TestConn_ReadWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Generate separate ciphers for each direction to avoid races
	_, serverEnc, serverDec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}
	_, clientEnc, clientDec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	// Each connection gets its own cipher pair
	serverConn := NewConn(server, serverEnc, serverDec)
	clientConn := NewConn(client, clientEnc, clientDec)

	testData := []byte("Hello, obfuscated2!")

	done := make(chan error, 2)

	// Writer - server sends encrypted data
	go func() {
		_, err := serverConn.Write(testData)
		done <- err
	}()

	// Reader - client reads (won't decrypt correctly but tests the pipe)
	go func() {
		buf := make([]byte, len(testData))
		_, err := io.ReadFull(clientConn, buf)
		done <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Errorf("Error: %v", err)
		}
	}
}

// TestConn_LargeWrite tests writing data larger than buffer.
func TestConn_LargeWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Generate separate ciphers for each connection to avoid races
	_, serverEnc, serverDec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}
	_, clientEnc, clientDec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	serverConn := NewConn(server, serverEnc, serverDec)
	clientConn := NewConn(client, clientEnc, clientDec)

	// Large data (larger than 128KB buffer)
	testData := make([]byte, 200*1024)
	rand.Read(testData)

	done := make(chan error, 2)

	go func() {
		_, err := serverConn.Write(testData)
		done <- err
	}()

	go func() {
		buf := make([]byte, len(testData))
		_, err := io.ReadFull(clientConn, buf)
		done <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Errorf("Error: %v", err)
		}
	}
}

// TestConn_EmptyWrite tests writing empty data.
func TestConn_EmptyWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, enc, dec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	conn := NewConn(client, enc, dec)

	n, err := conn.Write([]byte{})
	if err != nil {
		t.Errorf("Write empty: %v", err)
	}
	if n != 0 {
		t.Errorf("Write empty returned %d, want 0", n)
	}

	_ = server // Keep server alive
}

// TestConn_CloseRead tests CloseRead.
func TestConn_CloseRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, enc, dec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	conn := NewConn(client, enc, dec)

	err = conn.CloseRead()
	// net.Pipe doesn't support CloseRead, so this should return nil
	if err != nil {
		t.Logf("CloseRead: %v (may not be supported)", err)
	}
}

// TestConn_CloseWrite tests CloseWrite.
func TestConn_CloseWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, enc, dec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	conn := NewConn(client, enc, dec)

	err = conn.CloseWrite()
	// net.Pipe doesn't support CloseWrite, so this should return nil
	if err != nil {
		t.Logf("CloseWrite: %v (may not be supported)", err)
	}
}

// TestConn_Unwrap tests getting underlying connection.
func TestConn_Unwrap(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, enc, dec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	conn := NewConn(client, enc, dec)

	unwrapped := conn.Unwrap()
	if unwrapped != client {
		t.Error("Unwrap should return underlying connection")
	}
}

// TestConn_ConcurrentWrites tests concurrent write safety.
func TestConn_ConcurrentWrites(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, enc, dec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	conn := NewConn(client, enc, dec)

	const numWriters = 10
	const writeSize = 100

	var wg sync.WaitGroup
	wg.Add(numWriters)

	// Start reader to consume data
	go func() {
		buf := make([]byte, numWriters*writeSize*2)
		io.ReadAtLeast(server, buf, numWriters*writeSize)
	}()

	// Concurrent writers
	for i := 0; i < numWriters; i++ {
		go func() {
			defer wg.Done()
			data := make([]byte, writeSize)
			rand.Read(data)
			conn.Write(data)
		}()
	}

	wg.Wait()
}

// TestConn_ReadFromClosed tests reading from closed connection.
func TestConn_ReadFromClosed(t *testing.T) {
	client, server := net.Pipe()

	_, enc, dec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	conn := NewConn(client, enc, dec)

	// Close both ends
	server.Close()
	client.Close()

	buf := make([]byte, 10)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("Read from closed connection should fail")
	}
}

// TestConn_WriteToClosed tests writing to closed connection.
func TestConn_WriteToClosed(t *testing.T) {
	client, server := net.Pipe()

	_, enc, dec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	conn := NewConn(client, enc, dec)

	// Close both ends
	server.Close()
	client.Close()

	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Error("Write to closed connection should fail")
	}
}

// TestConn_EncryptionVerification tests that data is actually encrypted.
func TestConn_EncryptionVerification(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, enc, dec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	conn := NewConn(client, enc, dec)

	testData := []byte("This should be encrypted")

	done := make(chan struct{})

	// Read raw data from server side
	go func() {
		buf := make([]byte, len(testData)+100)
		n, _ := server.Read(buf)
		// The data should NOT match original (it's encrypted)
		if bytes.Equal(buf[:n], testData) {
			t.Error("Data should be encrypted")
		}
		close(done)
	}()

	_, err = conn.Write(testData)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}

	<-done
}

// TestConn_SmallReads tests reading small amounts.
func TestConn_SmallReads(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Generate separate ciphers for each connection to avoid races
	_, serverEnc, serverDec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}
	_, clientEnc, clientDec, err := GenerateServerFrame(2)
	if err != nil {
		t.Fatal(err)
	}

	serverConn := NewConn(server, serverEnc, serverDec)
	clientConn := NewConn(client, clientEnc, clientDec)

	testData := []byte("ABCDEFGHIJ")

	done := make(chan error, 1)

	go func() {
		_, err := serverConn.Write(testData)
		done <- err
	}()

	// Read one byte at a time
	for i := 0; i < len(testData); i++ {
		buf := make([]byte, 1)
		_, err := clientConn.Read(buf)
		if err != nil {
			t.Errorf("Read byte %d failed: %v", i, err)
		}
	}

	if err := <-done; err != nil {
		t.Errorf("Write error: %v", err)
	}
}
