package transport

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// TestLoopbackThroughput measures actual throughput through the full stack
// using loopback, eliminating network latency as a factor.
func TestLoopbackThroughput(t *testing.T) {
	// Create loopback connection pair
	server, client := net.Pipe()

	// Setup faketls on both ends
	ftlsServer := faketls.NewConn(server)
	ftlsClient := faketls.NewConn(client)

	// Setup obfuscated2 on both ends (simulated - same keys for testing)
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	encServer, _ := obfuscated2.NewAESCTR(key, iv)
	decServer, _ := obfuscated2.NewAESCTR(key, iv)
	encClient, _ := obfuscated2.NewAESCTR(key, iv)
	decClient, _ := obfuscated2.NewAESCTR(key, iv)

	o2Server := obfuscated2.NewConn(ftlsServer, encServer, decServer)
	o2Client := obfuscated2.NewConn(ftlsClient, encClient, decClient)

	// Test data
	dataSize := 10 * 1024 * 1024 // 10 MB
	data := make([]byte, 128*1024)
	rand.Read(data)

	var wg sync.WaitGroup
	var serverBytes int64
	var clientWriteTime time.Duration

	// Server: read all data
	wg.Go(func() {
		buf := make([]byte, 128*1024)
		for serverBytes < int64(dataSize) {
			n, err := o2Server.Read(buf)
			if err != nil {
				if err != io.EOF {
					t.Logf("server read error: %v", err)
				}
				return
			}
			serverBytes += int64(n)
		}
	})

	// Client: write data
	start := time.Now()
	written := 0
	for written < dataSize {
		n := len(data)
		if written+n > dataSize {
			n = dataSize - written
		}
		_, err := o2Client.Write(data[:n])
		if err != nil {
			t.Fatalf("client write error: %v", err)
		}
		written += n
	}
	o2Client.Close()
	clientWriteTime = time.Since(start)

	wg.Wait()

	throughput := float64(serverBytes) / clientWriteTime.Seconds() / 1024 / 1024
	t.Logf("Loopback throughput: %.2f MB/s (%d bytes in %v)", throughput, serverBytes, clientWriteTime)
}

// TestRawLoopbackThroughput measures raw net.Pipe throughput
func TestRawLoopbackThroughput(t *testing.T) {
	server, client := net.Pipe()

	dataSize := 10 * 1024 * 1024
	data := make([]byte, 128*1024)
	rand.Read(data)

	var wg sync.WaitGroup
	var serverBytes int64

	wg.Go(func() {
		buf := make([]byte, 128*1024)
		for serverBytes < int64(dataSize) {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			serverBytes += int64(n)
		}
	})

	start := time.Now()
	written := 0
	for written < dataSize {
		n := len(data)
		if written+n > dataSize {
			n = dataSize - written
		}
		_, err := client.Write(data[:n])
		if err != nil {
			t.Fatalf("write error: %v", err)
		}
		written += n
	}
	client.Close()
	elapsed := time.Since(start)

	wg.Wait()

	throughput := float64(serverBytes) / elapsed.Seconds() / 1024 / 1024
	t.Logf("Raw loopback throughput: %.2f MB/s", throughput)
}

// TestTCPLoopbackThroughput measures TCP loopback throughput
func TestTCPLoopbackThroughput(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	dataSize := 100 * 1024 * 1024 // 100 MB
	data := make([]byte, 128*1024)
	rand.Read(data)

	var wg sync.WaitGroup
	var serverBytes int64

	wg.Go(func() {
		conn, _ := ln.Accept()
		defer conn.Close()
		buf := make([]byte, 128*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			serverBytes += int64(n)
		}
	})

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	written := 0
	for written < dataSize {
		n := len(data)
		if written+n > dataSize {
			n = dataSize - written
		}
		_, err := conn.Write(data[:n])
		if err != nil {
			t.Fatalf("write error: %v", err)
		}
		written += n
	}
	conn.Close()
	elapsed := time.Since(start)

	wg.Wait()

	throughput := float64(serverBytes) / elapsed.Seconds() / 1024 / 1024
	t.Logf("TCP loopback throughput: %.2f MB/s", throughput)
}

// TestO2OnlyThroughput measures obfuscated2 overhead without faketls
func TestO2OnlyThroughput(t *testing.T) {
	server, client := net.Pipe()

	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	encServer, _ := obfuscated2.NewAESCTR(key, iv)
	decServer, _ := obfuscated2.NewAESCTR(key, iv)
	encClient, _ := obfuscated2.NewAESCTR(key, iv)
	decClient, _ := obfuscated2.NewAESCTR(key, iv)

	o2Server := obfuscated2.NewConn(server, encServer, decServer)
	o2Client := obfuscated2.NewConn(client, encClient, decClient)

	dataSize := 10 * 1024 * 1024
	data := make([]byte, 128*1024)
	rand.Read(data)

	var wg sync.WaitGroup
	var serverBytes int64

	wg.Go(func() {
		buf := make([]byte, 128*1024)
		for serverBytes < int64(dataSize) {
			n, err := o2Server.Read(buf)
			if err != nil {
				return
			}
			serverBytes += int64(n)
		}
	})

	start := time.Now()
	written := 0
	for written < dataSize {
		n := len(data)
		if written+n > dataSize {
			n = dataSize - written
		}
		_, err := o2Client.Write(data[:n])
		if err != nil {
			t.Fatalf("write error: %v", err)
		}
		written += n
	}
	o2Client.Close()
	elapsed := time.Since(start)

	wg.Wait()

	throughput := float64(serverBytes) / elapsed.Seconds() / 1024 / 1024
	t.Logf("O2-only throughput: %.2f MB/s", throughput)
}

// TestFakeTLSOnlyThroughput measures faketls overhead without o2
func TestFakeTLSOnlyThroughput(t *testing.T) {
	server, client := net.Pipe()

	ftlsServer := faketls.NewConn(server)
	ftlsClient := faketls.NewConn(client)

	dataSize := 10 * 1024 * 1024
	data := make([]byte, 128*1024)
	rand.Read(data)

	var wg sync.WaitGroup
	var serverBytes int64

	wg.Go(func() {
		buf := make([]byte, 128*1024)
		for serverBytes < int64(dataSize) {
			n, err := ftlsServer.Read(buf)
			if err != nil {
				if err != io.EOF {
					t.Logf("server read error: %v", err)
				}
				return
			}
			serverBytes += int64(n)
		}
	})

	start := time.Now()
	written := 0
	for written < dataSize {
		n := len(data)
		if written+n > dataSize {
			n = dataSize - written
		}
		_, err := ftlsClient.Write(data[:n])
		if err != nil {
			t.Fatalf("write error: %v", err)
		}
		written += n
	}
	ftlsClient.Close()
	elapsed := time.Since(start)

	wg.Wait()

	throughput := float64(serverBytes) / elapsed.Seconds() / 1024 / 1024
	t.Logf("FakeTLS-only throughput: %.2f MB/s", throughput)
}

func TestPrintSummary(t *testing.T) {
	fmt.Println("\n=== Run individual tests above for throughput measurements ===")
	fmt.Println("go test -v -run TestRawLoopbackThroughput ./pkg/transport/")
	fmt.Println("go test -v -run TestTCPLoopbackThroughput ./pkg/transport/")
	fmt.Println("go test -v -run TestO2OnlyThroughput ./pkg/transport/")
	fmt.Println("go test -v -run TestFakeTLSOnlyThroughput ./pkg/transport/")
	fmt.Println("go test -v -run TestLoopbackThroughput ./pkg/transport/")
}
