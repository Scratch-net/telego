package transport

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
)

// BenchmarkRawTCP measures raw TCP loopback throughput
func BenchmarkRawTCP(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	// Server goroutine - just discard
	go func() {
		conn, _ := ln.Accept()
		io.Copy(io.Discard, conn)
		conn.Close()
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	data := make([]byte, 16*1024) // 16KB chunks like TLS records
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		conn.Write(data)
	}
}

// BenchmarkAESCTREncrypt measures AES-CTR encryption overhead
func BenchmarkAESCTREncrypt(b *testing.B) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	block, _ := aes.NewCipher(key)
	stream := cipher.NewCTR(block, iv)

	data := make([]byte, 16*1024)
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		stream.XORKeyStream(data, data)
	}
}

// BenchmarkAESCTREncryptDecrypt measures double encryption (proxy scenario)
func BenchmarkAESCTREncryptDecrypt(b *testing.B) {
	key1 := make([]byte, 32)
	iv1 := make([]byte, 16)
	key2 := make([]byte, 32)
	iv2 := make([]byte, 16)
	rand.Read(key1)
	rand.Read(iv1)
	rand.Read(key2)
	rand.Read(iv2)

	block1, _ := aes.NewCipher(key1)
	block2, _ := aes.NewCipher(key2)
	decrypt := cipher.NewCTR(block1, iv1)
	encrypt := cipher.NewCTR(block2, iv2)

	data := make([]byte, 16*1024)
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		decrypt.XORKeyStream(data, data)
		encrypt.XORKeyStream(data, data)
	}
}

// BenchmarkMemoryCopy measures memory copy overhead
func BenchmarkMemoryCopy(b *testing.B) {
	src := make([]byte, 16*1024)
	dst := make([]byte, 16*1024)
	rand.Read(src)

	b.SetBytes(int64(len(src)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy(dst, src)
	}
}

// BenchmarkTLSFrameParse simulates TLS record parsing
func BenchmarkTLSFrameParse(b *testing.B) {
	// Simulate a TLS record: 5 byte header + 16KB payload
	record := make([]byte, 5+16*1024)
	record[0] = 0x17 // Application data
	record[1] = 0x03
	record[2] = 0x03
	record[3] = 0x40 // 16384 = 0x4000
	record[4] = 0x00
	rand.Read(record[5:])

	reader := bytes.NewReader(record)

	b.SetBytes(int64(len(record) - 5))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader.Reset(record)

		// Read header
		header := make([]byte, 5)
		io.ReadFull(reader, header)

		// Parse length
		length := int(header[3])<<8 | int(header[4])

		// Read payload
		payload := make([]byte, length)
		io.ReadFull(reader, payload)
	}
}

// BenchmarkTLSFrameParsePooled simulates TLS record parsing with pooling
func BenchmarkTLSFrameParsePooled(b *testing.B) {
	record := make([]byte, 5+16*1024)
	record[0] = 0x17
	record[1] = 0x03
	record[2] = 0x03
	record[3] = 0x40
	record[4] = 0x00
	rand.Read(record[5:])

	reader := bytes.NewReader(record)

	headerPool := sync.Pool{New: func() any { b := make([]byte, 5); return &b }}
	payloadPool := sync.Pool{New: func() any { b := make([]byte, 16*1024); return &b }}

	b.SetBytes(int64(len(record) - 5))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader.Reset(record)

		// Read header from pool
		headerPtr := headerPool.Get().(*[]byte)
		header := *headerPtr
		io.ReadFull(reader, header)

		length := int(header[3])<<8 | int(header[4])
		headerPool.Put(headerPtr)

		// Read payload from pool
		payloadPtr := payloadPool.Get().(*[]byte)
		payload := (*payloadPtr)[:length]
		io.ReadFull(reader, payload)
		payloadPool.Put(payloadPtr)
	}
}

// BenchmarkFullPipeline simulates the full proxy pipeline
func BenchmarkFullPipeline(b *testing.B) {
	// Setup: TLS record with encrypted payload
	record := make([]byte, 5+16*1024)
	record[0] = 0x17
	record[1] = 0x03
	record[2] = 0x03
	record[3] = 0x40
	record[4] = 0x00
	rand.Read(record[5:])

	// Crypto setup
	key1 := make([]byte, 32)
	iv1 := make([]byte, 16)
	key2 := make([]byte, 32)
	iv2 := make([]byte, 16)
	rand.Read(key1)
	rand.Read(iv1)
	rand.Read(key2)
	rand.Read(iv2)

	block1, _ := aes.NewCipher(key1)
	block2, _ := aes.NewCipher(key2)
	clientDecrypt := cipher.NewCTR(block1, iv1)
	telegramEncrypt := cipher.NewCTR(block2, iv2)

	reader := bytes.NewReader(record)
	output := make([]byte, 16*1024)

	b.SetBytes(int64(len(record) - 5))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		reader.Reset(record)

		// 1. Read TLS header
		header := make([]byte, 5)
		io.ReadFull(reader, header)
		length := int(header[3])<<8 | int(header[4])

		// 2. Read payload directly into output
		io.ReadFull(reader, output[:length])

		// 3. Decrypt (client -> proxy)
		clientDecrypt.XORKeyStream(output[:length], output[:length])

		// 4. Encrypt (proxy -> telegram)
		telegramEncrypt.XORKeyStream(output[:length], output[:length])

		// 5. "Write" to telegram (simulated)
		_ = output[:length]
	}
}

// BenchmarkSyncPoolOverhead measures sync.Pool get/put overhead
func BenchmarkSyncPoolOverhead(b *testing.B) {
	pool := sync.Pool{New: func() any { b := make([]byte, 5); return &b }}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ptr := pool.Get().(*[]byte)
		pool.Put(ptr)
	}
}

// BenchmarkStackAlloc5Bytes measures stack allocation for 5 bytes
func BenchmarkStackAlloc5Bytes(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var header [5]byte
		_ = header
	}
}
