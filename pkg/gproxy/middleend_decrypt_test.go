package gproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"testing"
)

func TestMiddleEndDecryptChunkContinuityAndAccounting(t *testing.T) {
	want := bytes.Repeat([]byte("continuous client cipher"), 8000)
	wire := make([]byte, len(want))
	directTestCipher(t, 7).XORKeyStream(wire, want)
	client := &middleEndClient{decryptor: directTestCipher(t, 7)}
	var got []byte
	for len(wire) > 0 {
		n := min(len(wire), middleEndDecryptChunk)
		client.decryptIntoPending(wire[:n])
		if client.pendingPlainRetained != n || cap(client.pendingPlain) != n {
			t.Fatalf("plaintext capacity accounting = %d/%d, want %d", client.pendingPlainRetained, cap(client.pendingPlain), n)
		}
		got = append(got, client.pendingPlain...)
		clear(client.pendingPlain)
		client.pendingPlain = nil
		wire = wire[n:]
	}
	if !bytes.Equal(got, want) {
		t.Fatal("cipher continuity changed between decrypted chunks")
	}
}

func BenchmarkMiddleEndDecryptChunk(b *testing.B) {
	for _, size := range []int{16 << 10, middleEndDecryptChunk} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			block, err := aes.NewCipher(make([]byte, 32))
			if err != nil {
				b.Fatal(err)
			}
			client := &middleEndClient{decryptor: cipher.NewCTR(block, make([]byte, aes.BlockSize))}
			wire := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				client.decryptIntoPending(wire)
				clear(client.pendingPlain)
				client.pendingPlain = nil
			}
		})
	}
}
