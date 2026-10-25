package middleend

import (
	"bytes"
	"crypto/aes"
	"slices"
	"testing"
)

func TestCBCEncryptOwnedPreservesCipherStreamAndOutputOwnership(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	iv := bytes.Repeat([]byte{0x17}, aes.BlockSize)
	copying, err := NewCBCEncrypter(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := NewCBCEncrypter(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	publicEncoder, err := NewFrameEncoder(0, MaxMEFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	ownedEncoder, err := NewFrameEncoder(0, MaxMEFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	var previous, previousCopy []byte
	for _, size := range []int{4, 8, 12, 16, 65536, 65540, 65544, 65548, MaxClientPacketSize} {
		payload := bytes.Repeat([]byte{byte(size / 4)}, size)
		publicFrame, err := publicEncoder.Encode(payload)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := ownedEncoder.encodeForCBC(payload)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(frame, publicFrame) || cap(publicFrame) != len(publicFrame) {
			t.Fatal("private allocation changed frame bytes or public capacity")
		}
		wantCapacity := (len(frame) + aes.BlockSize - 1) &^ (aes.BlockSize - 1)
		if cap(frame) != wantCapacity {
			t.Fatalf("frame capacity %d, want %d", cap(frame), wantCapacity)
		}
		plainCopy := slices.Clone(publicFrame)
		want, err := copying.Encrypt(publicFrame)
		if err != nil {
			t.Fatal(err)
		}
		storage := &frame[0]
		got, err := owned.encryptOwned(frame)
		if err != nil {
			t.Fatal(err)
		}
		if &got[0] != storage || !bytes.Equal(got, want) {
			t.Fatalf("size %d: in-place ciphertext differs or uses another allocation", size)
		}
		if !bytes.Equal(publicFrame, plainCopy) || !bytes.Equal(payload, plainCopy[8:len(plainCopy)-4]) {
			t.Fatal("encoding mutated caller-owned plaintext")
		}
		if !bytes.Equal(previous, previousCopy) {
			t.Fatal("later encryption changed previously returned ciphertext")
		}
		previous, previousCopy = got, slices.Clone(got)
	}
}
