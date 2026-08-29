package middleend

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestCBCContinuousGoldenAndFragmentedDecode(t *testing.T) {
	params := goldenKDFParams(
		netip.MustParseAddrPort("192.0.2.10:8888"),
		netip.MustParseAddrPort("198.51.100.20:54321"),
	)
	keys, err := DeriveKeys(params, RoleClient)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	handshakeFrame := mustDecodeHex(t, "2c000000fffffffff5ee827600080000146433c631d4d204000033660a0200c0b822000000000000f153944e")
	pingFrame := mustDecodeHex(t, "1800000000000000dfa230570807060504030201c2c3f3f8")
	wantHandshake := mustDecodeHex(t, "a48c97721c378d1028c87045c72e3c008be69fac6547ea9ecbb331d812d729563c2b48297862a53faef5b33bc0f54d82")
	wantPing := mustDecodeHex(t, "a45e1b73e39be3579ab1872254e7b64d095c6dcfd7e36a918eaacd11ed4ba33f")

	encrypter, err := NewCBCEncrypter(keys.WriteKey[:], keys.WriteIV[:])
	if err != nil {
		t.Fatalf("NewCBCEncrypter: %v", err)
	}
	encryptedHandshake, err := encrypter.Encrypt(handshakeFrame)
	if err != nil {
		t.Fatalf("encrypt handshake: %v", err)
	}
	encryptedPing, err := encrypter.Encrypt(pingFrame)
	if err != nil {
		t.Fatalf("encrypt ping: %v", err)
	}
	if !bytes.Equal(encryptedHandshake, wantHandshake) {
		t.Fatalf("encrypted handshake = %x, want %x", encryptedHandshake, wantHandshake)
	}
	if !bytes.Equal(encryptedPing, wantPing) {
		t.Fatalf("encrypted continuous ping = %x, want %x", encryptedPing, wantPing)
	}

	decrypter, err := NewCBCDecrypter(keys.WriteKey[:], keys.WriteIV[:])
	if err != nil {
		t.Fatalf("NewCBCDecrypter: %v", err)
	}
	frameDecoder, err := NewFrameDecoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}

	ciphertext := append(slices.Clone(encryptedHandshake), encryptedPing...)
	var got []Frame
	for _, value := range ciphertext {
		consumed, plaintext := decrypter.Feed([]byte{value})
		if consumed != 1 {
			t.Fatalf("decrypt Feed consumed %d bytes, want 1", consumed)
		}
		frameConsumed, err := frameDecoder.Feed(plaintext)
		if err != nil {
			t.Fatalf("frame Feed: %v", err)
		}
		if frameConsumed != len(plaintext) {
			t.Fatalf("frame Feed consumed %d/%d bytes", frameConsumed, len(plaintext))
		}
		for {
			frame, ok, err := frameDecoder.Next()
			if err != nil {
				t.Fatalf("frame Next: %v", err)
			}
			if !ok {
				break
			}
			got = append(got, frame)
			if frame.Sequence == -1 {
				peer, err := ParseHandshakePacket(frame.Payload)
				if err != nil {
					t.Fatalf("ParseHandshakePacket: %v", err)
				}
				if err := frameDecoder.ApplyPeerHandshake(peer, HandshakePacket{Flags: HandshakeFlagCRC32C}); err != nil {
					t.Fatalf("ApplyPeerHandshake: %v", err)
				}
			}
		}
	}

	if err := decrypter.Finish(); err != nil {
		t.Fatalf("decrypter Finish: %v", err)
	}
	if err := frameDecoder.Finish(); err != nil {
		t.Fatalf("frame decoder Finish: %v", err)
	}
	if len(got) != 2 || got[0].Sequence != -1 || got[1].Sequence != 0 {
		t.Fatalf("decoded frames = %+v", got)
	}
}

func TestCBCRejectsInvalidInputs(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)

	for _, keySize := range []int{16, 24, 31} {
		if _, err := NewCBCEncrypter(key[:keySize], iv); err == nil {
			t.Errorf("NewCBCEncrypter accepted a %d-byte key", keySize)
		}
	}
	if _, err := NewCBCEncrypter(key, iv[:15]); err == nil {
		t.Fatal("NewCBCEncrypter accepted a short IV")
	}
	for _, keySize := range []int{16, 24, 31} {
		if _, err := NewCBCDecrypter(key[:keySize], iv); err == nil {
			t.Errorf("NewCBCDecrypter accepted a %d-byte key", keySize)
		}
	}
	if _, err := NewCBCDecrypter(key, iv[:15]); err == nil {
		t.Fatal("NewCBCDecrypter accepted a short IV")
	}

	encrypter, err := NewCBCEncrypter(key, iv)
	if err != nil {
		t.Fatalf("NewCBCEncrypter: %v", err)
	}
	for _, plaintext := range [][]byte{nil, {1, 2, 3, 4, 5}} {
		if _, err := encrypter.Encrypt(plaintext); !errors.Is(err, ErrInvalidPlaintext) {
			t.Fatalf("Encrypt(%x) error = %v, want %v", plaintext, err, ErrInvalidPlaintext)
		}
	}
	if _, err := encrypter.Encrypt(make([]byte, MaxMEFrameSize+NoopFrameSize)); !errors.Is(err, ErrInvalidPlaintext) {
		t.Fatalf("Encrypt over local batch maximum error = %v, want %v", err, ErrInvalidPlaintext)
	}

	plaintext := make([]byte, 20, 32)
	for i := range plaintext {
		plaintext[i] = byte(i + 1)
	}
	wantPlaintext := slices.Clone(plaintext)
	ciphertext, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt valid plaintext: %v", err)
	}
	if !bytes.Equal(plaintext, wantPlaintext) {
		t.Fatal("Encrypt modified its plaintext input")
	}
	if len(ciphertext) != 32 {
		t.Fatalf("ciphertext length = %d, want 32", len(ciphertext))
	}
	ciphertext[0] ^= 0xff
	if !bytes.Equal(plaintext, wantPlaintext) {
		t.Fatal("ciphertext aliases plaintext input")
	}
}

func TestCBCDecrypterFinishRejectsIncompleteBlock(t *testing.T) {
	decrypter, err := NewCBCDecrypter(make([]byte, 32), make([]byte, 16))
	if err != nil {
		t.Fatalf("NewCBCDecrypter: %v", err)
	}
	consumed, plaintext := decrypter.Feed(make([]byte, 15))
	if consumed != 15 {
		t.Fatalf("Feed consumed %d bytes, want 15", consumed)
	}
	if len(plaintext) != 0 {
		t.Fatalf("Feed returned %d plaintext bytes, want 0", len(plaintext))
	}
	if err := decrypter.Finish(); !errors.Is(err, ErrIncompleteBlock) {
		t.Fatalf("Finish error = %v, want %v", err, ErrIncompleteBlock)
	}
}

func TestCBCDecrypterPartiallyConsumesLargeCoalescedInput(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	first, err := EncodeFrame(0, make([]byte, MaxMEFrameSize-FullFrameOverhead), ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame first: %v", err)
	}
	second, err := EncodeFrame(1, []byte{1, 2, 3, 4}, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame second: %v", err)
	}

	encrypter, err := NewCBCEncrypter(key, iv)
	if err != nil {
		t.Fatalf("NewCBCEncrypter: %v", err)
	}
	firstCiphertext, err := encrypter.Encrypt(first)
	if err != nil {
		t.Fatalf("Encrypt first: %v", err)
	}
	secondCiphertext, err := encrypter.Encrypt(second)
	if err != nil {
		t.Fatalf("Encrypt second: %v", err)
	}
	ciphertext := append(slices.Clone(firstCiphertext), secondCiphertext...)
	if len(ciphertext) <= MaxMEFrameSize {
		t.Fatalf("coalesced ciphertext length = %d, want over %d", len(ciphertext), MaxMEFrameSize)
	}

	t.Run("aligned fast path", func(t *testing.T) {
		decrypter, err := NewCBCDecrypter(key, iv)
		if err != nil {
			t.Fatalf("NewCBCDecrypter: %v", err)
		}
		consumed, plaintext := decrypter.Feed(ciphertext)
		if consumed != MaxMEFrameSize || len(plaintext) != MaxMEFrameSize {
			t.Fatalf("first Feed consumed %d and returned %d, want %d", consumed, len(plaintext), MaxMEFrameSize)
		}
		if len(decrypter.pending) != 0 {
			t.Fatalf("pending bytes = %d, want 0", len(decrypter.pending))
		}

		secondConsumed, secondPlaintext := decrypter.Feed(ciphertext[consumed:])
		if secondConsumed != len(secondCiphertext) || !bytes.Equal(secondPlaintext, second) {
			t.Fatalf("second Feed consumed %d/%d, plaintext length %d", secondConsumed, len(secondCiphertext), len(secondPlaintext))
		}
		if !bytes.Equal(plaintext, first) {
			t.Fatal("first plaintext does not match first frame")
		}
		if err := decrypter.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
	})

	t.Run("partial block boundary", func(t *testing.T) {
		decrypter, err := NewCBCDecrypter(key, iv)
		if err != nil {
			t.Fatalf("NewCBCDecrypter: %v", err)
		}
		consumed, plaintext := decrypter.Feed(ciphertext[:15])
		if consumed != 15 || len(plaintext) != 0 {
			t.Fatalf("partial Feed consumed %d, plaintext %d", consumed, len(plaintext))
		}
		consumed, plaintext = decrypter.Feed(ciphertext[15:])
		if consumed != MaxMEFrameSize-15 || !bytes.Equal(plaintext, first) {
			t.Fatalf("continuation consumed %d, plaintext length %d", consumed, len(plaintext))
		}
		if len(decrypter.pending) >= 16 {
			t.Fatalf("pending bytes = %d, want fewer than 16", len(decrypter.pending))
		}
		remainder := ciphertext[15+consumed:]
		consumed, plaintext = decrypter.Feed(remainder)
		if consumed != len(remainder) || !bytes.Equal(plaintext, second) {
			t.Fatalf("remainder consumed %d/%d, plaintext %d", consumed, len(remainder), len(plaintext))
		}
	})
}
