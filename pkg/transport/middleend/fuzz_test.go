package middleend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"testing"
)

func FuzzFrameDecoderPartitionsAndCoalescing(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{1, 2, 3, 7, 15, 31, 63, 127, 255})

	f.Fuzz(func(t *testing.T, partitions []byte) {
		firstPayload := []byte{1, 2, 3, 4}
		secondPayload, err := (HandshakePacket{}).MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary handshake: %v", err)
		}
		first, err := EncodeFrame(-2, firstPayload, ChecksumCRC32)
		if err != nil {
			t.Fatalf("EncodeFrame first: %v", err)
		}
		second, err := EncodeFrame(-1, secondPayload, ChecksumCRC32)
		if err != nil {
			t.Fatalf("EncodeFrame second: %v", err)
		}

		stream := make([]byte, 0, len(first)+len(second)+3*NoopFrameSize)
		stream = binary.LittleEndian.AppendUint32(stream, NoopFrameSize)
		stream = append(stream, first...)
		stream = binary.LittleEndian.AppendUint32(stream, NoopFrameSize)
		stream = binary.LittleEndian.AppendUint32(stream, NoopFrameSize)
		stream = append(stream, second...)

		decoder, err := NewFrameDecoder(-2, max(len(first), len(second)))
		if err != nil {
			t.Fatalf("NewFrameDecoder: %v", err)
		}

		var got []Frame
		feedByPartitions(t, stream, partitions, func(chunk []byte) bool {
			for len(chunk) != 0 {
				consumed, err := decoder.Feed(chunk)
				if err != nil {
					t.Fatalf("Feed: %v", err)
				}
				chunk = chunk[consumed:]
				progressed := consumed != 0
				for {
					frame, ok, err := decoder.Next()
					if err != nil {
						t.Fatalf("Next: %v", err)
					}
					if !ok {
						break
					}
					progressed = true
					got = append(got, frame)
					if frame.Sequence == -1 {
						peer, err := ParseHandshakePacket(frame.Payload)
						if err != nil {
							t.Fatalf("ParseHandshakePacket: %v", err)
						}
						if err := decoder.ApplyPeerHandshake(peer, HandshakePacket{}); err != nil {
							t.Fatalf("ApplyPeerHandshake: %v", err)
						}
					}
				}
				if !progressed {
					t.Fatal("decoder made no progress")
				}
			}
			return true
		})

		if err := decoder.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("decoded %d frames, want 2", len(got))
		}
		if got[0].Sequence != -2 || !bytes.Equal(got[0].Payload, firstPayload) {
			t.Fatalf("first frame = %+v", got[0])
		}
		if got[1].Sequence != -1 || !bytes.Equal(got[1].Payload, secondPayload) {
			t.Fatalf("second frame = %+v", got[1])
		}
	})
}

func FuzzFrameDecoderMaxSequenceTerminalStream(f *testing.F) {
	f.Add(byte(0), byte(0), []byte{})
	f.Add(byte(3), byte(0), []byte{0})
	f.Add(byte(1), byte(1), []byte{2, 0, 7})
	f.Add(byte(2), byte(2), []byte{1, 3, 15})
	f.Add(byte(3), byte(3), []byte{0, 4, 8})
	f.Add(byte(3), byte(4), []byte{255})

	f.Fuzz(func(t *testing.T, noopSelector, terminalSelector byte, partitions []byte) {
		payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		terminalFrame, err := EncodeFrame(math.MaxInt32, payload, ChecksumCRC32)
		if err != nil {
			t.Fatalf("EncodeFrame terminal: %v", err)
		}

		noopCount := int(noopSelector % 4)
		terminalKind := int(terminalSelector % 5)
		stream := slices.Clone(terminalFrame)
		for range noopCount {
			stream = binary.LittleEndian.AppendUint32(stream, NoopFrameSize)
		}

		switch terminalKind {
		case 0:
			// Complete padding followed by EOF is valid.
		case 1, 2, 3:
			var noop [NoopFrameSize]byte
			binary.LittleEndian.PutUint32(noop[:], NoopFrameSize)
			stream = append(stream, noop[:terminalKind]...)
		case 4:
			successor, err := EncodeFrame(0, []byte{9, 10, 11, 12}, ChecksumCRC32)
			if err != nil {
				t.Fatalf("EncodeFrame successor: %v", err)
			}
			stream = append(stream, successor...)
		}

		decoder, err := NewFrameDecoder(math.MaxInt32, len(terminalFrame))
		if err != nil {
			t.Fatalf("NewFrameDecoder: %v", err)
		}

		decoded := 0
		var terminalErr error
		feedByPartitions(t, stream, partitions, func(chunk []byte) bool {
			for len(chunk) != 0 {
				consumed, err := decoder.Feed(chunk)
				if err != nil {
					terminalErr = err
					return false
				}
				chunk = chunk[consumed:]
				progressed := consumed != 0
				for {
					frame, ok, err := decoder.Next()
					if err != nil {
						terminalErr = err
						return false
					}
					if !ok {
						break
					}
					progressed = true
					decoded++
					if frame.Sequence != math.MaxInt32 || !bytes.Equal(frame.Payload, payload) {
						t.Fatalf("decoded terminal frame = %+v", frame)
					}
				}
				if !progressed {
					t.Fatal("decoder made no progress")
				}
			}
			return true
		})

		if decoded != 1 {
			t.Fatalf("decoded %d frames, want 1", decoded)
		}
		if !decoder.Exhausted() || decoder.NextSequence() != math.MaxInt32 {
			t.Fatalf("decoder terminal state = exhausted %t, next %d", decoder.Exhausted(), decoder.NextSequence())
		}

		switch terminalKind {
		case 0:
			if terminalErr != nil {
				t.Fatalf("terminal stream error = %v", terminalErr)
			}
			if _, ok, err := decoder.Next(); err != nil || ok {
				t.Fatalf("Next at terminal EOF = ok %t, error %v", ok, err)
			}
			if err := decoder.Finish(); err != nil {
				t.Fatalf("Finish terminal stream: %v", err)
			}
		case 1, 2, 3:
			if terminalErr != nil {
				t.Fatalf("truncated padding stream error before EOF = %v", terminalErr)
			}
			if _, ok, err := decoder.Next(); err != nil || ok {
				t.Fatalf("Next with truncated padding = ok %t, error %v", ok, err)
			}
			if err := decoder.Finish(); !errors.Is(err, ErrIncompleteFrame) {
				t.Fatalf("Finish truncated padding error = %v, want %v", err, ErrIncompleteFrame)
			}
		case 4:
			if !errors.Is(terminalErr, ErrSequenceExhausted) {
				t.Fatalf("successor error = %v, want %v", terminalErr, ErrSequenceExhausted)
			}
			if consumed, err := decoder.Feed([]byte{NoopFrameSize, 0, 0, 0}); consumed != 0 || !errors.Is(err, ErrSequenceExhausted) {
				t.Fatalf("Feed after terminal error consumed %d, error %v", consumed, err)
			}
			if _, _, err := decoder.Next(); !errors.Is(err, ErrSequenceExhausted) {
				t.Fatalf("Next after terminal error = %v", err)
			}
			if err := decoder.Finish(); !errors.Is(err, ErrSequenceExhausted) {
				t.Fatalf("Finish after terminal error = %v", err)
			}
		}
	})
}

func FuzzFrameDecoderMalformedAndNoopFloods(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f}, []byte{1})
	f.Add(bytes.Repeat([]byte{4, 0, 0, 0}, 65), []byte{})
	f.Add([]byte{16, 0, 0, 0, 0, 0, 0, 0}, []byte{1, 3, 7})

	f.Fuzz(func(t *testing.T, input, partitions []byte) {
		const maxFrameSize = 256
		input = slices.Clone(input[:min(len(input), maxFrameSize+1)])
		decoder, err := NewFrameDecoder(0, maxFrameSize)
		if err != nil {
			t.Fatalf("NewFrameDecoder: %v", err)
		}

		feedByPartitions(t, input, partitions, func(chunk []byte) bool {
			for len(chunk) != 0 {
				consumed, err := decoder.Feed(chunk)
				if err != nil {
					return false
				}
				chunk = chunk[consumed:]
				progressed := consumed != 0
				for range maxFrameSize/NoopFrameSize + 1 {
					_, ok, err := decoder.Next()
					if err != nil {
						return false
					}
					if !ok {
						break
					}
					progressed = true
				}
				if !progressed {
					return false
				}
			}
			return true
		})

		if len(decoder.buffer) > maxFrameSize {
			t.Fatalf("decoder retained %d bytes, maximum %d", len(decoder.buffer), maxFrameSize)
		}
		_ = decoder.Finish()
	})
}

func FuzzCBCDecrypterPartitions(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{1, 2, 15, 16, 17, 31, 32, 255})

	f.Fuzz(func(t *testing.T, partitions []byte) {
		key := make([]byte, 32)
		iv := make([]byte, 16)
		for i := range key {
			key[i] = byte(i + 1)
		}
		for i := range iv {
			iv[i] = byte(0xf0 + i)
		}

		first, err := EncodeFrame(-1, []byte{1, 2, 3, 4}, ChecksumCRC32)
		if err != nil {
			t.Fatalf("EncodeFrame first: %v", err)
		}
		second, err := EncodeFrame(0, []byte{5, 6, 7, 8, 9, 10, 11, 12}, ChecksumCRC32)
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

		decrypter, err := NewCBCDecrypter(key, iv)
		if err != nil {
			t.Fatalf("NewCBCDecrypter: %v", err)
		}
		var plaintext []byte
		feedByPartitions(t, ciphertext, partitions, func(chunk []byte) bool {
			for len(chunk) != 0 {
				consumed, decrypted := decrypter.Feed(chunk)
				if consumed == 0 {
					t.Fatal("decrypter made no progress")
				}
				plaintext = append(plaintext, decrypted...)
				chunk = chunk[consumed:]
			}
			return true
		})
		if err := decrypter.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}

		want := appendCBCNoops(slices.Clone(first))
		want = append(want, appendCBCNoops(slices.Clone(second))...)
		if !bytes.Equal(plaintext, want) {
			t.Fatalf("plaintext = %x, want %x", plaintext, want)
		}
	})
}

func FuzzCBCDecrypterMalformedPartitions(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 15), []byte{1, 2, 3})
	f.Add(make([]byte, 32), []byte{})

	f.Fuzz(func(t *testing.T, input, partitions []byte) {
		input = slices.Clone(input[:min(len(input), 1024)])
		decrypter, err := NewCBCDecrypter(make([]byte, 32), make([]byte, 16))
		if err != nil {
			t.Fatalf("NewCBCDecrypter: %v", err)
		}
		feedByPartitions(t, input, partitions, func(chunk []byte) bool {
			for len(chunk) != 0 {
				consumed, _ := decrypter.Feed(chunk)
				if consumed == 0 {
					return false
				}
				chunk = chunk[consumed:]
			}
			return true
		})
		if len(decrypter.pending) >= 16 {
			t.Fatalf("decrypter retained %d bytes, want fewer than 16", len(decrypter.pending))
		}
		_ = decrypter.Finish()
	})
}

func feedByPartitions(t *testing.T, data, partitions []byte, consume func([]byte) bool) {
	t.Helper()
	if len(partitions) == 0 {
		consume(data)
		return
	}

	for offset, partitionIndex := 0, 0; offset < len(data); partitionIndex++ {
		chunkSize := int(partitions[partitionIndex%len(partitions)]) + 1
		end := min(offset+chunkSize, len(data))
		if !consume(data[offset:end]) {
			return
		}
		offset = end
	}
}

func appendCBCNoops(plaintext []byte) []byte {
	paddingSize := -len(plaintext) & 15
	for range paddingSize / NoopFrameSize {
		plaintext = binary.LittleEndian.AppendUint32(plaintext, NoopFrameSize)
	}
	return plaintext
}
