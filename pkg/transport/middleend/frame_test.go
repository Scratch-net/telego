package middleend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"testing"
)

func TestEncodeFrameGoldenCRC32(t *testing.T) {
	payload := mustDecodeHex(t, "aa87cb7a010203040100000011223366f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	want := mustDecodeHex(t, "2c000000feffffffaa87cb7a010203040100000011223366f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff52d97a14")

	got, err := EncodeFrame(-2, payload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("frame = %x, want %x", got, want)
	}

	decoded, err := DecodeFrame(got, -2, ChecksumCRC32, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if decoded.Sequence != -2 || !bytes.Equal(decoded.Payload, payload) {
		t.Fatalf("decoded frame = %+v, want sequence -2 payload %x", decoded, payload)
	}

	got[8] ^= 0xff
	if !bytes.Equal(decoded.Payload, payload) {
		t.Fatal("DecodeFrame payload aliases input")
	}
}

func TestEncodeFrameGoldenCRC32C(t *testing.T) {
	payload := mustDecodeHex(t, "dfa230570807060504030201")
	want := mustDecodeHex(t, "1800000000000000dfa230570807060504030201c2c3f3f8")

	got, err := EncodeFrame(0, payload, ChecksumCRC32C)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("frame = %x, want %x", got, want)
	}
}

func TestFrameConstructorsRejectInvalidMaximum(t *testing.T) {
	tests := []struct {
		name string
		max  int
		want error
	}{
		{name: "negative", max: -1, want: ErrInvalidFrameSize},
		{name: "zero", max: 0, want: ErrInvalidFrameSize},
		{name: "below minimum", max: MinimumFullFrameSize - 1, want: ErrInvalidFrameSize},
		{name: "above local ME maximum", max: MaxMEFrameSize + 1, want: ErrFrameTooLarge},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewFrameEncoder(0, tc.max); !errors.Is(err, tc.want) {
				t.Errorf("NewFrameEncoder error = %v, want %v", err, tc.want)
			}
			if _, err := NewFrameDecoder(0, tc.max); !errors.Is(err, tc.want) {
				t.Errorf("NewFrameDecoder error = %v, want %v", err, tc.want)
			}
			if _, err := DecodeFrame(make([]byte, MinimumFullFrameSize), 0, ChecksumCRC32, tc.max); !errors.Is(err, tc.want) {
				t.Errorf("DecodeFrame error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestFrameEncoderHonorsConfiguredMaximum(t *testing.T) {
	encoder, err := NewFrameEncoder(0, 20)
	if err != nil {
		t.Fatalf("NewFrameEncoder: %v", err)
	}
	if _, err := encoder.Encode(make([]byte, 8)); err != nil {
		t.Fatalf("Encode at maximum: %v", err)
	}
	if _, err := encoder.Encode(make([]byte, 12)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("Encode over maximum error = %v, want %v", err, ErrFrameTooLarge)
	}
}

func TestFrameEncoderLocksOfficialChecksumTransition(t *testing.T) {
	handshakePayload, err := (HandshakePacket{Flags: HandshakeFlagCRC32C}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary handshake: %v", err)
	}
	encoder, err := NewFrameEncoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameEncoder: %v", err)
	}
	if err := encoder.ApplyPeerHandshake(HandshakePacket{Flags: HandshakeFlagCRC32C}); !errors.Is(err, ErrChecksumTransition) {
		t.Fatalf("early transition error = %v, want %v", err, ErrChecksumTransition)
	}

	handshakeFrame, err := encoder.Encode(handshakePayload)
	if err != nil {
		t.Fatalf("Encode handshake: %v", err)
	}
	if _, err := DecodeFrame(handshakeFrame, -1, ChecksumCRC32, MaxMEFrameSize); err != nil {
		t.Fatalf("handshake is not CRC32: %v", err)
	}
	if encoder.ChecksumMode() != ChecksumCRC32 {
		t.Fatalf("pre-negotiation mode = %d, want CRC32", encoder.ChecksumMode())
	}
	if err := encoder.ApplyPeerHandshake(HandshakePacket{Flags: HandshakeFlagCRC32C}); err != nil {
		t.Fatalf("ApplyPeerHandshake: %v", err)
	}
	if encoder.ChecksumMode() != ChecksumCRC32C {
		t.Fatalf("post-negotiation mode = %d, want CRC32C", encoder.ChecksumMode())
	}
	if err := encoder.ApplyPeerHandshake(HandshakePacket{Flags: HandshakeFlagCRC32C}); !errors.Is(err, ErrChecksumTransition) {
		t.Fatalf("second transition error = %v, want %v", err, ErrChecksumTransition)
	}

	payload := (Ping{ID: 1}).MarshalBinary()
	wire, err := encoder.Encode(payload)
	if err != nil {
		t.Fatalf("Encode post-handshake: %v", err)
	}
	if _, err := DecodeFrame(wire, 0, ChecksumCRC32C, MaxMEFrameSize); err != nil {
		t.Fatalf("post-handshake frame is not CRC32C: %v", err)
	}
	if _, err := DecodeFrame(wire, 0, ChecksumCRC32, MaxMEFrameSize); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("CRC32 decode error = %v, want %v", err, ErrChecksumMismatch)
	}
}

func TestFrameEncoderRejectedSequenceZeroEncodeKeepsTransitionOpen(t *testing.T) {
	local := HandshakePacket{Flags: HandshakeFlagCRC32C}
	handshakePayload, err := local.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary handshake: %v", err)
	}
	encoder, err := NewFrameEncoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameEncoder: %v", err)
	}
	if _, err := encoder.Encode(handshakePayload); err != nil {
		t.Fatalf("Encode handshake: %v", err)
	}
	if _, err := encoder.Encode([]byte{1, 2, 3}); !errors.Is(err, ErrInvalidFrameSize) {
		t.Fatalf("rejected sequence 0 error = %v, want %v", err, ErrInvalidFrameSize)
	}
	if err := encoder.ApplyPeerHandshake(HandshakePacket{Flags: HandshakeFlagCRC32C}); err != nil {
		t.Fatalf("ApplyPeerHandshake after rejected Encode: %v", err)
	}
	wire, err := encoder.Encode((Ping{ID: 1}).MarshalBinary())
	if err != nil {
		t.Fatalf("retry Encode: %v", err)
	}
	if _, err := DecodeFrame(wire, 0, ChecksumCRC32C, MaxMEFrameSize); err != nil {
		t.Fatalf("retried frame is not CRC32C: %v", err)
	}
}

func TestFrameEncoderRejectsUnilateralPeerCRC32C(t *testing.T) {
	handshakePayload, err := (HandshakePacket{}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary handshake: %v", err)
	}
	encoder, err := NewFrameEncoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameEncoder: %v", err)
	}
	if _, err := encoder.Encode(handshakePayload); err != nil {
		t.Fatalf("Encode handshake: %v", err)
	}
	if err := encoder.ApplyPeerHandshake(HandshakePacket{Flags: HandshakeFlagCRC32C}); !errors.Is(err, ErrChecksumTransition) {
		t.Fatalf("unilateral transition error = %v, want %v", err, ErrChecksumTransition)
	}
	if _, err := encoder.Encode((Ping{ID: 1}).MarshalBinary()); !errors.Is(err, ErrChecksumTransition) {
		t.Fatalf("Encode after rejected handshake error = %v, want %v", err, ErrChecksumTransition)
	}
}

func TestFrameEncoderMayRemainCRC32AndRejectsLateTransition(t *testing.T) {
	handshakePayload, err := (HandshakePacket{}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary handshake: %v", err)
	}
	encoder, err := NewFrameEncoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameEncoder: %v", err)
	}
	if _, err := encoder.Encode(handshakePayload); err != nil {
		t.Fatalf("Encode handshake: %v", err)
	}
	wire, err := encoder.Encode((Ping{ID: 1}).MarshalBinary())
	if err != nil {
		t.Fatalf("Encode post-handshake: %v", err)
	}
	if encoder.ChecksumMode() != ChecksumCRC32 {
		t.Fatalf("mode = %d, want CRC32", encoder.ChecksumMode())
	}
	if _, err := DecodeFrame(wire, 0, ChecksumCRC32, MaxMEFrameSize); err != nil {
		t.Fatalf("post-handshake frame is not CRC32: %v", err)
	}
	if err := encoder.ApplyPeerHandshake(HandshakePacket{Flags: HandshakeFlagCRC32C}); !errors.Is(err, ErrChecksumTransition) {
		t.Fatalf("late transition error = %v, want %v", err, ErrChecksumTransition)
	}

	invalid, err := NewFrameEncoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameEncoder invalid fixture: %v", err)
	}
	if _, err := invalid.Encode([]byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("Encode non-handshake sequence -1: %v", err)
	}
	if err := invalid.ApplyPeerHandshake(HandshakePacket{Flags: HandshakeFlagCRC32C}); !errors.Is(err, ErrChecksumTransition) {
		t.Fatalf("non-handshake transition error = %v, want %v", err, ErrChecksumTransition)
	}
}

func TestFrameSequenceExhaustionDoesNotWrap(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	encoder, err := NewFrameEncoder(math.MaxInt32, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameEncoder: %v", err)
	}
	wire, err := encoder.Encode(payload)
	if err != nil {
		t.Fatalf("Encode MaxInt32: %v", err)
	}
	if !encoder.Exhausted() {
		t.Fatal("encoder did not mark MaxInt32 sequence exhausted")
	}
	if _, err := encoder.Encode(payload); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("Encode after MaxInt32 error = %v, want %v", err, ErrSequenceExhausted)
	}

	decoded, err := DecodeFrame(wire, math.MaxInt32, ChecksumCRC32, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("DecodeFrame MaxInt32: %v", err)
	}
	if decoded.Sequence != math.MaxInt32 {
		t.Fatalf("sequence = %d, want %d", decoded.Sequence, math.MaxInt32)
	}

	decoder, err := NewFrameDecoder(math.MaxInt32, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}
	if consumed, err := decoder.Feed(wire); err != nil || consumed != len(wire) {
		t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(wire), err)
	}
	frame, ok, err := decoder.Next()
	if err != nil || !ok || frame.Sequence != math.MaxInt32 {
		t.Fatalf("Next MaxInt32 = %+v, ok %t, error %v", frame, ok, err)
	}
	if !decoder.Exhausted() {
		t.Fatal("decoder did not mark MaxInt32 sequence exhausted")
	}
	if _, ok, err := decoder.Next(); err != nil || ok {
		t.Fatalf("Next exhausted empty stream = ok %t, error %v", ok, err)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("Finish exhausted clean stream: %v", err)
	}
}

func TestFrameRejectsSequenceBelowHandshakeRange(t *testing.T) {
	if _, err := NewFrameEncoder(-3, MaxMEFrameSize); !errors.Is(err, ErrSequenceMismatch) {
		t.Errorf("NewFrameEncoder error = %v, want %v", err, ErrSequenceMismatch)
	}
	if _, err := NewFrameDecoder(-3, MaxMEFrameSize); !errors.Is(err, ErrSequenceMismatch) {
		t.Errorf("NewFrameDecoder error = %v, want %v", err, ErrSequenceMismatch)
	}
	if _, err := EncodeFrame(-3, []byte{1, 2, 3, 4}, ChecksumCRC32); !errors.Is(err, ErrSequenceMismatch) {
		t.Errorf("EncodeFrame error = %v, want %v", err, ErrSequenceMismatch)
	}
	wire, err := EncodeFrame(0, []byte{1, 2, 3, 4}, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame valid fixture: %v", err)
	}
	if _, err := DecodeFrame(wire, -3, ChecksumCRC32, MaxMEFrameSize); !errors.Is(err, ErrSequenceMismatch) {
		t.Errorf("DecodeFrame expected -3 error = %v, want %v", err, ErrSequenceMismatch)
	}
}

func TestFrameDecoderExhaustedAcceptsOnlyNoopPadding(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	wire, err := EncodeFrame(math.MaxInt32, payload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	if len(wire)%16 == 0 {
		t.Fatalf("fixture length %d is unexpectedly AES aligned", len(wire))
	}
	padding := make([]byte, 0, 12)
	for range 3 {
		padding = binary.LittleEndian.AppendUint32(padding, NoopFrameSize)
	}

	t.Run("coalesced padding", func(t *testing.T) {
		decoder, err := NewFrameDecoder(math.MaxInt32, len(wire)+len(padding))
		if err != nil {
			t.Fatalf("NewFrameDecoder: %v", err)
		}
		coalesced := append(slices.Clone(wire), padding...)
		if consumed, err := decoder.Feed(coalesced); err != nil || consumed != len(coalesced) {
			t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(coalesced), err)
		}
		if frame, ok, err := decoder.Next(); err != nil || !ok || frame.Sequence != math.MaxInt32 {
			t.Fatalf("Next MaxInt32 = %+v, ok %t, error %v", frame, ok, err)
		}
		if _, ok, err := decoder.Next(); err != nil || ok {
			t.Fatalf("Next padding = ok %t, error %v", ok, err)
		}
		if decoder.bufferedLen() != 0 {
			t.Fatalf("retained %d bytes after padding", decoder.bufferedLen())
		}
		if err := decoder.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
	})

	t.Run("padding split in caller remainder", func(t *testing.T) {
		decoder, err := NewFrameDecoder(math.MaxInt32, len(wire))
		if err != nil {
			t.Fatalf("NewFrameDecoder: %v", err)
		}
		coalesced := append(slices.Clone(wire), padding...)
		consumed, err := decoder.Feed(coalesced)
		if err != nil || consumed != len(wire) {
			t.Fatalf("first Feed consumed %d/%d, error %v", consumed, len(wire), err)
		}
		if _, ok, err := decoder.Next(); err != nil || !ok {
			t.Fatalf("Next MaxInt32 = ok %t, error %v", ok, err)
		}
		remainder := coalesced[consumed:]
		for _, chunkSize := range []int{2, 5, 5} {
			chunk := remainder[:chunkSize]
			remainder = remainder[chunkSize:]
			if chunkConsumed, err := decoder.Feed(chunk); err != nil || chunkConsumed != len(chunk) {
				t.Fatalf("padding Feed consumed %d/%d, error %v", chunkConsumed, len(chunk), err)
			}
			if _, ok, err := decoder.Next(); err != nil || ok {
				t.Fatalf("Next split padding = ok %t, error %v", ok, err)
			}
		}
		if len(remainder) != 0 {
			t.Fatalf("unconsumed padding = %d bytes", len(remainder))
		}
		if err := decoder.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
	})

	t.Run("padding then illegal frame", func(t *testing.T) {
		decoder, err := NewFrameDecoder(math.MaxInt32, len(wire))
		if err != nil {
			t.Fatalf("NewFrameDecoder: %v", err)
		}
		illegal, err := EncodeFrame(0, []byte{9, 10, 11, 12}, ChecksumCRC32)
		if err != nil {
			t.Fatalf("EncodeFrame illegal successor fixture: %v", err)
		}
		stream := append(slices.Clone(wire), padding...)
		stream = append(stream, illegal...)
		consumed, err := decoder.Feed(stream)
		if err != nil || consumed != len(wire) {
			t.Fatalf("first Feed consumed %d/%d, error %v", consumed, len(wire), err)
		}
		if _, ok, err := decoder.Next(); err != nil || !ok {
			t.Fatalf("Next MaxInt32 = ok %t, error %v", ok, err)
		}
		remaining := stream[consumed:]
		consumed, err = decoder.Feed(remaining)
		if err != nil || consumed != len(wire) {
			t.Fatalf("successor Feed consumed %d/%d, error %v", consumed, len(wire), err)
		}
		if _, _, err := decoder.Next(); !errors.Is(err, ErrSequenceExhausted) {
			t.Fatalf("Next illegal successor error = %v, want %v", err, ErrSequenceExhausted)
		}
		if err := decoder.Finish(); !errors.Is(err, ErrSequenceExhausted) {
			t.Fatalf("Finish illegal successor error = %v, want %v", err, ErrSequenceExhausted)
		}
	})

	t.Run("partial padding at EOF", func(t *testing.T) {
		decoder, err := NewFrameDecoder(math.MaxInt32, len(wire))
		if err != nil {
			t.Fatalf("NewFrameDecoder: %v", err)
		}
		if consumed, err := decoder.Feed(wire); err != nil || consumed != len(wire) {
			t.Fatalf("frame Feed consumed %d/%d, error %v", consumed, len(wire), err)
		}
		if _, ok, err := decoder.Next(); err != nil || !ok {
			t.Fatalf("Next MaxInt32 = ok %t, error %v", ok, err)
		}
		if consumed, err := decoder.Feed(padding[:3]); err != nil || consumed != 3 {
			t.Fatalf("padding Feed consumed %d/3, error %v", consumed, err)
		}
		if _, ok, err := decoder.Next(); err != nil || ok {
			t.Fatalf("Next partial padding = ok %t, error %v", ok, err)
		}
		if err := decoder.Finish(); !errors.Is(err, ErrIncompleteFrame) {
			t.Fatalf("Finish partial padding error = %v, want %v", err, ErrIncompleteFrame)
		}
	})
}

func TestDecodeFrameRejectsInvalidFrames(t *testing.T) {
	valid, err := EncodeFrame(7, []byte{1, 2, 3, 4, 5, 6, 7, 8}, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}

	tests := []struct {
		name string
		wire func() []byte
		seq  int32
		mode ChecksumMode
		max  int
		want error
	}{
		{
			name: "bad checksum",
			wire: func() []byte {
				wire := slices.Clone(valid)
				wire[len(wire)-1] ^= 1
				return wire
			},
			seq:  7,
			mode: ChecksumCRC32,
			max:  MaxMEFrameSize,
			want: ErrChecksumMismatch,
		},
		{
			name: "bad sequence",
			wire: func() []byte { return slices.Clone(valid) },
			seq:  8,
			mode: ChecksumCRC32,
			max:  MaxMEFrameSize,
			want: ErrSequenceMismatch,
		},
		{
			name: "declared size mismatch",
			wire: func() []byte {
				wire := slices.Clone(valid)
				binary.LittleEndian.PutUint32(wire[:4], uint32(len(wire)+4))
				return wire
			},
			seq:  7,
			mode: ChecksumCRC32,
			max:  MaxMEFrameSize,
			want: ErrInvalidFrameSize,
		},
		{
			name: "too small",
			wire: func() []byte { return slices.Clone(valid[:12]) },
			seq:  7,
			mode: ChecksumCRC32,
			max:  MaxMEFrameSize,
			want: ErrInvalidFrameSize,
		},
		{
			name: "over configured maximum",
			wire: func() []byte { return slices.Clone(valid) },
			seq:  7,
			mode: ChecksumCRC32,
			max:  MinimumFullFrameSize,
			want: ErrFrameTooLarge,
		},
		{
			name: "wrong checksum mode",
			wire: func() []byte { return slices.Clone(valid) },
			seq:  7,
			mode: ChecksumMode(9),
			max:  MaxMEFrameSize,
			want: ErrInvalidChecksumMode,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeFrame(tc.wire(), tc.seq, tc.mode, tc.max)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecodeFrameChecksChecksumBeforeSequence(t *testing.T) {
	wire, err := EncodeFrame(7, []byte{1, 2, 3, 4}, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame: %v", err)
	}
	wire[4] ^= 1

	_, err = DecodeFrame(wire, 7, ChecksumCRC32, MaxMEFrameSize)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("error = %v, want %v", err, ErrChecksumMismatch)
	}
}

func TestFrameDecoderFragmentationNoopsAndChecksumTransition(t *testing.T) {
	handshakePayload := mustDecodeHex(t, "f5ee827600080000146433c631d4d204000033660a0200c0b822000000000000")
	handshakeFrame, err := EncodeFrame(-1, handshakePayload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("encode handshake: %v", err)
	}
	pingPayload := mustDecodeHex(t, "dfa230570807060504030201")
	pingFrame, err := EncodeFrame(0, pingPayload, ChecksumCRC32C)
	if err != nil {
		t.Fatalf("encode ping: %v", err)
	}

	stream := make([]byte, 0, len(handshakeFrame)+NoopFrameSize+len(pingFrame))
	stream = append(stream, handshakeFrame...)
	stream = binary.LittleEndian.AppendUint32(stream, NoopFrameSize)
	stream = append(stream, pingFrame...)

	decoder, err := NewFrameDecoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}

	var frames []Frame
	for _, value := range stream {
		consumed, err := decoder.Feed([]byte{value})
		if err != nil {
			t.Fatalf("Feed: %v", err)
		}
		if consumed != 1 {
			t.Fatalf("Feed consumed %d bytes, want 1", consumed)
		}
		for {
			frame, ok, err := decoder.Next()
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			if !ok {
				break
			}
			frames = append(frames, frame)
			if frame.Sequence == -1 {
				peer, err := ParseHandshakePacket(frame.Payload)
				if err != nil {
					t.Fatalf("ParseHandshakePacket: %v", err)
				}
				if err := decoder.ApplyPeerHandshake(peer, HandshakePacket{Flags: HandshakeFlagCRC32C}); err != nil {
					t.Fatalf("ApplyPeerHandshake: %v", err)
				}
			}
		}
	}

	if err := decoder.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("decoded %d frames, want 2", len(frames))
	}
	if frames[0].Sequence != -1 || !bytes.Equal(frames[0].Payload, handshakePayload) {
		t.Errorf("handshake frame = %+v", frames[0])
	}
	if frames[1].Sequence != 0 || !bytes.Equal(frames[1].Payload, pingPayload) {
		t.Errorf("ping frame = %+v", frames[1])
	}
	if decoder.NextSequence() != 1 {
		t.Errorf("next sequence = %d, want 1", decoder.NextSequence())
	}
	if decoder.ChecksumMode() != ChecksumCRC32C {
		t.Errorf("checksum mode = %d, want CRC32C", decoder.ChecksumMode())
	}
}

func TestFrameDecoderRemainsCRC32WithoutNegotiatedHandshake(t *testing.T) {
	handshakePayload, err := (HandshakePacket{}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary handshake: %v", err)
	}
	handshakeFrame, err := EncodeFrame(-1, handshakePayload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame handshake: %v", err)
	}
	payload := (Ping{ID: 1}).MarshalBinary()
	nextFrame, err := EncodeFrame(0, payload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame next: %v", err)
	}
	stream := append(handshakeFrame, nextFrame...)
	decoder, err := NewFrameDecoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}
	if consumed, err := decoder.Feed(stream); err != nil || consumed != len(stream) {
		t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(stream), err)
	}
	frame, ok, err := decoder.Next()
	if err != nil || !ok {
		t.Fatalf("Next handshake = ok %t, error %v", ok, err)
	}
	peer, err := ParseHandshakePacket(frame.Payload)
	if err != nil {
		t.Fatalf("ParseHandshakePacket: %v", err)
	}
	if err := decoder.ApplyPeerHandshake(peer, HandshakePacket{}); err != nil {
		t.Fatalf("ApplyPeerHandshake: %v", err)
	}
	if decoder.ChecksumMode() != ChecksumCRC32 {
		t.Fatalf("post-handshake mode = %d, want CRC32", decoder.ChecksumMode())
	}
	if frame, ok, err := decoder.Next(); err != nil || !ok || !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("Next payload = %+v, ok %t, error %v", frame, ok, err)
	}
}

func TestFrameDecoderCoalescedSequenceZeroWaitsForHandshakeCommit(t *testing.T) {
	peer := HandshakePacket{Flags: HandshakeFlagCRC32C}
	handshakePayload, err := peer.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary handshake: %v", err)
	}
	handshakeFrame, err := EncodeFrame(-1, handshakePayload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame handshake: %v", err)
	}
	payload := (Ping{ID: 1}).MarshalBinary()
	nextFrame, err := EncodeFrame(0, payload, ChecksumCRC32C)
	if err != nil {
		t.Fatalf("EncodeFrame next: %v", err)
	}
	stream := append(slices.Clone(handshakeFrame), nextFrame...)
	decoder, err := NewFrameDecoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}
	if consumed, err := decoder.Feed(stream); err != nil || consumed != len(stream) {
		t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(stream), err)
	}
	frame, ok, err := decoder.Next()
	if err != nil || !ok || frame.Sequence != -1 {
		t.Fatalf("Next handshake = %+v, ok %t, error %v", frame, ok, err)
	}
	buffered := decoder.bufferedLen()
	if buffered != len(nextFrame) {
		t.Fatalf("buffered sequence 0 bytes = %d, want %d", buffered, len(nextFrame))
	}
	if _, ok, err := decoder.Next(); err != nil || ok {
		t.Fatalf("Next before commit = ok %t, error %v", ok, err)
	}
	if decoder.bufferedLen() != buffered {
		t.Fatalf("Next before commit consumed %d bytes", buffered-decoder.bufferedLen())
	}
	if err := decoder.Finish(); !errors.Is(err, ErrChecksumTransition) {
		t.Fatalf("Finish before commit error = %v, want %v", err, ErrChecksumTransition)
	}
	if err := decoder.ApplyPeerHandshake(peer, HandshakePacket{Flags: HandshakeFlagCRC32C}); err != nil {
		t.Fatalf("ApplyPeerHandshake: %v", err)
	}
	frame, ok, err = decoder.Next()
	if err != nil || !ok || !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("Next sequence 0 = %+v, ok %t, error %v", frame, ok, err)
	}
}

func TestFrameDecoderInvalidHandshakeFailsWithoutConsumingSequenceZero(t *testing.T) {
	tests := []struct {
		name      string
		peer      HandshakePacket
		local     HandshakePacket
		applyPeer HandshakePacket
	}{
		{
			name:  "unilateral CRC32C",
			peer:  HandshakePacket{Flags: HandshakeFlagCRC32C},
			local: HandshakePacket{},
		},
		{
			name:      "different applied peer",
			peer:      HandshakePacket{},
			local:     HandshakePacket{},
			applyPeer: HandshakePacket{Sender: ProcessID{PID: 1}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handshakePayload, err := tc.peer.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary handshake: %v", err)
			}
			handshakeFrame, err := EncodeFrame(-1, handshakePayload, ChecksumCRC32)
			if err != nil {
				t.Fatalf("EncodeFrame handshake: %v", err)
			}
			nextFrame, err := EncodeFrame(0, (Ping{ID: 1}).MarshalBinary(), ChecksumCRC32)
			if err != nil {
				t.Fatalf("EncodeFrame next: %v", err)
			}
			stream := append(slices.Clone(handshakeFrame), nextFrame...)
			decoder, err := NewFrameDecoder(-1, MaxMEFrameSize)
			if err != nil {
				t.Fatalf("NewFrameDecoder: %v", err)
			}
			if consumed, err := decoder.Feed(stream); err != nil || consumed != len(stream) {
				t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(stream), err)
			}
			if _, ok, err := decoder.Next(); err != nil || !ok {
				t.Fatalf("Next handshake = ok %t, error %v", ok, err)
			}
			buffered := decoder.bufferedLen()
			applyPeer := tc.applyPeer
			if applyPeer == (HandshakePacket{}) {
				applyPeer = tc.peer
			}
			if err := decoder.ApplyPeerHandshake(applyPeer, tc.local); !errors.Is(err, ErrChecksumTransition) {
				t.Fatalf("ApplyPeerHandshake error = %v, want %v", err, ErrChecksumTransition)
			}
			if decoder.bufferedLen() != buffered {
				t.Fatalf("invalid commit consumed %d sequence 0 bytes", buffered-decoder.bufferedLen())
			}
			if _, _, err := decoder.Next(); !errors.Is(err, ErrChecksumTransition) {
				t.Fatalf("Next after invalid commit error = %v, want %v", err, ErrChecksumTransition)
			}
			if consumed, err := decoder.Feed([]byte{1}); consumed != 0 || !errors.Is(err, ErrChecksumTransition) {
				t.Fatalf("Feed after invalid commit consumed %d, error %v", consumed, err)
			}
		})
	}
}

func TestFrameDecoderMalformedSequenceMinusOneFailsBeforeSequenceZero(t *testing.T) {
	malformedFrame, err := EncodeFrame(-1, (Ping{ID: 1}).MarshalBinary(), ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame malformed handshake: %v", err)
	}
	nextFrame, err := EncodeFrame(0, (Ping{ID: 2}).MarshalBinary(), ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame next: %v", err)
	}
	stream := append(slices.Clone(malformedFrame), nextFrame...)
	decoder, err := NewFrameDecoder(-1, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}
	if consumed, err := decoder.Feed(stream); err != nil || consumed != len(stream) {
		t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(stream), err)
	}
	if _, _, err := decoder.Next(); !errors.Is(err, ErrInvalidHandshake) {
		t.Fatalf("Next error = %v, want %v", err, ErrInvalidHandshake)
	}
	if decoder.bufferedLen() != len(nextFrame) {
		t.Fatalf("buffered bytes = %d, want untouched sequence 0 size %d", decoder.bufferedLen(), len(nextFrame))
	}
}

func TestFrameDecoderFailsClosed(t *testing.T) {
	decoder, err := NewFrameDecoder(0, 64)
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, 68)
	if consumed, err := decoder.Feed(header); err != nil || consumed != len(header) {
		t.Fatalf("Feed: %v", err)
	}
	_, _, firstErr := decoder.Next()
	if !errors.Is(firstErr, ErrFrameTooLarge) {
		t.Fatalf("first error = %v, want %v", firstErr, ErrFrameTooLarge)
	}
	if consumed, err := decoder.Feed([]byte{4, 0, 0, 0}); consumed != 0 || !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("Feed after failure = %v, want prior failure", err)
	}
	_, _, nextErr := decoder.Next()
	if !errors.Is(nextErr, ErrFrameTooLarge) {
		t.Fatalf("Next after failure = %v, want prior failure", nextErr)
	}
}

func TestFrameDecoderPartiallyConsumesFragmentedAndCoalescedFrames(t *testing.T) {
	firstPayload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	first, err := EncodeFrame(0, firstPayload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame first: %v", err)
	}
	secondPayload := []byte{9, 10, 11, 12}
	second, err := EncodeFrame(1, secondPayload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame second: %v", err)
	}
	decoder, err := NewFrameDecoder(0, len(first))
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}

	if consumed, err := decoder.Feed(first[:10]); err != nil || consumed != 10 {
		t.Fatalf("first Feed consumed %d, error %v", consumed, err)
	}
	if _, ok, err := decoder.Next(); err != nil || ok {
		t.Fatalf("Next partial = ok %t, error %v", ok, err)
	}

	coalesced := append(slices.Clone(first[10:]), second...)
	consumed, err := decoder.Feed(coalesced)
	if err != nil {
		t.Fatalf("coalesced Feed: %v", err)
	}
	wantConsumed := len(first) - 10
	if consumed != wantConsumed {
		t.Fatalf("coalesced Feed consumed %d bytes, want boundary %d", consumed, wantConsumed)
	}
	if decoder.bufferedLen() != len(first) {
		t.Fatalf("retained %d bytes, want maximum %d", decoder.bufferedLen(), len(first))
	}
	if consumed, err := decoder.Feed(coalesced[consumed:]); err != nil || consumed != 0 {
		t.Fatalf("Feed before drain consumed %d, error %v; want 0, nil", consumed, err)
	}

	frame, ok, err := decoder.Next()
	if err != nil || !ok {
		t.Fatalf("Next first = ok %t, error %v", ok, err)
	}
	if !bytes.Equal(frame.Payload, firstPayload) {
		t.Fatalf("first payload = %x, want %x", frame.Payload, firstPayload)
	}

	remainder := coalesced[consumed:]
	consumed, err = decoder.Feed(remainder)
	if err != nil || consumed != len(remainder) {
		t.Fatalf("resume Feed consumed %d/%d, error %v", consumed, len(remainder), err)
	}
	frame, ok, err = decoder.Next()
	if err != nil || !ok {
		t.Fatalf("Next second = ok %t, error %v", ok, err)
	}
	if !bytes.Equal(frame.Payload, secondPayload) {
		t.Fatalf("second payload = %x, want %x", frame.Payload, secondPayload)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
}

func TestFrameDecoderReusesDrainedBackingBuffer(t *testing.T) {
	const maximum = 64 * 1024
	firstPayload := bytes.Repeat([]byte{0x11}, maximum-FullFrameOverhead)
	secondPayload := bytes.Repeat([]byte{0x22}, maximum-FullFrameOverhead)
	first, err := EncodeFrame(0, firstPayload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame first: %v", err)
	}
	second, err := EncodeFrame(1, secondPayload, ChecksumCRC32)
	if err != nil {
		t.Fatalf("EncodeFrame second: %v", err)
	}
	decoder, err := NewFrameDecoder(0, maximum)
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}

	for offset := 0; offset < len(first); {
		end := min(offset+4096, len(first))
		consumed, err := decoder.Feed(first[offset:end])
		if err != nil || consumed != end-offset {
			t.Fatalf("Feed first consumed %d/%d, error %v", consumed, end-offset, err)
		}
		offset = end
	}
	frame, ok, err := decoder.Next()
	if err != nil || !ok || !bytes.Equal(frame.Payload, firstPayload) {
		t.Fatalf("Next first = sequence %d, ok %t, error %v", frame.Sequence, ok, err)
	}
	if len(decoder.buffer) != 0 || cap(decoder.buffer) < len(first) {
		t.Fatalf("drained buffer length %d capacity %d", len(decoder.buffer), cap(decoder.buffer))
	}
	backing := decoder.buffer[:cap(decoder.buffer)]
	backingStart := &backing[0]
	backingCapacity := cap(decoder.buffer)

	if consumed, err := decoder.Feed(second); err != nil || consumed != len(second) {
		t.Fatalf("Feed second consumed %d/%d, error %v", consumed, len(second), err)
	}
	if &decoder.buffer[0] != backingStart || cap(decoder.buffer) != backingCapacity {
		t.Fatalf("second frame replaced backing buffer: capacity %d, want %d", cap(decoder.buffer), backingCapacity)
	}
	frame, ok, err = decoder.Next()
	if err != nil || !ok || !bytes.Equal(frame.Payload, secondPayload) {
		t.Fatalf("Next second = sequence %d, ok %t, error %v", frame.Sequence, ok, err)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	decoder.retire()
	for index, value := range backing {
		if value != 0 {
			t.Fatalf("retired backing byte %d = 0x%02x", index, value)
		}
	}
	if decoder.buffer != nil || decoder.head != 0 {
		t.Fatalf("retired decoder retains buffer %v or head %d", decoder.buffer, decoder.head)
	}
}

func TestFrameDecoderDrainsNoopFloodWithinLimit(t *testing.T) {
	decoder, err := NewFrameDecoder(0, 64)
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}
	noops := make([]byte, 0, 64)
	for range 16 {
		noops = binary.LittleEndian.AppendUint32(noops, NoopFrameSize)
	}
	if consumed, err := decoder.Feed(noops); err != nil || consumed != len(noops) {
		t.Fatalf("Feed: %v", err)
	}
	if _, ok, err := decoder.Next(); err != nil || ok {
		t.Fatalf("Next = ok %t, error %v; want no frame", ok, err)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
}

func TestFrameDecoderFinishRejectsTruncatedFrame(t *testing.T) {
	decoder, err := NewFrameDecoder(0, MaxMEFrameSize)
	if err != nil {
		t.Fatalf("NewFrameDecoder: %v", err)
	}
	if consumed, err := decoder.Feed([]byte{16, 0, 0}); err != nil || consumed != 3 {
		t.Fatalf("Feed: %v", err)
	}
	if err := decoder.Finish(); !errors.Is(err, ErrIncompleteFrame) {
		t.Fatalf("Finish error = %v, want %v", err, ErrIncompleteFrame)
	}
}
