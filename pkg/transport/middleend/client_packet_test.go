package middleend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

func TestClientPacketDecoderGoldenFramings(t *testing.T) {
	shortPacket := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	longPacket := make([]byte, 0x7f*4)
	for i := range longPacket {
		longPacket[i] = byte(i)
	}

	tests := []struct {
		name           string
		connectionType obfuscated2.ConnectionType
		wire           []byte
		wantPacket     []byte
		wantQuickAck   bool
	}{
		{
			name:           "abridged short",
			connectionType: obfuscated2.ConnectionTypeAbridged,
			wire:           append([]byte{0x02}, shortPacket...),
			wantPacket:     shortPacket,
		},
		{
			name:           "abridged short quick ack",
			connectionType: obfuscated2.ConnectionTypeAbridged,
			wire:           append([]byte{0x82}, shortPacket...),
			wantPacket:     shortPacket,
			wantQuickAck:   true,
		},
		{
			name:           "abridged extended quick ack",
			connectionType: obfuscated2.ConnectionTypeAbridged,
			wire:           append([]byte{0xff, 0x7f, 0x00, 0x00}, longPacket...),
			wantPacket:     longPacket,
			wantQuickAck:   true,
		},
		{
			name:           "intermediate",
			connectionType: obfuscated2.ConnectionTypeIntermediate,
			wire:           append([]byte{0x08, 0x00, 0x00, 0x00}, shortPacket...),
			wantPacket:     shortPacket,
		},
		{
			name:           "intermediate quick ack",
			connectionType: obfuscated2.ConnectionTypeIntermediate,
			wire:           append([]byte{0x08, 0x00, 0x00, 0x80}, shortPacket...),
			wantPacket:     shortPacket,
			wantQuickAck:   true,
		},
		{
			name:           "padded intermediate strips three bytes",
			connectionType: obfuscated2.ConnectionTypePaddedIntermediate,
			wire:           append([]byte{0x0b, 0x00, 0x00, 0x80}, append(slices.Clone(shortPacket), 0xaa, 0xbb, 0xcc)...),
			wantPacket:     shortPacket,
			wantQuickAck:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decoder, err := NewClientPacketDecoder(tc.connectionType, max(1024, len(tc.wire)))
			if err != nil {
				t.Fatalf("NewClientPacketDecoder: %v", err)
			}
			for _, value := range tc.wire {
				consumed, err := decoder.Feed([]byte{value})
				if err != nil || consumed != 1 {
					t.Fatalf("Feed consumed %d, error %v", consumed, err)
				}
			}
			packet, ok, err := decoder.Next()
			if err != nil || !ok {
				t.Fatalf("Next = ok %t, error %v", ok, err)
			}
			if !bytes.Equal(packet.Payload, tc.wantPacket) || packet.QuickAck != tc.wantQuickAck {
				t.Fatalf("packet = %+v, want payload %x quickAck %t", packet, tc.wantPacket, tc.wantQuickAck)
			}
			if err := decoder.Finish(); err != nil {
				t.Fatalf("Finish: %v", err)
			}

			tc.wire[len(tc.wire)-1] ^= 0xff
			if !bytes.Equal(packet.Payload, tc.wantPacket) {
				t.Fatal("decoded packet aliases wire input")
			}
		})
	}
}

func TestClientPacketDecoderFragmentationAndCoalescing(t *testing.T) {
	first := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	second := []byte{9, 10, 11, 12}

	for _, connectionType := range []obfuscated2.ConnectionType{
		obfuscated2.ConnectionTypeAbridged,
		obfuscated2.ConnectionTypeIntermediate,
		obfuscated2.ConnectionTypePaddedIntermediate,
	} {
		t.Run(clientFramingName(connectionType), func(t *testing.T) {
			firstWire := encodeClientInputFixture(t, connectionType, first, true, []byte{0xaa, 0xbb, 0xcc})
			secondWire := encodeClientInputFixture(t, connectionType, second, false, []byte{0xdd})
			stream := append(slices.Clone(firstWire), secondWire...)

			decoder, err := NewClientPacketDecoder(connectionType, 1024)
			if err != nil {
				t.Fatalf("NewClientPacketDecoder: %v", err)
			}
			var got []ClientPacket
			feedClientPartitions(t, decoder, stream, []byte{0, 1, 2, 6, 15}, &got)
			if err := decoder.Finish(); err != nil {
				t.Fatalf("Finish: %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("decoded %d packets, want 2", len(got))
			}
			if !bytes.Equal(got[0].Payload, first) || !got[0].QuickAck {
				t.Fatalf("first packet = %+v", got[0])
			}
			if !bytes.Equal(got[1].Payload, second) || got[1].QuickAck {
				t.Fatalf("second packet = %+v", got[1])
			}
		})
	}
}

func TestClientPacketDecoderBoundedPartialConsumption(t *testing.T) {
	packet := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	first := encodeClientInputFixture(t, obfuscated2.ConnectionTypeIntermediate, packet, false, nil)
	second := encodeClientInputFixture(t, obfuscated2.ConnectionTypeIntermediate, packet, false, nil)
	stream := append(slices.Clone(first), second...)

	decoder, err := NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, len(packet))
	if err != nil {
		t.Fatalf("NewClientPacketDecoder: %v", err)
	}
	consumed, err := decoder.Feed(stream)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if consumed != len(first) {
		t.Fatalf("Feed consumed %d, want one bounded packet %d", consumed, len(first))
	}
	if len(decoder.buffer) > len(packet)+maxClientPacketHeaderSize {
		t.Fatalf("decoder retained %d bytes over bound", len(decoder.buffer))
	}
	if cap(decoder.buffer) > len(packet)+maxClientPacketHeaderSize {
		t.Fatalf("decoder retained capacity %d over bound", cap(decoder.buffer))
	}
	if consumedAgain, err := decoder.Feed(stream[consumed:]); err != nil || consumedAgain != 0 {
		t.Fatalf("Feed before drain consumed %d, error %v", consumedAgain, err)
	}
	if _, ok, err := decoder.Next(); err != nil || !ok {
		t.Fatalf("Next first = ok %t, error %v", ok, err)
	}
	if consumedAgain, err := decoder.Feed(stream[consumed:]); err != nil || consumedAgain != len(second) {
		t.Fatalf("Feed after drain consumed %d/%d, error %v", consumedAgain, len(second), err)
	}
	if _, ok, err := decoder.Next(); err != nil || !ok {
		t.Fatalf("Next second = ok %t, error %v", ok, err)
	}
}

func TestClientPacketDecoderOwnsBoundedInputAndPayload(t *testing.T) {
	packet := make([]byte, 64)
	for i := range packet {
		packet[i] = byte(i + 1)
	}
	want := slices.Clone(packet)
	wire := encodeClientInputFixture(t, obfuscated2.ConnectionTypeIntermediate, packet, false, nil)
	hostile := make([]byte, 1<<20)
	copy(hostile, wire)
	input := hostile[:len(wire)]

	decoder, err := NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, len(packet))
	if err != nil {
		t.Fatalf("NewClientPacketDecoder: %v", err)
	}
	consumed, err := decoder.Feed(input)
	if err != nil || consumed != len(input) {
		t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(input), err)
	}
	if got, limit := cap(decoder.buffer), len(packet)+maxClientPacketHeaderSize; got > limit {
		t.Fatalf("decoder retained capacity %d over bound %d", got, limit)
	}
	input[maxClientPacketHeaderSize] ^= 0xff

	retained := decoder.buffer[:len(decoder.buffer):len(decoder.buffer)]
	decoded, ok, err := decoder.Next()
	if err != nil || !ok {
		t.Fatalf("Next = ok %t, error %v", ok, err)
	}
	if !bytes.Equal(decoded.Payload, want) {
		t.Fatalf("payload = %x, want %x", decoded.Payload, want)
	}
	if cap(decoded.Payload) != len(decoded.Payload) {
		t.Fatalf("payload capacity = %d, want exact %d", cap(decoded.Payload), len(decoded.Payload))
	}
	for i, value := range retained {
		if value != 0 {
			t.Fatalf("retained plaintext byte %d = 0x%02x after consumption", i, value)
		}
	}
	inputValue := input[maxClientPacketHeaderSize]
	decoded.Payload[0] ^= 0x80
	if input[maxClientPacketHeaderSize] != inputValue {
		t.Fatal("mutating decoded payload changed input")
	}
}

func TestClientPacketDecoderReleasesLargeCompletedBuffer(t *testing.T) {
	packet := make([]byte, maxRetainedClientPacketBuffer+4)
	packet[0] = 1
	wire := encodeClientInputFixture(t, obfuscated2.ConnectionTypeIntermediate, packet, false, nil)
	decoder, err := NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, len(packet))
	if err != nil {
		t.Fatalf("NewClientPacketDecoder: %v", err)
	}
	if consumed, err := decoder.Feed(wire); err != nil || consumed != len(wire) {
		t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(wire), err)
	}
	if decoder.BufferedBytes() != len(wire) {
		t.Fatalf("BufferedBytes = %d, want %d", decoder.BufferedBytes(), len(wire))
	}
	decoded, ok, err := decoder.Next()
	if err != nil || !ok || !bytes.Equal(decoded.Payload, packet) {
		t.Fatalf("Next = payload %x, ok %t, error %v", decoded.Payload, ok, err)
	}
	if decoder.buffer != nil || decoder.BufferedBytes() != 0 {
		t.Fatalf("completed large buffer retained length %d capacity %d", len(decoder.buffer), cap(decoder.buffer))
	}
	if decoder.RetainedCapacityBytes() != 0 {
		t.Fatalf("RetainedCapacityBytes = %d, want 0", decoder.RetainedCapacityBytes())
	}
}

func TestClientPacketDecoderClearsPrefixAndReusesBoundedBuffer(t *testing.T) {
	first := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	second := []byte{9, 10, 11, 12}
	third := []byte{13, 14, 15, 16}
	firstWire := encodeClientInputFixture(t, obfuscated2.ConnectionTypeIntermediate, first, false, nil)
	secondWire := encodeClientInputFixture(t, obfuscated2.ConnectionTypeIntermediate, second, false, nil)
	thirdWire := encodeClientInputFixture(t, obfuscated2.ConnectionTypeIntermediate, third, false, nil)
	stream := append(slices.Clone(firstWire), secondWire...)

	decoder, err := NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, 64)
	if err != nil {
		t.Fatalf("NewClientPacketDecoder: %v", err)
	}
	if consumed, err := decoder.Feed(stream); err != nil || consumed != len(stream) {
		t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(stream), err)
	}
	backing := decoder.buffer[:len(decoder.buffer):cap(decoder.buffer)]
	backingStart := &decoder.buffer[0]
	originalCapacity := cap(decoder.buffer)

	decoded, ok, err := decoder.Next()
	if err != nil || !ok || !bytes.Equal(decoded.Payload, first) {
		t.Fatalf("Next first = payload %x, ok %t, error %v", decoded.Payload, ok, err)
	}
	for i, value := range backing[:len(firstWire)] {
		if value != 0 {
			t.Fatalf("consumed prefix byte %d = 0x%02x", i, value)
		}
	}
	if !bytes.Equal(decoder.retainedPlaintext(), secondWire) {
		t.Fatalf("retained plaintext = %x, want %x", decoder.retainedPlaintext(), secondWire)
	}

	if consumed, err := decoder.Feed(thirdWire); err != nil || consumed != len(thirdWire) {
		t.Fatalf("Feed third consumed %d/%d, error %v", consumed, len(thirdWire), err)
	}
	if decoder.head != 0 {
		t.Fatalf("decoder head = %d after compaction, want 0", decoder.head)
	}
	if cap(decoder.buffer) != originalCapacity {
		t.Fatalf("decoder capacity changed from %d to %d during reuse", originalCapacity, cap(decoder.buffer))
	}
	if &decoder.buffer[0] != backingStart {
		t.Fatal("decoder reallocated despite sufficient reusable capacity")
	}
	wantRetained := append(slices.Clone(secondWire), thirdWire...)
	if !bytes.Equal(decoder.retainedPlaintext(), wantRetained) {
		t.Fatalf("retained plaintext = %x, want %x", decoder.retainedPlaintext(), wantRetained)
	}

	for i, want := range [][]byte{second, third} {
		decoded, ok, err = decoder.Next()
		if err != nil || !ok || !bytes.Equal(decoded.Payload, want) {
			t.Fatalf("Next %d = payload %x, ok %t, error %v", i+2, decoded.Payload, ok, err)
		}
		if cap(decoded.Payload) != len(decoded.Payload) {
			t.Fatalf("payload %d capacity = %d, want exact %d", i+2, cap(decoded.Payload), len(decoded.Payload))
		}
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
}

func TestClientPacketDecoderCloseClearsAndRetires(t *testing.T) {
	decoder, err := NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, 64)
	if err != nil {
		t.Fatalf("NewClientPacketDecoder: %v", err)
	}
	partial := []byte{8, 0, 0, 0, 0xaa}
	if consumed, err := decoder.Feed(partial); err != nil || consumed != len(partial) {
		t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(partial), err)
	}
	retained := decoder.buffer[:len(decoder.buffer):len(decoder.buffer)]
	if err := decoder.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := decoder.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	for i, value := range retained {
		if value != 0 {
			t.Fatalf("retained plaintext byte %d = 0x%02x after Close", i, value)
		}
	}
	if decoder.buffer != nil || decoder.head != 0 {
		t.Fatalf("retired decoder retains buffer %v or head %d", decoder.buffer, decoder.head)
	}
	if consumed, err := decoder.Feed([]byte{1}); consumed != 0 || !errors.Is(err, ErrClientPacketDecoderClosed) {
		t.Fatalf("Feed after Close consumed %d, error %v", consumed, err)
	}
	if _, ok, err := decoder.Next(); ok || !errors.Is(err, ErrClientPacketDecoderClosed) {
		t.Fatalf("Next after Close = ok %t, error %v", ok, err)
	}
	if err := decoder.Finish(); !errors.Is(err, ErrClientPacketDecoderClosed) {
		t.Fatalf("Finish after Close error = %v", err)
	}

	var nilDecoder *ClientPacketDecoder
	if err := nilDecoder.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}

func TestClientPacketDecoderRejectsMalformedHeaders(t *testing.T) {
	tests := []struct {
		name           string
		connectionType obfuscated2.ConnectionType
		maxPacketSize  int
		wire           []byte
		want           error
	}{
		{
			name:           "abridged zero words",
			connectionType: obfuscated2.ConnectionTypeAbridged,
			maxPacketSize:  16,
			wire:           []byte{0},
			want:           ErrInvalidClientPacket,
		},
		{
			name:           "abridged overlong extended header",
			connectionType: obfuscated2.ConnectionTypeAbridged,
			maxPacketSize:  1024,
			wire:           []byte{0x7f, 0x7e, 0x00, 0x00},
			want:           ErrInvalidClientPacket,
		},
		{
			name:           "abridged over maximum",
			connectionType: obfuscated2.ConnectionTypeAbridged,
			maxPacketSize:  8,
			wire:           []byte{3},
			want:           ErrClientPacketTooLarge,
		},
		{
			name:           "intermediate zero",
			connectionType: obfuscated2.ConnectionTypeIntermediate,
			maxPacketSize:  16,
			wire:           []byte{0, 0, 0, 0},
			want:           ErrInvalidClientPacket,
		},
		{
			name:           "intermediate below minimum",
			connectionType: obfuscated2.ConnectionTypeIntermediate,
			maxPacketSize:  16,
			wire:           []byte{3, 0, 0, 0},
			want:           ErrInvalidClientPacket,
		},
		{
			name:           "intermediate unaligned",
			connectionType: obfuscated2.ConnectionTypeIntermediate,
			maxPacketSize:  16,
			wire:           []byte{6, 0, 0, 0},
			want:           ErrInvalidClientPacket,
		},
		{
			name:           "intermediate reserved high bit",
			connectionType: obfuscated2.ConnectionTypeIntermediate,
			maxPacketSize:  16,
			wire:           []byte{4, 0, 0, 0x40},
			want:           ErrInvalidClientPacket,
		},
		{
			name:           "intermediate quick ack over maximum",
			connectionType: obfuscated2.ConnectionTypeIntermediate,
			maxPacketSize:  8,
			wire:           []byte{12, 0, 0, 0x80},
			want:           ErrClientPacketTooLarge,
		},
		{
			name:           "padded below minimum",
			connectionType: obfuscated2.ConnectionTypePaddedIntermediate,
			maxPacketSize:  16,
			wire:           []byte{3, 0, 0, 0},
			want:           ErrInvalidClientPacket,
		},
		{
			name:           "padded declared wire length over maximum",
			connectionType: obfuscated2.ConnectionTypePaddedIntermediate,
			maxPacketSize:  8,
			wire:           []byte{12, 0, 0, 0},
			want:           ErrClientPacketTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decoder, err := NewClientPacketDecoder(tc.connectionType, tc.maxPacketSize)
			if err != nil {
				t.Fatalf("NewClientPacketDecoder: %v", err)
			}
			if consumed, err := decoder.Feed(tc.wire); err != nil || consumed != len(tc.wire) {
				t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(tc.wire), err)
			}
			retained := decoder.buffer[:len(decoder.buffer):len(decoder.buffer)]
			if _, _, err := decoder.Next(); !errors.Is(err, tc.want) {
				t.Fatalf("Next error = %v, want %v", err, tc.want)
			}
			for i, value := range retained {
				if value != 0 {
					t.Fatalf("retained plaintext byte %d = 0x%02x after failure", i, value)
				}
			}
			if decoder.buffer != nil || decoder.head != 0 {
				t.Fatalf("failed decoder retains buffer %v or head %d", decoder.buffer, decoder.head)
			}
			if consumed, err := decoder.Feed([]byte{1}); consumed != 0 || !errors.Is(err, tc.want) {
				t.Fatalf("Feed after failure consumed %d, error %v", consumed, err)
			}
			if err := decoder.Finish(); !errors.Is(err, tc.want) {
				t.Fatalf("Finish after failure error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestClientPacketDecoderFinishRejectsTruncation(t *testing.T) {
	tests := []struct {
		name           string
		connectionType obfuscated2.ConnectionType
		wire           []byte
	}{
		{name: "abridged partial extended header", connectionType: obfuscated2.ConnectionTypeAbridged, wire: []byte{0x7f, 0x7f}},
		{name: "abridged partial packet", connectionType: obfuscated2.ConnectionTypeAbridged, wire: []byte{2, 1, 2}},
		{name: "intermediate partial header", connectionType: obfuscated2.ConnectionTypeIntermediate, wire: []byte{8, 0, 0}},
		{name: "padded partial packet", connectionType: obfuscated2.ConnectionTypePaddedIntermediate, wire: []byte{7, 0, 0, 0, 1, 2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			decoder, err := NewClientPacketDecoder(tc.connectionType, 64)
			if err != nil {
				t.Fatalf("NewClientPacketDecoder: %v", err)
			}
			if consumed, err := decoder.Feed(tc.wire); err != nil || consumed != len(tc.wire) {
				t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(tc.wire), err)
			}
			if _, ok, err := decoder.Next(); err != nil || ok {
				t.Fatalf("Next = ok %t, error %v", ok, err)
			}
			retained := decoder.buffer[:len(decoder.buffer):len(decoder.buffer)]
			if err := decoder.Finish(); !errors.Is(err, ErrIncompleteClientPacket) {
				t.Fatalf("Finish error = %v, want %v", err, ErrIncompleteClientPacket)
			}
			for i, value := range retained {
				if value != 0 {
					t.Fatalf("retained plaintext byte %d = 0x%02x after Finish", i, value)
				}
			}
			if decoder.buffer != nil || decoder.head != 0 {
				t.Fatalf("finished decoder retains buffer %v or head %d", decoder.buffer, decoder.head)
			}
			if consumed, err := decoder.Feed([]byte{1}); consumed != 0 || !errors.Is(err, ErrIncompleteClientPacket) {
				t.Fatalf("Feed after Finish consumed %d, error %v", consumed, err)
			}
			if _, ok, err := decoder.Next(); ok || !errors.Is(err, ErrIncompleteClientPacket) {
				t.Fatalf("Next after Finish = ok %t, error %v", ok, err)
			}
			if err := decoder.Close(); err != nil {
				t.Fatalf("Close after Finish: %v", err)
			}
			if err := decoder.Finish(); !errors.Is(err, ErrIncompleteClientPacket) {
				t.Fatalf("Finish after Close error = %v, want sticky truncation", err)
			}
		})
	}
}

func TestClientPacketCodecConstructorsRejectInvalidBounds(t *testing.T) {
	for _, connectionType := range []obfuscated2.ConnectionType{
		obfuscated2.ConnectionTypeAbridged,
		obfuscated2.ConnectionTypeIntermediate,
		obfuscated2.ConnectionTypePaddedIntermediate,
	} {
		if _, err := NewClientPacketDecoder(connectionType, 3); !errors.Is(err, ErrInvalidClientPacket) {
			t.Errorf("decoder short maximum error = %v", err)
		}
		if _, err := NewClientPacketEncoder(connectionType, MaxClientPacketSize+1); !errors.Is(err, ErrClientPacketTooLarge) {
			t.Errorf("encoder large maximum error = %v", err)
		}
	}
	if _, err := NewClientPacketDecoder(obfuscated2.ConnectionType(1), 64); !errors.Is(err, ErrUnsupportedClientFraming) {
		t.Fatalf("decoder framing error = %v, want %v", err, ErrUnsupportedClientFraming)
	}
	if _, err := NewClientPacketEncoder(obfuscated2.ConnectionType(1), 64); !errors.Is(err, ErrUnsupportedClientFraming) {
		t.Fatalf("encoder framing error = %v, want %v", err, ErrUnsupportedClientFraming)
	}
	if _, err := newClientPacketEncoder(obfuscated2.ConnectionTypeIntermediate, 64, nil); !errors.Is(err, ErrInvalidClientPacket) {
		t.Fatalf("nil source error = %v, want %v", err, ErrInvalidClientPacket)
	}
}

func TestClientPacketEncoderGoldenResponses(t *testing.T) {
	shortPacket := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	longPacket := make([]byte, 0x7f*4)
	for i := range longPacket {
		longPacket[i] = byte(i)
	}

	tests := []struct {
		name           string
		connectionType obfuscated2.ConnectionType
		packet         []byte
		paddingSource  io.Reader
		want           []byte
	}{
		{
			name:           "abridged short",
			connectionType: obfuscated2.ConnectionTypeAbridged,
			packet:         shortPacket,
			paddingSource:  bytes.NewReader(nil),
			want:           mustDecodeHex(t, "020001020304050607"),
		},
		{
			name:           "abridged extended",
			connectionType: obfuscated2.ConnectionTypeAbridged,
			packet:         longPacket,
			paddingSource:  bytes.NewReader(nil),
			want:           append([]byte{0x7f, 0x7f, 0, 0}, longPacket...),
		},
		{
			name:           "intermediate",
			connectionType: obfuscated2.ConnectionTypeIntermediate,
			packet:         shortPacket,
			paddingSource:  bytes.NewReader(nil),
			want:           mustDecodeHex(t, "080000000001020304050607"),
		},
		{
			name:           "padded intermediate three bytes",
			connectionType: obfuscated2.ConnectionTypePaddedIntermediate,
			packet:         shortPacket,
			paddingSource:  bytes.NewReader([]byte{3, 0xa0, 0xa1, 0xa2}),
			want:           mustDecodeHex(t, "0b0000000001020304050607a0a1a2"),
		},
		{
			name:           "padded intermediate one byte",
			connectionType: obfuscated2.ConnectionTypePaddedIntermediate,
			packet:         shortPacket,
			paddingSource:  bytes.NewReader([]byte{1, 0xa0}),
			want:           mustDecodeHex(t, "090000000001020304050607a0"),
		},
		{
			name:           "padded intermediate two bytes",
			connectionType: obfuscated2.ConnectionTypePaddedIntermediate,
			packet:         shortPacket,
			paddingSource:  bytes.NewReader([]byte{2, 0xa0, 0xa1}),
			want:           mustDecodeHex(t, "0a0000000001020304050607a0a1"),
		},
		{
			name:           "padded intermediate zero bytes",
			connectionType: obfuscated2.ConnectionTypePaddedIntermediate,
			packet:         shortPacket,
			paddingSource:  bytes.NewReader([]byte{0}),
			want:           mustDecodeHex(t, "080000000001020304050607"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantPacket := slices.Clone(tc.packet)
			encoder, err := newClientPacketEncoder(tc.connectionType, 1024, tc.paddingSource)
			if err != nil {
				t.Fatalf("newClientPacketEncoder: %v", err)
			}
			wire, err := encoder.Encode(tc.packet)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if !bytes.Equal(wire, tc.want) {
				t.Fatalf("wire = %x, want %x", wire, tc.want)
			}
			wire[len(wire)-1] ^= 0xff
			if !bytes.Equal(tc.packet, wantPacket) {
				t.Fatal("encoded wire aliases its packet input")
			}
		})
	}
}

func TestClientPacketEncoderMaximumPaddedPacketAllPaddingSizes(t *testing.T) {
	packet := make([]byte, MaxClientPacketSize)
	for paddingSize := range 4 {
		t.Run(fmt.Sprintf("padding_%d", paddingSize), func(t *testing.T) {
			paddingBytes := bytes.Repeat([]byte{0xa5}, paddingSize)
			source := bytes.NewReader(append([]byte{byte(paddingSize)}, paddingBytes...))
			encoder, err := newClientPacketEncoder(
				obfuscated2.ConnectionTypePaddedIntermediate,
				MaxClientPacketSize,
				source,
			)
			if err != nil {
				t.Fatalf("newClientPacketEncoder: %v", err)
			}
			wire, err := encoder.Encode(packet)
			if err != nil {
				t.Fatalf("Encode maximum packet: %v", err)
			}
			if got, want := len(wire), maxClientPacketHeaderSize+MaxClientPacketSize+paddingSize; got != want {
				t.Fatalf("wire length = %d, want %d", got, want)
			}

			decoder, err := NewClientPacketDecoder(obfuscated2.ConnectionTypePaddedIntermediate, MaxClientPacketSize)
			if err != nil {
				t.Fatalf("NewClientPacketDecoder: %v", err)
			}
			consumed, err := decoder.Feed(wire)
			if err != nil {
				t.Fatalf("Feed: %v", err)
			}
			if paddingSize == 0 {
				if consumed != len(wire) {
					t.Fatalf("Feed consumed %d/%d", consumed, len(wire))
				}
				decoded, ok, err := decoder.Next()
				if err != nil || !ok || len(decoded.Payload) != MaxClientPacketSize {
					t.Fatalf("Next = payload %d, ok %t, error %v", len(decoded.Payload), ok, err)
				}
				return
			}
			if got, want := consumed, maxClientPacketHeaderSize+MaxClientPacketSize; got != want {
				t.Fatalf("Feed consumed %d, want official retention cap %d", got, want)
			}
			if _, _, err := decoder.Next(); !errors.Is(err, ErrClientPacketTooLarge) {
				t.Fatalf("Next error = %v, want %v", err, ErrClientPacketTooLarge)
			}
		})
	}
}

func TestClientPacketDecoderPaddedOfficialWireBoundary(t *testing.T) {
	for paddingSize := range 4 {
		t.Run(fmt.Sprintf("padding_%d", paddingSize), func(t *testing.T) {
			payloadSize := MaxClientPacketSize
			if paddingSize != 0 {
				payloadSize -= 4
			}
			payload := make([]byte, payloadSize)
			padding := bytes.Repeat([]byte{0xa5}, paddingSize)
			wire := encodeClientInputFixture(
				t,
				obfuscated2.ConnectionTypePaddedIntermediate,
				payload,
				false,
				padding,
			)
			if len(wire)-maxClientPacketHeaderSize > MaxClientPacketSize {
				t.Fatalf("fixture declared size %d exceeds official bound", len(wire)-maxClientPacketHeaderSize)
			}
			decoder, err := NewClientPacketDecoder(obfuscated2.ConnectionTypePaddedIntermediate, MaxClientPacketSize)
			if err != nil {
				t.Fatalf("NewClientPacketDecoder: %v", err)
			}
			if consumed, err := decoder.Feed(wire); err != nil || consumed != len(wire) {
				t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(wire), err)
			}
			decoded, ok, err := decoder.Next()
			if err != nil || !ok || len(decoded.Payload) != payloadSize {
				t.Fatalf("Next = payload %d, ok %t, error %v", len(decoded.Payload), ok, err)
			}
		})
	}
}

func TestClientPacketEncoderRejectsInvalidPacketsAndRandomFailure(t *testing.T) {
	encoder, err := NewClientPacketEncoder(obfuscated2.ConnectionTypeIntermediate, 16)
	if err != nil {
		t.Fatalf("NewClientPacketEncoder: %v", err)
	}
	for _, packet := range [][]byte{nil, {1, 2, 3}, {1, 2, 3, 4, 5}} {
		if _, err := encoder.Encode(packet); !errors.Is(err, ErrInvalidClientPacket) {
			t.Fatalf("packet length %d error = %v, want %v", len(packet), err, ErrInvalidClientPacket)
		}
	}
	if _, err := encoder.Encode(make([]byte, 20)); !errors.Is(err, ErrClientPacketTooLarge) {
		t.Fatalf("large packet error = %v, want %v", err, ErrClientPacketTooLarge)
	}

	wantErr := errors.New("random failed")
	padded, err := newClientPacketEncoder(obfuscated2.ConnectionTypePaddedIntermediate, 16, errReader{err: wantErr})
	if err != nil {
		t.Fatalf("newClientPacketEncoder: %v", err)
	}
	if _, err := padded.Encode(make([]byte, 8)); !errors.Is(err, wantErr) {
		t.Fatalf("padding error = %v, want %v", err, wantErr)
	}
}

func TestRandomBoundedIntRejectsBiasedTail(t *testing.T) {
	got, err := randomBoundedInt(bytes.NewReader([]byte{0xff, 0x02}), 2)
	if err != nil {
		t.Fatalf("randomBoundedInt: %v", err)
	}
	if got != 2 {
		t.Fatalf("randomBoundedInt = %d, want 2", got)
	}
}

func TestEncodeSimpleAckForClientByteOrder(t *testing.T) {
	const confirmKey = 0x11223344
	tests := []struct {
		name           string
		connectionType obfuscated2.ConnectionType
		want           []byte
	}{
		{name: "abridged big endian", connectionType: obfuscated2.ConnectionTypeAbridged, want: []byte{0x11, 0x22, 0x33, 0x44}},
		{name: "intermediate little endian", connectionType: obfuscated2.ConnectionTypeIntermediate, want: []byte{0x44, 0x33, 0x22, 0x11}},
		{name: "padded intermediate little endian", connectionType: obfuscated2.ConnectionTypePaddedIntermediate, want: []byte{0x44, 0x33, 0x22, 0x11}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EncodeSimpleAckForClient(tc.connectionType, confirmKey)
			if err != nil {
				t.Fatalf("EncodeSimpleAckForClient: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("ack = %x, want %x", got, tc.want)
			}
		})
	}
	if _, err := EncodeSimpleAckForClient(obfuscated2.ConnectionType(1), confirmKey); !errors.Is(err, ErrUnsupportedClientFraming) {
		t.Fatalf("unsupported error = %v, want %v", err, ErrUnsupportedClientFraming)
	}
}

func FuzzClientPacketDecoderPartitionsAndCoalescing(f *testing.F) {
	f.Add(byte(0), []byte{})
	f.Add(byte(1), []byte{0})
	f.Add(byte(2), []byte{1, 2, 3, 7, 15, 31, 63, 255})

	f.Fuzz(func(t *testing.T, typeSelector byte, partitions []byte) {
		connectionType := clientConnectionTypeFromSelector(typeSelector)
		first := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		second := []byte{9, 10, 11, 12}
		firstWire := encodeClientInputFixture(t, connectionType, first, true, []byte{0xaa, 0xbb})
		secondWire := encodeClientInputFixture(t, connectionType, second, false, []byte{0xcc})
		stream := append(slices.Clone(firstWire), secondWire...)

		decoder, err := NewClientPacketDecoder(connectionType, 64)
		if err != nil {
			t.Fatalf("NewClientPacketDecoder: %v", err)
		}
		var got []ClientPacket
		feedClientPartitions(t, decoder, stream, partitions, &got)
		if err := decoder.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		if len(got) != 2 || !bytes.Equal(got[0].Payload, first) || !got[0].QuickAck || !bytes.Equal(got[1].Payload, second) || got[1].QuickAck {
			t.Fatalf("decoded packets = %+v", got)
		}
	})
}

func FuzzClientPacketEncoderRoundTrip(f *testing.F) {
	f.Add(byte(0), []byte{})
	f.Add(byte(1), []byte{1, 2, 3, 4})
	f.Add(byte(2), bytes.Repeat([]byte{0xff}, 65))

	f.Fuzz(func(t *testing.T, typeSelector byte, input []byte) {
		connectionType := clientConnectionTypeFromSelector(typeSelector)
		input = input[:min(len(input), 4096)]
		packetSize := max(4, (len(input)+3)&^3)
		packet := make([]byte, packetSize)
		copy(packet, input)

		encoder, err := newClientPacketEncoder(connectionType, 8192, bytes.NewReader(bytes.Repeat([]byte{3, 0xaa, 0xbb, 0xcc}, 4)))
		if err != nil {
			t.Fatalf("newClientPacketEncoder: %v", err)
		}
		wire, err := encoder.Encode(packet)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		decoder, err := NewClientPacketDecoder(connectionType, 8192)
		if err != nil {
			t.Fatalf("NewClientPacketDecoder: %v", err)
		}
		if consumed, err := decoder.Feed(wire); err != nil || consumed != len(wire) {
			t.Fatalf("Feed consumed %d/%d, error %v", consumed, len(wire), err)
		}
		decoded, ok, err := decoder.Next()
		if err != nil || !ok {
			t.Fatalf("Next = ok %t, error %v", ok, err)
		}
		if !bytes.Equal(decoded.Payload, packet) || decoded.QuickAck {
			t.Fatalf("decoded packet = %+v, want %x", decoded, packet)
		}
	})
}

func FuzzClientPacketDecoderMalformedBounded(f *testing.F) {
	f.Add(byte(0), []byte{}, []byte{})
	f.Add(byte(1), []byte{0xff, 0xff, 0xff, 0xff}, []byte{1})
	f.Add(byte(2), bytes.Repeat([]byte{0}, 300), []byte{1, 3, 7})

	f.Fuzz(func(t *testing.T, typeSelector byte, input, partitions []byte) {
		const maxPacketSize = 256
		connectionType := clientConnectionTypeFromSelector(typeSelector)
		maximumBuffered := maxPacketSize + maxClientPacketHeaderSize
		input = slices.Clone(input[:min(len(input), maximumBuffered+1)])
		decoder, err := NewClientPacketDecoder(connectionType, maxPacketSize)
		if err != nil {
			t.Fatalf("NewClientPacketDecoder: %v", err)
		}

		feedMalformedClientPartitions(decoder, input, partitions)
		if len(decoder.buffer) > maximumBuffered || cap(decoder.buffer) > maximumBuffered {
			t.Fatalf(
				"decoder retained len %d cap %d over bound %d",
				len(decoder.buffer),
				cap(decoder.buffer),
				maximumBuffered,
			)
		}
		_ = decoder.Finish()
	})
}

type errReader struct {
	err error
}

func (r errReader) Read([]byte) (int, error) {
	return 0, r.err
}

func encodeClientInputFixture(
	t *testing.T,
	connectionType obfuscated2.ConnectionType,
	packet []byte,
	quickAck bool,
	padding []byte,
) []byte {
	t.Helper()
	switch connectionType {
	case obfuscated2.ConnectionTypeAbridged:
		wordCount := len(packet) / 4
		if wordCount <= 0x7e {
			header := byte(wordCount)
			if quickAck {
				header |= 0x80
			}
			return append([]byte{header}, packet...)
		}
		header := []byte{0x7f, byte(wordCount), byte(wordCount >> 8), byte(wordCount >> 16)}
		if quickAck {
			header[0] |= 0x80
		}
		return append(header, packet...)
	case obfuscated2.ConnectionTypeIntermediate, obfuscated2.ConnectionTypePaddedIntermediate:
		if connectionType == obfuscated2.ConnectionTypeIntermediate {
			padding = nil
		}
		wireSize := len(packet) + len(padding)
		header := uint32(wireSize)
		if quickAck {
			header |= uint32(ProxyRequestFlagQuickAck)
		}
		wire := binary.LittleEndian.AppendUint32(nil, header)
		wire = append(wire, packet...)
		wire = append(wire, padding...)
		return wire
	default:
		t.Fatalf("unsupported fixture connection type %08x", uint32(connectionType))
		return nil
	}
}

func feedClientPartitions(
	t *testing.T,
	decoder *ClientPacketDecoder,
	stream, partitions []byte,
	packets *[]ClientPacket,
) {
	t.Helper()
	consume := func(chunk []byte) {
		for len(chunk) != 0 {
			consumed, err := decoder.Feed(chunk)
			if err != nil {
				t.Fatalf("Feed: %v", err)
			}
			chunk = chunk[consumed:]
			progressed := consumed != 0
			for {
				packet, ok, err := decoder.Next()
				if err != nil {
					t.Fatalf("Next: %v", err)
				}
				if !ok {
					break
				}
				*packets = append(*packets, packet)
				progressed = true
			}
			if !progressed {
				t.Fatal("decoder made no progress")
			}
		}
	}
	if len(partitions) == 0 {
		consume(stream)
		return
	}
	for offset, partitionIndex := 0, 0; offset < len(stream); partitionIndex++ {
		chunkSize := int(partitions[partitionIndex%len(partitions)]) + 1
		end := min(offset+chunkSize, len(stream))
		consume(stream[offset:end])
		offset = end
	}
}

func feedMalformedClientPartitions(decoder *ClientPacketDecoder, stream, partitions []byte) {
	consume := func(chunk []byte) bool {
		for len(chunk) != 0 {
			consumed, err := decoder.Feed(chunk)
			if err != nil {
				return false
			}
			chunk = chunk[consumed:]
			progressed := consumed != 0
			for range 65 {
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
	}
	if len(partitions) == 0 {
		consume(stream)
		return
	}
	for offset, partitionIndex := 0, 0; offset < len(stream); partitionIndex++ {
		chunkSize := int(partitions[partitionIndex%len(partitions)]) + 1
		end := min(offset+chunkSize, len(stream))
		if !consume(stream[offset:end]) {
			return
		}
		offset = end
	}
}

func clientConnectionTypeFromSelector(selector byte) obfuscated2.ConnectionType {
	switch selector % 3 {
	case 0:
		return obfuscated2.ConnectionTypeAbridged
	case 1:
		return obfuscated2.ConnectionTypeIntermediate
	default:
		return obfuscated2.ConnectionTypePaddedIntermediate
	}
}

func clientFramingName(connectionType obfuscated2.ConnectionType) string {
	switch connectionType {
	case obfuscated2.ConnectionTypeAbridged:
		return "abridged"
	case obfuscated2.ConnectionTypeIntermediate:
		return "intermediate"
	case obfuscated2.ConnectionTypePaddedIntermediate:
		return "padded intermediate"
	default:
		return "unsupported"
	}
}
