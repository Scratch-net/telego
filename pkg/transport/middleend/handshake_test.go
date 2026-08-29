package middleend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNoncePacketGoldenRoundTripAndValidation(t *testing.T) {
	var nonce [16]byte
	for i := range nonce {
		nonce[i] = byte(0xf0 + i)
	}
	packet := NoncePacket{
		KeySelector: 0x04030201,
		Timestamp:   0x66332211,
		Nonce:       nonce,
	}
	want := mustDecodeHex(t, "aa87cb7a010203040100000011223366f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("nonce packet = %x, want %x", wire, want)
	}
	parsed, err := ParseNoncePacket(wire)
	if err != nil {
		t.Fatalf("ParseNoncePacket: %v", err)
	}
	if parsed != packet {
		t.Fatalf("parsed packet = %+v, want %+v", parsed, packet)
	}
	if err := parsed.Validate(packet.KeySelector, time.Unix(int64(packet.Timestamp)+30, 0)); err != nil {
		t.Fatalf("Validate at skew boundary: %v", err)
	}
}

func TestNoncePacketRejectsInvalidData(t *testing.T) {
	valid := mustDecodeHex(t, "aa87cb7a010203040100000011223366f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	tests := []struct {
		name string
		wire func() []byte
	}{
		{name: "short", wire: func() []byte { return slices.Clone(valid[:31]) }},
		{
			name: "wrong operation",
			wire: func() []byte {
				wire := slices.Clone(valid)
				binary.LittleEndian.PutUint32(wire[:4], 1)
				return wire
			},
		},
		{
			name: "zero selector",
			wire: func() []byte {
				wire := slices.Clone(valid)
				binary.LittleEndian.PutUint32(wire[4:8], 0)
				return wire
			},
		},
		{
			name: "unsupported schema",
			wire: func() []byte {
				wire := slices.Clone(valid)
				binary.LittleEndian.PutUint32(wire[8:12], 3)
				return wire
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseNoncePacket(tc.wire())
			if !errors.Is(err, ErrInvalidNonce) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidNonce)
			}
		})
	}

	if _, err := (NoncePacket{}).MarshalBinary(); !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("zero-selector MarshalBinary error = %v, want %v", err, ErrInvalidNonce)
	}
}

func TestNoncePacketValidationFailures(t *testing.T) {
	packet := NoncePacket{KeySelector: 7, Timestamp: 1_000}
	if err := packet.Validate(8, time.Unix(1_000, 0)); !errors.Is(err, ErrKeySelector) {
		t.Fatalf("selector error = %v, want %v", err, ErrKeySelector)
	}
	for _, reference := range []int64{969, 1_031} {
		if err := packet.Validate(7, time.Unix(reference, 0)); !errors.Is(err, ErrTimestampSkew) {
			t.Fatalf("timestamp %d error = %v, want %v", reference, err, ErrTimestampSkew)
		}
	}
}

func TestHandshakePacketGoldenRoundTrip(t *testing.T) {
	packet := HandshakePacket{
		Flags: HandshakeFlagCRC32C,
		Sender: ProcessID{
			IP:     0xc6336414,
			Port:   54321,
			PID:    1234,
			Uptime: 0x66330000,
		},
		Peer: ProcessID{
			IP:   0xc000020a,
			Port: 8888,
		},
	}
	want := mustDecodeHex(t, "f5ee827600080000146433c631d4d204000033660a0200c0b822000000000000")

	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("handshake = %x, want %x", wire, want)
	}
	parsed, err := ParseHandshakePacket(wire)
	if err != nil {
		t.Fatalf("ParseHandshakePacket: %v", err)
	}
	if !reflect.DeepEqual(parsed, packet) {
		t.Fatalf("parsed = %+v, want %+v", parsed, packet)
	}
	if parsed.NegotiatedChecksum() != ChecksumCRC32C {
		t.Fatalf("checksum = %d, want CRC32C", parsed.NegotiatedChecksum())
	}

	local := ProcessID{IP: packet.Peer.IP, Port: packet.Peer.Port, PID: 9, Uptime: 10}
	if err := parsed.ValidatePeer(local); err != nil {
		t.Fatalf("ValidatePeer wildcard match: %v", err)
	}
	if err := parsed.ValidatePeer(ProcessID{IP: 1, Port: packet.Peer.Port}); !errors.Is(err, ErrProcessIDMismatch) {
		t.Fatalf("ValidatePeer mismatch = %v, want %v", err, ErrProcessIDMismatch)
	}
}

func TestHandshakePacketRejectsInvalidData(t *testing.T) {
	valid := mustDecodeHex(t, "f5ee827600080000146433c631d4d204000033660a0200c0b822000000000000")
	tests := []struct {
		name string
		wire func() []byte
	}{
		{name: "short", wire: func() []byte { return slices.Clone(valid[:31]) }},
		{
			name: "wrong operation",
			wire: func() []byte {
				wire := slices.Clone(valid)
				binary.LittleEndian.PutUint32(wire[:4], 1)
				return wire
			},
		},
		{
			name: "low byte flag",
			wire: func() []byte {
				wire := slices.Clone(valid)
				binary.LittleEndian.PutUint32(wire[4:8], 1)
				return wire
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseHandshakePacket(tc.wire())
			if !errors.Is(err, ErrInvalidHandshake) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidHandshake)
			}
		})
	}
}

func TestHandshakeErrorPacketRoundTrip(t *testing.T) {
	want := HandshakeErrorPacket{
		ErrorCode: -8,
		Sender:    ProcessID{IP: 0x01020304, Port: 443, PID: 99, Uptime: 12345},
	}
	wire := want.MarshalBinary()
	got, err := ParseHandshakeErrorPacket(wire)
	if err != nil {
		t.Fatalf("ParseHandshakeErrorPacket: %v", err)
	}
	if got != want {
		t.Fatalf("parsed = %+v, want %+v", got, want)
	}

	badOperation := slices.Clone(wire)
	binary.LittleEndian.PutUint32(badOperation[:4], OperationHandshake)
	if _, err := ParseHandshakeErrorPacket(badOperation); !errors.Is(err, ErrInvalidHandshake) {
		t.Fatalf("operation error = %v, want %v", err, ErrInvalidHandshake)
	}
	if _, err := ParseHandshakeErrorPacket(wire[:len(wire)-1]); !errors.Is(err, ErrInvalidHandshake) {
		t.Fatalf("length error = %v, want %v", err, ErrInvalidHandshake)
	}
}

func TestProcessIDMatchesWildcards(t *testing.T) {
	processID := ProcessID{IP: 1, Port: 2, PID: 3, Uptime: 4}
	if !processID.Matches(ProcessID{}) {
		t.Fatal("zero pattern did not match")
	}
	if !processID.Matches(processID) {
		t.Fatal("exact pattern did not match")
	}
	if processID.Matches(ProcessID{PID: 5}) {
		t.Fatal("different nonzero PID matched")
	}
}

func TestHandshakePeerMismatchErrorNamesFieldsWithoutValues(t *testing.T) {
	local := ProcessID{
		IP:     0x11223344,
		Port:   12345,
		PID:    23456,
		Uptime: 1_700_000_000,
	}
	packet := HandshakePacket{
		Peer: ProcessID{
			IP:     0x55667788,
			Port:   54321,
			PID:    34567,
			Uptime: 1_600_000_000,
		},
	}

	err := packet.ValidatePeer(local)
	if !errors.Is(err, ErrProcessIDMismatch) {
		t.Fatalf("ValidatePeer error = %v, want %v", err, ErrProcessIDMismatch)
	}
	message := err.Error()
	for _, field := range []string{"ip", "port", "pid", "uptime"} {
		if !strings.Contains(message, field) {
			t.Errorf("error %q does not identify mismatched %s field", message, field)
		}
	}
	for _, value := range []string{
		"11223344", "55667788",
		"287454020", "1432778632",
		"12345", "54321", "23456", "34567",
		"1700000000", "1600000000",
	} {
		if strings.Contains(message, value) {
			t.Errorf("error %q contains process/address value %q", message, value)
		}
	}
}
