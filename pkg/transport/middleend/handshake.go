package middleend

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// NoncePacket is Telegram's fixed 32-byte AES nonce negotiation payload.
type NoncePacket struct {
	KeySelector uint32
	Timestamp   int32
	Nonce       [16]byte
}

// String prevents accidental disclosure of nonce and key-selector material.
func (NoncePacket) String() string {
	return "middleend.NoncePacket{redacted}"
}

// GoString prevents accidental disclosure of nonce and key-selector material.
func (NoncePacket) GoString() string {
	return "middleend.NoncePacket{redacted}"
}

// MarshalBinary encodes a strict AES nonce packet.
func (p NoncePacket) MarshalBinary() ([]byte, error) {
	if p.KeySelector == 0 {
		return nil, fmt.Errorf("%w: key selector is zero", ErrInvalidNonce)
	}

	wire := make([]byte, NoncePacketSize)
	binary.LittleEndian.PutUint32(wire[0:4], OperationNonce)
	binary.LittleEndian.PutUint32(wire[4:8], p.KeySelector)
	binary.LittleEndian.PutUint32(wire[8:12], uint32(CryptoSchemaAES))
	binary.LittleEndian.PutUint32(wire[12:16], uint32(p.Timestamp))
	copy(wire[16:], p.Nonce[:])
	return wire, nil
}

// ParseNoncePacket decodes the AES-only nonce form used by Middle-End links.
func ParseNoncePacket(wire []byte) (NoncePacket, error) {
	var packet NoncePacket
	if len(wire) != NoncePacketSize {
		return packet, fmt.Errorf("%w: length %d, want %d", ErrInvalidNonce, len(wire), NoncePacketSize)
	}
	if operation := binary.LittleEndian.Uint32(wire[0:4]); operation != OperationNonce {
		return packet, fmt.Errorf("%w: operation %08x", ErrInvalidNonce, operation)
	}
	packet.KeySelector = binary.LittleEndian.Uint32(wire[4:8])
	if packet.KeySelector == 0 {
		return NoncePacket{}, fmt.Errorf("%w: key selector is zero", ErrInvalidNonce)
	}
	if schema := int32(binary.LittleEndian.Uint32(wire[8:12])); schema != CryptoSchemaAES {
		return NoncePacket{}, fmt.Errorf("%w: crypto schema %d", ErrInvalidNonce, schema)
	}
	packet.Timestamp = int32(binary.LittleEndian.Uint32(wire[12:16]))
	copy(packet.Nonce[:], wire[16:])
	return packet, nil
}

// Validate checks the infrastructure secret selector and the official
// 30-second timestamp tolerance against referenceTime.
func (p NoncePacket) Validate(expectedSelector uint32, referenceTime time.Time) error {
	if expectedSelector == 0 || p.KeySelector != expectedSelector {
		return ErrKeySelector
	}
	delta := int64(p.Timestamp) - referenceTime.Unix()
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(NonceClockSkew/time.Second) {
		return fmt.Errorf("%w: %d seconds", ErrTimestampSkew, delta)
	}
	return nil
}

// ProcessID is the 12-byte process identifier embedded in an RPC handshake.
type ProcessID struct {
	IP     uint32
	Port   uint16
	PID    uint16
	Uptime int32
}

// Matches reports whether p matches pattern. Zero fields in pattern are
// wildcards, matching Telegram's common/pid.c semantics.
func (p ProcessID) Matches(pattern ProcessID) bool {
	return (pattern.IP == 0 || p.IP == pattern.IP) &&
		(pattern.Port == 0 || p.Port == pattern.Port) &&
		(pattern.PID == 0 || p.PID == pattern.PID) &&
		(pattern.Uptime == 0 || p.Uptime == pattern.Uptime)
}

// HandshakePacket is the fixed 32-byte RPC handshake payload.
type HandshakePacket struct {
	Flags  uint32
	Sender ProcessID
	Peer   ProcessID
}

// MarshalBinary encodes a handshake payload.
func (p HandshakePacket) MarshalBinary() ([]byte, error) {
	if err := validateHandshakeFlags(p.Flags); err != nil {
		return nil, err
	}
	wire := make([]byte, HandshakePacketSize)
	binary.LittleEndian.PutUint32(wire[0:4], OperationHandshake)
	binary.LittleEndian.PutUint32(wire[4:8], p.Flags)
	putProcessID(wire[8:20], p.Sender)
	putProcessID(wire[20:32], p.Peer)
	return wire, nil
}

// ParseHandshakePacket decodes and validates a handshake payload.
func ParseHandshakePacket(wire []byte) (HandshakePacket, error) {
	var packet HandshakePacket
	if len(wire) != HandshakePacketSize {
		return packet, fmt.Errorf("%w: length %d, want %d", ErrInvalidHandshake, len(wire), HandshakePacketSize)
	}
	if operation := binary.LittleEndian.Uint32(wire[0:4]); operation != OperationHandshake {
		return packet, fmt.Errorf("%w: operation %08x", ErrInvalidHandshake, operation)
	}
	packet.Flags = binary.LittleEndian.Uint32(wire[4:8])
	if err := validateHandshakeFlags(packet.Flags); err != nil {
		return HandshakePacket{}, err
	}
	packet.Sender = parseProcessID(wire[8:20])
	packet.Peer = parseProcessID(wire[20:32])
	return packet, nil
}

// ValidatePeer verifies the peer pattern from the remote handshake against the
// local process identifier.
func (p HandshakePacket) ValidatePeer(local ProcessID) error {
	if !local.Matches(p.Peer) {
		fields := mismatchedProcessIDFields(local, p.Peer)
		return fmt.Errorf("%w: peer pattern fields %s do not match", ErrProcessIDMismatch, strings.Join(fields, ","))
	}
	return nil
}

func mismatchedProcessIDFields(local, pattern ProcessID) []string {
	fields := make([]string, 0, 4)
	if pattern.IP != 0 && local.IP != pattern.IP {
		fields = append(fields, "ip")
	}
	if pattern.Port != 0 && local.Port != pattern.Port {
		fields = append(fields, "port")
	}
	if pattern.PID != 0 && local.PID != pattern.PID {
		fields = append(fields, "pid")
	}
	if pattern.Uptime != 0 && local.Uptime != pattern.Uptime {
		fields = append(fields, "uptime")
	}
	return fields
}

// NegotiatedChecksum returns the checksum requested or accepted by the
// handshake flags.
func (p HandshakePacket) NegotiatedChecksum() ChecksumMode {
	if p.Flags&HandshakeFlagCRC32C != 0 {
		return ChecksumCRC32C
	}
	return ChecksumCRC32
}

// HandshakeErrorPacket is the fixed 20-byte RPC handshake rejection payload.
type HandshakeErrorPacket struct {
	ErrorCode int32
	Sender    ProcessID
}

// MarshalBinary encodes a handshake rejection payload.
func (p HandshakeErrorPacket) MarshalBinary() []byte {
	wire := make([]byte, HandshakeErrorPacketSize)
	binary.LittleEndian.PutUint32(wire[0:4], OperationHandshakeError)
	binary.LittleEndian.PutUint32(wire[4:8], uint32(p.ErrorCode))
	putProcessID(wire[8:20], p.Sender)
	return wire
}

// ParseHandshakeErrorPacket decodes a handshake rejection payload.
func ParseHandshakeErrorPacket(wire []byte) (HandshakeErrorPacket, error) {
	var packet HandshakeErrorPacket
	if len(wire) != HandshakeErrorPacketSize {
		return packet, fmt.Errorf("%w: error length %d, want %d", ErrInvalidHandshake, len(wire), HandshakeErrorPacketSize)
	}
	if operation := binary.LittleEndian.Uint32(wire[0:4]); operation != OperationHandshakeError {
		return packet, fmt.Errorf("%w: error operation %08x", ErrInvalidHandshake, operation)
	}
	packet.ErrorCode = int32(binary.LittleEndian.Uint32(wire[4:8]))
	packet.Sender = parseProcessID(wire[8:20])
	return packet, nil
}

func putProcessID(dst []byte, processID ProcessID) {
	binary.LittleEndian.PutUint32(dst[0:4], processID.IP)
	binary.LittleEndian.PutUint16(dst[4:6], processID.Port)
	binary.LittleEndian.PutUint16(dst[6:8], processID.PID)
	binary.LittleEndian.PutUint32(dst[8:12], uint32(processID.Uptime))
}

func parseProcessID(src []byte) ProcessID {
	return ProcessID{
		IP:     binary.LittleEndian.Uint32(src[0:4]),
		Port:   binary.LittleEndian.Uint16(src[4:6]),
		PID:    binary.LittleEndian.Uint16(src[6:8]),
		Uptime: int32(binary.LittleEndian.Uint32(src[8:12])),
	}
}

func validateHandshakeFlags(flags uint32) error {
	// Telegram rejects low-byte mode flags during this handshake. Higher flags
	// are forward-compatible; CRC32C is the only one interpreted here.
	if flags&0xff != 0 {
		return fmt.Errorf("%w: unsupported low-byte flags %08x", ErrInvalidHandshake, flags)
	}
	return nil
}
