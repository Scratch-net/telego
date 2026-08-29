package middleend

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

const (
	maxClientPacketHeaderSize = 4
	// A completed large packet must not pin its maximum-sized plaintext buffer
	// for the lifetime of an otherwise idle client. The frontend decrypts in
	// 64 KiB chunks, so retaining more capacity cannot avoid a decrypt copy.
	maxRetainedClientPacketBuffer = 64 * 1024
)

// ErrClientPacketDecoderClosed reports use of a retired client packet decoder.
var ErrClientPacketDecoderClosed = errors.New("MTProto client packet decoder is closed")

// ClientPacket is one decoded MTProto packet from an Obfuscated2 stream.
// Payload excludes transport framing and padded-intermediate random padding.
type ClientPacket struct {
	Payload  []byte
	QuickAck bool
}

// ClientPacketDecoder incrementally decodes one Obfuscated2 inner packet
// stream. It retains at most maxPacketSize plus a four-byte header and is not
// safe for concurrent use.
type ClientPacketDecoder struct {
	connectionType obfuscated2.ConnectionType
	maxPacketSize  int
	buffer         []byte
	head           int
	err            error
}

// NewClientPacketDecoder creates a bounded decoder for one client stream.
func NewClientPacketDecoder(
	connectionType obfuscated2.ConnectionType,
	maxPacketSize int,
) (*ClientPacketDecoder, error) {
	if err := validateClientPacketCodec(connectionType, maxPacketSize); err != nil {
		return nil, err
	}
	return &ClientPacketDecoder{
		connectionType: connectionType,
		maxPacketSize:  maxPacketSize,
	}, nil
}

// Feed retains as much input as fits in the configured bound and returns the
// number of bytes consumed. The caller must call Next to drain packets before
// resuming with data[consumed:] when Feed consumes only a prefix.
func (d *ClientPacketDecoder) Feed(data []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	maximumBuffered := d.maxPacketSize + maxClientPacketHeaderSize
	retained := len(d.buffer) - d.head
	consumed := min(len(data), maximumBuffered-retained)
	if consumed == 0 {
		return 0, nil
	}
	d.ensureBufferCapacity(retained + consumed)
	d.buffer = append(d.buffer, data[:consumed]...)
	return consumed, nil
}

// Next returns the next complete packet. The boolean is false when more bytes
// are required. After a protocol error, the decoder remains permanently
// failed.
func (d *ClientPacketDecoder) Next() (ClientPacket, bool, error) {
	var packet ClientPacket
	if d.err != nil {
		return packet, false, d.err
	}

	data := d.retainedPlaintext()
	headerSize, wirePacketSize, payloadSize, quickAck, complete, err := d.parseHeader(data)
	if err != nil {
		return packet, false, d.fail(err)
	}
	if !complete || len(data) < headerSize+wirePacketSize {
		return packet, false, nil
	}

	packet.Payload = make([]byte, payloadSize)
	copy(packet.Payload, data[headerSize:headerSize+payloadSize])
	packet.QuickAck = quickAck
	d.consumePlaintext(headerSize + wirePacketSize)
	return packet, true, nil
}

// Finish reports a truncated packet at end of stream.
func (d *ClientPacketDecoder) Finish() error {
	if d.err != nil {
		return d.err
	}
	if retained := len(d.buffer) - d.head; retained != 0 {
		return d.fail(fmt.Errorf("%w: %d buffered bytes", ErrIncompleteClientPacket, retained))
	}
	return nil
}

// BufferedBytes returns the plaintext bytes retained for an incomplete packet.
func (d *ClientPacketDecoder) BufferedBytes() int {
	if d == nil {
		return 0
	}
	return len(d.buffer) - d.head
}

// RetainedCapacityBytes returns the plaintext allocation that remains owned by
// the decoder. It includes reusable capacity after the buffered length is zero.
func (d *ClientPacketDecoder) RetainedCapacityBytes() int {
	if d == nil {
		return 0
	}
	return cap(d.buffer)
}

// Close permanently retires the decoder and clears all retained plaintext.
// It is idempotent. An earlier protocol or truncation error remains the sticky
// terminal error; otherwise subsequent operations return
// ErrClientPacketDecoderClosed.
func (d *ClientPacketDecoder) Close() error {
	if d == nil {
		return nil
	}
	if d.err == nil {
		d.err = ErrClientPacketDecoderClosed
	}
	d.clearPlaintext()
	return nil
}

func (d *ClientPacketDecoder) ensureBufferCapacity(required int) {
	if required <= cap(d.buffer)-d.head {
		return
	}

	retained := d.retainedPlaintext()
	if d.head != 0 {
		copy(d.buffer, retained)
		clear(d.buffer[len(retained):])
		d.buffer = d.buffer[:len(retained)]
		d.head = 0
	}
	if required <= cap(d.buffer) {
		return
	}

	maximumBuffered := d.maxPacketSize + maxClientPacketHeaderSize
	capacity := required
	if grown := cap(d.buffer) * 2; grown > capacity {
		capacity = grown
	}
	capacity = min(capacity, maximumBuffered)
	replacement := make([]byte, len(d.buffer), capacity)
	copy(replacement, d.buffer)
	clear(d.buffer)
	d.buffer = replacement
}

func (d *ClientPacketDecoder) retainedPlaintext() []byte {
	return d.buffer[d.head:]
}

func (d *ClientPacketDecoder) consumePlaintext(size int) {
	clear(d.buffer[d.head : d.head+size])
	d.head += size
	if d.head == len(d.buffer) {
		if cap(d.buffer) > maxRetainedClientPacketBuffer {
			d.buffer = nil
			d.head = 0
			return
		}
		d.buffer = d.buffer[:0]
		d.head = 0
	}
}

func (d *ClientPacketDecoder) fail(err error) error {
	if d.err == nil {
		d.err = err
	}
	d.clearPlaintext()
	return d.err
}

func (d *ClientPacketDecoder) clearPlaintext() {
	clear(d.buffer)
	d.buffer = nil
	d.head = 0
}

func (d *ClientPacketDecoder) parseHeader(data []byte) (int, int, int, bool, bool, error) {
	switch d.connectionType {
	case obfuscated2.ConnectionTypeAbridged:
		return d.parseAbridgedHeader(data)
	case obfuscated2.ConnectionTypeIntermediate, obfuscated2.ConnectionTypePaddedIntermediate:
		return d.parseIntermediateHeader(data)
	default:
		return 0, 0, 0, false, false, fmt.Errorf("%w: 0x%08x", ErrUnsupportedClientFraming, uint32(d.connectionType))
	}
}

func (d *ClientPacketDecoder) parseAbridgedHeader(data []byte) (int, int, int, bool, bool, error) {
	if len(data) < 1 {
		return 0, 0, 0, false, false, nil
	}

	first := data[0]
	quickAck := first&0x80 != 0
	wordCount := uint32(first & 0x7f)
	headerSize := 1
	if wordCount == 0x7f {
		if len(data) < maxClientPacketHeaderSize {
			return 0, 0, 0, false, false, nil
		}
		wordCount = uint32(data[1]) |
			uint32(data[2])<<8 |
			uint32(data[3])<<16
		headerSize = maxClientPacketHeaderSize
		if wordCount < 0x7f {
			return 0, 0, 0, false, false, fmt.Errorf("%w: overlong abridged word count %d", ErrInvalidClientPacket, wordCount)
		}
	}
	if wordCount == 0 {
		return 0, 0, 0, false, false, fmt.Errorf("%w: zero abridged word count", ErrInvalidClientPacket)
	}

	wirePacketSize := wordCount * 4
	if wirePacketSize > uint32(d.maxPacketSize) {
		return 0, 0, 0, false, false, fmt.Errorf("%w: %d > %d", ErrClientPacketTooLarge, wirePacketSize, d.maxPacketSize)
	}
	packetSize := int(wirePacketSize)
	return headerSize, packetSize, packetSize, quickAck, true, nil
}

func (d *ClientPacketDecoder) parseIntermediateHeader(data []byte) (int, int, int, bool, bool, error) {
	if len(data) < maxClientPacketHeaderSize {
		return 0, 0, 0, false, false, nil
	}

	declared := binary.LittleEndian.Uint32(data[:maxClientPacketHeaderSize])
	quickAck := declared&uint32(ProxyRequestFlagQuickAck) != 0
	declared &^= uint32(ProxyRequestFlagQuickAck)
	if declared&0x40000000 != 0 {
		return 0, 0, 0, false, false, fmt.Errorf("%w: intermediate length uses reserved high bit", ErrInvalidClientPacket)
	}
	if declared < 4 {
		return 0, 0, 0, false, false, fmt.Errorf("%w: intermediate length %d is below 4", ErrInvalidClientPacket, declared)
	}
	payloadSize := declared
	if d.connectionType == obfuscated2.ConnectionTypePaddedIntermediate {
		if declared > uint32(d.maxPacketSize) {
			return 0, 0, 0, false, false, fmt.Errorf("%w: padded wire length %d > %d", ErrClientPacketTooLarge, declared, d.maxPacketSize)
		}
		payloadSize &^= 3
	} else {
		if declared > uint32(d.maxPacketSize) {
			return 0, 0, 0, false, false, fmt.Errorf("%w: %d > %d", ErrClientPacketTooLarge, declared, d.maxPacketSize)
		}
		if declared%4 != 0 {
			return 0, 0, 0, false, false, fmt.Errorf("%w: intermediate length %d is not word-aligned", ErrInvalidClientPacket, declared)
		}
	}
	if payloadSize < 4 {
		return 0, 0, 0, false, false, fmt.Errorf("%w: payload length %d is below 4", ErrInvalidClientPacket, payloadSize)
	}
	return maxClientPacketHeaderSize, int(declared), int(payloadSize), quickAck, true, nil
}

// ClientPacketEncoder frames complete MTProto response packets for one
// Obfuscated2 client stream. It is not safe for concurrent use.
type ClientPacketEncoder struct {
	connectionType obfuscated2.ConnectionType
	maxPacketSize  int
	paddingSource  io.Reader
}

// NewClientPacketEncoder creates a bounded response encoder. Secure random
// bytes are used for padded-intermediate transport padding.
func NewClientPacketEncoder(
	connectionType obfuscated2.ConnectionType,
	maxPacketSize int,
) (*ClientPacketEncoder, error) {
	return newClientPacketEncoder(connectionType, maxPacketSize, rand.Reader)
}

func newClientPacketEncoder(
	connectionType obfuscated2.ConnectionType,
	maxPacketSize int,
	paddingSource io.Reader,
) (*ClientPacketEncoder, error) {
	if err := validateClientPacketCodec(connectionType, maxPacketSize); err != nil {
		return nil, err
	}
	if paddingSource == nil {
		return nil, fmt.Errorf("%w: nil padding source", ErrInvalidClientPacket)
	}
	return &ClientPacketEncoder{
		connectionType: connectionType,
		maxPacketSize:  maxPacketSize,
		paddingSource:  paddingSource,
	}, nil
}

// Encode frames one complete MTProto response packet. Padded-intermediate
// responses receive zero to three fresh random bytes, matching
// tcp_rpc_write_packet_compact in Telegram's net/net-tcp-rpc-common.c.
func (e *ClientPacketEncoder) Encode(packet []byte) ([]byte, error) {
	if len(packet) < 4 || len(packet)%4 != 0 {
		return nil, fmt.Errorf("%w: response packet length %d", ErrInvalidClientPacket, len(packet))
	}
	if len(packet) > e.maxPacketSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrClientPacketTooLarge, len(packet), e.maxPacketSize)
	}

	switch e.connectionType {
	case obfuscated2.ConnectionTypeAbridged:
		return encodeAbridgedPacket(packet)
	case obfuscated2.ConnectionTypeIntermediate:
		wire := make([]byte, maxClientPacketHeaderSize+len(packet))
		binary.LittleEndian.PutUint32(wire[:maxClientPacketHeaderSize], uint32(len(packet)))
		copy(wire[maxClientPacketHeaderSize:], packet)
		return wire, nil
	case obfuscated2.ConnectionTypePaddedIntermediate:
		return e.encodePaddedIntermediatePacket(packet)
	default:
		return nil, fmt.Errorf("%w: 0x%08x", ErrUnsupportedClientFraming, uint32(e.connectionType))
	}
}

func encodeAbridgedPacket(packet []byte) ([]byte, error) {
	wordCount := len(packet) / 4
	if wordCount > 0xffffff {
		return nil, fmt.Errorf("%w: abridged word count %d", ErrClientPacketTooLarge, wordCount)
	}
	if wordCount <= 0x7e {
		wire := make([]byte, 1+len(packet))
		wire[0] = byte(wordCount)
		copy(wire[1:], packet)
		return wire, nil
	}

	wire := make([]byte, maxClientPacketHeaderSize+len(packet))
	wire[0] = 0x7f
	wire[1] = byte(wordCount)
	wire[2] = byte(wordCount >> 8)
	wire[3] = byte(wordCount >> 16)
	copy(wire[maxClientPacketHeaderSize:], packet)
	return wire, nil
}

func (e *ClientPacketEncoder) encodePaddedIntermediatePacket(packet []byte) ([]byte, error) {
	paddingSize, err := randomBoundedInt(e.paddingSource, 3)
	if err != nil {
		return nil, fmt.Errorf("generate padded-intermediate length: %w", err)
	}

	wirePacketSize := len(packet) + paddingSize
	wire := make([]byte, maxClientPacketHeaderSize+wirePacketSize)
	binary.LittleEndian.PutUint32(wire[:maxClientPacketHeaderSize], uint32(wirePacketSize))
	copy(wire[maxClientPacketHeaderSize:], packet)
	if paddingSize != 0 {
		if _, err := io.ReadFull(e.paddingSource, wire[maxClientPacketHeaderSize+len(packet):]); err != nil {
			return nil, fmt.Errorf("generate padded-intermediate bytes: %w", err)
		}
	}
	return wire, nil
}

// EncodeSimpleAckForClient converts RPC_SIMPLE_ACK's integer to the raw
// four-byte quick-ack representation expected by the client transport.
// Telegram byte-swaps abridged acknowledgements and sends the other modes in
// little-endian order.
func EncodeSimpleAckForClient(
	connectionType obfuscated2.ConnectionType,
	confirmKey uint32,
) ([]byte, error) {
	wire := make([]byte, 4)
	switch connectionType {
	case obfuscated2.ConnectionTypeAbridged:
		binary.BigEndian.PutUint32(wire, confirmKey)
	case obfuscated2.ConnectionTypeIntermediate, obfuscated2.ConnectionTypePaddedIntermediate:
		binary.LittleEndian.PutUint32(wire, confirmKey)
	default:
		return nil, fmt.Errorf("%w: 0x%08x", ErrUnsupportedClientFraming, uint32(connectionType))
	}
	return wire, nil
}

func validateClientPacketCodec(connectionType obfuscated2.ConnectionType, maxPacketSize int) error {
	switch connectionType {
	case obfuscated2.ConnectionTypeAbridged,
		obfuscated2.ConnectionTypeIntermediate,
		obfuscated2.ConnectionTypePaddedIntermediate:
	default:
		return fmt.Errorf("%w: 0x%08x", ErrUnsupportedClientFraming, uint32(connectionType))
	}
	if maxPacketSize < 4 {
		return fmt.Errorf("%w: maximum %d is below 4", ErrInvalidClientPacket, maxPacketSize)
	}
	if maxPacketSize > MaxClientPacketSize {
		return fmt.Errorf("%w: maximum %d exceeds %d", ErrClientPacketTooLarge, maxPacketSize, MaxClientPacketSize)
	}
	return nil
}

func randomBoundedInt(source io.Reader, maximum int) (int, error) {
	if maximum <= 0 {
		return 0, nil
	}
	choices := maximum + 1
	limit := 256 - 256%choices
	var value [1]byte
	for {
		if _, err := io.ReadFull(source, value[:]); err != nil {
			return 0, err
		}
		if int(value[0]) < limit {
			return int(value[0]) % choices, nil
		}
	}
}
