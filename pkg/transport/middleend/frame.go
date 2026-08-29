package middleend

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
	"slices"
)

// ChecksumMode selects the checksum used by a full TCP RPC frame.
type ChecksumMode uint8

const (
	ChecksumCRC32 ChecksumMode = iota
	ChecksumCRC32C
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// Frame is one decoded full TCP RPC frame.
type Frame struct {
	Sequence int32
	Payload  []byte
}

// FrameEncoder owns the outbound sequence of one TCP RPC stream and encodes
// full frames up to a fixed protocol limit. It is not safe for concurrent use.
type FrameEncoder struct {
	nextSequence           int32
	maxFrameSize           int
	mode                   ChecksumMode
	localHandshake         HandshakePacket
	checksumTransitionOpen bool
	checksumTransitionDone bool
	exhausted              bool
	err                    error
}

// NewFrameEncoder creates an encoder with a limit no greater than the package's
// documented local Middle-End frame cap.
func NewFrameEncoder(nextSequence int32, maxFrameSize int) (*FrameEncoder, error) {
	if err := validateSequence(nextSequence); err != nil {
		return nil, err
	}
	if err := validateMaxFrameSize(maxFrameSize); err != nil {
		return nil, err
	}
	return &FrameEncoder{
		nextSequence: nextSequence,
		maxFrameSize: maxFrameSize,
		mode:         ChecksumCRC32,
	}, nil
}

// EncodeFrame is a stateless low-level helper that encodes one explicitly
// numbered full TCP RPC frame. It validates the individual sequence but cannot
// prevent a caller from reusing or reordering sequences across calls. Stream
// implementations must use FrameEncoder instead.
func EncodeFrame(sequence int32, payload []byte, mode ChecksumMode) ([]byte, error) {
	if err := validateSequence(sequence); err != nil {
		return nil, err
	}
	return encodeFrame(sequence, payload, mode, MaxMEFrameSize)
}

// Encode encodes a frame with the stream's locked checksum state. Streams
// start with CRC32. A caller may apply the validated peer handshake exactly
// once between sequence -1 and sequence 0 to negotiate CRC32C.
func (e *FrameEncoder) Encode(payload []byte) ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	if e.exhausted {
		return nil, ErrSequenceExhausted
	}

	sequence := e.nextSequence
	wire, err := encodeFrame(sequence, payload, e.mode, e.maxFrameSize)
	if err != nil {
		return nil, err
	}
	if e.checksumTransitionOpen && sequence >= 0 {
		e.checksumTransitionOpen = false
		e.checksumTransitionDone = true
	}
	if e.nextSequence == math.MaxInt32 {
		e.exhausted = true
	} else {
		e.nextSequence++
	}
	if sequence == -1 {
		if handshake, err := ParseHandshakePacket(payload); err == nil {
			e.localHandshake = handshake
			e.checksumTransitionOpen = true
		}
	}
	return wire, nil
}

// ApplyPeerHandshake locks the post-handshake checksum selected by a
// validated peer handshake. It is valid only after this encoder emitted the
// sequence -1 handshake and before it emits sequence 0. Telegram's client
// switches both directions only after accepting the peer handshake.
func (e *FrameEncoder) ApplyPeerHandshake(peer HandshakePacket) error {
	if !e.checksumTransitionOpen || e.checksumTransitionDone || e.nextSequence != 0 {
		return ErrChecksumTransition
	}
	mode, err := negotiatedChecksum(e.localHandshake, peer)
	if err != nil {
		e.checksumTransitionOpen = false
		e.checksumTransitionDone = true
		e.err = err
		return err
	}
	e.mode = mode
	e.checksumTransitionOpen = false
	e.checksumTransitionDone = true
	return nil
}

// ChecksumMode reports the checksum locked for the next outbound frame.
func (e *FrameEncoder) ChecksumMode() ChecksumMode {
	return e.mode
}

// Exhausted reports whether the encoder emitted the last valid sequence.
func (e *FrameEncoder) Exhausted() bool {
	return e.exhausted
}

func encodeFrame(sequence int32, payload []byte, mode ChecksumMode, maxFrameSize int) ([]byte, error) {
	if err := validateChecksumMode(mode); err != nil {
		return nil, err
	}
	if len(payload) < 4 || len(payload)%4 != 0 {
		return nil, fmt.Errorf("%w: payload length %d", ErrInvalidFrameSize, len(payload))
	}

	if len(payload) > maxFrameSize-FullFrameOverhead {
		return nil, fmt.Errorf("%w: payload %d exceeds frame maximum %d", ErrFrameTooLarge, len(payload), maxFrameSize)
	}
	frameSize := len(payload) + FullFrameOverhead

	frame := make([]byte, frameSize)
	binary.LittleEndian.PutUint32(frame[0:4], uint32(frameSize))
	binary.LittleEndian.PutUint32(frame[4:8], uint32(sequence))
	copy(frame[8:frameSize-4], payload)
	binary.LittleEndian.PutUint32(frame[frameSize-4:], checksum(frame[:frameSize-4], mode))
	return frame, nil
}

// DecodeFrame is a stateless low-level helper that validates and decodes one
// explicitly checksummed full TCP RPC frame. Stream implementations must use
// FrameDecoder so checksum mode cannot drift between calls.
func DecodeFrame(wire []byte, expectedSequence int32, mode ChecksumMode, maxFrameSize int) (Frame, error) {
	var frame Frame
	if err := validateSequence(expectedSequence); err != nil {
		return frame, err
	}
	if err := validateChecksumMode(mode); err != nil {
		return frame, err
	}
	if err := validateMaxFrameSize(maxFrameSize); err != nil {
		return frame, err
	}
	if len(wire) < MinimumFullFrameSize || len(wire)%4 != 0 {
		return frame, fmt.Errorf("%w: %d", ErrInvalidFrameSize, len(wire))
	}

	declaredSize := int(binary.LittleEndian.Uint32(wire[:4]))
	if declaredSize != len(wire) {
		return frame, fmt.Errorf("%w: declared %d, received %d", ErrInvalidFrameSize, declaredSize, len(wire))
	}
	if declaredSize > maxFrameSize {
		return frame, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, declaredSize, maxFrameSize)
	}

	wantChecksum := binary.LittleEndian.Uint32(wire[len(wire)-4:])
	gotChecksum := checksum(wire[:len(wire)-4], mode)
	if gotChecksum != wantChecksum {
		return frame, fmt.Errorf("%w: got %08x, want %08x", ErrChecksumMismatch, gotChecksum, wantChecksum)
	}

	sequence := int32(binary.LittleEndian.Uint32(wire[4:8]))
	if sequence != expectedSequence {
		return frame, fmt.Errorf("%w: got %d, want %d", ErrSequenceMismatch, sequence, expectedSequence)
	}

	frame.Sequence = sequence
	frame.Payload = slices.Clone(wire[8 : len(wire)-4])
	return frame, nil
}

// FrameDecoder owns the inbound sequence of one plaintext TCP RPC stream. It
// is not safe for concurrent use. Feed accepts arbitrary network fragmentation
// and coalescing through partial consumption. Next skips official four-byte
// no-op frames used to align encrypted output to an AES block.
//
// After accepting sequence MaxInt32, the decoder enters a padding-only state:
// Feed continues accepting bounded data, Next consumes complete no-op frames,
// and Finish accepts only an empty buffer after complete no-ops. A partial
// no-op at EOF is incomplete; any complete non-no-op header is
// ErrSequenceExhausted.
type FrameDecoder struct {
	buffer                 []byte
	head                   int
	nextSequence           int32
	mode                   ChecksumMode
	maxFrameSize           int
	peerHandshake          HandshakePacket
	checksumTransitionOpen bool
	checksumTransitionDone bool
	exhausted              bool
	err                    error
}

// NewFrameDecoder creates a strict decoder starting at nextSequence.
func NewFrameDecoder(nextSequence int32, maxFrameSize int) (*FrameDecoder, error) {
	if err := validateSequence(nextSequence); err != nil {
		return nil, err
	}
	if err := validateMaxFrameSize(maxFrameSize); err != nil {
		return nil, err
	}
	return &FrameDecoder{
		nextSequence: nextSequence,
		mode:         ChecksumCRC32,
		maxFrameSize: maxFrameSize,
	}, nil
}

// Feed retains as much decrypted stream data as fits in one configured maximum
// frame and returns the number of bytes consumed. A caller must drain Next and
// resume with data[consumed:] when Feed consumes only part of a coalesced read.
func (d *FrameDecoder) Feed(data []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}

	buffered := d.bufferedLen()
	consumed := min(len(data), d.maxFrameSize-buffered)
	if d.head != 0 && consumed != 0 {
		copy(d.buffer, d.buffer[d.head:])
		clear(d.buffer[buffered:])
		d.buffer = d.buffer[:buffered]
		d.head = 0
	}
	d.buffer = append(d.buffer, data[:consumed]...)
	return consumed, nil
}

// Next returns the next complete frame. The boolean is false when more bytes
// are required. On a protocol error, the decoder remains permanently failed.
func (d *FrameDecoder) Next() (Frame, bool, error) {
	var frame Frame
	if d.err != nil {
		return frame, false, d.err
	}
	if d.checksumTransitionOpen {
		return frame, false, nil
	}
	if d.exhausted {
		if err := d.consumeExhaustedPadding(); err != nil {
			return frame, false, err
		}
		return frame, false, nil
	}

	for {
		buffer := d.buffered()
		if len(buffer) < 4 {
			return frame, false, nil
		}

		declaredSize := int(binary.LittleEndian.Uint32(buffer[:4]))
		if declaredSize == NoopFrameSize {
			d.discardBuffered(NoopFrameSize)
			continue
		}
		if declaredSize < MinimumFullFrameSize || declaredSize%4 != 0 {
			d.err = fmt.Errorf("%w: declared %d", ErrInvalidFrameSize, declaredSize)
			return frame, false, d.err
		}
		if declaredSize > d.maxFrameSize {
			d.err = fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, declaredSize, d.maxFrameSize)
			return frame, false, d.err
		}
		if len(buffer) < declaredSize {
			return frame, false, nil
		}

		decoded, err := DecodeFrame(buffer[:declaredSize], d.nextSequence, d.mode, d.maxFrameSize)
		if err != nil {
			d.err = err
			return frame, false, err
		}
		d.discardBuffered(declaredSize)
		if decoded.Sequence == -1 {
			handshake, err := ParseHandshakePacket(decoded.Payload)
			if err != nil {
				d.err = err
				return Frame{}, false, err
			}
			d.peerHandshake = handshake
			d.checksumTransitionOpen = true
		}
		if d.nextSequence == math.MaxInt32 {
			d.exhausted = true
		} else {
			d.nextSequence++
		}
		return decoded, true, nil
	}
}

// ApplyPeerHandshake commits the pending sequence -1 handshake after the
// caller has validated its process IDs. peer must be the exact packet returned
// in the decoded frame, and local must be the handshake advertised on this
// connection. CRC32C is selected only when both handshakes advertise it.
func (d *FrameDecoder) ApplyPeerHandshake(peer HandshakePacket, local HandshakePacket) error {
	if !d.checksumTransitionOpen || d.checksumTransitionDone || d.nextSequence != 0 {
		return ErrChecksumTransition
	}
	if peer != d.peerHandshake {
		d.err = fmt.Errorf("%w: applied peer handshake differs from decoded sequence -1 packet", ErrChecksumTransition)
		d.checksumTransitionOpen = false
		d.checksumTransitionDone = true
		return d.err
	}
	mode, err := negotiatedChecksum(local, peer)
	if err != nil {
		d.err = err
		d.checksumTransitionOpen = false
		d.checksumTransitionDone = true
		return err
	}
	d.mode = mode
	d.checksumTransitionOpen = false
	d.checksumTransitionDone = true
	return nil
}

// ChecksumMode reports the checksum locked for the next inbound frame.
func (d *FrameDecoder) ChecksumMode() ChecksumMode {
	return d.mode
}

// NextSequence returns the sequence expected by the next non-no-op frame. Once
// exhausted, it remains MaxInt32; callers must also check Exhausted.
func (d *FrameDecoder) NextSequence() int32 {
	return d.nextSequence
}

// Exhausted reports whether the decoder accepted the last valid sequence.
func (d *FrameDecoder) Exhausted() bool {
	return d.exhausted
}

// Finish reports a truncated frame at end of stream.
func (d *FrameDecoder) Finish() error {
	if d.err != nil {
		return d.err
	}
	if d.checksumTransitionOpen {
		return ErrChecksumTransition
	}
	if d.exhausted {
		if err := d.consumeExhaustedPadding(); err != nil {
			return err
		}
	}
	if buffered := d.bufferedLen(); buffered != 0 {
		return fmt.Errorf("%w: %d buffered bytes", ErrIncompleteFrame, buffered)
	}
	return nil
}

func (d *FrameDecoder) buffered() []byte {
	return d.buffer[d.head:]
}

func (d *FrameDecoder) bufferedLen() int {
	return len(d.buffer) - d.head
}

func (d *FrameDecoder) discardBuffered(size int) {
	d.head += size
	if d.head != len(d.buffer) {
		return
	}
	d.buffer = d.buffer[:0]
	d.head = 0
}

func (d *FrameDecoder) retire() {
	if d == nil {
		return
	}
	clear(d.buffer[:cap(d.buffer)])
	*d = FrameDecoder{}
}

func negotiatedChecksum(local HandshakePacket, peer HandshakePacket) (ChecksumMode, error) {
	if err := validateHandshakeFlags(local.Flags); err != nil {
		return ChecksumCRC32, fmt.Errorf("%w: invalid local handshake: %w", ErrChecksumTransition, err)
	}
	if err := validateHandshakeFlags(peer.Flags); err != nil {
		return ChecksumCRC32, fmt.Errorf("%w: invalid peer handshake: %w", ErrChecksumTransition, err)
	}
	if peer.Flags&HandshakeFlagCRC32C == 0 {
		return ChecksumCRC32, nil
	}
	if local.Flags&HandshakeFlagCRC32C == 0 {
		return ChecksumCRC32, fmt.Errorf("%w: peer advertised CRC32C without local capability", ErrChecksumTransition)
	}
	return ChecksumCRC32C, nil
}

func (d *FrameDecoder) consumeExhaustedPadding() error {
	for d.bufferedLen() >= NoopFrameSize {
		if binary.LittleEndian.Uint32(d.buffered()[:NoopFrameSize]) != NoopFrameSize {
			d.err = ErrSequenceExhausted
			return d.err
		}
		d.discardBuffered(NoopFrameSize)
	}
	return nil
}

func checksum(data []byte, mode ChecksumMode) uint32 {
	if mode == ChecksumCRC32C {
		return crc32.Checksum(data, crc32cTable)
	}
	return crc32.ChecksumIEEE(data)
}

func validateChecksumMode(mode ChecksumMode) error {
	if mode != ChecksumCRC32 && mode != ChecksumCRC32C {
		return fmt.Errorf("%w: %d", ErrInvalidChecksumMode, mode)
	}
	return nil
}

func validateMaxFrameSize(maxFrameSize int) error {
	if maxFrameSize < MinimumFullFrameSize {
		return fmt.Errorf("%w: maximum %d", ErrInvalidFrameSize, maxFrameSize)
	}
	if maxFrameSize > MaxMEFrameSize {
		return fmt.Errorf("%w: maximum %d > %d", ErrFrameTooLarge, maxFrameSize, MaxMEFrameSize)
	}
	return nil
}

func validateSequence(sequence int32) error {
	if sequence < -2 {
		return fmt.Errorf("%w: %d is below handshake sequence -2", ErrSequenceMismatch, sequence)
	}
	return nil
}
