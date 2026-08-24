package webproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	FrameHeaderSize     = 8
	MaxFramePayload     = 1024 * 1024
	MaxBatchFrames      = 4096
	MaxStreamID         = 0xFFFFFF
	InitialStreamWindow = 4 * 1024 * 1024
	RelayDataChunk      = 64 * 1024
	maxPingPayload      = 64
)

var (
	ErrEmptyFrameBatch = errors.New("empty WEB frame batch")
	ErrIncompleteFrame = errors.New("incomplete WEB frame")
	ErrTooManyFrames   = errors.New("WEB frame batch contains too many frames")
	ErrPayloadTooLarge = errors.New("WEB frame payload exceeds limit")
	ErrInvalidFrame    = errors.New("invalid WEB frame")
)

// FrameType identifies a WEB shared-frame message.
type FrameType uint8

const (
	FrameOpen    FrameType = 0x01
	FrameData    FrameType = 0x02
	FrameClose   FrameType = 0x03
	FrameWindow  FrameType = 0x04
	FramePing    FrameType = 0x05
	FramePong    FrameType = 0x06
	FrameHello   FrameType = 0x10
	FrameWelcome FrameType = 0x11
	FrameBye     FrameType = 0x1f
)

// Direction identifies the sender of a shared frame.
type Direction uint8

const (
	ClientToRelay Direction = iota
	RelayToClient
)

// Frame is one complete WEB shared frame. Payload returned by ParseBatch aliases
// the input buffer and must not outlive or mutate independently from it.
type Frame struct {
	Type     FrameType
	StreamID uint32
	Payload  []byte
}

// EncodeFrame encodes one shape-valid frame.
func EncodeFrame(frame Frame) ([]byte, error) {
	return AppendFrame(nil, frame)
}

// AppendFrame appends one shape-valid frame to dst.
func AppendFrame(dst []byte, frame Frame) ([]byte, error) {
	if err := validateFrameShape(frame); err != nil {
		return dst, err
	}
	start := len(dst)
	dst = append(dst, make([]byte, FrameHeaderSize+len(frame.Payload))...)
	dst[start] = byte(frame.Type)
	dst[start+1] = byte(frame.StreamID >> 16)
	dst[start+2] = byte(frame.StreamID >> 8)
	dst[start+3] = byte(frame.StreamID)
	binary.BigEndian.PutUint32(dst[start+4:start+FrameHeaderSize], uint32(len(frame.Payload)))
	copy(dst[start+FrameHeaderSize:], frame.Payload)
	return dst, nil
}

// ParseBatch parses and shape-validates one nonempty frame batch. Payload slices
// in the result alias input.
func ParseBatch(input []byte) ([]Frame, error) {
	if len(input) == 0 {
		return nil, ErrEmptyFrameBatch
	}

	frames := make([]Frame, 0, min(4, MaxBatchFrames))
	for len(input) != 0 {
		if len(frames) == MaxBatchFrames {
			return nil, ErrTooManyFrames
		}
		if len(input) < FrameHeaderSize {
			return nil, ErrIncompleteFrame
		}
		payloadSize := binary.BigEndian.Uint32(input[4:FrameHeaderSize])
		if payloadSize > MaxFramePayload {
			return nil, ErrPayloadTooLarge
		}
		frameSize := FrameHeaderSize + int(payloadSize)
		if frameSize > len(input) {
			return nil, ErrIncompleteFrame
		}
		var payload []byte
		if payloadSize != 0 {
			payload = input[FrameHeaderSize:frameSize]
		}
		frame := Frame{
			Type:     FrameType(input[0]),
			StreamID: uint32(input[1])<<16 | uint32(input[2])<<8 | uint32(input[3]),
			Payload:  payload,
		}
		if err := validateFrameShape(frame); err != nil {
			return nil, err
		}
		frames = append(frames, frame)
		input = input[frameSize:]
	}
	return frames, nil
}

// ValidateFrame checks both the frame's exact shape and whether its type is
// valid in the supplied direction.
func ValidateFrame(frame Frame, direction Direction) error {
	if err := validateFrameShape(frame); err != nil {
		return err
	}
	switch direction {
	case ClientToRelay:
		switch frame.Type {
		case FrameOpen, FrameData, FrameClose, FrameWindow, FramePong, FrameHello:
			return nil
		}
	case RelayToClient:
		switch frame.Type {
		case FrameData, FrameClose, FrameWindow, FramePing, FrameWelcome, FrameBye:
			return nil
		}
	default:
		return fmt.Errorf("%w: unknown direction %d", ErrInvalidFrame, direction)
	}
	return fmt.Errorf("%w: type %#x is invalid in direction %d", ErrInvalidFrame, frame.Type, direction)
}

// ValidateClientFrame validates a normal authenticated uplink frame. HELLO is
// excluded because it is valid only as the standalone session-creation body
// accepted by ParseHello.
func ValidateClientFrame(frame Frame) error {
	if frame.Type == FrameHello {
		return fmt.Errorf("%w: HELLO is valid only during session creation", ErrInvalidFrame)
	}
	return ValidateFrame(frame, ClientToRelay)
}

// ParseHello accepts exactly one v1 HELLO frame and no other bytes.
func ParseHello(input []byte) error {
	frames, err := ParseBatch(input)
	if err != nil {
		return err
	}
	if len(frames) != 1 || frames[0].Type != FrameHello {
		return fmt.Errorf("%w: session creation requires exactly one HELLO", ErrInvalidFrame)
	}
	return ValidateFrame(frames[0], ClientToRelay)
}

// WindowDelta decodes a nonzero WINDOW credit delta.
func WindowDelta(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, fmt.Errorf("%w: WINDOW payload must contain four bytes", ErrInvalidFrame)
	}
	delta := binary.BigEndian.Uint32(payload)
	if delta == 0 {
		return 0, fmt.Errorf("%w: WINDOW delta must be nonzero", ErrInvalidFrame)
	}
	return delta, nil
}

// WindowPayload encodes a nonzero WINDOW credit delta.
func WindowPayload(delta uint32) ([]byte, error) {
	if delta == 0 {
		return nil, fmt.Errorf("%w: WINDOW delta must be nonzero", ErrInvalidFrame)
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, delta)
	return payload, nil
}

func validateFrameShape(frame Frame) error {
	if frame.StreamID > MaxStreamID {
		return fmt.Errorf("%w: stream ID exceeds 24 bits", ErrInvalidFrame)
	}
	if len(frame.Payload) > MaxFramePayload {
		return ErrPayloadTooLarge
	}

	switch frame.Type {
	case FrameOpen, FrameClose:
		if frame.StreamID == 0 || len(frame.Payload) != 0 {
			return fmt.Errorf("%w: OPEN and CLOSE require a nonzero stream and empty payload", ErrInvalidFrame)
		}
	case FrameData:
		if frame.StreamID == 0 || len(frame.Payload) == 0 {
			return fmt.Errorf("%w: DATA requires a nonzero stream and nonempty payload", ErrInvalidFrame)
		}
	case FrameWindow:
		if frame.StreamID == 0 {
			return fmt.Errorf("%w: WINDOW requires a nonzero stream", ErrInvalidFrame)
		}
		if _, err := WindowDelta(frame.Payload); err != nil {
			return err
		}
	case FramePing, FramePong:
		if frame.StreamID != 0 || len(frame.Payload) > maxPingPayload {
			return fmt.Errorf("%w: PING and PONG require stream zero and at most %d payload bytes", ErrInvalidFrame, maxPingPayload)
		}
	case FrameHello:
		if frame.StreamID != 0 || len(frame.Payload) != 1 || frame.Payload[0] != 1 {
			return fmt.Errorf("%w: HELLO requires stream zero and version byte 01", ErrInvalidFrame)
		}
	case FrameWelcome:
		if frame.StreamID != 0 || len(frame.Payload) != 0 {
			return fmt.Errorf("%w: WELCOME requires stream zero and empty payload", ErrInvalidFrame)
		}
	case FrameBye:
		if frame.StreamID != 0 {
			return fmt.Errorf("%w: BYE requires stream zero", ErrInvalidFrame)
		}
	default:
		return fmt.Errorf("%w: unknown type %#x", ErrInvalidFrame, frame.Type)
	}
	return nil
}
