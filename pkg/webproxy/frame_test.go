package webproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func TestFrameCodecRoundTrip(t *testing.T) {
	t.Parallel()

	window, err := WindowPayload(0x01020304)
	if err != nil {
		t.Fatal(err)
	}
	input := []Frame{
		{Type: FrameOpen, StreamID: MaxStreamID},
		{Type: FrameData, StreamID: 7, Payload: []byte("payload")},
		{Type: FrameClose, StreamID: 7},
		{Type: FrameWindow, StreamID: 8, Payload: window},
		{Type: FramePing, Payload: []byte("token")},
		{Type: FramePong, Payload: []byte("token")},
		{Type: FrameHello, Payload: []byte{1}},
		{Type: FrameWelcome},
		{Type: FrameBye, Payload: []byte("reason")},
	}

	var encoded []byte
	for _, frame := range input {
		encoded, err = AppendFrame(encoded, frame)
		if err != nil {
			t.Fatal(err)
		}
	}
	decoded, err := ParseBatch(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, input) {
		t.Fatalf("decoded frames = %#v, want %#v", decoded, input)
	}
}

func TestFrameHeaderUsesBigEndian(t *testing.T) {
	t.Parallel()

	encoded, err := EncodeFrame(Frame{Type: FrameData, StreamID: 0x010203, Payload: []byte{0xaa, 0xbb}})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x02, 0x01, 0x02, 0x03, 0, 0, 0, 2, 0xaa, 0xbb}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded frame = %x, want %x", encoded, want)
	}
}

func TestValidateFrameShapes(t *testing.T) {
	t.Parallel()

	window, err := WindowPayload(1)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		frame     Frame
		direction Direction
	}{
		{"open", Frame{Type: FrameOpen, StreamID: 1}, ClientToRelay},
		{"data client", Frame{Type: FrameData, StreamID: 1, Payload: []byte{1}}, ClientToRelay},
		{"data relay", Frame{Type: FrameData, StreamID: 1, Payload: []byte{1}}, RelayToClient},
		{"close client", Frame{Type: FrameClose, StreamID: 1}, ClientToRelay},
		{"close relay", Frame{Type: FrameClose, StreamID: 1}, RelayToClient},
		{"window client", Frame{Type: FrameWindow, StreamID: 1, Payload: window}, ClientToRelay},
		{"window relay", Frame{Type: FrameWindow, StreamID: 1, Payload: window}, RelayToClient},
		{"ping", Frame{Type: FramePing, Payload: []byte("token")}, RelayToClient},
		{"pong", Frame{Type: FramePong, Payload: []byte("token")}, ClientToRelay},
		{"hello", Frame{Type: FrameHello, Payload: []byte{1}}, ClientToRelay},
		{"welcome", Frame{Type: FrameWelcome}, RelayToClient},
		{"bye empty", Frame{Type: FrameBye}, RelayToClient},
		{"bye reason", Frame{Type: FrameBye, Payload: []byte("reason")}, RelayToClient},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateFrame(test.frame, test.direction); err != nil {
				t.Fatal(err)
			}
			if _, err := EncodeFrame(test.frame); err != nil {
				t.Fatalf("EncodeFrame: %v", err)
			}
		})
	}
}

func TestRejectInvalidFrameShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		frame Frame
	}{
		{"unknown type", Frame{Type: 0xff}},
		{"stream too large", Frame{Type: FrameOpen, StreamID: MaxStreamID + 1}},
		{"open stream zero", Frame{Type: FrameOpen}},
		{"open payload", Frame{Type: FrameOpen, StreamID: 1, Payload: []byte{1}}},
		{"data stream zero", Frame{Type: FrameData, Payload: []byte{1}}},
		{"data empty", Frame{Type: FrameData, StreamID: 1}},
		{"close stream zero", Frame{Type: FrameClose}},
		{"close payload", Frame{Type: FrameClose, StreamID: 1, Payload: []byte{1}}},
		{"window stream zero", Frame{Type: FrameWindow, Payload: []byte{0, 0, 0, 1}}},
		{"window short", Frame{Type: FrameWindow, StreamID: 1, Payload: []byte{1}}},
		{"window zero", Frame{Type: FrameWindow, StreamID: 1, Payload: []byte{0, 0, 0, 0}}},
		{"ping stream", Frame{Type: FramePing, StreamID: 1}},
		{"ping oversized", Frame{Type: FramePing, Payload: make([]byte, maxPingPayload+1)}},
		{"pong stream", Frame{Type: FramePong, StreamID: 1}},
		{"pong oversized", Frame{Type: FramePong, Payload: make([]byte, maxPingPayload+1)}},
		{"hello stream", Frame{Type: FrameHello, StreamID: 1, Payload: []byte{1}}},
		{"hello empty", Frame{Type: FrameHello}},
		{"hello version", Frame{Type: FrameHello, Payload: []byte{2}}},
		{"welcome stream", Frame{Type: FrameWelcome, StreamID: 1}},
		{"welcome payload", Frame{Type: FrameWelcome, Payload: []byte{1}}},
		{"bye stream", Frame{Type: FrameBye, StreamID: 1}},
		{"payload too large", Frame{Type: FrameData, StreamID: 1, Payload: make([]byte, MaxFramePayload+1)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := EncodeFrame(test.frame); err == nil {
				t.Fatal("invalid frame was encoded")
			}
		})
	}
}

func TestRejectWrongDirection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		frame     Frame
		direction Direction
	}{
		{Frame{Type: FrameOpen, StreamID: 1}, RelayToClient},
		{Frame{Type: FramePing}, ClientToRelay},
		{Frame{Type: FramePong}, RelayToClient},
		{Frame{Type: FrameHello, Payload: []byte{1}}, RelayToClient},
		{Frame{Type: FrameWelcome}, ClientToRelay},
		{Frame{Type: FrameBye}, ClientToRelay},
		{Frame{Type: FrameClose, StreamID: 1}, Direction(99)},
	}
	for _, test := range tests {
		if err := ValidateFrame(test.frame, test.direction); !errors.Is(err, ErrInvalidFrame) {
			t.Errorf("ValidateFrame(%#v, %d) error = %v", test.frame, test.direction, err)
		}
	}
	if err := ValidateClientFrame(Frame{Type: FrameHello, Payload: []byte{1}}); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("ValidateClientFrame(HELLO) error = %v", err)
	}
}

func TestParseHello(t *testing.T) {
	t.Parallel()

	hello, err := EncodeFrame(Frame{Type: FrameHello, Payload: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseHello(hello); err != nil {
		t.Fatal(err)
	}
	welcome, err := EncodeFrame(Frame{Type: FrameWelcome})
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string][]byte{
		"empty":         nil,
		"welcome":       welcome,
		"two hellos":    append(bytes.Clone(hello), hello...),
		"trailing byte": append(bytes.Clone(hello), 0),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ParseHello(input); err == nil {
				t.Fatal("invalid HELLO body was accepted")
			}
		})
	}
}

func TestParseBatchRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	data, err := EncodeFrame(Frame{Type: FrameData, StreamID: 1, Payload: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	closeFrame, err := EncodeFrame(Frame{Type: FrameClose, StreamID: 1})
	if err != nil {
		t.Fatal(err)
	}

	oversized := make([]byte, FrameHeaderSize)
	oversized[0] = byte(FrameData)
	oversized[3] = 1
	binary.BigEndian.PutUint32(oversized[4:], MaxFramePayload+1)
	unknown := bytes.Clone(closeFrame)
	unknown[0] = 0xff
	invalidShape := bytes.Clone(closeFrame)
	invalidShape[3] = 0

	tests := []struct {
		name  string
		input []byte
		want  error
	}{
		{"empty", nil, ErrEmptyFrameBatch},
		{"partial header", data[:FrameHeaderSize-1], ErrIncompleteFrame},
		{"partial payload", data[:FrameHeaderSize], ErrIncompleteFrame},
		{"oversized", oversized, ErrPayloadTooLarge},
		{"unknown", unknown, ErrInvalidFrame},
		{"invalid shape", invalidShape, ErrInvalidFrame},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseBatch(test.input); !errors.Is(err, test.want) {
				t.Fatalf("ParseBatch error = %v, want %v", err, test.want)
			}
		})
	}

	maxBatch := bytes.Repeat(closeFrame, MaxBatchFrames)
	if frames, err := ParseBatch(maxBatch); err != nil || len(frames) != MaxBatchFrames {
		t.Fatalf("maximum frame batch: len=%d error=%v", len(frames), err)
	}
	if _, err := ParseBatch(append(maxBatch, closeFrame...)); !errors.Is(err, ErrTooManyFrames) {
		t.Fatalf("oversized frame batch error = %v", err)
	}
}

func TestWindowHelpers(t *testing.T) {
	t.Parallel()

	for _, delta := range []uint32{1, InitialStreamWindow, ^uint32(0)} {
		payload, err := WindowPayload(delta)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := WindowDelta(payload)
		if err != nil || decoded != delta {
			t.Fatalf("WindowDelta(%d) = %d, %v", delta, decoded, err)
		}
	}
	if _, err := WindowPayload(0); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("WindowPayload(0) error = %v", err)
	}
	for _, payload := range [][]byte{nil, {0}, {0, 0, 0, 0}, {0, 0, 0, 0, 1}} {
		if _, err := WindowDelta(payload); !errors.Is(err, ErrInvalidFrame) {
			t.Errorf("WindowDelta(%x) error = %v", payload, err)
		}
	}
}
