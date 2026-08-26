package webproxy

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/gobwas/ws"
)

func TestWebSocketDecoderLengthBoundariesAndMasking(t *testing.T) {
	for _, size := range []int{1, 125, 126, 65535, 65536, maxWebSocketMessageBytes} {
		t.Run(stringSize(size), func(t *testing.T) {
			payload := bytes.Repeat([]byte{byte(size)}, size)
			frame := maskedClientFrame(t, ws.OpBinary, true, payload)
			decoder := testWebSocketDecoder(t, maxWebSocketMessageBytes)
			consumed, message, emitted, err := decoder.Decode(frame)
			if err != nil {
				t.Fatal(err)
			}
			if consumed != len(frame) || !emitted || message.typeID != webSocketMessageBinary ||
				!bytes.Equal(webSocketTestPayload(message), payload) {
				t.Fatalf("consumed=%d emitted=%t message=%#v", consumed, emitted, message)
			}
		})
	}

	unmasked := serverFrame(t, ws.OpBinary, true, []byte("x"))
	if _, _, _, err := testWebSocketDecoder(t, maxWebSocketMessageBytes).Decode(unmasked); !errors.Is(err, errWebSocketProtocol) {
		t.Fatalf("unmasked error = %v", err)
	}

	oversizedHeader := maskedClientHeader(t, ws.OpBinary, true, maxWebSocketMessageBytes+1)
	if _, _, _, err := testWebSocketDecoder(t, maxWebSocketMessageBytes).Decode(oversizedHeader); !errors.Is(err, errWebSocketTooLarge) {
		t.Fatalf("oversized header error = %v", err)
	}

	fragmented := maskedClientFrame(t, ws.OpBinary, false, bytes.Repeat([]byte("x"), maxWebSocketMessageBytes))
	fragmented = append(fragmented, maskedClientHeader(t, ws.OpContinuation, true, 1)...)
	decoder := testWebSocketDecoder(t, maxWebSocketMessageBytes)
	consumed, _, _, err := decoder.Decode(fragmented)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := decoder.Decode(fragmented[consumed:]); !errors.Is(err, errWebSocketTooLarge) {
		t.Fatalf("oversized fragmented header error = %v", err)
	}
}

func TestWebSocketDecoderConfiguredMessageLimit(t *testing.T) {
	const limit = 32
	for _, invalid := range []int{-1, 0, maxWebSocketMessageBytes + 1} {
		if _, err := newWebSocketDecoder(invalid, func(int) bool { return true }); !errors.Is(err, errInvalidWebSocketMessageLimit) {
			t.Fatalf("newWebSocketDecoder(%d) = %v", invalid, err)
		}
	}
	if _, err := newWebSocketDecoder(limit, nil); !errors.Is(err, errInvalidWebSocketReserver) {
		t.Fatalf("nil payload reserver = %v", err)
	}

	withinLimit := maskedClientFrame(t, ws.OpBinary, true, bytes.Repeat([]byte("x"), limit))
	if _, _, emitted, err := testWebSocketDecoder(t, limit).Decode(withinLimit); err != nil || !emitted {
		t.Fatalf("message at configured limit: emitted=%t err=%v", emitted, err)
	}
	overLimit := maskedClientHeader(t, ws.OpBinary, true, limit+1)
	if _, _, _, err := testWebSocketDecoder(t, limit).Decode(overLimit); !errors.Is(err, errWebSocketTooLarge) {
		t.Fatalf("message over configured limit = %v", err)
	}

	fragmentedAtLimit := maskedClientFrame(t, ws.OpBinary, false, bytes.Repeat([]byte("x"), limit/2))
	fragmentedAtLimit = append(fragmentedAtLimit,
		maskedClientFrame(t, ws.OpContinuation, true, bytes.Repeat([]byte("y"), limit/2))...)
	if _, message, emitted, err := testWebSocketDecoder(t, limit).Decode(fragmentedAtLimit); err != nil || !emitted || len(webSocketTestPayload(message)) != limit {
		t.Fatalf("fragmented message at configured limit: emitted=%t bytes=%d err=%v", emitted, len(webSocketTestPayload(message)), err)
	}

	fragmented := maskedClientFrame(t, ws.OpBinary, false, bytes.Repeat([]byte("x"), limit))
	fragmented = append(fragmented, maskedClientHeader(t, ws.OpContinuation, true, 1)...)
	decoder := testWebSocketDecoder(t, limit)
	consumed, _, _, err := decoder.Decode(fragmented)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := decoder.Decode(fragmented[consumed:]); !errors.Is(err, errWebSocketTooLarge) {
		t.Fatalf("fragmented message over configured limit = %v", err)
	}
}

func TestWebSocketDecoderReservesBeforePayloadAllocation(t *testing.T) {
	const announced = 1024
	requests := make([]int, 0, 1)
	decoder, err := newWebSocketDecoder(maxWebSocketMessageBytes, func(size int) bool {
		requests = append(requests, size)
		return false
	})
	if err != nil {
		t.Fatal(err)
	}
	header := maskedClientHeader(t, ws.OpBinary, true, announced)
	consumed, transformed, _, emitted, decodeErr := decoder.DecodeBounded(
		header,
		maxWebSocketPayloadBytesPerTraffic,
	)
	if !errors.Is(decodeErr, errWebSocketResource) || consumed != 0 || transformed != 0 || emitted {
		t.Fatalf("rejected frame: consumed=%d transformed=%d emitted=%t err=%v", consumed, transformed, emitted, decodeErr)
	}
	if len(requests) != 1 || requests[0] != announced {
		t.Fatalf("reservation requests = %v", requests)
	}
	if decoder.pending != nil || decoder.messageBytes != 0 || decoder.firstPayload != nil || decoder.firstFragment != nil {
		t.Fatalf("decoder allocated after rejected reservation: %#v", decoder)
	}
}

func TestWebSocketDecoderHeaderOnlyDoesNotAllocateAnnouncedPayload(t *testing.T) {
	requests := make([]int, 0, 1)
	decoder, err := newWebSocketDecoder(maxWebSocketMessageBytes, func(size int) bool {
		requests = append(requests, size)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	header := maskedClientHeader(t, ws.OpBinary, true, maxWebSocketMessageBytes)
	consumed, transformed, _, emitted, decodeErr := decoder.DecodeBounded(
		header,
		maxWebSocketPayloadBytesPerTraffic,
	)
	if decodeErr != nil || consumed != len(header) || transformed != 0 || emitted {
		t.Fatalf("header decode: consumed=%d transformed=%d emitted=%t err=%v", consumed, transformed, emitted, decodeErr)
	}
	chunks := (maxWebSocketMessageBytes + maxWebSocketPayloadBytesPerTraffic - 1) /
		maxWebSocketPayloadBytesPerTraffic
	wantOwned := maxWebSocketMessageBytes + (chunks-1)*webSocketFragmentBytes
	if len(requests) != 1 || requests[0] != wantOwned || decoder.messageOwned != wantOwned {
		t.Fatalf("reservations=%v decoder-owned=%d want=%d", requests, decoder.messageOwned, wantOwned)
	}
	if decoder.pending == nil || decoder.pending.payload != nil || decoder.pending.received != 0 ||
		webSocketDecoderStorageCapacity(decoder) != 0 {
		t.Fatalf("header-only frame allocated payload storage: %#v", decoder)
	}
}

func TestWebSocketDecoderBoundsPayloadWorkPerCall(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, maxWebSocketMessageBytes)
	frame := maskedClientFrame(t, ws.OpBinary, true, payload)
	decoder := testWebSocketDecoder(t, maxWebSocketMessageBytes)
	input := frame
	calls := 0
	allocated := 0
	var message webSocketMessage
	for len(input) != 0 {
		consumed, transformed, decoded, emitted, err := decoder.DecodeBounded(
			input,
			maxWebSocketPayloadBytesPerTraffic,
		)
		if err != nil {
			t.Fatal(err)
		}
		if transformed > maxWebSocketPayloadBytesPerTraffic {
			t.Fatalf("transformed %d bytes in one call", transformed)
		}
		if consumed == 0 {
			t.Fatal("decoder made no progress")
		}
		calls++
		currentAllocated := webSocketDecoderStorageCapacity(decoder)
		if emitted {
			currentAllocated = webSocketMessageStorageCapacity(decoded)
		}
		if growth := currentAllocated - allocated; growth < 0 || growth > maxWebSocketPayloadBytesPerTraffic {
			t.Fatalf("payload storage grew by %d bytes in one call", growth)
		}
		allocated = currentAllocated
		input = input[consumed:]
		if emitted {
			message = decoded
		}
	}
	if calls <= 1 {
		t.Fatalf("large frame completed in %d call", calls)
	}
	if !bytes.Equal(webSocketTestPayload(message), payload) {
		t.Fatal("incremental decode corrupted the payload")
	}
}

func webSocketDecoderStorageCapacity(decoder *webSocketDecoder) int {
	if decoder == nil {
		return 0
	}
	capacity := cap(decoder.firstPayload)
	for fragment := decoder.firstFragment; fragment != nil; fragment = fragment.next {
		capacity += cap(fragment.payload)
	}
	return capacity
}

func webSocketMessageStorageCapacity(message webSocketMessage) int {
	capacity := cap(message.payload)
	for fragment := message.fragments; fragment != nil; fragment = fragment.next {
		capacity += cap(fragment.payload)
	}
	return capacity
}

func TestWebSocketDecoderPartialHeadersAndPayload(t *testing.T) {
	frame := maskedClientFrame(t, ws.OpBinary, true, bytes.Repeat([]byte("x"), 65536))
	for split := 0; split < ws.MaxHeaderSize; split++ {
		decoder := testWebSocketDecoder(t, maxWebSocketMessageBytes)
		consumed, _, emitted, err := decoder.Decode(frame[:split])
		if err != nil || consumed != 0 || emitted {
			t.Fatalf("split %d: consumed=%d emitted=%t err=%v", split, consumed, emitted, err)
		}
	}
	decoder := testWebSocketDecoder(t, maxWebSocketMessageBytes)
	if consumed, _, emitted, err := decoder.Decode(frame[:len(frame)-1]); err != nil || consumed != len(frame)-1 || emitted {
		t.Fatalf("partial payload: consumed=%d emitted=%t err=%v", consumed, emitted, err)
	}
}

func TestWebSocketDecoderFragmentationAndControls(t *testing.T) {
	input := append(maskedClientFrame(t, ws.OpBinary, false, []byte("hello")),
		maskedClientFrame(t, ws.OpPing, true, []byte("probe"))...)
	continuation := maskedClientFrame(t, ws.OpContinuation, true, []byte(" world"))
	input = append(input, continuation...)
	decoder := testWebSocketDecoder(t, maxWebSocketMessageBytes)
	consumed, message, emitted, err := decoder.Decode(input)
	if err != nil || !emitted || message.typeID != webSocketMessagePing || string(message.payload) != "probe" {
		t.Fatalf("first decode: consumed=%d emitted=%t message=%#v err=%v", consumed, emitted, message, err)
	}
	if !bytes.Equal(input[consumed:], continuation) {
		t.Fatal("first decode did not preserve the continuation suffix")
	}
	secondConsumed, message, emitted, err := decoder.Decode(input[consumed:])
	if err != nil || secondConsumed != len(continuation) || !emitted ||
		message.typeID != webSocketMessageBinary || string(webSocketTestPayload(message)) != "hello world" {
		t.Fatalf("second decode: consumed=%d emitted=%t message=%#v err=%v", secondConsumed, emitted, message, err)
	}

	for name, input := range map[string][]byte{
		"unexpected continuation": maskedClientFrame(t, ws.OpContinuation, true, []byte("x")),
		"second data start": append(maskedClientFrame(t, ws.OpBinary, false, []byte("x")),
			maskedClientFrame(t, ws.OpBinary, true, []byte("y"))...),
		"text":         maskedClientFrame(t, ws.OpText, true, []byte("x")),
		"empty binary": maskedClientFrame(t, ws.OpBinary, true, nil),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, decodeErr := testWebSocketDecoder(t, maxWebSocketMessageBytes).Decode(input); !errors.Is(decodeErr, errWebSocketProtocol) {
				t.Fatalf("error = %v", decodeErr)
			}
		})
	}
}

func TestWebSocketDecoderBoundsFramesAndEventsPerCall(t *testing.T) {
	ping := maskedClientFrame(t, ws.OpPing, true, nil)
	controlFlood := bytes.Repeat(ping, maxWebSocketFramesPerDecode+1)
	decoder := testWebSocketDecoder(t, maxWebSocketMessageBytes)
	consumed, message, emitted, err := decoder.Decode(controlFlood)
	if err != nil || consumed != len(ping) || !emitted || message.typeID != webSocketMessagePing {
		t.Fatalf("control flood: consumed=%d emitted=%t message=%#v err=%v", consumed, emitted, message, err)
	}
	if !bytes.Equal(controlFlood[consumed:], controlFlood[len(ping):]) {
		t.Fatal("control flood suffix changed")
	}

	start := maskedClientFrame(t, ws.OpBinary, false, []byte("x"))
	emptyContinuation := maskedClientFrame(t, ws.OpContinuation, false, nil)
	final := maskedClientFrame(t, ws.OpContinuation, true, []byte("y"))
	fragmentFlood := append(bytes.Clone(start), bytes.Repeat(emptyContinuation, maxWebSocketFramesPerDecode)...)
	fragmentFlood = append(fragmentFlood, final...)
	decoder = testWebSocketDecoder(t, maxWebSocketMessageBytes)
	consumed, work, _, emitted, err := decoder.decodeWindow(fragmentFlood, maxWebSocketMessageBytes)
	wantConsumed := len(start) + (maxWebSocketFramesPerDecode-1)*len(emptyContinuation)
	if err != nil || consumed != wantConsumed || emitted || work.limit != webSocketDecodeFrameLimit {
		t.Fatalf("fragment flood: consumed=%d want=%d emitted=%t limit=%d err=%v",
			consumed, wantConsumed, emitted, work.limit, err)
	}
	wantSuffix := append(bytes.Clone(emptyContinuation), final...)
	if !bytes.Equal(fragmentFlood[consumed:], wantSuffix) {
		t.Fatal("fragment flood suffix changed")
	}
	secondConsumed, message, emitted, err := decoder.Decode(fragmentFlood[consumed:])
	if err != nil || secondConsumed != len(wantSuffix) || !emitted ||
		message.typeID != webSocketMessageBinary || string(webSocketTestPayload(message)) != "xy" {
		t.Fatalf("fragment completion: consumed=%d emitted=%t message=%#v err=%v", secondConsumed, emitted, message, err)
	}
}

func TestWebSocketDecoderRejectsInvalidHeaderAndClosePayload(t *testing.T) {
	validClose := []byte{0x03, 0xe8}
	input := maskedClientFrame(t, ws.OpClose, true, validClose)
	_, message, emitted, err := testWebSocketDecoder(t, maxWebSocketMessageBytes).Decode(input)
	if err != nil || !emitted || message.typeID != webSocketMessageClose {
		t.Fatalf("valid close: emitted=%t message=%#v err=%v", emitted, message, err)
	}

	tests := map[string][]byte{
		"close one byte":      maskedClientFrame(t, ws.OpClose, true, []byte{1}),
		"reserved close code": maskedClientFrame(t, ws.OpClose, true, []byte{0x03, 0xed}),
		"invalid close UTF-8": maskedClientFrame(t, ws.OpClose, true, []byte{0x03, 0xe8, 0xff}),
		"fragmented control":  maskedClientFrame(t, ws.OpPing, false, nil),
	}
	for name, frame := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, _, decodeErr := testWebSocketDecoder(t, maxWebSocketMessageBytes).Decode(frame); !errors.Is(decodeErr, errWebSocketProtocol) {
				t.Fatalf("error = %v", decodeErr)
			}
		})
	}

	rsv := maskedClientFrame(t, ws.OpBinary, true, []byte("x"))
	rsv[0] |= 0x40
	if _, _, _, err := testWebSocketDecoder(t, maxWebSocketMessageBytes).Decode(rsv); !errors.Is(err, errWebSocketProtocol) {
		t.Fatalf("RSV error = %v", err)
	}

	afterClose := append(maskedClientFrame(t, ws.OpClose, true, validClose),
		maskedClientFrame(t, ws.OpBinary, true, []byte("late"))...)
	if _, _, _, err := testWebSocketDecoder(t, maxWebSocketMessageBytes).Decode(afterClose); !errors.Is(err, errWebSocketProtocol) {
		t.Fatalf("post-close error = %v", err)
	}
}

func TestWebSocketDecoderRejectsNonCanonicalLengths(t *testing.T) {
	for name, frame := range map[string][]byte{
		"16-bit for 125": {0x82, 0xfe, 0, 125, 1, 2, 3, 4},
		"64-bit for 65535": {
			0x82, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := testWebSocketDecoder(t, maxWebSocketMessageBytes).Decode(frame); !errors.Is(err, errWebSocketProtocol) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestWebSocketServerEncodingIsFinalAndUnmasked(t *testing.T) {
	for _, message := range []webSocketMessage{
		{typeID: webSocketMessageBinary, payload: []byte("data")},
		{typeID: webSocketMessagePing},
		{typeID: webSocketMessagePong, payload: []byte("probe")},
		{typeID: webSocketMessageClose, payload: []byte{0x03, 0xe8}},
	} {
		encoded, err := encodeWebSocketServerMessage(message)
		if err != nil {
			t.Fatal(err)
		}
		header, readErr := ws.ReadHeader(bytes.NewReader(encoded))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !header.Fin || header.Masked || header.Length != int64(len(message.payload)) {
			t.Fatalf("header = %#v", header)
		}
	}
}

func FuzzWebSocketDecoder(f *testing.F) {
	f.Add(maskedClientFrame(f, ws.OpBinary, true, []byte("payload")))
	f.Add(maskedClientFrame(f, ws.OpPing, true, nil))
	f.Add([]byte{0x82, 0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoder := testWebSocketDecoder(t, maxWebSocketMessageBytes)
		consumed, message, emitted, _ := decoder.Decode(input)
		if consumed < 0 || consumed > len(input) {
			t.Fatalf("consumed = %d for %d bytes", consumed, len(input))
		}
		if emitted && len(webSocketTestPayload(message)) > maxWebSocketMessageBytes {
			t.Fatalf("oversized decoded payload: %d", len(webSocketTestPayload(message)))
		}
	})
}

func webSocketTestPayload(message webSocketMessage) []byte {
	if !message.chunked {
		return message.payload
	}
	payload := make([]byte, 0, message.payloadBytes)
	payload = append(payload, message.payload...)
	for fragment := message.fragments; fragment != nil; fragment = fragment.next {
		payload = append(payload, fragment.payload...)
	}
	return payload
}

func testWebSocketDecoder(t testing.TB, maxMessageBytes int) *webSocketDecoder {
	t.Helper()
	decoder, err := newWebSocketDecoder(maxMessageBytes, func(int) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	return decoder
}

func maskedClientFrame(t testing.TB, opcode ws.OpCode, final bool, payload []byte) []byte {
	t.Helper()
	header := maskedClientHeader(t, opcode, final, len(payload))
	masked := bytes.Clone(payload)
	ws.Cipher(masked, [4]byte{1, 2, 3, 4}, 0)
	return append(header, masked...)
}

func maskedClientHeader(t testing.TB, opcode ws.OpCode, final bool, length int) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := ws.WriteHeader(&buffer, ws.Header{
		Fin:    final,
		OpCode: opcode,
		Masked: true,
		Mask:   [4]byte{1, 2, 3, 4},
		Length: int64(length),
	}); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func serverFrame(t testing.TB, opcode ws.OpCode, final bool, payload []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	if err := ws.WriteHeader(&buffer, ws.Header{Fin: final, OpCode: opcode, Length: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	_, _ = buffer.Write(payload)
	return buffer.Bytes()
}

func stringSize(size int) string {
	return strconv.Itoa(size)
}
