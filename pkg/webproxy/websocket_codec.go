package webproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"unsafe"

	"github.com/gobwas/ws"
)

const (
	maxWebSocketMessageBytes           = maxCarrierBatchBytes
	maxWebSocketFramesPerDecode        = 16
	maxWebSocketPayloadBytesPerTraffic = 64 * 1024
)

var (
	errWebSocketProtocol            = errors.New("invalid WEB WebSocket frame")
	errWebSocketTooLarge            = errors.New("WEB WebSocket message exceeds configured limit")
	errWebSocketResource            = errors.New("WEB WebSocket input budget exhausted")
	errInvalidWebSocketMessageLimit = errors.New("WEB WebSocket message limit must be between 1 byte and 2 MiB")
	errInvalidWebSocketReserver     = errors.New("WEB WebSocket payload reserver is required")
)

type webSocketMessageType uint8

const (
	webSocketMessageBinary webSocketMessageType = iota + 1
	webSocketMessagePing
	webSocketMessagePong
	webSocketMessageClose
)

type webSocketMessage struct {
	typeID       webSocketMessageType
	payload      []byte
	fragments    *webSocketFragment
	payloadBytes int
	chunked      bool
}

type webSocketFragment struct {
	payload []byte
	next    *webSocketFragment
}

var webSocketFragmentBytes = int(unsafe.Sizeof(webSocketFragment{}))

type webSocketPayloadReserver func(size int) bool

type webSocketDecodeLimit uint8

const (
	webSocketDecodeNoLimit webSocketDecodeLimit = iota
	webSocketDecodePayloadLimit
	webSocketDecodeFrameLimit
)

type webSocketDecodeWork struct {
	transformed int
	limit       webSocketDecodeLimit
}

type webSocketPendingFrame struct {
	header   ws.Header
	payload  []byte
	received int
	data     bool
}

// webSocketDecoder incrementally copies and unmasks client payloads into
// decoder-owned storage. It never retains input, which lets callers pass a
// gnet-owned Peek buffer safely.
type webSocketDecoder struct {
	state           ws.State
	firstPayload    []byte
	firstFragment   *webSocketFragment
	lastFragment    *webSocketFragment
	messageBytes    int
	messageOwned    int
	pending         *webSocketPendingFrame
	maxMessageBytes int
	reservePayload  webSocketPayloadReserver
	closed          bool
}

func newWebSocketDecoder(
	maxMessageBytes int,
	reservePayload webSocketPayloadReserver,
) (*webSocketDecoder, error) {
	if maxMessageBytes <= 0 || maxMessageBytes > maxWebSocketMessageBytes {
		return nil, errInvalidWebSocketMessageLimit
	}
	if reservePayload == nil {
		return nil, errInvalidWebSocketReserver
	}
	return &webSocketDecoder{
		state:           ws.StateServerSide,
		maxMessageBytes: maxMessageBytes,
		reservePayload:  reservePayload,
	}, nil
}

// Decode consumes at most one protocol event, maxWebSocketFramesPerDecode
// frames, and payloadBudget bytes of clone/unmask work. The caller must retain
// input[consumed:] unchanged.
func (d *webSocketDecoder) DecodeBounded(
	input []byte,
	payloadBudget int,
) (consumed, transformed int, message webSocketMessage, emitted bool, err error) {
	consumed, work, message, emitted, err := d.decodeWindow(input, payloadBudget)
	return consumed, work.transformed, message, emitted, err
}

func (d *webSocketDecoder) decodeWindow(
	input []byte,
	payloadBudget int,
) (consumed int, work webSocketDecodeWork, message webSocketMessage, emitted bool, err error) {
	if d == nil || d.closed {
		return 0, work, message, false, errWebSocketProtocol
	}
	if payloadBudget <= 0 {
		work.limit = webSocketDecodePayloadLimit
		return 0, work, message, false, nil
	}
	for range maxWebSocketFramesPerDecode {
		if d.pending == nil {
			if consumed == len(input) {
				return consumed, work, message, false, nil
			}
			header, headerBytes, complete, decodeErr := decodeWebSocketHeader(input[consumed:])
			if decodeErr != nil {
				return consumed, work, message, false, decodeErr
			}
			if !complete {
				return consumed, work, message, false, nil
			}
			if prepareErr := d.prepareFrame(header); prepareErr != nil {
				return consumed, work, message, false, prepareErr
			}
			consumed += headerBytes
		}

		pending := d.pending
		for pending.received != int(pending.header.Length) {
			remaining := int(pending.header.Length) - pending.received
			available := len(input) - consumed
			allowance := payloadBudget - work.transformed
			if available == 0 {
				return consumed, work, message, false, nil
			}
			if allowance == 0 {
				work.limit = webSocketDecodePayloadLimit
				return consumed, work, message, false, nil
			}
			take := min(remaining, available, allowance, maxWebSocketPayloadBytesPerTraffic)
			if pending.data {
				d.appendPayload(
					input[consumed:consumed+take],
					pending.header.Mask,
					pending.received,
					remaining,
				)
			} else {
				chunk := pending.payload[pending.received : pending.received+take]
				copy(chunk, input[consumed:consumed+take])
				ws.Cipher(chunk, pending.header.Mask, pending.received)
			}
			pending.received += take
			consumed += take
			work.transformed += take
		}

		header := pending.header
		payload := pending.payload
		d.pending = nil
		if pending.data {
			d.messageBytes += int(header.Length)
		}
		var messageErr error
		message, emitted, messageErr = d.applyFrame(header, payload)
		if messageErr != nil {
			return consumed, work, message, false, messageErr
		}
		if d.closed && consumed != len(input) {
			return consumed, work, message, emitted, errWebSocketProtocol
		}
		if emitted {
			return consumed, work, message, true, nil
		}
		if work.transformed == payloadBudget {
			work.limit = webSocketDecodePayloadLimit
			return consumed, work, message, false, nil
		}
	}
	work.limit = webSocketDecodeFrameLimit
	return consumed, work, message, false, nil
}

// Decode is the unbounded convenience used by codec tests and non-event-loop
// callers. The gnet transport uses DecodeBounded to cap work per callback.
func (d *webSocketDecoder) Decode(
	input []byte,
) (consumed int, message webSocketMessage, emitted bool, err error) {
	consumed, _, message, emitted, err = d.DecodeBounded(input, d.maxMessageBytes)
	return consumed, message, emitted, err
}

func (d *webSocketDecoder) prepareFrame(header ws.Header) error {
	if checkErr := ws.CheckHeader(header, d.state); checkErr != nil {
		return errors.Join(errWebSocketProtocol, checkErr)
	}
	if header.OpCode == ws.OpText {
		return errWebSocketProtocol
	}
	if header.OpCode.IsData() && header.OpCode != ws.OpBinary && header.OpCode != ws.OpContinuation {
		return errWebSocketProtocol
	}
	if header.Length < 0 {
		return errWebSocketProtocol
	}
	if !header.OpCode.IsControl() && header.Length > int64(d.maxMessageBytes-d.messageBytes) {
		return errWebSocketTooLarge
	}

	length := int(header.Length)
	if header.OpCode.IsControl() {
		d.pending = &webSocketPendingFrame{header: header, payload: make([]byte, length)}
		return nil
	}
	chunks := 0
	if length != 0 {
		chunks = (length + maxWebSocketPayloadBytesPerTraffic - 1) / maxWebSocketPayloadBytesPerTraffic
	}
	nodes := chunks
	if chunks != 0 && d.firstPayload == nil {
		nodes--
	}
	owned := d.messageOwned + length + nodes*webSocketFragmentBytes
	if !d.reservePayload(owned) {
		return errWebSocketResource
	}
	d.messageOwned = owned
	d.pending = &webSocketPendingFrame{header: header, data: true}
	return nil
}

func (d *webSocketDecoder) Reset() {
	if d == nil {
		return
	}
	d.firstPayload = nil
	d.firstFragment = nil
	d.lastFragment = nil
	d.messageBytes = 0
	d.messageOwned = 0
	d.pending = nil
	d.closed = true
}

func (d *webSocketDecoder) fragmentedMessageOpen() bool {
	if d == nil || d.closed {
		return false
	}
	if d.state.Fragmented() {
		return true
	}
	return d.pending != nil && d.pending.data &&
		d.pending.header.OpCode == ws.OpBinary && !d.pending.header.Fin
}

func decodeWebSocketHeader(input []byte) (header ws.Header, size int, complete bool, err error) {
	if len(input) < ws.MinHeaderSize {
		return header, 0, false, nil
	}
	probe := input[:min(len(input), ws.MaxHeaderSize)]
	reader := bytes.NewReader(probe)
	header, err = ws.ReadHeader(reader)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ws.Header{}, 0, false, nil
	}
	if err != nil {
		return ws.Header{}, 0, false, errors.Join(errWebSocketProtocol, err)
	}
	size = len(probe) - reader.Len()
	lengthMarker := input[1] & 0x7f
	if lengthMarker == 126 && header.Length < 126 || lengthMarker == 127 && header.Length <= 65535 {
		return ws.Header{}, 0, false, errWebSocketProtocol
	}
	return header, size, true, nil
}

func (d *webSocketDecoder) applyFrame(
	header ws.Header,
	payload []byte,
) (message webSocketMessage, emitted bool, err error) {
	switch header.OpCode {
	case ws.OpBinary:
		if header.Fin {
			if d.messageBytes == 0 {
				return message, false, errWebSocketProtocol
			}
			return d.completeBinaryMessage(), true, nil
		}
		d.state = d.state.Set(ws.StateFragmented)
		return message, false, nil

	case ws.OpContinuation:
		if !header.Fin {
			return message, false, nil
		}
		if d.messageBytes == 0 {
			return message, false, errWebSocketProtocol
		}
		d.state = d.state.Clear(ws.StateFragmented)
		return d.completeBinaryMessage(), true, nil

	case ws.OpPing:
		return webSocketMessage{typeID: webSocketMessagePing, payload: payload}, true, nil
	case ws.OpPong:
		return webSocketMessage{typeID: webSocketMessagePong, payload: payload}, true, nil
	case ws.OpClose:
		if err := validateWebSocketClosePayload(payload); err != nil {
			return message, false, err
		}
		d.closed = true
		return webSocketMessage{typeID: webSocketMessageClose, payload: payload}, true, nil
	default:
		return message, false, errWebSocketProtocol
	}
}

func (d *webSocketDecoder) appendPayload(payload []byte, mask [4]byte, offset, frameRemaining int) {
	if len(payload) == 0 {
		return
	}
	for len(payload) != 0 {
		var current *[]byte
		if d.firstPayload == nil {
			d.firstPayload = make([]byte, 0, min(frameRemaining, maxWebSocketPayloadBytesPerTraffic))
			current = &d.firstPayload
		} else if d.lastFragment == nil && len(d.firstPayload) != cap(d.firstPayload) {
			current = &d.firstPayload
		} else if d.lastFragment != nil && len(d.lastFragment.payload) != cap(d.lastFragment.payload) {
			current = &d.lastFragment.payload
		} else {
			fragment := &webSocketFragment{
				payload: make([]byte, 0, min(frameRemaining, maxWebSocketPayloadBytesPerTraffic)),
			}
			if d.lastFragment == nil {
				d.firstFragment = fragment
			} else {
				d.lastFragment.next = fragment
			}
			d.lastFragment = fragment
			current = &fragment.payload
		}
		available := cap(*current) - len(*current)
		take := min(len(payload), available)
		start := len(*current)
		*current = append(*current, payload[:take]...)
		ws.Cipher((*current)[start:], mask, offset)
		payload = payload[take:]
		offset += take
		frameRemaining -= take
	}
}

func (d *webSocketDecoder) completeBinaryMessage() webSocketMessage {
	message := webSocketMessage{
		typeID:       webSocketMessageBinary,
		payload:      d.firstPayload,
		fragments:    d.firstFragment,
		payloadBytes: d.messageBytes,
		chunked:      true,
	}
	d.firstPayload = nil
	d.firstFragment = nil
	d.lastFragment = nil
	d.messageBytes = 0
	d.messageOwned = 0
	return message
}

func validateWebSocketClosePayload(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	if len(payload) == 1 {
		return errWebSocketProtocol
	}
	code := ws.StatusCode(binary.BigEndian.Uint16(payload[:2]))
	if err := ws.CheckCloseFrameData(code, string(payload[2:])); err != nil {
		return errors.Join(errWebSocketProtocol, err)
	}
	return nil
}

func encodeWebSocketServerMessage(message webSocketMessage) ([]byte, error) {
	header, payload, err := encodeWebSocketServerParts(message)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, len(header)+len(payload))
	encoded = append(encoded, header...)
	encoded = append(encoded, payload...)
	return encoded, nil
}

func encodeWebSocketServerParts(message webSocketMessage) (header, payload []byte, err error) {
	var opcode ws.OpCode
	switch message.typeID {
	case webSocketMessageBinary:
		if len(message.payload) == 0 || len(message.payload) > maxWebSocketMessageBytes {
			return nil, nil, errWebSocketProtocol
		}
		opcode = ws.OpBinary
	case webSocketMessagePing:
		opcode = ws.OpPing
	case webSocketMessagePong:
		opcode = ws.OpPong
	case webSocketMessageClose:
		if err := validateWebSocketClosePayload(message.payload); err != nil {
			return nil, nil, err
		}
		opcode = ws.OpClose
	default:
		return nil, nil, errWebSocketProtocol
	}
	if opcode.IsControl() && len(message.payload) > ws.MaxControlFramePayloadSize {
		return nil, nil, errWebSocketProtocol
	}

	var encoded bytes.Buffer
	encoded.Grow(ws.MaxHeaderSize)
	if err := ws.WriteHeader(&encoded, ws.Header{
		Fin:    true,
		OpCode: opcode,
		Length: int64(len(message.payload)),
	}); err != nil {
		return nil, nil, errors.Join(errWebSocketProtocol, err)
	}
	return encoded.Bytes(), message.payload, nil
}
