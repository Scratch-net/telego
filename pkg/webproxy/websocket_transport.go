package webproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/panjf2000/gnet/v2"
)

const (
	maxWebSocketOutboundMessages = 16
	// Telegram Desktop can place up to 512 frames in its WebView boundary.
	// Decode those frames into the existing session/global budgets instead of
	// letting gnet accumulate uncharged socket bytes while one uplink runs.
	maxWebSocketInboundItemsPerSocket = 512
	// The private gnet server reads and the decoder transforms one 64 KiB
	// quantum at a time. Retain at most one unread quantum when frame-count,
	// rather than payload work, exhausts the decoder callback, or after a
	// control frame is emitted.
	maxWebSocketControlInputBytes = maxWebSocketPayloadBytesPerTraffic
	webSocketBackpressureTimeout  = 30 * time.Second
	webSocketBackpressureRetry    = 50 * time.Millisecond
)

type webSocketPhase uint8

const (
	webSocketHandshake webSocketPhase = iota + 1
	webSocketOpen
	webSocketClosing
)

type webSocketInbound struct {
	body         []byte
	fragments    *webSocketFragment
	payloadBytes int
	chunked      bool
	reservation  *webSocketOwnedInput
}

type webSocketUplinkResult struct {
	code ws.StatusCode
}

type webSocketOutbound struct {
	message    webSocketMessage
	lease      *PollLease
	done       chan error
	writeBatch [][]byte
	control    bool
	closeAfter bool
}

type webSocketFailure struct {
	code ws.StatusCode
}

type webSocketInboundBuffer interface {
	InboundBuffered() int
	Discard(int) (int, error)
}

type webSocketInboundBudget struct {
	mu       sync.Mutex
	bytes    int
	items    int
	maxBytes int
	maxItems int
}

type webSocketOwnedInput struct {
	mu       sync.Mutex
	session  *webSocketInputReservation
	local    *webSocketInboundBudget
	size     int
	released bool
}

func (b *webSocketInboundBudget) reserve(size int) bool {
	if b == nil || size < 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.items >= b.maxItems || size > b.maxBytes-b.bytes {
		return false
	}
	b.bytes += size
	b.items++
	return true
}

func (b *webSocketInboundBudget) resize(previous, next int) bool {
	if b == nil || previous < 0 || next < 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.items == 0 || previous > b.bytes {
		return false
	}
	delta := next - previous
	if delta > 0 && delta > b.maxBytes-b.bytes {
		return false
	}
	b.bytes += delta
	return true
}

func (b *webSocketInboundBudget) release(size int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if size < 0 || b.items == 0 || size > b.bytes {
		panic("invalid WEB WebSocket local budget release")
	}
	b.bytes -= size
	b.items--
}

func (b *webSocketInboundBudget) snapshot() (int, int) {
	if b == nil {
		return 0, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bytes, b.items
}

func newWebSocketOwnedInput(
	session *Session,
	local *webSocketInboundBudget,
	size int,
) (*webSocketOwnedInput, bool) {
	if !local.reserve(size) {
		return nil, false
	}
	reserved, ok := session.reserveWebSocketInput(size)
	if !ok {
		local.release(size)
		return nil, false
	}
	return &webSocketOwnedInput{session: reserved, local: local, size: size}, true
}

func (r *webSocketOwnedInput) resize(size int) bool {
	if r == nil || size < 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resizeLocked(size)
}

func (r *webSocketOwnedInput) grow(delta int) bool {
	if r == nil || delta < 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	size, ok := checkedAddInt(r.size, delta)
	if !ok {
		return false
	}
	return r.resizeLocked(size)
}

func (r *webSocketOwnedInput) resizeLocked(size int) bool {
	if r.released || size == r.size {
		return !r.released
	}
	previous := r.size
	if !r.local.resize(previous, size) {
		return false
	}
	if !r.session.resize(size) {
		if !r.local.resize(size, previous) {
			panic("failed to roll back WEB WebSocket local budget")
		}
		return false
	}
	r.size = size
	return true
}

func (r *webSocketOwnedInput) Release() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return
	}
	r.released = true
	r.session.Release()
	r.local.release(r.size)
	r.size = 0
}

type webSocketConnection struct {
	session *Session
	lane    *WebSocketLaneLease
	decoder *webSocketDecoder
	manager *Manager

	ctx    context.Context
	cancel context.CancelFunc

	phase               webSocketPhase
	handshakeWritten    bool
	asyncWritePending   bool
	uplinkPending       int
	livenessExpired     bool
	controlInputBytes   int
	controlOutputItems  int
	current             *webSocketOutbound
	fragmentReservation *webSocketOwnedInput
	inboundBudget       *webSocketInboundBudget
	decoderOwnedLimit   int
	inbound             chan webSocketInbound
	uplinkResults       chan webSocketUplinkResult
	outbound            chan *webSocketOutbound
	failures            chan webSocketFailure
	liveness            *time.Timer
	livenessID          uint64
	workers             sync.WaitGroup
	closeOnce           sync.Once
	queueMu             sync.Mutex
	closed              bool
	metricsActive       bool
	backpressureTimeout time.Duration
	backpressureRetry   time.Duration
}

func newWebSocketConnection(
	session *Session,
	lane *WebSocketLaneLease,
	manager *Manager,
) (*webSocketConnection, error) {
	messageLimit := min(session.limits.MaxBodyBytes, maxWebSocketMessageBytes)
	ctx, cancel := context.WithCancel(context.Background())
	connection := &webSocketConnection{
		session: session,
		lane:    lane,
		manager: manager,
		ctx:     ctx,
		cancel:  cancel,
		phase:   webSocketHandshake,
		inboundBudget: &webSocketInboundBudget{
			// Chunked messages are coalesced off the event loop. During that
			// transition, payload, linked metadata, and contiguous body coexist.
			maxBytes: 3 * messageLimit,
			maxItems: maxWebSocketInboundItemsPerSocket,
		},
		decoderOwnedLimit:   2 * messageLimit,
		inbound:             make(chan webSocketInbound, maxWebSocketInboundItemsPerSocket),
		uplinkResults:       make(chan webSocketUplinkResult, maxWebSocketInboundItemsPerSocket),
		outbound:            make(chan *webSocketOutbound, maxWebSocketOutboundMessages),
		failures:            make(chan webSocketFailure, 1),
		backpressureTimeout: webSocketBackpressureTimeout,
		backpressureRetry:   webSocketBackpressureRetry,
	}
	decoder, err := newWebSocketDecoder(messageLimit, connection.reserveDecodedPayload)
	if err != nil {
		cancel()
		return nil, err
	}
	connection.decoder = decoder
	return connection, nil
}

func (w *webSocketConnection) reserveDecodedPayload(size int) bool {
	if w == nil || w.session == nil || w.inboundBudget == nil || size > w.decoderOwnedLimit {
		return false
	}
	if w.fragmentReservation == nil {
		reservation, ok := newWebSocketOwnedInput(w.session, w.inboundBudget, size)
		if !ok {
			return false
		}
		w.fragmentReservation = reservation
		return true
	}
	return w.fragmentReservation.resize(size)
}

func (w *webSocketConnection) resetControlBurstIfDrained(connection webSocketInboundBuffer) {
	if connection.InboundBuffered() == 0 && w.controlOutputItems == 0 {
		w.controlInputBytes = 0
	}
}

func (w *webSocketConnection) canDecodeWhileUplinkPending(input []byte) bool {
	if w.uplinkPending == 0 || w.decoder.pending != nil {
		return true
	}
	header, _, complete, err := decodeWebSocketHeader(input)
	if err != nil || !complete || ws.CheckHeader(header, w.decoder.state) != nil {
		return false
	}
	return header.OpCode == ws.OpBinary || header.OpCode == ws.OpContinuation
}

func (w *webSocketConnection) boundUnreadInput(
	connection webSocketInboundBuffer,
	work webSocketDecodeWork,
	message webSocketMessage,
	emitted bool,
	emittedControl bool,
	denseControlSuffix bool,
) (bool, error) {
	if (emitted && message.typeID == webSocketMessageBinary) || (work.transformed != 0 && !emittedControl) {
		w.controlInputBytes = 0
	}
	if emittedControl {
		controlBytes, ok := checkedAddInt(ws.MinHeaderSize+4, len(message.payload))
		if !ok {
			return true, nil
		}
		w.controlInputBytes, ok = checkedAddInt(w.controlInputBytes, controlBytes)
		if !ok || w.controlInputBytes >= maxWebSocketControlInputBytes {
			_, err := connection.Discard(connection.InboundBuffered())
			return true, err
		}
		if denseControlSuffix {
			_, err := connection.Discard(connection.InboundBuffered())
			return true, err
		}
	}
	if !emittedControl && (work.limit != webSocketDecodeFrameLimit || !w.decoder.fragmentedMessageOpen()) {
		return false, nil
	}
	buffered := connection.InboundBuffered()
	if emittedControl && buffered >= maxWebSocketControlInputBytes-w.controlInputBytes {
		_, err := connection.Discard(buffered)
		return true, err
	}
	if buffered <= maxWebSocketControlInputBytes {
		return false, nil
	}
	_, err := connection.Discard(buffered)
	return true, err
}

func (w *webSocketConnection) hasDenseControlSuffix(input []byte) bool {
	for range maxWebSocketOutboundMessages {
		header, headerBytes, complete, err := decodeWebSocketHeader(input)
		if err != nil || !complete || header.OpCode != ws.OpPing && header.OpCode != ws.OpPong ||
			ws.CheckHeader(header, w.decoder.state) != nil {
			return false
		}
		frameBytes := headerBytes + int(header.Length)
		if frameBytes > len(input) {
			return false
		}
		input = input[frameBytes:]
	}
	return true
}

func (w *webSocketConnection) start(connection gnet.Conn) {
	w.phase = webSocketOpen
	if w.manager != nil {
		w.manager.webSocketsActive.Add(1)
		w.metricsActive = true
	}
	w.touchLiveness(connection)
	w.workers.Go(func() { w.uplinkLoop(connection) })
	w.workers.Go(func() { w.downlinkLoop(connection) })
	w.workers.Go(func() {
		select {
		case <-w.session.doneChannel():
			w.fail(connection, ws.StatusNormalClosure)
		case <-w.ctx.Done():
		}
	})
}

func (w *webSocketConnection) uplinkLoop(connection gnet.Conn) {
	sequence := uint64(1)
	for {
		select {
		case input := <-w.inbound:
			code := w.processUplink(sequence, input)
			if w.ctx.Err() != nil {
				return
			}
			select {
			case w.uplinkResults <- webSocketUplinkResult{code: code}:
				_ = connection.Wake(nil)
			case <-w.ctx.Done():
				return
			}
			if code != 0 {
				return
			}
			sequence++
		case <-w.ctx.Done():
			return
		}
	}
}

func (w *webSocketConnection) processUplink(
	sequence uint64,
	input webSocketInbound,
) ws.StatusCode {
	defer input.reservation.Release()
	if input.chunked {
		size := input.payloadBytes
		if !input.reservation.grow(size) {
			return ws.StatusInternalServerError
		}
		first := input.body
		input.body = make([]byte, size)
		offset := copy(input.body, first)
		for input.fragments != nil {
			offset += copy(input.body[offset:], input.fragments.payload)
			input.fragments = input.fragments.next
		}
		if offset != size {
			return ws.StatusInternalServerError
		}
	}
	deadline := time.NewTimer(w.backpressureTimeout)
	defer deadline.Stop()
	retry := time.NewTicker(w.backpressureRetry)
	defer retry.Stop()
	for {
		var acknowledged uint64
		var err error
		if w.lane != nil {
			acknowledged, err = w.lane.ProcessUp(sequence, input.body)
		} else {
			acknowledged, err = w.session.ProcessUp(sequence, input.body)
		}
		if err == nil && acknowledged == sequence {
			return 0
		}
		if err == nil || !errors.Is(err, ErrBackpressure) {
			return ws.StatusProtocolError
		}
		select {
		case <-w.ctx.Done():
			return ws.StatusNormalClosure
		case <-deadline.C:
			return ws.StatusInternalServerError
		case <-retry.C:
		}
	}
}

func (w *webSocketConnection) downlinkLoop(connection gnet.Conn) {
	cursor := uint64(0)
	for {
		var body []byte
		var next uint64
		var laneClosed bool
		var lease *PollLease
		var err error
		if w.lane != nil {
			body, next, laneClosed, lease, err = w.lane.PollCarrier(w.ctx, cursor)
		} else {
			body, next, lease, err = w.session.PollCarrier(w.ctx, cursor)
		}
		if err != nil {
			if w.ctx.Err() == nil {
				w.fail(connection, ws.StatusProtocolError)
			}
			return
		}
		if laneClosed {
			w.fail(connection, ws.StatusNormalClosure)
			return
		}
		message := webSocketMessage{typeID: webSocketMessagePing}
		if len(body) != 0 {
			message = webSocketMessage{typeID: webSocketMessageBinary, payload: body}
			cursor = next
		}
		item := &webSocketOutbound{message: message, lease: lease, done: make(chan error, 1)}
		if !w.sendOutbound(connection, item) {
			return
		}
	}
}

func (w *webSocketConnection) sendOutbound(connection gnet.Conn, item *webSocketOutbound) bool {
	if w.enqueueOutbound(item) {
		_ = connection.Wake(nil)
	} else {
		item.lease.Release()
		if w.ctx.Err() == nil {
			w.fail(connection, ws.StatusInternalServerError)
		}
		return false
	}
	select {
	case err := <-item.done:
		return err == nil
	case <-w.ctx.Done():
		return false
	}
}

func (w *webSocketConnection) enqueueOutbound(item *webSocketOutbound) bool {
	w.queueMu.Lock()
	defer w.queueMu.Unlock()
	if w.closed {
		return false
	}
	select {
	case w.outbound <- item:
		return true
	default:
		return false
	}
}

func (w *webSocketConnection) fail(connection gnet.Conn, code ws.StatusCode) {
	if w.ctx.Err() != nil {
		return
	}
	select {
	case w.failures <- webSocketFailure{code: code}:
	default:
	}
	_ = connection.Wake(nil)
}

func (w *webSocketConnection) touchLiveness(connection gnet.Conn) {
	if w.phase != webSocketOpen {
		return
	}
	if w.liveness != nil {
		w.liveness.Stop()
	}
	w.livenessID++
	w.livenessExpired = false
	id := w.livenessID
	idle := 2 * w.session.timeouts.LongPoll
	w.liveness = time.AfterFunc(idle, func() {
		_ = connection.EventLoop().Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
			if w.phase != webSocketOpen || w.livenessID != id {
				return nil
			}
			if w.uplinkPending != 0 {
				w.livenessExpired = true
				return nil
			}
			return connection.EventLoop().Close(connection)
		}))
	})
}

func (w *webSocketConnection) beginClose(
	connection gnet.Conn,
	code ws.StatusCode,
	payload []byte,
) bool {
	if w.phase == webSocketClosing {
		return true
	}
	w.phase = webSocketClosing
	w.cancel()
	w.livenessID++
	if w.liveness != nil {
		w.liveness.Stop()
		w.liveness = nil
	}
	w.releaseInbound()
	closePayload := payload
	if len(closePayload) == 0 && code != 0 {
		closePayload = make([]byte, 2)
		binary.BigEndian.PutUint16(closePayload, uint16(code))
	}
	item := &webSocketOutbound{
		message:    webSocketMessage{typeID: webSocketMessageClose, payload: closePayload},
		done:       make(chan error, 1),
		closeAfter: true,
	}
	if w.enqueueOutbound(item) {
		_ = connection.Wake(nil)
		return true
	}
	return false
}

func (w *webSocketConnection) releaseInbound() {
	if w.decoder != nil {
		w.decoder.Reset()
	}
	if w.fragmentReservation != nil {
		w.fragmentReservation.Release()
		w.fragmentReservation = nil
	}
	for {
		select {
		case input := <-w.inbound:
			input.reservation.Release()
		default:
			return
		}
	}
}

func (w *webSocketConnection) close() {
	w.closeOnce.Do(func() {
		if w.metricsActive {
			w.manager.webSocketsActive.Add(-1)
			w.metricsActive = false
		}
		w.queueMu.Lock()
		w.closed = true
		w.cancel()
		w.livenessID++
		if w.liveness != nil {
			w.liveness.Stop()
		}
		w.releaseInbound()
		w.finishCurrent(errors.New("WebSocket connection closed"))
		for {
			select {
			case item := <-w.outbound:
				item.lease.Release()
				select {
				case item.done <- ErrClosed:
				default:
				}
			default:
				w.queueMu.Unlock()
				if w.lane != nil {
					w.lane.Release()
				} else {
					w.session.Close()
				}
				return
			}
		}
	})
}

func (w *webSocketConnection) finishCurrent(err error) bool {
	if w.current == nil {
		return false
	}
	item := w.current
	w.current = nil
	w.asyncWritePending = false
	item.writeBatch = nil
	if item.control {
		if w.controlOutputItems <= 0 {
			panic("invalid WEB WebSocket control output count")
		}
		w.controlOutputItems--
	}
	item.lease.Release()
	select {
	case item.done <- err:
	default:
	}
	return item.closeAfter
}

func webSocketHandshakeResponse(upgrade webSocketUpgrade) []byte {
	var response strings.Builder
	response.Grow(256)
	response.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ")
	response.WriteString(upgrade.accept)
	response.WriteString("\r\nSec-WebSocket-Protocol: ")
	response.WriteString(upgrade.protocol)
	response.WriteString("\r\n\r\n")
	return []byte(response.String())
}

func (h *httpEventHandler) upgradeWebSocket(
	connection gnet.Conn,
	state *httpConnectionState,
	request *preparedRequest,
) gnet.Action {
	transport, err := newWebSocketConnection(request.session, request.webSocketLane, h.server.config.Manager)
	if err != nil {
		request.releaseWebSocket()
		return h.writeImmediate(connection, state, h.sanitizedFallback())
	}
	transport.backpressureTimeout = h.server.config.webSocketBackpressureTimeout
	transport.backpressureRetry = h.server.config.webSocketBackpressureRetry
	request.webSocketLane = nil
	request.webSocketMultiplex = false
	state.beginWebSocket(connection, transport, h.server.config.WriteTimeout)
	err = connection.AsyncWrite(webSocketHandshakeResponse(request.webSocket), func(current gnet.Conn, writeErr error) error {
		if writeErr != nil {
			return current.EventLoop().Close(current)
		}
		transport.handshakeWritten = true
		return current.Wake(nil)
	})
	if err != nil {
		state.close()
		return gnet.Close
	}
	return gnet.None
}

func (h *httpEventHandler) onWebSocketTraffic(
	connection gnet.Conn,
	state *httpConnectionState,
	transport *webSocketConnection,
) gnet.Action {
	if transport.phase == webSocketHandshake {
		if !transport.handshakeWritten {
			if connection.InboundBuffered() != 0 {
				return gnet.Close
			}
			return gnet.None
		}
		if connection.OutboundBuffered() != 0 {
			if connection.InboundBuffered() != 0 {
				return gnet.Close
			}
			state.armDrainWake(connection)
			return gnet.None
		}
		state.invalidateDeadline()
		transport.start(connection)
	}
	select {
	case failure := <-transport.failures:
		if !transport.beginClose(connection, failure.code, nil) {
			return gnet.Close
		}
	default:
	}
uplinkResults:
	for {
		select {
		case result := <-transport.uplinkResults:
			if transport.uplinkPending <= 0 {
				return gnet.Close
			}
			transport.uplinkPending--
			if result.code != 0 {
				if !transport.beginClose(connection, result.code, nil) {
					return gnet.Close
				}
			}
		default:
			break uplinkResults
		}
	}
	if transport.livenessExpired && transport.uplinkPending == 0 && transport.phase == webSocketOpen {
		transport.touchLiveness(connection)
	}
	if action := h.pumpWebSocketWrites(connection, state, transport); action != gnet.None {
		return action
	}
	transport.resetControlBurstIfDrained(connection)
	if transport.phase != webSocketOpen {
		return gnet.None
	}

	buffered := connection.InboundBuffered()
	if buffered == 0 {
		return gnet.None
	}
	peeked, err := connection.Peek(min(buffered, maxWebSocketPayloadBytesPerTraffic))
	if err != nil {
		return gnet.Close
	}
	if !transport.canDecodeWhileUplinkPending(peeked) {
		return gnet.None
	}
	consumed, work, message, emitted, decodeErr := transport.decoder.decodeWindow(
		peeked,
		maxWebSocketPayloadBytesPerTraffic,
	)
	emittedControl := emitted && (message.typeID == webSocketMessagePing ||
		message.typeID == webSocketMessagePong || message.typeID == webSocketMessageClose)
	denseControlSuffix := emittedControl && transport.hasDenseControlSuffix(peeked[consumed:])
	if consumed != 0 {
		if _, err := connection.Discard(consumed); err != nil {
			return gnet.Close
		}
	}
	unreadOverflow, boundErr := transport.boundUnreadInput(
		connection,
		work,
		message,
		emitted,
		emittedControl,
		denseControlSuffix,
	)
	if boundErr != nil {
		return gnet.Close
	}
	if unreadOverflow {
		if !transport.beginClose(connection, ws.StatusInternalServerError, nil) {
			return gnet.Close
		}
		action := h.pumpWebSocketWrites(connection, state, transport)
		transport.resetControlBurstIfDrained(connection)
		return action
	}
	if decodeErr != nil {
		code := ws.StatusProtocolError
		switch {
		case errors.Is(decodeErr, errWebSocketTooLarge):
			code = ws.StatusMessageTooBig
		case errors.Is(decodeErr, errWebSocketResource):
			code = ws.StatusInternalServerError
		}
		if !transport.beginClose(connection, code, nil) {
			return gnet.Close
		}
	} else if emitted {
		switch message.typeID {
		case webSocketMessageBinary:
			input := webSocketInbound{
				body:         message.payload,
				fragments:    message.fragments,
				payloadBytes: message.payloadBytes,
				chunked:      message.chunked,
				reservation:  transport.fragmentReservation,
			}
			transport.fragmentReservation = nil
			select {
			case transport.inbound <- input:
				transport.uplinkPending++
				transport.touchLiveness(connection)
			default:
				input.reservation.Release()
				return gnet.Close
			}
		case webSocketMessagePing:
			if !h.enqueueWebSocketControl(transport, webSocketMessage{typeID: webSocketMessagePong, payload: message.payload}, false) {
				return gnet.Close
			}
		case webSocketMessagePong:
			transport.touchLiveness(connection)
		case webSocketMessageClose:
			if !transport.beginClose(connection, 0, message.payload) {
				return gnet.Close
			}
		}
	}
	if consumed != 0 && connection.InboundBuffered() != 0 && transport.phase == webSocketOpen {
		buffered := connection.InboundBuffered()
		peeked, peekErr := connection.Peek(min(buffered, maxWebSocketPayloadBytesPerTraffic))
		if peekErr != nil {
			return gnet.Close
		}
		if transport.canDecodeWhileUplinkPending(peeked) {
			if work.limit == webSocketDecodeFrameLimit {
				state.armDrainWake(connection)
			} else {
				_ = connection.Wake(nil)
			}
		}
	}
	action := h.pumpWebSocketWrites(connection, state, transport)
	transport.resetControlBurstIfDrained(connection)
	return action
}

func (h *httpEventHandler) enqueueWebSocketControl(
	transport *webSocketConnection,
	message webSocketMessage,
	closeAfter bool,
) bool {
	item := &webSocketOutbound{
		message: message, done: make(chan error, 1), control: true, closeAfter: closeAfter,
	}
	if !transport.enqueueOutbound(item) {
		return false
	}
	transport.controlOutputItems++
	return true
}

func (h *httpEventHandler) pumpWebSocketWrites(
	connection gnet.Conn,
	state *httpConnectionState,
	transport *webSocketConnection,
) gnet.Action {
	if transport.current != nil {
		if transport.asyncWritePending {
			return gnet.None
		}
		if connection.OutboundBuffered() != 0 {
			state.armDrainWake(connection)
			return gnet.None
		}
		state.invalidateDeadline()
		if transport.finishCurrent(nil) {
			return gnet.Close
		}
	}
	item := (*webSocketOutbound)(nil)
	select {
	case item = <-transport.outbound:
	default:
		return gnet.None
	}
	header, payload, err := encodeWebSocketServerParts(item.message)
	if err != nil {
		item.lease.Release()
		select {
		case item.done <- err:
		default:
		}
		return gnet.Close
	}
	item.writeBatch = [][]byte{header}
	if len(payload) != 0 {
		item.writeBatch = append(item.writeBatch, payload)
	}
	transport.current = item
	transport.asyncWritePending = true
	state.armDeadline(connection, h.server.config.WriteTimeout)
	if err := connection.AsyncWritev(item.writeBatch, func(current gnet.Conn, writeErr error) error {
		transport.asyncWritePending = false
		if writeErr != nil {
			transport.finishCurrent(writeErr)
			return current.EventLoop().Close(current)
		}
		return current.Wake(nil)
	}); err != nil {
		transport.finishCurrent(err)
		return gnet.Close
	}
	return gnet.None
}
