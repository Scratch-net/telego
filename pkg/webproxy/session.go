package webproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"
)

type pendingClass uint8

const (
	pendingUplink pendingClass = iota
	pendingDownlink
	pendingControl
)

type sessionOptions struct {
	profile               Profile
	clientIP              string
	backendNet            string
	backend               string
	limits                Limits
	timeouts              Timeouts
	dialBackend           BackendDialContextFunc
	budget                func(int, int, pendingClass) bool
	onFinished            func(*Session)
	acquireStream         func() bool
	onBackendDialFinished func()
	onStreamFinished      func()
}

type streamState struct {
	backend           *backendStream
	receiveWindow     uint32
	sendCredit        uint64
	pendingWriteBytes int
	pendingWriteCost  int
	pendingWriteItems int
	writes            [][]byte
	writeNotify       chan struct{}
	creditNotify      chan struct{}
}

type streamSnapshot struct {
	receiveWindow uint32
	sendCredit    uint64
}

type queuedFrame struct {
	encoded   []byte
	frameType FrameType
	streamID  uint32
	cost      int
}

type downBatch struct {
	body  []byte
	cost  int
	items int
}

// Session is one authenticated serialized-HTTPS carrier session. Its methods
// are safe for one concurrent uplink and downlink request.
type Session struct {
	profile     Profile
	clientIP    string
	backendNet  string
	backend     string
	limits      Limits
	timeouts    Timeouts
	dialBackend BackendDialContextFunc
	budget      func(int, int, pendingClass) bool

	mu             sync.Mutex
	streams        map[uint32]*streamState
	usedStreams    streamIDHistory
	tombstones     boundedSet[uint32]
	pendingFrames  []queuedFrame
	pendingWindows map[uint32]int
	pendingCost    int
	pendingItems   int
	unacked        []byte
	unackedCost    int
	unackedItems   int
	unackedBase    uint64
	downCursor     uint64
	lastUpSequence uint64
	lastUpDigest   [sha256.Size]byte
	upActive       bool
	downActive     bool
	superseded     chan struct{}
	downSlot       chan struct{}
	closed         bool
	lastActivity   time.Time
	notify         chan struct{}
	budgetNotify   chan struct{}
	done           chan struct{}
	finishNotified chan struct{}
	finishOnce     sync.Once
	backendWG      sync.WaitGroup

	onFinished            func(*Session)
	acquireStream         func() bool
	onBackendDialFinished func()
	onStreamFinished      func()
}

func newSession(options sessionOptions) *Session {
	session := &Session{
		profile:               options.profile,
		clientIP:              options.clientIP,
		backendNet:            options.backendNet,
		backend:               options.backend,
		limits:                options.limits,
		timeouts:              options.timeouts,
		dialBackend:           options.dialBackend,
		budget:                options.budget,
		streams:               make(map[uint32]*streamState),
		tombstones:            newBoundedSet[uint32](options.limits.MaxClosedStreamIDs),
		pendingWindows:        make(map[uint32]int),
		lastActivity:          time.Now(),
		notify:                make(chan struct{}),
		budgetNotify:          make(chan struct{}),
		done:                  make(chan struct{}),
		finishNotified:        make(chan struct{}),
		onFinished:            options.onFinished,
		acquireStream:         options.acquireStream,
		onBackendDialFinished: options.onBackendDialFinished,
		onStreamFinished:      options.onStreamFinished,
	}
	session.downSlot = make(chan struct{}, 1)
	session.downSlot <- struct{}{}
	return session
}

// Profile returns the immutable WEB credential associated with the session.
func (s *Session) Profile() Profile { return s.profile }

// ProcessUp applies the next serialized uplink batch or acknowledges a
// byte-identical retry of the last committed sequence.
func (s *Session) ProcessUp(sequence uint64, body []byte) (uint64, error) {
	digest := sha256.Sum256(body)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	s.lastActivity = time.Now()
	if sequence == s.lastUpSequence && sequence != 0 {
		matches := bytes.Equal(digest[:], s.lastUpDigest[:])
		s.mu.Unlock()
		if !matches {
			s.protocolFailure()
			return 0, ErrProtocol
		}
		return sequence, nil
	}
	if sequence == 0 || sequence != s.lastUpSequence+1 {
		backends := s.closeLocked()
		s.mu.Unlock()
		requestBackendCloses(backends)
		return 0, ErrProtocol
	}
	if s.upActive {
		s.mu.Unlock()
		return 0, ErrBackpressure
	}
	if len(body) > s.limits.MaxBodyBytes {
		backends := s.closeLocked()
		s.mu.Unlock()
		requestBackendCloses(backends)
		return 0, ErrProtocol
	}
	s.upActive = true
	s.mu.Unlock()

	frames, parseErr := ParseBatch(body)
	if parseErr == nil {
		for _, frame := range frames {
			if err := ValidateClientFrame(frame); err != nil {
				parseErr = err
				break
			}
		}
	}

	s.mu.Lock()
	s.upActive = false
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	if parseErr != nil || !s.validateBatchLocked(frames) {
		backends := s.closeLocked()
		s.mu.Unlock()
		requestBackendCloses(backends)
		return 0, ErrProtocol
	}
	reservedCost, reservedItems, ok := s.backendWriteReservationLocked(frames)
	if !ok || ((reservedCost != 0 || reservedItems != 0) &&
		!s.reservePendingLocked(reservedCost, reservedItems, pendingUplink)) {
		s.mu.Unlock()
		return 0, ErrBackpressure
	}
	opened, closed, unusedCost, unusedItems, applied := s.applyBatchLocked(
		frames,
		reservedCost,
		reservedItems,
	)
	if unusedCost != 0 || unusedItems != 0 {
		s.releasePendingLocked(unusedCost, unusedItems)
	}
	s.backendWG.Add(len(opened))
	if applied {
		s.lastUpSequence = sequence
		s.lastUpDigest = digest
	}
	s.mu.Unlock()

	requestBackendCloses(closed)
	for _, backend := range opened {
		go s.runBackend(backend)
	}
	if !applied {
		s.Close()
		return 0, ErrClosed
	}
	return sequence, nil
}

// PollLease keeps one completed carrier response as the active downlink poll
// until the HTTP layer has drained that response. A newer poll supersedes it.
type PollLease struct {
	session  *Session
	claim    chan struct{}
	ownsSlot bool
	once     sync.Once
}

// Superseded reports whether a newer downlink poll replaced this response.
func (l *PollLease) Superseded() bool {
	if l == nil || l.claim == nil {
		return false
	}
	select {
	case <-l.claim:
		return true
	default:
		return false
	}
}

// Release ends this response's claim if it is still the newest poll.
func (l *PollLease) Release() {
	if l == nil || l.session == nil || l.claim == nil {
		return
	}
	l.session.mu.Lock()
	l.releaseLocked()
	l.session.mu.Unlock()
}

// releaseLocked ends this lease while the caller holds the session mutex.
func (l *PollLease) releaseLocked() {
	if l == nil || l.session == nil || l.claim == nil {
		return
	}
	l.once.Do(func() {
		if l.session.superseded == l.claim {
			l.session.downActive = false
			l.session.superseded = nil
		}
		if l.ownsSlot {
			l.session.downSlot <- struct{}{}
			l.ownsSlot = false
		}
	})
}

// Poll acknowledges cursor, replays any unacknowledged batch, or waits for the
// next batch. Direct callers release the response claim before Poll returns.
func (s *Session) Poll(ctx context.Context, cursor uint64) ([]byte, uint64, error) {
	body, next, lease, err := s.PollCarrier(ctx, cursor)
	lease.Release()
	return body, next, err
}

// PollCarrier retains the newest-poll claim until the returned lease is
// released by the carrier after its HTTP response drains.
func (s *Session) PollCarrier(ctx context.Context, cursor uint64) ([]byte, uint64, *PollLease, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, cursor, nil, ErrClosed
	}
	s.lastActivity = time.Now()
	// Claim newest-poll ownership before cursor replay. Otherwise every
	// concurrent old-cursor request can bypass downActive and independently
	// materialize the same replay response.
	if s.downActive && s.superseded != nil {
		close(s.superseded)
	}
	mine := make(chan struct{})
	s.superseded = mine
	s.downActive = true
	lease := &PollLease{session: s, claim: mine}
	s.mu.Unlock()

	// Only the lease holding downSlot may materialize or wait on a carrier
	// response. A newer poll claims ownership immediately, but it cannot replay
	// an unacknowledged batch until the superseded response has drained and
	// released this slot.
	select {
	case <-s.downSlot:
		lease.ownsSlot = true
	case <-ctx.Done():
		lease.Release()
		return nil, cursor, nil, ctx.Err()
	case <-mine:
		lease.Release()
		return nil, cursor, nil, nil
	case <-s.done:
		lease.Release()
		return nil, cursor, nil, ErrClosed
	}

	s.mu.Lock()
	if s.superseded != mine {
		lease.releaseLocked()
		s.mu.Unlock()
		return nil, cursor, nil, nil
	}
	if s.closed {
		lease.releaseLocked()
		s.mu.Unlock()
		return nil, cursor, nil, ErrClosed
	}
	timer := time.NewTimer(s.timeouts.LongPoll)
	defer timer.Stop()
	if len(s.unacked) != 0 {
		if cursor == s.unackedBase {
			body := bytes.Clone(s.unacked)
			next := s.downCursor
			s.mu.Unlock()
			return body, next, lease, nil
		}
		if cursor != s.downCursor {
			backends := s.closeLocked()
			lease.releaseLocked()
			s.mu.Unlock()
			requestBackendCloses(backends)
			return nil, cursor, nil, ErrProtocol
		}
		s.releasePendingLocked(s.unackedCost, s.unackedItems)
		s.unacked = nil
		s.unackedCost = 0
		s.unackedItems = 0
	} else if cursor != s.downCursor {
		backends := s.closeLocked()
		lease.releaseLocked()
		s.mu.Unlock()
		requestBackendCloses(backends)
		return nil, cursor, nil, ErrProtocol
	}

	for {
		if s.superseded != mine {
			lease.releaseLocked()
			s.mu.Unlock()
			return nil, cursor, nil, nil
		}
		if len(s.pendingFrames) != 0 {
			batch := s.takeDownBatchLocked()
			s.downCursor++
			s.unackedBase = cursor
			s.unacked = batch.body
			s.unackedCost = batch.cost
			s.unackedItems = batch.items
			next := s.downCursor
			body := bytes.Clone(batch.body)
			s.mu.Unlock()
			return body, next, lease, nil
		}
		if s.closed {
			lease.releaseLocked()
			s.mu.Unlock()
			return nil, cursor, nil, ErrClosed
		}
		pollNotify := s.notify
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			s.mu.Lock()
			lease.releaseLocked()
			s.mu.Unlock()
			return nil, cursor, nil, ctx.Err()
		case <-mine:
			s.mu.Lock()
			lease.releaseLocked()
			s.mu.Unlock()
			return nil, cursor, nil, nil
		case <-s.done:
			lease.Release()
			return nil, cursor, nil, ErrClosed
		case <-timer.C:
			s.mu.Lock()
			if s.superseded != mine {
				lease.releaseLocked()
				s.mu.Unlock()
				return nil, cursor, nil, nil
			}
			if len(s.pendingFrames) != 0 {
				continue
			}
			s.lastActivity = time.Now()
			s.mu.Unlock()
			return nil, cursor, lease, nil
		case <-pollNotify:
			s.mu.Lock()
		}
	}
}

// LastActivity returns the last carrier activity used for reconnect expiry.
func (s *Session) LastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastActivity
}

// Close aborts all logical streams and wakes parked carrier operations.
func (s *Session) Close() {
	s.mu.Lock()
	backends := s.closeLocked()
	s.mu.Unlock()
	requestBackendCloses(backends)
}

func (s *Session) wait() {
	<-s.finishNotified
}

func (s *Session) validateBatchLocked(frames []Frame) bool {
	live := make(map[uint32]streamSnapshot, len(s.streams))
	for id, state := range s.streams {
		live[id] = streamSnapshot{
			receiveWindow: state.receiveWindow,
			sendCredit:    state.sendCredit,
		}
	}
	var usedInBatch map[uint32]struct{}
	for _, frame := range frames {
		if frame.StreamID == 0 {
			if frame.Type != FramePong {
				return false
			}
			continue
		}
		state, isLive := live[frame.StreamID]
		_, usedEarlierInBatch := usedInBatch[frame.StreamID]
		wasUsed := usedEarlierInBatch || s.usedStreams.Contains(frame.StreamID)
		switch frame.Type {
		case FrameOpen:
			if isLive || wasUsed {
				return false
			}
			if usedInBatch == nil {
				usedInBatch = make(map[uint32]struct{}, min(len(frames), s.limits.MaxStreamsPerSession))
			}
			usedInBatch[frame.StreamID] = struct{}{}
			live[frame.StreamID] = streamSnapshot{
				receiveWindow: InitialStreamWindow,
				sendCredit:    InitialStreamWindow,
			}
		case FrameData:
			if !isLive {
				if wasUsed {
					continue
				}
				return false
			}
			if uint32(len(frame.Payload)) > state.receiveWindow {
				return false
			}
			state.receiveWindow -= uint32(len(frame.Payload))
			live[frame.StreamID] = state
		case FrameWindow:
			if !isLive {
				if wasUsed {
					continue
				}
				return false
			}
			delta, _ := WindowDelta(frame.Payload)
			state.sendCredit = min(uint64(math.MaxUint32), state.sendCredit+uint64(delta))
			live[frame.StreamID] = state
		case FrameClose:
			if !isLive {
				if wasUsed {
					continue
				}
				return false
			}
			delete(live, frame.StreamID)
		default:
			return false
		}
	}
	return true
}

func (s *Session) backendWriteReservationLocked(frames []Frame) (int, int, bool) {
	live := make(map[uint32]bool, len(s.streams))
	for id := range s.streams {
		live[id] = true
	}
	cost := 0
	items := 0
	for _, frame := range frames {
		if frame.StreamID == 0 {
			continue
		}
		switch frame.Type {
		case FrameOpen:
			live[frame.StreamID] = true
		case FrameData:
			if !live[frame.StreamID] {
				continue
			}
			itemCost, ok := checkedAddInt(len(frame.Payload), queueItemCost)
			if !ok {
				return 0, 0, false
			}
			cost, ok = checkedAddInt(cost, itemCost)
			if !ok || items == math.MaxInt {
				return 0, 0, false
			}
			items++
		case FrameClose:
			delete(live, frame.StreamID)
		}
	}
	return cost, items, true
}

func (s *Session) applyBatchLocked(frames []Frame, reservedCost, reservedItems int) (
	opened []*backendStream,
	closed []*backendStream,
	unusedCost int,
	unusedItems int,
	applied bool,
) {
	unusedCost = reservedCost
	unusedItems = reservedItems
	for _, frame := range frames {
		if frame.StreamID == 0 {
			continue
		}
		state := s.streams[frame.StreamID]
		wasUsed := s.usedStreams.Contains(frame.StreamID)
		switch frame.Type {
		case FrameOpen:
			s.usedStreams.Add(frame.StreamID)
			if len(s.streams) >= s.limits.MaxStreamsPerSession ||
				(s.acquireStream != nil && !s.acquireStream()) {
				s.rememberClosedLocked(frame.StreamID)
				if !s.queueFrameLocked(FrameClose, frame.StreamID, nil) {
					return opened, closed, unusedCost, unusedItems, false
				}
				continue
			}
			backend := newBackendStream(s, frame.StreamID)
			state = &streamState{
				backend:       backend,
				receiveWindow: InitialStreamWindow,
				sendCredit:    InitialStreamWindow,
				writeNotify:   make(chan struct{}, 1),
				creditNotify:  make(chan struct{}, 1),
			}
			s.streams[frame.StreamID] = state
			opened = append(opened, backend)
		case FrameData:
			if state == nil && wasUsed {
				continue
			}
			cost, items := s.appendBackendWriteLocked(state, frame.Payload)
			unusedCost -= cost
			unusedItems -= items
			state.receiveWindow -= uint32(len(frame.Payload))
			signal(state.writeNotify)
		case FrameWindow:
			if state == nil && wasUsed {
				continue
			}
			delta, _ := WindowDelta(frame.Payload)
			state.sendCredit = min(uint64(math.MaxUint32), state.sendCredit+uint64(delta))
			signal(state.creditNotify)
		case FrameClose:
			if state == nil && wasUsed {
				continue
			}
			s.dropPendingStreamFramesLocked(frame.StreamID)
			s.releaseStreamWritesLocked(state)
			state.backend.cancelContext()
			delete(s.streams, frame.StreamID)
			s.rememberClosedLocked(frame.StreamID)
			closed = append(closed, state.backend)
		}
	}
	return opened, closed, unusedCost, unusedItems, true
}

func (s *Session) appendBackendWriteLocked(state *streamState, payload []byte) (int, int) {
	cost := len(payload) + queueItemCost
	items := 1
	coalesce := len(state.writes) != 0 && len(state.writes[len(state.writes)-1])+len(payload) <= RelayDataChunk
	if coalesce {
		cost = len(payload)
		items = 0
		last := len(state.writes) - 1
		state.writes[last] = append(state.writes[last], payload...)
	} else {
		state.writes = append(state.writes, bytes.Clone(payload))
	}
	state.pendingWriteBytes += len(payload)
	state.pendingWriteCost += cost
	state.pendingWriteItems += items
	return cost, items
}

func (s *Session) nextWrite(streamID uint32, streamDone <-chan struct{}) ([]byte, bool) {
	for {
		s.mu.Lock()
		state := s.streams[streamID]
		if s.closed || state == nil {
			s.mu.Unlock()
			return nil, false
		}
		if len(state.writes) != 0 {
			data := state.writes[0]
			state.writes[0] = nil
			state.writes = state.writes[1:]
			s.mu.Unlock()
			return data, true
		}
		notify := state.writeNotify
		s.mu.Unlock()
		select {
		case <-notify:
		case <-s.done:
			return nil, false
		case <-streamDone:
			return nil, false
		}
	}
}

func (s *Session) backendDrained(streamID uint32, amount int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.streams[streamID]
	if s.closed || state == nil || amount <= 0 || amount > state.pendingWriteBytes ||
		amount > state.pendingWriteCost || uint64(state.receiveWindow)+uint64(amount) > InitialStreamWindow {
		return false
	}
	state.pendingWriteBytes -= amount
	state.pendingWriteCost -= amount
	s.releasePendingLocked(amount, 0)
	state.receiveWindow += uint32(amount)
	payload, err := WindowPayload(uint32(amount))
	return err == nil && s.queueFrameLocked(FrameWindow, streamID, payload)
}

func (s *Session) backendWriteFinished(streamID uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.streams[streamID]
	if s.closed || state == nil || state.pendingWriteItems == 0 || state.pendingWriteCost < queueItemCost {
		return false
	}
	state.pendingWriteItems--
	state.pendingWriteCost -= queueItemCost
	s.releasePendingLocked(queueItemCost, 1)
	return true
}

func (s *Session) nextReadAllowance(streamID uint32, streamDone <-chan struct{}) (int, bool) {
	for {
		s.mu.Lock()
		state := s.streams[streamID]
		if s.closed || state == nil {
			s.mu.Unlock()
			return 0, false
		}
		if state.sendCredit != 0 {
			allowance := min(int(state.sendCredit), RelayDataChunk)
			allowance = s.dataFrameAllowanceLocked(allowance)
			if allowance != 0 {
				s.mu.Unlock()
				return allowance, true
			}
		}
		creditNotify := state.creditNotify
		budgetNotify := s.budgetNotify
		s.mu.Unlock()
		select {
		case <-creditNotify:
		case <-budgetNotify:
		case <-s.done:
			return 0, false
		case <-streamDone:
			return 0, false
		}
	}
}

func (s *Session) backendData(streamID uint32, data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.streams[streamID]
	if s.closed || state == nil || len(data) == 0 || uint64(len(data)) > state.sendCredit {
		return false
	}
	state.sendCredit -= uint64(len(data))
	return s.queueFrameLocked(FrameData, streamID, data)
}

func (s *Session) backendClosed(streamID uint32, backend *backendStream) {
	var detached []*backendStream
	s.mu.Lock()
	state := s.streams[streamID]
	if !s.closed && state != nil && state.backend == backend {
		s.dropPendingStreamFramesLocked(streamID)
		s.releaseStreamWritesLocked(state)
		backend.cancelContext()
		delete(s.streams, streamID)
		s.rememberClosedLocked(streamID)
		if !s.queueFrameLocked(FrameClose, streamID, nil) {
			detached = s.closeLocked()
		}
	}
	s.mu.Unlock()
	requestBackendCloses(detached)
	backend.close()
}

func (s *Session) queueFrameLocked(frameType FrameType, streamID uint32, payload []byte) bool {
	if frameType == FrameWindow {
		if index, exists := s.pendingWindows[streamID]; exists {
			queued := &s.pendingFrames[index]
			previous, _ := WindowDelta(queued.encoded[FrameHeaderSize:])
			delta, _ := WindowDelta(payload)
			total := uint64(previous) + uint64(delta)
			if total <= math.MaxUint32 {
				binary.BigEndian.PutUint32(queued.encoded[FrameHeaderSize:], uint32(total))
				s.signalPollLocked()
				return true
			}
		}
	}
	if len(s.pendingFrames) != 0 {
		last := &s.pendingFrames[len(s.pendingFrames)-1]
		if last.frameType == FrameData && frameType == FrameData && last.streamID == streamID &&
			len(last.encoded)-FrameHeaderSize+len(payload) <= MaxFramePayload {
			if !s.reservePendingLocked(len(payload), 0, pendingDownlink) {
				return false
			}
			last.encoded = append(last.encoded, payload...)
			last.cost += len(payload)
			binary.BigEndian.PutUint32(last.encoded[4:FrameHeaderSize], uint32(len(last.encoded)-FrameHeaderSize))
			s.signalPollLocked()
			return true
		}
	}
	encoded, err := EncodeFrame(Frame{Type: frameType, StreamID: streamID, Payload: payload})
	if err != nil {
		return false
	}
	cost, ok := checkedAddInt(len(encoded), queueItemCost)
	if !ok {
		return false
	}
	class := pendingControl
	if frameType == FrameData {
		class = pendingDownlink
	}
	if !s.reservePendingLocked(cost, 1, class) {
		return false
	}
	s.pendingFrames = append(s.pendingFrames, queuedFrame{
		encoded:   encoded,
		frameType: frameType,
		streamID:  streamID,
		cost:      cost,
	})
	if frameType == FrameWindow {
		s.pendingWindows[streamID] = len(s.pendingFrames) - 1
	}
	s.signalPollLocked()
	return true
}

func (s *Session) uplinkPendingLimits() (int, int) {
	reserveCost, reserveItems, _ := pendingControlReserve(s.limits)
	return subtractReserve(
		s.limits.MaxPendingPerSession,
		s.limits.MaxPendingItemsPerSession,
		reserveCost,
		reserveItems,
	)
}

func (s *Session) downlinkPendingLimits() (int, int) {
	cost, items := s.uplinkPendingLimits()
	reserveCost, reserveItems, _ := pendingUplinkReserve(s.limits)
	return subtractReserve(cost, items, reserveCost, reserveItems)
}

func subtractReserve(cost, items, reserveCost, reserveItems int) (int, int) {
	cost = max(0, cost-reserveCost)
	items = max(0, items-reserveItems)
	return cost, items
}

func (s *Session) dataFrameAllowanceLocked(limit int) int {
	costLimit, itemLimit := s.downlinkPendingLimits()
	if s.pendingItems >= itemLimit {
		return 0
	}
	available := costLimit - s.pendingCost - queueItemCost - FrameHeaderSize
	if available <= 0 {
		return 0
	}
	return min(limit, available)
}

func (s *Session) reservePendingLocked(cost, items int, class pendingClass) bool {
	if cost == 0 && items == 0 {
		return true
	}
	costLimit := s.limits.MaxPendingPerSession
	itemLimit := s.limits.MaxPendingItemsPerSession
	switch class {
	case pendingUplink:
		costLimit, itemLimit = s.uplinkPendingLimits()
	case pendingDownlink:
		costLimit, itemLimit = s.downlinkPendingLimits()
	}
	if cost <= 0 || items < 0 || cost > costLimit || items > itemLimit ||
		s.pendingCost > costLimit-cost || s.pendingItems > itemLimit-items {
		return false
	}
	if s.budget != nil && !s.budget(cost, items, class) {
		return false
	}
	s.pendingCost += cost
	s.pendingItems += items
	return true
}

func (s *Session) releasePendingLocked(cost, items int) {
	if cost == 0 && items == 0 {
		return
	}
	if cost < 0 || items < 0 || cost > s.pendingCost || items > s.pendingItems {
		panic("invalid WEB session pending budget release")
	}
	s.pendingCost -= cost
	s.pendingItems -= items
	if s.budget != nil {
		s.budget(-cost, -items, pendingUplink)
	}
	close(s.budgetNotify)
	s.budgetNotify = make(chan struct{})
}

func (s *Session) takeDownBatchLocked() downBatch {
	size := 0
	cost := 0
	count := 0
	for count < len(s.pendingFrames) && count < MaxBatchFrames {
		next := len(s.pendingFrames[count].encoded)
		if count != 0 && size+next > s.limits.CarrierBatchBytes {
			break
		}
		size += next
		cost += s.pendingFrames[count].cost
		count++
	}
	body := make([]byte, 0, size)
	for index := range count {
		frame := s.pendingFrames[index]
		if frame.frameType == FrameWindow && s.pendingWindows[frame.streamID] == index {
			delete(s.pendingWindows, frame.streamID)
		}
		body = append(body, frame.encoded...)
		s.pendingFrames[index] = queuedFrame{}
	}
	s.pendingFrames = s.pendingFrames[count:]
	for streamID, index := range s.pendingWindows {
		s.pendingWindows[streamID] = index - count
	}
	if len(s.pendingFrames) == 0 {
		s.pendingFrames = nil
	}
	return downBatch{body: body, cost: cost, items: count}
}

func (s *Session) rememberClosedLocked(streamID uint32) {
	s.tombstones.Add(streamID)
}

func (s *Session) dropPendingStreamFramesLocked(streamID uint32) {
	kept := s.pendingFrames[:0]
	releasedCost := 0
	releasedItems := 0
	for index := range s.pendingFrames {
		frame := s.pendingFrames[index]
		if frame.streamID == streamID {
			releasedCost += frame.cost
			releasedItems++
			s.pendingFrames[index] = queuedFrame{}
			continue
		}
		kept = append(kept, frame)
	}
	s.pendingFrames = kept
	clear(s.pendingWindows)
	for index := range s.pendingFrames {
		frame := s.pendingFrames[index]
		if frame.frameType == FrameWindow {
			s.pendingWindows[frame.streamID] = index
		}
	}
	if len(s.pendingFrames) == 0 {
		s.pendingFrames = nil
	}
	if releasedCost != 0 || releasedItems != 0 {
		s.releasePendingLocked(releasedCost, releasedItems)
	}
}

func (s *Session) releaseStreamWritesLocked(state *streamState) {
	if state == nil {
		return
	}
	if state.pendingWriteCost != 0 || state.pendingWriteItems != 0 {
		s.releasePendingLocked(state.pendingWriteCost, state.pendingWriteItems)
	}
	state.pendingWriteBytes = 0
	state.pendingWriteCost = 0
	state.pendingWriteItems = 0
	state.writes = nil
}

func (s *Session) protocolFailure() {
	s.mu.Lock()
	backends := s.closeLocked()
	s.mu.Unlock()
	requestBackendCloses(backends)
}

func (s *Session) closeLocked() []*backendStream {
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.done)
	backends := make([]*backendStream, 0, len(s.streams))
	for _, state := range s.streams {
		state.backend.cancelContext()
		backends = append(backends, state.backend)
	}
	s.streams = nil
	if s.pendingCost != 0 || s.pendingItems != 0 {
		if s.budget != nil {
			s.budget(-s.pendingCost, -s.pendingItems, pendingUplink)
		}
		s.pendingCost = 0
		s.pendingItems = 0
	}
	s.pendingFrames = nil
	s.pendingWindows = nil
	s.unacked = nil
	s.unackedCost = 0
	s.unackedItems = 0
	s.signalPollLocked()
	s.finishOnce.Do(func() {
		go func() {
			s.backendWG.Wait()
			if s.onFinished != nil {
				s.onFinished(s)
			}
			close(s.finishNotified)
		}()
	})
	return backends
}

func (s *Session) signalPollLocked() {
	close(s.notify)
	s.notify = make(chan struct{})
}

func (s *Session) runBackend(backend *backendStream) {
	defer s.backendWG.Done()
	if s.onStreamFinished != nil {
		defer s.onStreamFinished()
	}
	backend.run()
}

func signal(channel chan struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}

func requestBackendCloses(backends []*backendStream) {
	for _, backend := range backends {
		go backend.close()
	}
}

type backendStream struct {
	session   *Session
	id        uint32
	ctx       context.Context
	cancel    context.CancelFunc
	connMu    sync.Mutex
	conn      net.Conn
	closeOnce sync.Once
}

func newBackendStream(session *Session, id uint32) *backendStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &backendStream{
		session: session,
		id:      id,
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (b *backendStream) run() {
	defer b.session.backendClosed(b.id, b)

	dialCtx, cancel := context.WithTimeout(b.ctx, b.session.timeouts.BackendDial)
	connection, err := b.session.dialBackend(
		dialCtx,
		b.session.backendNet,
		b.session.backend,
		b.session.clientIP,
	)
	cancel()
	if b.session.onBackendDialFinished != nil {
		b.session.onBackendDialFinished()
	}
	if err != nil {
		return
	}
	b.connMu.Lock()
	if b.ctx.Err() != nil {
		b.connMu.Unlock()
		_ = connection.Close()
		return
	}
	b.conn = connection
	b.connMu.Unlock()

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		b.writeLoop(connection)
		b.close()
	}()
	b.readLoop(connection)
	b.close()
	<-writeDone
}

func (b *backendStream) writeLoop(connection net.Conn) {
	for {
		data, ok := b.session.nextWrite(b.id, b.ctx.Done())
		if !ok {
			return
		}
		for len(data) != 0 {
			written, err := connection.Write(data)
			if written > 0 {
				if !b.session.backendDrained(b.id, written) {
					return
				}
				data = data[written:]
			}
			if err != nil || written == 0 {
				return
			}
		}
		if !b.session.backendWriteFinished(b.id) {
			return
		}
	}
}

func (b *backendStream) readLoop(connection net.Conn) {
	buffer := make([]byte, RelayDataChunk)
	for {
		allowance, ok := b.session.nextReadAllowance(b.id, b.ctx.Done())
		if !ok {
			return
		}
		read, err := connection.Read(buffer[:allowance])
		if read > 0 && !b.session.backendData(b.id, buffer[:read]) {
			return
		}
		if err != nil || read == 0 {
			if err != nil && !errors.Is(err, io.EOF) && b.ctx.Err() == nil {
				return
			}
			return
		}
	}
}

func (b *backendStream) close() {
	b.closeOnce.Do(func() {
		b.cancel()
		b.connMu.Lock()
		if b.conn != nil {
			_ = b.conn.Close()
			b.conn = nil
		}
		b.connMu.Unlock()
	})
}

func (b *backendStream) cancelContext() {
	b.cancel()
}
