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
	carrier               CarrierMode
	clientIP              string
	backendNet            string
	backend               string
	limits                Limits
	timeouts              Timeouts
	dialBackend           BackendDialContextFunc
	budget                func(int, int, pendingClass) bool
	onFinished            func(*Session, sessionCloseReason)
	onCarrierRetry        func(carrierOperation)
	onBackpressure        func(carrierOperation)
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

type carrierLane struct {
	pendingFrames  []queuedFrame
	pendingWindows map[uint32]int
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
	notify         chan struct{}
}

func newCarrierLane() *carrierLane {
	lane := &carrierLane{
		pendingWindows: make(map[uint32]int),
		downSlot:       make(chan struct{}, 1),
		notify:         make(chan struct{}),
	}
	lane.downSlot <- struct{}{}
	return lane
}

// Session is one authenticated HTTPS carrier session. The serialized carrier
// permits one uplink and downlink. The lanes carrier permits one pair per lane.
type Session struct {
	profile     Profile
	carrier     CarrierMode
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
	carrierLanes   map[uint32]*carrierLane
	pendingCost    int
	pendingItems   int
	closed         bool
	closeReason    sessionCloseReason
	lastActivity   time.Time
	budgetNotify   chan struct{}
	done           chan struct{}
	finishNotified chan struct{}
	finishOnce     sync.Once
	backendWG      sync.WaitGroup

	onFinished            func(*Session, sessionCloseReason)
	onCarrierRetry        func(carrierOperation)
	onBackpressure        func(carrierOperation)
	acquireStream         func() bool
	onBackendDialFinished func()
	onStreamFinished      func()
}

func newSession(options sessionOptions) *Session {
	carrier := options.carrier
	if carrier == "" {
		carrier = CarrierHTTPS
	}
	session := &Session{
		profile:               options.profile,
		carrier:               carrier,
		clientIP:              options.clientIP,
		backendNet:            options.backendNet,
		backend:               options.backend,
		limits:                options.limits,
		timeouts:              options.timeouts,
		dialBackend:           options.dialBackend,
		budget:                options.budget,
		streams:               make(map[uint32]*streamState),
		tombstones:            newBoundedSet[uint32](options.limits.MaxClosedStreamIDs),
		carrierLanes:          map[uint32]*carrierLane{0: newCarrierLane()},
		lastActivity:          time.Now(),
		budgetNotify:          make(chan struct{}),
		done:                  make(chan struct{}),
		finishNotified:        make(chan struct{}),
		onFinished:            options.onFinished,
		onCarrierRetry:        options.onCarrierRetry,
		onBackpressure:        options.onBackpressure,
		acquireStream:         options.acquireStream,
		onBackendDialFinished: options.onBackendDialFinished,
		onStreamFinished:      options.onStreamFinished,
	}
	return session
}

// Profile returns the immutable WEB credential associated with the session.
func (s *Session) Profile() Profile { return s.profile }

// CarrierMode returns the immutable transport selected for this session.
func (s *Session) CarrierMode() CarrierMode { return s.carrier }

// ProcessUp applies the next serialized uplink batch or acknowledges a
// byte-identical retry of the last committed sequence.
func (s *Session) ProcessUp(sequence uint64, body []byte) (uint64, error) {
	if s.carrier != CarrierHTTPS {
		return 0, ErrProtocol
	}
	return s.processUp(0, sequence, body, false)
}

// ProcessUpLane applies one uplink batch to an independent stream lane.
func (s *Session) ProcessUpLane(laneID uint32, sequence uint64, body []byte) (uint64, error) {
	if s.carrier != CarrierHTTPSLanes || laneID > MaxStreamID {
		return 0, ErrProtocol
	}
	return s.processUp(laneID, sequence, body, true)
}

func (s *Session) processUp(laneID uint32, sequence uint64, body []byte, lanes bool) (uint64, error) {
	digest := sha256.Sum256(body)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	s.lastActivity = time.Now()
	if sequence == 0 || len(body) > s.limits.MaxBodyBytes {
		backends := s.closeLocked(sessionCloseProtocol)
		s.mu.Unlock()
		requestBackendCloses(backends)
		return 0, ErrProtocol
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		if !lanes || laneID == 0 || !batchStartsWithOpen(body, laneID) {
			s.mu.Unlock()
			frames, err := parseUplinkBatch(body, laneID, lanes)
			if lanes && err == nil && onlyLateLaneFrames(frames) {
				s.recordCarrierRetry(carrierOperationUplink)
				return sequence, nil
			}
			s.protocolFailure()
			return 0, ErrProtocol
		}
		lane = newCarrierLane()
		s.carrierLanes[laneID] = lane
	}
	if sequence == lane.lastUpSequence {
		matches := bytes.Equal(digest[:], lane.lastUpDigest[:])
		s.mu.Unlock()
		if !matches {
			s.protocolFailure()
			return 0, ErrProtocol
		}
		s.recordCarrierRetry(carrierOperationUplink)
		return sequence, nil
	}
	if sequence != lane.lastUpSequence+1 {
		backends := s.closeLocked(sessionCloseProtocol)
		s.mu.Unlock()
		requestBackendCloses(backends)
		return 0, ErrProtocol
	}
	if lane.upActive {
		s.mu.Unlock()
		s.recordBackpressure(carrierOperationUplink)
		return 0, ErrBackpressure
	}
	lane.upActive = true
	s.mu.Unlock()

	frames, parseErr := parseUplinkBatch(body, laneID, lanes)

	s.mu.Lock()
	if current := s.carrierLanes[laneID]; current != lane {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	lane.upActive = false
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	if parseErr != nil || !s.validateBatchLocked(frames) {
		backends := s.closeLocked(sessionCloseProtocol)
		s.mu.Unlock()
		requestBackendCloses(backends)
		return 0, ErrProtocol
	}
	reservedCost, reservedItems, ok := s.backendWriteReservationLocked(frames)
	if !ok || ((reservedCost != 0 || reservedItems != 0) &&
		!s.reservePendingLocked(reservedCost, reservedItems, pendingUplink)) {
		s.mu.Unlock()
		s.recordBackpressure(carrierOperationUplink)
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
		lane.lastUpSequence = sequence
		lane.lastUpDigest = digest
	}
	s.mu.Unlock()

	requestBackendCloses(closed)
	for _, backend := range opened {
		go s.runBackend(backend)
	}
	if !applied {
		s.closeWithReason(sessionCloseResource)
		return 0, ErrClosed
	}
	return sequence, nil
}

func parseUplinkBatch(body []byte, laneID uint32, lanes bool) ([]Frame, error) {
	frames, err := ParseBatch(body)
	if err != nil {
		return nil, err
	}
	for _, frame := range frames {
		if lanes && frame.StreamID != laneID {
			return nil, ErrInvalidFrame
		}
		if err := ValidateClientFrame(frame); err != nil {
			return nil, err
		}
	}
	return frames, nil
}

func batchStartsWithOpen(body []byte, laneID uint32) bool {
	return len(body) >= FrameHeaderSize && FrameType(body[0]) == FrameOpen &&
		uint32(body[1])<<16|uint32(body[2])<<8|uint32(body[3]) == laneID
}

func onlyLateLaneFrames(frames []Frame) bool {
	if len(frames) == 0 {
		return false
	}
	for _, frame := range frames {
		if frame.Type != FrameData && frame.Type != FrameWindow && frame.Type != FrameClose {
			return false
		}
	}
	return true
}

// PollLease keeps one completed carrier response as the active downlink poll
// until the HTTP layer has drained that response. A newer poll supersedes it.
type PollLease struct {
	session  *Session
	lane     *carrierLane
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
		if l.lane.superseded == l.claim {
			l.lane.downActive = false
			l.lane.superseded = nil
		}
		if l.ownsSlot {
			l.lane.downSlot <- struct{}{}
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

// PollLane acknowledges and polls one independent stream lane.
func (s *Session) PollLane(ctx context.Context, laneID uint32, cursor uint64) ([]byte, uint64, bool, error) {
	body, next, closed, lease, err := s.PollCarrierLane(ctx, laneID, cursor)
	lease.Release()
	return body, next, closed, err
}

// PollCarrier retains the newest-poll claim until the returned lease is
// released by the carrier after its HTTP response drains.
func (s *Session) PollCarrier(ctx context.Context, cursor uint64) ([]byte, uint64, *PollLease, error) {
	if s.carrier != CarrierHTTPS {
		return nil, cursor, nil, ErrProtocol
	}
	body, next, _, lease, err := s.pollCarrier(ctx, 0, cursor, false)
	return body, next, lease, err
}

// PollCarrierLane retains the per-lane response claim until HTTP drains it.
func (s *Session) PollCarrierLane(
	ctx context.Context,
	laneID uint32,
	cursor uint64,
) ([]byte, uint64, bool, *PollLease, error) {
	if s.carrier != CarrierHTTPSLanes || laneID > MaxStreamID {
		return nil, cursor, false, nil, ErrProtocol
	}
	return s.pollCarrier(ctx, laneID, cursor, true)
}

func (s *Session) pollCarrier(
	ctx context.Context,
	laneID uint32,
	cursor uint64,
	lanes bool,
) ([]byte, uint64, bool, *PollLease, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, cursor, false, nil, ErrClosed
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		closed := lanes && s.usedStreams.Contains(laneID)
		if !closed {
			backends := s.closeLocked(sessionCloseProtocol)
			s.mu.Unlock()
			requestBackendCloses(backends)
			return nil, cursor, false, nil, ErrProtocol
		}
		s.mu.Unlock()
		return nil, cursor, true, nil, nil
	}
	s.lastActivity = time.Now()
	// Claim newest-poll ownership before cursor replay. Otherwise every
	// concurrent old-cursor request can bypass downActive and independently
	// materialize the same replay response.
	if lane.downActive && lane.superseded != nil {
		close(lane.superseded)
	}
	mine := make(chan struct{})
	lane.superseded = mine
	lane.downActive = true
	lease := &PollLease{session: s, lane: lane, claim: mine}
	s.mu.Unlock()

	// Only the lease holding downSlot may materialize or wait on a carrier
	// response. A newer poll claims ownership immediately, but it cannot replay
	// an unacknowledged batch until the superseded response has drained and
	// released this slot.
	select {
	case <-lane.downSlot:
		lease.ownsSlot = true
	case <-ctx.Done():
		lease.Release()
		return nil, cursor, false, nil, ctx.Err()
	case <-mine:
		lease.Release()
		return nil, cursor, false, nil, nil
	case <-s.done:
		lease.Release()
		return nil, cursor, false, nil, ErrClosed
	}

	s.mu.Lock()
	if lane.superseded != mine {
		lease.releaseLocked()
		s.mu.Unlock()
		return nil, cursor, false, nil, nil
	}
	if s.closed {
		lease.releaseLocked()
		s.mu.Unlock()
		return nil, cursor, false, nil, ErrClosed
	}
	if s.carrierLanes[laneID] != lane {
		lease.releaseLocked()
		s.mu.Unlock()
		return nil, cursor, lanes, nil, nil
	}
	timer := time.NewTimer(s.timeouts.LongPoll)
	defer timer.Stop()
	if len(lane.unacked) != 0 {
		if cursor == lane.unackedBase {
			body := bytes.Clone(lane.unacked)
			next := lane.downCursor
			s.mu.Unlock()
			s.recordCarrierRetry(carrierOperationDownlink)
			return body, next, false, lease, nil
		}
		if cursor != lane.downCursor {
			backends := s.closeLocked(sessionCloseProtocol)
			lease.releaseLocked()
			s.mu.Unlock()
			requestBackendCloses(backends)
			return nil, cursor, false, nil, ErrProtocol
		}
		s.releasePendingLocked(lane.unackedCost, lane.unackedItems)
		lane.unacked = nil
		lane.unackedCost = 0
		lane.unackedItems = 0
	} else if cursor != lane.downCursor {
		backends := s.closeLocked(sessionCloseProtocol)
		lease.releaseLocked()
		s.mu.Unlock()
		requestBackendCloses(backends)
		return nil, cursor, false, nil, ErrProtocol
	}

	for {
		if lane.superseded != mine {
			lease.releaseLocked()
			s.mu.Unlock()
			return nil, cursor, false, nil, nil
		}
		if len(lane.pendingFrames) != 0 {
			if lane.downCursor == math.MaxUint64 {
				backends := s.closeLocked(sessionCloseProtocol)
				lease.releaseLocked()
				s.mu.Unlock()
				requestBackendCloses(backends)
				return nil, cursor, false, nil, ErrProtocol
			}
			batch := s.takeDownBatchLocked(lane)
			lane.downCursor++
			lane.unackedBase = cursor
			lane.unacked = batch.body
			lane.unackedCost = batch.cost
			lane.unackedItems = batch.items
			next := lane.downCursor
			body := bytes.Clone(batch.body)
			s.mu.Unlock()
			return body, next, false, lease, nil
		}
		if lanes && laneID != 0 && s.streams[laneID] == nil && s.tombstones.Contains(laneID) {
			lease.releaseLocked()
			s.mu.Unlock()
			return nil, cursor, true, nil, nil
		}
		if s.closed {
			lease.releaseLocked()
			s.mu.Unlock()
			return nil, cursor, false, nil, ErrClosed
		}
		pollNotify := lane.notify
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			s.mu.Lock()
			lease.releaseLocked()
			s.mu.Unlock()
			return nil, cursor, false, nil, ctx.Err()
		case <-mine:
			s.mu.Lock()
			lease.releaseLocked()
			s.mu.Unlock()
			return nil, cursor, false, nil, nil
		case <-s.done:
			lease.Release()
			return nil, cursor, false, nil, ErrClosed
		case <-timer.C:
			s.mu.Lock()
			if lane.superseded != mine {
				lease.releaseLocked()
				s.mu.Unlock()
				return nil, cursor, false, nil, nil
			}
			if s.carrierLanes[laneID] != lane {
				lease.releaseLocked()
				s.mu.Unlock()
				return nil, cursor, lanes, nil, nil
			}
			if len(lane.pendingFrames) != 0 {
				continue
			}
			if lanes && laneID != 0 && s.streams[laneID] == nil && s.tombstones.Contains(laneID) {
				lease.releaseLocked()
				s.mu.Unlock()
				return nil, cursor, true, nil, nil
			}
			s.lastActivity = time.Now()
			s.mu.Unlock()
			return nil, cursor, false, lease, nil
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
	s.closeWithReason(sessionCloseClient)
}

func (s *Session) closeWithReason(reason sessionCloseReason) {
	s.mu.Lock()
	backends := s.closeLocked(reason)
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
			detached = s.closeLocked(sessionCloseResource)
		}
	}
	s.mu.Unlock()
	requestBackendCloses(detached)
	backend.close()
}

func (s *Session) queueFrameLocked(frameType FrameType, streamID uint32, payload []byte) bool {
	laneID := uint32(0)
	if s.carrier == CarrierHTTPSLanes {
		laneID = streamID
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		return false
	}
	if frameType == FrameWindow {
		if index, exists := lane.pendingWindows[streamID]; exists {
			queued := &lane.pendingFrames[index]
			previous, _ := WindowDelta(queued.encoded[FrameHeaderSize:])
			delta, _ := WindowDelta(payload)
			total := uint64(previous) + uint64(delta)
			if total <= math.MaxUint32 {
				binary.BigEndian.PutUint32(queued.encoded[FrameHeaderSize:], uint32(total))
				s.signalPollLocked(lane)
				return true
			}
		}
	}
	if len(lane.pendingFrames) != 0 {
		last := &lane.pendingFrames[len(lane.pendingFrames)-1]
		if last.frameType == FrameData && frameType == FrameData && last.streamID == streamID &&
			len(last.encoded)-FrameHeaderSize+len(payload) <= MaxFramePayload {
			if !s.reservePendingLocked(len(payload), 0, pendingDownlink) {
				return false
			}
			last.encoded = append(last.encoded, payload...)
			last.cost += len(payload)
			binary.BigEndian.PutUint32(last.encoded[4:FrameHeaderSize], uint32(len(last.encoded)-FrameHeaderSize))
			s.signalPollLocked(lane)
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
	lane.pendingFrames = append(lane.pendingFrames, queuedFrame{
		encoded:   encoded,
		frameType: frameType,
		streamID:  streamID,
		cost:      cost,
	})
	if frameType == FrameWindow {
		lane.pendingWindows[streamID] = len(lane.pendingFrames) - 1
	}
	s.signalPollLocked(lane)
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

func (s *Session) takeDownBatchLocked(lane *carrierLane) downBatch {
	size := 0
	cost := 0
	count := 0
	for count < len(lane.pendingFrames) && count < MaxBatchFrames {
		next := len(lane.pendingFrames[count].encoded)
		if count != 0 && size+next > s.limits.CarrierBatchBytes {
			break
		}
		size += next
		cost += lane.pendingFrames[count].cost
		count++
	}
	body := make([]byte, 0, size)
	for index := range count {
		frame := lane.pendingFrames[index]
		if frame.frameType == FrameWindow && lane.pendingWindows[frame.streamID] == index {
			delete(lane.pendingWindows, frame.streamID)
		}
		body = append(body, frame.encoded...)
		lane.pendingFrames[index] = queuedFrame{}
	}
	lane.pendingFrames = lane.pendingFrames[count:]
	for streamID, index := range lane.pendingWindows {
		lane.pendingWindows[streamID] = index - count
	}
	if len(lane.pendingFrames) == 0 {
		lane.pendingFrames = nil
	}
	return downBatch{body: body, cost: cost, items: count}
}

func (s *Session) rememberClosedLocked(streamID uint32) {
	evicted, ok := s.tombstones.Add(streamID)
	if s.carrier == CarrierHTTPSLanes {
		if ok {
			s.releaseCarrierLaneLocked(evicted)
		}
		if lane := s.carrierLanes[streamID]; lane != nil {
			s.signalPollLocked(lane)
		}
	}
}

func (s *Session) dropPendingStreamFramesLocked(streamID uint32) {
	laneID := uint32(0)
	if s.carrier == CarrierHTTPSLanes {
		laneID = streamID
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		return
	}
	kept := lane.pendingFrames[:0]
	releasedCost := 0
	releasedItems := 0
	for index := range lane.pendingFrames {
		frame := lane.pendingFrames[index]
		if frame.streamID == streamID {
			releasedCost += frame.cost
			releasedItems++
			lane.pendingFrames[index] = queuedFrame{}
			continue
		}
		kept = append(kept, frame)
	}
	lane.pendingFrames = kept
	clear(lane.pendingWindows)
	for index := range lane.pendingFrames {
		frame := lane.pendingFrames[index]
		if frame.frameType == FrameWindow {
			lane.pendingWindows[frame.streamID] = index
		}
	}
	if len(lane.pendingFrames) == 0 {
		lane.pendingFrames = nil
	}
	if releasedCost != 0 || releasedItems != 0 {
		s.releasePendingLocked(releasedCost, releasedItems)
	}
}

func (s *Session) releaseCarrierLaneLocked(laneID uint32) {
	if laneID == 0 {
		return
	}
	lane := s.carrierLanes[laneID]
	if lane == nil {
		return
	}
	delete(s.carrierLanes, laneID)
	cost := lane.unackedCost
	items := lane.unackedItems
	for index := range lane.pendingFrames {
		cost += lane.pendingFrames[index].cost
		items++
		lane.pendingFrames[index] = queuedFrame{}
	}
	lane.pendingFrames = nil
	lane.pendingWindows = nil
	lane.unacked = nil
	lane.unackedCost = 0
	lane.unackedItems = 0
	s.signalPollLocked(lane)
	if cost != 0 || items != 0 {
		s.releasePendingLocked(cost, items)
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
	backends := s.closeLocked(sessionCloseProtocol)
	s.mu.Unlock()
	requestBackendCloses(backends)
}

func (s *Session) closeLocked(reason sessionCloseReason) []*backendStream {
	if s.closed {
		return nil
	}
	s.closed = true
	s.closeReason = reason
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
	for _, lane := range s.carrierLanes {
		lane.pendingFrames = nil
		lane.pendingWindows = nil
		lane.unacked = nil
		lane.unackedCost = 0
		lane.unackedItems = 0
		s.signalPollLocked(lane)
	}
	s.carrierLanes = nil
	closeReason := s.closeReason
	s.finishOnce.Do(func() {
		go func() {
			s.backendWG.Wait()
			if s.onFinished != nil {
				s.onFinished(s, closeReason)
			}
			close(s.finishNotified)
		}()
	})
	return backends
}

func (s *Session) recordCarrierRetry(operation carrierOperation) {
	if s.onCarrierRetry != nil {
		s.onCarrierRetry(operation)
	}
}

func (s *Session) recordBackpressure(operation carrierOperation) {
	if s.onBackpressure != nil {
		s.onBackpressure(operation)
	}
}

func (s *Session) signalPollLocked(lane *carrierLane) {
	close(lane.notify)
	lane.notify = make(chan struct{})
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
