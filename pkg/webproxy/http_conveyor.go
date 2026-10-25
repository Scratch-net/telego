package webproxy

import (
	"context"
	"encoding/binary"
	"math"
	"slices"
	"sync"

	"github.com/zeebo/xxh3"
)

const httpUpWindow = 4

// Rejected bodies are streamed to Discard, never queued. These independent
// permits bound connection metadata without consuming protected queue budgets.
func httpUpDiscardLimits(limits Limits) (local, global int, ok bool) {
	localLanes, ok := checkedAddInt(limits.MaxStreamsPerSession, 1)
	if !ok {
		return 0, 0, false
	}
	globalLanes, ok := checkedAddInt(limits.MaxStreams, limits.MaxSessions)
	if !ok {
		return 0, 0, false
	}
	local, ok = checkedMulInt(localLanes, httpUpWindow)
	if !ok {
		return 0, 0, false
	}
	global, ok = checkedMulInt(globalLanes, httpUpWindow)
	return max(2*httpUpWindow, local), max(2*httpUpWindow, global), ok
}

type httpUpDiscardReservation struct{ releaseOnce func() }

func (s *Session) reserveHTTPUpDiscard() *httpUpDiscardReservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit, ok := 0, true
	if s.manager != nil {
		limit = s.manager.httpUpDiscardPerSession
	} else {
		limit, _, ok = httpUpDiscardLimits(s.limits)
	}
	if !ok || s.closed || s.httpUpDiscards >= limit {
		return nil
	}
	if manager := s.manager; manager != nil {
		manager.mu.Lock()
		if manager.closed || manager.httpUpDiscards >= manager.httpUpDiscardLimit {
			manager.mu.Unlock()
			return nil
		}
		manager.httpUpDiscards++
		manager.mu.Unlock()
	}
	s.httpUpDiscards++
	return &httpUpDiscardReservation{releaseOnce: sync.OnceFunc(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.httpUpDiscards--
		if manager := s.manager; manager != nil {
			manager.mu.Lock()
			manager.httpUpDiscards--
			manager.mu.Unlock()
		}
	})}
}

func (r *httpUpDiscardReservation) Release() {
	if r != nil {
		r.releaseOnce()
	}
}

type upCommit struct {
	sequence uint64
	digest   [16]byte
}

type httpUpBatch struct {
	digest                  [16]byte
	known                   bool
	readers                 int
	ownedCost, ownedItems   int
	escrowCost, escrowItems int
}

type httpUpEscrow struct{ cost, items int }

type httpUpEscrowPlan struct {
	batches              map[uint64]httpUpEscrow
	cost, items, missing int
}

type httpUpLane struct {
	pending  map[uint64]*httpUpBatch
	notify   chan struct{}
	readers  int
	applying bool
}

// One reusable application reserve serves the session's ordered HTTP heads.
// Occupied credit follows backend copies; only original uplink releases can
// replenish the free reserve. Other sessions cannot steal progress capacity.
type httpApplicationPool struct {
	cost, items             int
	targetCost, targetItems int
	waiters                 []*httpUpReservation
	applying                bool
}

// httpUpReservation owns body storage before allocation. A complete head can
// borrow exact DATA capacity from the session pool before application.
type httpUpReservation struct {
	session               *Session
	lane                  *httpUpLane
	laneID                uint32
	sequence              uint64
	bodySize              int
	cost, items           int
	applyCost, applyItems int
	batch                 *httpUpBatch
	releaseOnce           func()
}

func (s *Session) releaseHTTPApplicationPoolLocked() {
	pool := &s.httpApplication
	cost, items := pool.cost, pool.items
	pool.cost, pool.items, pool.targetCost, pool.targetItems = 0, 0, 0, 0
	s.carrierOwnedCost -= cost
	s.carrierOwnedItems -= items
	s.releasePendingLocked(cost, items)
}

// Only HTTP bodies/escrow and backend source writes were acquired from the
// ordinary uplink partition. Never recycle control, downlink, or core handoff
// releases here: those have their own protected capacity.
func (s *Session) releaseUplinkPendingLocked(cost, items int) {
	s.releaseUplinkPendingQuietLocked(cost, items)
	s.scheduleBackendPumpLocked()
}

func (s *Session) releaseUplinkPendingQuietLocked(cost, items int) {
	pool := &s.httpApplication
	refillCost, refillItems := 0, 0
	if !s.closed {
		refillCost = min(cost, pool.targetCost-pool.cost)
		refillItems = min(items, pool.targetItems-pool.items)
	}
	pool.cost += refillCost
	pool.items += refillItems
	s.carrierOwnedCost += refillCost
	s.carrierOwnedItems += refillItems
	s.releasePendingQuietLocked(cost-refillCost, items-refillItems)
	if refillCost != 0 || refillItems != 0 {
		close(s.budgetNotify)
		s.budgetNotify = make(chan struct{})
	}
}

func (s *Session) reserveHTTPUp(laneID uint32, sequence uint64, size int) (*httpUpReservation, error) {
	if sequence == 0 || size < FrameHeaderSize || size > min(s.limits.MaxBodyBytes, maxCarrierBatchBytes) ||
		(s.carrier != CarrierHTTPS && s.carrier != CarrierHTTPSLanes) || laneID > MaxStreamID ||
		(s.carrier == CarrierHTTPS && laneID != 0) {
		return nil, ErrProtocol
	}
	applyItems := min(size/FrameHeaderSize, MaxBatchFrames)
	applyCost := size + applyItems*queueItemCost
	cost, items := size+queueItemCost, 1
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	committed := uint64(0)
	if lane := s.carrierLanes[laneID]; lane != nil {
		committed = lane.lastUpSequence
	}
	retired := s.retiredHTTPUpLaneLocked(laneID)
	if !retired && sequence > committed && sequence-committed > httpUpWindow {
		return nil, ErrProtocol
	}
	if !retired && sequence <= committed && (committed-sequence >= httpUpWindow || committed == 0) {
		return nil, ErrProtocol
	}
	lane := s.httpUpLanes[laneID]
	if lane == nil {
		if len(s.httpUpLanes) >= s.limits.MaxStreamsPerSession+1 {
			return nil, ErrBackpressure
		}
		lane = &httpUpLane{pending: make(map[uint64]*httpUpBatch), notify: make(chan struct{})}
	}
	// A later request depends on every earlier sequence, even when an earlier
	// reader cancels or its retry has a larger body. Prepay those obligations
	// before admitting the later body, against both existing pending budgets.
	s.releaseHTTPUpEscrowLocked(laneID, lane)
	plan := s.httpUpEscrowPlanLocked(laneID, lane, sequence, cost, items)
	escrowCost, escrowItems := lane.escrowCharge()
	additionalCost, additionalItems := cost+plan.cost-escrowCost, items+plan.items-escrowItems
	pool := &s.httpApplication
	targetCost, targetItems := pool.targetCost, pool.targetItems
	if !retired && sequence > committed {
		if sequence-committed > 1 {
			maxBody := min(s.limits.MaxBodyBytes, maxCarrierBatchBytes)
			applyItems = min(maxBody/FrameHeaderSize, MaxBatchFrames)
			applyCost = maxBody + applyItems*queueItemCost
		}
		targetCost, targetItems = max(targetCost, applyCost), max(targetItems, applyItems)
	}
	poolCost, poolItems := targetCost-pool.targetCost, targetItems-pool.targetItems
	additionalCost += poolCost
	additionalItems += poolItems
	if lane.readers+1+plan.missing > 2*httpUpWindow ||
		!s.reservePendingLocked(additionalCost, additionalItems, pendingUplink) {
		return nil, ErrBackpressure
	}
	if s.httpUpLanes == nil {
		s.httpUpLanes = make(map[uint32]*httpUpLane)
	}
	s.httpUpLanes[laneID] = lane
	lane.readers++
	lane.applyEscrow(plan)
	pool.targetCost, pool.targetItems = targetCost, targetItems
	pool.cost += poolCost
	pool.items += poolItems
	s.carrierOwnedCost += additionalCost
	s.carrierOwnedItems += additionalItems
	reservation := &httpUpReservation{session: s, lane: lane, laneID: laneID, sequence: sequence, bodySize: size,
		cost: cost, items: items}
	if !retired && sequence > committed {
		reservation.batch = lane.pending[sequence]
		reservation.batch.readers++
		reservation.batch.ownedCost += cost
		reservation.batch.ownedItems += items
	}
	reservation.releaseOnce = sync.OnceFunc(reservation.releaseOwned)
	return reservation, nil
}

// An uncommitted predecessor owns enough storage for a maximum body, shared
// by its live readers and escrow. Application credit is shared by the session.
// Missing readers also retain a slot; the highest sequence needs no escrow.
func (s *Session) httpUpEscrowPlanLocked(laneID uint32, lane *httpUpLane, incoming uint64, cost, items int) httpUpEscrowPlan {
	plan := httpUpEscrowPlan{}
	if s.closed || s.retiredHTTPUpLaneLocked(laneID) {
		return plan
	}
	committed := uint64(0)
	if carrier := s.carrierLanes[laneID]; carrier != nil {
		committed = carrier.lastUpSequence
	}
	if incoming <= committed {
		incoming = 0
	}
	highest := committed
	for sequence, batch := range lane.pending {
		if batch.readers != 0 && sequence > highest {
			highest = sequence
		}
	}
	highest = max(highest, incoming)
	if highest == committed {
		return plan
	}
	maxBody := min(s.limits.MaxBodyBytes, maxCarrierBatchBytes)
	maxItems := 1
	maxCost := maxBody + queueItemCost
	plan.batches = make(map[uint64]httpUpEscrow, httpUpWindow)
	for sequence := committed; sequence < highest; {
		sequence++ // highest can be MaxUint64; never increment past it.
		ownedCost, ownedItems, readers := 0, 0, 0
		if batch := lane.pending[sequence]; batch != nil {
			ownedCost, ownedItems, readers = batch.ownedCost, batch.ownedItems, batch.readers
		}
		if sequence == incoming {
			ownedCost += cost
			ownedItems += items
			readers++
		}
		escrow := httpUpEscrow{}
		if sequence < highest {
			escrow.cost = max(0, maxCost-ownedCost)
			escrow.items = max(0, maxItems-ownedItems)
		}
		if readers == 0 {
			plan.missing++
		}
		plan.batches[sequence] = escrow
		plan.cost += escrow.cost
		plan.items += escrow.items
	}
	return plan
}

func (l *httpUpLane) escrowCharge() (cost, items int) {
	for _, batch := range l.pending {
		cost += batch.escrowCost
		items += batch.escrowItems
	}
	return cost, items
}

func (l *httpUpLane) applyEscrow(plan httpUpEscrowPlan) {
	for sequence, batch := range l.pending {
		if _, keep := plan.batches[sequence]; !keep {
			batch.escrowCost, batch.escrowItems = 0, 0
			delete(l.pending, sequence)
		}
	}
	for sequence, escrow := range plan.batches {
		batch := l.pending[sequence]
		if batch == nil {
			batch = &httpUpBatch{}
			l.pending[sequence] = batch
		}
		batch.escrowCost, batch.escrowItems = escrow.cost, escrow.items
	}
}

// Commit or lane retirement can discard unused escrow, never live body storage.
func (s *Session) releaseHTTPUpEscrowLocked(laneID uint32, lane *httpUpLane) {
	plan := s.httpUpEscrowPlanLocked(laneID, lane, 0, 0, 0)
	cost, items := lane.escrowCharge()
	cost -= plan.cost
	items -= plan.items
	lane.applyEscrow(plan)
	s.carrierOwnedCost -= cost
	s.carrierOwnedItems -= items
	s.releaseUplinkPendingLocked(cost, items)
}

func (r *httpUpReservation) Release() {
	if r == nil {
		return
	}
	r.releaseOnce()
}

func (r *httpUpReservation) releaseOwned() {
	s := r.session
	s.mu.Lock()
	defer s.mu.Unlock()
	escrowCost, escrowItems := r.lane.escrowCharge()
	if r.batch != nil {
		r.batch.readers--
		r.batch.ownedCost -= r.bodySize + queueItemCost
		r.batch.ownedItems--
		if r.batch.readers == 0 {
			r.batch.known = false
		}
	}
	plan := s.httpUpEscrowPlanLocked(r.laneID, r.lane, 0, 0, 0)
	// Return a canceled predecessor's capacity to escrow while successors
	// still depend on it. Only now has the handler released its actual body.
	cost, items := r.cost+escrowCost-plan.cost, r.items+escrowItems-plan.items
	r.lane.applyEscrow(plan)
	s.carrierOwnedCost -= cost
	s.carrierOwnedItems -= items
	s.releaseUplinkPendingLocked(cost, items)
	r.cost = 0
	r.items = 0
	r.applyCost = 0
	r.applyItems = 0
	r.lane.readers--
	if r.lane.readers == 0 && s.httpUpLanes[r.laneID] == r.lane {
		delete(s.httpUpLanes, r.laneID)
	}
	if len(s.httpUpLanes) == 0 {
		s.releaseHTTPApplicationPoolLocked()
	}
	r.lane.signal()
}

func (l *httpUpLane) signal() { close(l.notify); l.notify = make(chan struct{}) }

func (r *httpUpReservation) leaveApplicationQueueLocked() {
	s := r.session
	pool := &s.httpApplication
	if index := slices.Index(pool.waiters, r); index >= 0 {
		pool.waiters = slices.Delete(pool.waiters, index, index+1)
		close(s.budgetNotify)
		s.budgetNotify = make(chan struct{})
	}
}

func (r *httpUpReservation) borrowApplicationLocked(cost, items int) bool {
	s := r.session
	pool := &s.httpApplication
	if cost == 0 && items == 0 {
		return true // WINDOW/CLOSE must not wait behind blocked DATA heads.
	}
	if !slices.Contains(pool.waiters, r) {
		pool.waiters = append(pool.waiters, r)
	}
	if pool.waiters[0] != r || pool.cost < cost || pool.items < items {
		return false
	}
	pool.cost -= cost
	pool.items -= items
	r.cost += cost
	r.items += items
	r.applyCost, r.applyItems = cost, items
	r.leaveApplicationQueueLocked()
	return true
}

// The structural cursor has already bounded the body. Track OPEN/CLOSE
// transitions without retaining a parsed frame array while waiting for credit.
// This matches backendWriteReservationLocked, including harmless late DATA.
func (s *Session) httpApplicationBoundLocked(body []byte) (cost, items int) {
	var changed map[uint32]bool
	for len(body) != 0 {
		payload := int(binary.BigEndian.Uint32(body[4:FrameHeaderSize]))
		streamID := uint32(body[1])<<16 | uint32(body[2])<<8 | uint32(body[3])
		if streamID != 0 {
			switch FrameType(body[0]) {
			case FrameOpen, FrameClose:
				if changed == nil {
					changed = make(map[uint32]bool)
				}
				changed[streamID] = FrameType(body[0]) == FrameOpen
			case FrameData:
				live, overridden := changed[streamID]
				if !overridden {
					live = s.streams[streamID] != nil
				}
				if live {
					cost += payload + queueItemCost
					items++
				}
			}
		}
		body = body[FrameHeaderSize+payload:]
	}
	return cost, items
}

// Retired lanes have no application work. After the structural cursor checks
// the body, validate one frame view at a time without a parsed frame workspace.
func validRetiredHTTPUp(body []byte, laneID uint32) bool {
	for len(body) != 0 {
		payload := int(binary.BigEndian.Uint32(body[4:FrameHeaderSize]))
		frame := Frame{
			Type:     FrameType(body[0]),
			StreamID: uint32(body[1])<<16 | uint32(body[2])<<8 | uint32(body[3]),
			Payload:  body[FrameHeaderSize : FrameHeaderSize+payload],
		}
		if frame.StreamID != laneID || ValidateClientFrame(frame) != nil ||
			(frame.Type != FrameData && frame.Type != FrameWindow && frame.Type != FrameClose) {
			return false
		}
		body = body[FrameHeaderSize+payload:]
	}
	return true
}

func (r *httpUpReservation) Process(ctx context.Context, body []byte) (uint64, error) {
	s := r.session
	if len(body) != r.bodySize {
		s.laneProtocolFailure(r.laneID, nil)
		return 0, ErrProtocol
	}
	// The existing cursor bounds frame count and skips payloads without a
	// second body allocation. Session application still validates live streams.
	_, dataItems, valid := (webSocketInbound{body: body}).applicationBound()
	if !valid {
		s.laneProtocolFailure(r.laneID, nil)
		return 0, ErrProtocol
	}
	defer func() {
		s.mu.Lock()
		r.leaveApplicationQueueLocked()
		s.mu.Unlock()
	}()
	digest := xxh3.Hash128(body).Bytes()
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return 0, ErrClosed
		}
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return 0, err
		}
		// Tombstone eviction retires replay history. The existing lane path
		// accepts only harmless late stream frames after that retirement.
		if s.retiredHTTPUpLaneLocked(r.laneID) {
			s.mu.Unlock()
			if !validRetiredHTTPUp(body, r.laneID) {
				s.laneProtocolFailure(r.laneID, nil)
				return 0, ErrProtocol
			}
			s.recordCarrierRetry(carrierOperationUplink)
			return r.sequence, nil
		}
		lane := s.carrierLanes[r.laneID]
		committed := uint64(0)
		if lane != nil {
			committed = lane.lastUpSequence
		}
		if r.sequence <= committed {
			previous := lane.upHistory[r.sequence%httpUpWindow]
			matches := previous.sequence == r.sequence && previous.digest == digest
			s.mu.Unlock()
			if !matches {
				s.laneProtocolFailure(r.laneID, nil)
				return 0, ErrProtocol
			}
			s.recordCarrierRetry(carrierOperationUplink)
			return r.sequence, nil
		}
		batch := r.lane.pending[r.sequence]
		if batch == nil || batch.known && batch.digest != digest {
			s.mu.Unlock()
			s.laneProtocolFailure(r.laneID, nil)
			return 0, ErrProtocol
		}
		batch.digest = digest
		batch.known = true
		ready := committed != math.MaxUint64 && r.sequence == committed+1 &&
			!r.lane.applying && !s.httpApplication.applying
		if ready {
			applyCost, applyItems := 0, 0
			if dataItems != 0 {
				applyCost, applyItems = s.httpApplicationBoundLocked(body)
			}
			ready = r.borrowApplicationLocked(applyCost, applyItems)
		}
		if ready {
			r.lane.applying = true
			s.httpApplication.applying = true
			s.mu.Unlock()
			ack, err := s.processUpWithDigest(r.laneID, r.sequence, body, s.carrier == CarrierHTTPSLanes, nil, r, digest)
			s.mu.Lock()
			r.lane.applying = false
			s.httpApplication.applying = false
			r.lane.signal()
			close(s.budgetNotify)
			s.budgetNotify = make(chan struct{})
			s.mu.Unlock()
			return ack, err
		}
		changed := r.lane.notify
		budgetChanged := s.budgetNotify
		s.mu.Unlock()
		select {
		case <-changed:
		case <-budgetChanged:
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.done:
			return 0, ErrClosed
		}
	}
}

func (s *Session) retiredHTTPUpLaneLocked(laneID uint32) bool {
	return s.carrier == CarrierHTTPSLanes && laneID != 0 &&
		s.carrierLanes[laneID] == nil && s.usedStreams.Contains(laneID)
}

// transferApplicationLocked moves prepaid capacity to backend queue ownership.
// The caller holds Session.mu. Unused application capacity becomes available
// only after the exact accepted backend charge has changed owners.
func (r *httpUpReservation) transferApplicationLocked(cost, items int) bool {
	if cost > r.applyCost || items > r.applyItems {
		return false
	}
	s := r.session
	s.carrierOwnedCost -= r.applyCost
	s.carrierOwnedItems -= r.applyItems
	s.releaseUplinkPendingQuietLocked(r.applyCost-cost, r.applyItems-items)
	r.cost -= r.applyCost
	r.items -= r.applyItems
	r.applyCost = 0
	r.applyItems = 0
	return true
}
