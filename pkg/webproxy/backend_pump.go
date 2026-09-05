package webproxy

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"slices"

	"github.com/panjf2000/gnet/v2"
)

func (s *Session) scheduleBackendPump() {
	s.mu.Lock()
	s.scheduleBackendPumpLocked()
	s.mu.Unlock()
}

func (s *Session) scheduleBackendPumpLocked() {
	if s.backendFactory == nil || s.owner == nil || s.ownerStopped || len(s.backends) == 0 {
		return
	}
	if len(s.pumpPending) > 0 || s.pumpQueued {
		s.pumpDirty = true
		return
	}
	s.pumpPending = make([]*backendStream, 0, len(s.backends))
	for backend := range s.backends {
		s.pumpPending = append(s.pumpPending, backend)
	}
	slices.SortFunc(s.pumpPending, func(a, b *backendStream) int { return cmp.Compare(a.id, b.id) })
	s.enqueueBackendPumpLocked()
}

// retireBackendOwner runs only after the owning engine has returned. Closed
// sessions remain registered with Manager until their backends acknowledge
// disposal, so this also reaches previously requested, abandoned closes.
func (s *Session) retireBackendOwner() {
	s.mu.Lock()
	if s.ownerStopped || s.backendFactory == nil {
		s.mu.Unlock()
		return
	}
	s.ownerStopped = true
	s.closeLocked(sessionCloseShutdown)
	s.pumpPending = nil
	s.pumpQueued = false
	s.pumpDirty = false
	backends := make([]*backendStream, 0, len(s.backends))
	for backend := range s.backends {
		backends = append(backends, backend)
	}
	s.mu.Unlock()
	for _, backend := range backends {
		backend.cancel()
		s.mu.Lock()
		logical, started := backend.logical, backend.started
		s.mu.Unlock()
		if retired, ok := logical.(ownerStoppedBackend); ok {
			retired.OwnerStopped()
		} else if logical != nil {
			_ = logical.Close()
		} else if !started {
			backend.complete(ErrClosed)
		}
	}
}

func (s *Session) enqueueBackendPumpLocked() {
	s.pumpQueued = true
	err := s.owner.Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		s.pumpBackends()
		return nil
	}))
	if err != nil {
		s.pumpQueued = false
		// Engine shutdown is exceptional. Each backend still receives Close so
		// its OnClosed callback, rather than this scheduler, owns finalization.
		go s.Close()
	}
}

func (s *Session) pumpBackends() {
	s.mu.Lock()
	s.pumpQueued = false
	// At most four streams perform one 64 KiB read and write each. Other
	// connections on this gnet loop regain control after at most 512 KiB.
	n := min(4, len(s.pumpPending))
	backends := s.pumpPending[:n:n]
	s.pumpPending = s.pumpPending[n:]
	s.mu.Unlock()
	progress := false
	for _, backend := range backends {
		progress = backend.pump() || progress
	}
	s.mu.Lock()
	if len(s.pumpPending) > 0 {
		if !s.pumpQueued {
			s.enqueueBackendPumpLocked()
		}
	} else if s.pumpDirty || progress {
		s.pumpDirty = false
		s.scheduleBackendPumpLocked()
	}
	s.mu.Unlock()
}

func (b *backendStream) pump() bool {
	s := b.session
	s.mu.Lock()
	if b.terminal {
		s.mu.Unlock()
		return false
	}
	if b.ctx.Err() != nil {
		backend := b.logical
		started := b.started
		s.mu.Unlock()
		if backend != nil {
			_ = backend.Close()
		} else if !started {
			b.complete(context.Canceled)
		}
		return false
	}
	if !b.started {
		b.started = true
		s.mu.Unlock()
		b.open()
		return true
	}
	backend, opened := b.logical, b.opened
	s.mu.Unlock()
	if backend == nil || !opened {
		return false
	}
	progress, err := b.pumpWrite(backend)
	if err == nil {
		var readProgress bool
		readProgress, err = b.pumpRead(backend)
		progress = readProgress || progress
	}
	if err != nil {
		b.cancel()
		_ = backend.Close()
	}
	return progress && err == nil
}

func (b *backendStream) open() {
	s := b.session
	headroom, items := backendHandoffReserve(s.limits)
	if headroom < 128 || items < 2 {
		b.complete(ErrLimit)
		return
	}
	ctx, cancel := context.WithTimeout(b.ctx, s.timeouts.BackendDial)
	options := BackendOpenOptions{
		Context: ctx, Owner: s.owner, ClientIP: s.clientIP,
		Network: s.backendNet, Address: s.backend,
		MaxInputBytes:  min(RelayDataChunk+256, headroom/2),
		MaxOutputBytes: min(MaxFramePayload+RelayDataChunk, headroom/2),
		MaxInputItems:  512, MaxOutputItems: 512,
		InputBudget: b.queueBudget(true), OutputBudget: b.queueBudget(false),
		Notify:   s.scheduleBackendPump,
		OnOpened: func(err error) { cancel(); b.openCompleted(err) },
		OnClosed: func(err error) { cancel(); b.complete(err) },
	}
	backend, err := s.backendFactory(options)
	if err != nil {
		cancel()
		b.complete(err)
		return
	}
	s.mu.Lock()
	b.logical = backend
	closed := b.ctx.Err() != nil || b.terminal
	s.mu.Unlock()
	if closed {
		_ = backend.Close()
	}
}

func (b *backendStream) openCompleted(err error) {
	b.openOnce.Do(func() {
		if b.session.onBackendDialFinished != nil {
			b.session.onBackendDialFinished()
		}
		b.session.mu.Lock()
		b.opened = err == nil
		b.session.mu.Unlock()
		if err != nil {
			b.cancel()
		}
		b.session.scheduleBackendPump()
	})
}

func (b *backendStream) complete(err error) {
	b.finishOnce.Do(func() {
		b.openCompleted(err)
		s := b.session
		s.mu.Lock()
		b.terminal = true
		delete(s.backends, b)
		s.mu.Unlock()
		s.backendClosed(b.id, b)
		if s.onStreamFinished != nil {
			s.onStreamFinished()
		}
		s.backendWG.Done()
	})
}

func (b *backendStream) queueBudget(input bool) BackendBudget {
	s := b.session
	return BackendBudget{
		Reserve: func(size, items int) bool {
			overhead, ok := checkedMulInt(queueItemCost, items)
			if !ok {
				return false
			}
			cost, ok := checkedAddInt(size, overhead)
			if !ok {
				return false
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			state := s.streams[b.id]
			if s.closed || state == nil || state.backend != b || b.ctx.Err() != nil {
				return false
			}
			class := pendingDownlink
			if input {
				class = pendingBackendInput
			}
			if !s.reservePendingLocked(cost, items, class) {
				return false
			}
			if input {
				b.inputCost += cost
				b.inputItems += items
			} else {
				b.outputCost += cost
				b.outputItems += items
			}
			return true
		},
		Release: func(size, items int) {
			cost := size + queueItemCost*items
			s.mu.Lock()
			defer s.mu.Unlock()
			if input {
				b.inputCost -= cost
				b.inputItems -= items
			} else {
				b.outputCost -= cost
				b.outputItems -= items
			}
			s.releasePendingLocked(cost, items)
		},
	}
}

func (b *backendStream) pumpWrite(backend Backend) (bool, error) {
	s := b.session
	s.mu.Lock()
	state := s.streams[b.id]
	if s.closed || state == nil || state.backend != b {
		s.mu.Unlock()
		return false, ErrClosed
	}
	if len(state.writes) == 0 {
		s.mu.Unlock()
		return false, nil
	}
	data := state.writes[0]
	offset := state.writeOffset
	end := min(len(data), offset+RelayDataChunk)
	s.mu.Unlock()
	written, err := backend.TryWrite(data[offset:end])
	if written < 0 || written > end-offset {
		return false, errors.New("WEB backend returned invalid write count")
	}
	if written == 0 {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.streams[b.id] != state {
		return false, ErrClosed
	}
	state.writeOffset += written
	state.pendingWriteBytes -= written
	state.receiveWindow += uint32(written)
	// Keep the entire source allocation charged across partial accepts. The
	// core independently charges its copy to bounded handoff capacity.
	if state.writeOffset == len(data) {
		cost := len(data) + queueItemCost
		state.writes[0] = nil
		state.writes = state.writes[1:]
		state.writeOffset = 0
		state.pendingWriteCost -= cost
		state.pendingWriteItems--
		s.releasePendingLocked(cost, 1)
	}
	payload, windowErr := WindowPayload(uint32(written))
	if windowErr != nil || !s.queueFrameLocked(FrameWindow, b.id, payload) {
		return false, ErrLimit
	}
	return true, err
}

func (b *backendStream) pumpRead(backend Backend) (bool, error) {
	s := b.session
	readable := RelayDataChunk
	if source, ok := backend.(readableBackend); ok {
		readable = source.ReadableBytes()
		if readable <= 0 {
			return false, nil
		}
	}
	s.mu.Lock()
	state := s.streams[b.id]
	if s.closed || state == nil || state.backend != b {
		s.mu.Unlock()
		return false, ErrClosed
	}
	allowance := min(int(state.sendCredit), RelayDataChunk, readable)
	controlBytes, _, _ := pendingControlReserve(s.limits)
	allowance = min(allowance, s.limits.MaxPendingPerSession-controlBytes-s.pendingCost-FrameHeaderSize-queueItemCost)
	if allowance <= 0 {
		s.mu.Unlock()
		return false, nil
	}
	// Reserve the destination before TryRead can release source ownership.
	// The handoff partition prevents a full ordinary queue from blocking this
	// ownership transfer. The reservation follows the encoded frame afterward.
	cost := allowance + FrameHeaderSize + queueItemCost
	if !s.reservePendingLocked(cost, 1, pendingHandoff) {
		s.mu.Unlock()
		return false, nil
	}
	s.mu.Unlock()
	encoded := make([]byte, FrameHeaderSize+allowance)
	n, err := backend.TryRead(encoded[FrameHeaderSize:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if n < 0 || n > allowance {
		s.releasePendingLocked(cost, 1)
		return false, errors.New("WEB backend returned invalid read count")
	}
	if s.closed || s.streams[b.id] != state {
		// closeLocked released this carrier-owned reservation already.
		if !s.closed {
			s.releasePendingLocked(cost, 1)
		}
		return false, ErrClosed
	}
	if n == 0 {
		s.releasePendingQuietLocked(cost, 1)
		return false, err
	}
	encoded[0] = byte(FrameData)
	encoded[1] = byte(b.id >> 16)
	encoded[2] = byte(b.id >> 8)
	encoded[3] = byte(b.id)
	binary.BigEndian.PutUint32(encoded[4:8], uint32(n))
	lane := s.carrierLanes[0]
	if s.carrier.usesLanes() {
		lane = s.carrierLanes[b.id]
	}
	if lane == nil {
		s.releasePendingLocked(cost, 1)
		return false, ErrClosed
	}
	// Cost includes the retained capacity even when the read fills only a
	// prefix. It is released with the frame, never with a shortened slice.
	lane.pendingFrames = append(lane.pendingFrames, queuedFrame{encoded: encoded[:FrameHeaderSize+n], frameType: FrameData, streamID: b.id, cost: cost})
	state.sendCredit -= uint64(n)
	s.signalPollLocked(lane)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	return true, err
}
