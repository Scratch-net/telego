package middleend

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

const (
	maxRefreshCandidatesPerManager = 8
	slotRefreshInterval            = time.Second
	slotRefreshMinimumUnused       = 45 * time.Second
	slotRefreshPreparationTimeout  = 10 * time.Second
	slotRefreshRetryInitial        = time.Second
	slotRefreshRetryMaximum        = 10 * time.Second
)

// A reservation includes construction, validation, and disposal. The old
// notification channels also identify its incarnation if failed-slot repair
// replaces the link while this candidate is being prepared.
type slotRefreshAttempt struct {
	old               *fixedBindingSlot
	oldLink           ClientLink
	oldEvents         <-chan LinkEvent
	oldCapacity       <-chan struct{}
	bindEpoch         uint64
	candidateEvents   <-chan LinkEvent
	candidateCapacity <-chan struct{}
}

type slotLinkChannels struct {
	events   <-chan LinkEvent
	capacity <-chan struct{}
}

func (m *fixedBindingManager) initializeSlotRefreshLocked(slot *fixedBindingSlot, index int, now time.Time) {
	slot.startedAt = now
	slot.unusedSince = now
	slot.refreshDelay = slotRefreshMinimumUnused + time.Duration(index%16)*time.Second
	slot.refreshAfter = now.Add(slot.refreshDelay)
	slot.refreshRetry = slotRefreshRetryInitial
	slot.refreshing = false
	slot.used = false
}

func slotAge(slot *fixedBindingSlot, now time.Time) time.Duration {
	if slot.startedAt.IsZero() {
		return 0
	}
	return max(0, now.Sub(slot.startedAt))
}

func (m *fixedBindingManager) readySlotsLocked(dcID DCID) int {
	ready := 0
	for _, slot := range m.slotGroups[dcID] {
		if !slot.failed && !slot.retired {
			ready++
		}
	}
	return ready
}

func (m *fixedBindingManager) dcSnapshotsLocked() []FixedBindingDCSnapshot {
	result := make([]FixedBindingDCSnapshot, 0, len(m.dcCounters))
	for dcID, counters := range m.dcCounters {
		counters.ReadySlots = m.readySlotsLocked(dcID)
		if m.refreshDCs[dcID] != nil {
			counters.RefreshingSlots = 1
		}
		result = append(result, counters)
	}
	slices.SortFunc(result, func(a, b FixedBindingDCSnapshot) int { return int(a.DCID) - int(b.DCID) })
	return result
}

func unusedSlotLocked(slot *fixedBindingSlot) bool {
	return !slot.failed && !slot.repairing && !slot.retired && slot.resident == 0 && len(slot.bindings) == 0 &&
		slot.pending == 0 && slot.bytes == 0 && slot.requestItems == 0 && slot.requestBytes == 0 &&
		slot.controlItems == 0 && slot.controlBytes == 0 && slot.waitHead == nil && slot.waitTail == nil &&
		slot.outHead == nil && slot.outTail == nil && slot.probe == nil
}

// refreshUnusedSlots only claims bounded work. A slow candidate does not stop
// another DC's maintenance, and this scheduler never waits for liveness probes.
func (m *fixedBindingManager) refreshUnusedSlots(ctx context.Context, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != fixedBindingManagerReady || !m.accepting || m.repairLink == nil || context.Cause(ctx) != nil {
		return
	}
	start := m.refreshNext
	for offset := 0; offset < len(m.order) && m.refreshes < maxRefreshCandidatesPerManager; offset++ {
		index := (start + offset) % len(m.order)
		slot := m.order[index]
		if m.refreshDCs[slot.dcID] != nil || !unusedSlotLocked(slot) || slot.unusedSince.IsZero() || now.Before(slot.refreshAfter) {
			continue
		}
		attempt := &slotRefreshAttempt{old: slot, oldLink: slot.link, oldEvents: slot.events, oldCapacity: slot.capacity, bindEpoch: slot.bindEpoch}
		m.refreshDCs[slot.dcID] = attempt
		m.refreshes++
		slot.refreshing = true
		m.refreshNext = (index + 1) % len(m.order)
		m.operations.Go(func() { m.refreshSlot(ctx, attempt) })
	}
}

func (m *fixedBindingManager) refreshSlot(parent context.Context, attempt *slotRefreshAttempt) {
	ctx, cancel := context.WithTimeout(parent, slotRefreshPreparationTimeout)
	stopManagerCancel := context.AfterFunc(m.refreshContext, cancel)
	success, canceled := false, false
	defer func() {
		cause := context.Cause(ctx)
		stopManagerCancel()
		cancel()
		m.finishSlotRefresh(attempt, success, canceled || cause != nil && !errors.Is(cause, context.DeadlineExceeded))
	}()

	replacement, err := m.repairLink(ctx, attempt.old.dcID)
	if nilClientLink(replacement.Link) {
		return
	}
	link := replacement.Link
	events, capacity := link.Events(), link.SubmissionReady()
	// Ownership must be established before Start or Close: a faulty factory
	// can return an already-owned link, including another unpublished candidate.
	m.mu.Lock()
	alias := m.linkChannelsOwnedLocked(events, capacity)
	if !alias {
		attempt.candidateEvents, attempt.candidateCapacity = events, capacity
	}
	m.mu.Unlock()
	if alias {
		return
	}
	transferred := false
	defer func() {
		if !transferred {
			closeRefreshCandidate(link, events)
		}
	}()
	if err != nil {
		return
	}
	if events == nil || capacity == nil || replacement.DCID != attempt.old.dcID {
		return
	}
	replacement.SourceIP = replacement.SourceIP.Unmap()
	if validatePublicEndpoint("refresh source", netip.AddrPortFrom(replacement.SourceIP, 1)) != nil {
		return
	}
	if err := link.Start(ctx); err != nil {
		return
	}
	if err := m.probeRefreshCandidate(ctx, link, events, capacity); err != nil {
		return
	}
	// No application work can enter the candidate before publication.
	candidateSnapshot := link.Snapshot()
	m.mu.Lock()
	old := attempt.old
	index := slices.Index(m.order, old)
	if context.Cause(ctx) != nil || m.state != fixedBindingManagerReady || !m.accepting || index < 0 ||
		old.events != attempt.oldEvents || old.bindEpoch != attempt.bindEpoch || !unusedSlotLocked(old) ||
		!refreshLinkIdle(candidateSnapshot) || channelClosed(old.link.Done()) || channelClosed(link.Done()) {
		m.mu.Unlock()
		canceled = true
		return
	}
	// Hold the manager lock across the incumbent snapshot: otherwise a stale
	// response can enqueue and submit a close between the link and queue checks.
	// GnetClientLink.Snapshot only takes its link lock; the link publishes events
	// through a channel and never calls back into this manager while locked.
	if !refreshLinkIdle(attempt.oldLink.Snapshot()) {
		m.mu.Unlock()
		canceled = true
		return
	}
	current := &fixedBindingSlot{
		dcID: old.dcID, sourceIP: replacement.SourceIP, link: link, events: events, capacity: capacity,
		requestWake: make(chan struct{}, 1), bindings: make(map[*clientBinding]struct{}), consumerDone: make(chan struct{}),
	}
	m.initializeSlotRefreshLocked(current, index, time.Now())
	m.order[index] = current
	group := m.slotGroups[old.dcID]
	group[slices.Index(group, old)] = current
	if m.slots[old.dcID] == old {
		m.slots[old.dcID] = current
	}
	old.retired = true
	old.refreshing = false
	m.consumers.Go(func() { m.consumeSlot(current) })
	transferred = true
	m.mu.Unlock()

	_ = old.link.Close()
	<-old.consumerDone
	// Err preserves the first terminal action. Record a peer failure which won
	// against orderly retirement, but never an arbitrary callback on a retired
	// pointer. Such a failure belongs only to the old physical incarnation.
	if cause := old.link.Err(); cause != nil {
		m.recordSlotFailure(old, attempt.oldEvents, cause, FixedBindingSlotFailureLinkTerminal, true)
	}
	success = true
}

func refreshLinkIdle(snapshot LinkSnapshot) bool {
	return snapshot.State == LinkStateReady && snapshot.PendingSubmissions == 0 && snapshot.PendingSubmissionBytes == 0 &&
		snapshot.PendingEvents == 0 && snapshot.PendingEventBytes == 0
}

func channelClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func (m *fixedBindingManager) linkChannelsOwnedLocked(events <-chan LinkEvent, capacity <-chan struct{}) bool {
	for _, slot := range m.order {
		if events != nil && events == slot.events || capacity != nil && capacity == slot.capacity {
			return true
		}
	}
	for _, attempt := range m.refreshDCs {
		if events != nil && (events == attempt.oldEvents || events == attempt.candidateEvents) ||
			capacity != nil && (capacity == attempt.oldCapacity || capacity == attempt.candidateCapacity) {
			return true
		}
	}
	for _, candidate := range m.repairCandidates {
		if events != nil && events == candidate.events || capacity != nil && capacity == candidate.capacity {
			return true
		}
	}
	return false
}

func closeRefreshCandidate(link ClientLink, events <-chan LinkEvent) {
	_ = link.Close()
	if events != nil {
		for event := range events {
			clearLinkEventPacket(&event)
		}
	}
}

func (m *fixedBindingManager) probeRefreshCandidate(ctx context.Context, link ClientLink, events <-chan LinkEvent, capacity <-chan struct{}) error {
	m.mu.Lock()
	pingID, err := m.allocateProbeIDLocked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	submissionID, err := allocateFixedBindingSubmissionID()
	if err != nil {
		return err
	}
	payload := (Ping{ID: pingID}).MarshalBinary()
	defer func() { clear(payload) }()
	submitted := false
	for {
		if context.Cause(ctx) != nil {
			return context.Cause(ctx)
		}
		if !submitted {
			err := link.TrySubmit(LinkSubmission{SubmissionID: submissionID, Payload: payload})
			if err == nil {
				payload = nil // Accepted payload belongs to the link.
				submitted = true
			} else if !errors.Is(err, ErrLinkBackpressure) {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-link.Done():
			return ErrLinkClosed
		case <-capacity:
		case event, ok := <-events:
			if !ok {
				return ErrLinkClosed
			}
			err := validateFixedBindingLinkEvent(event)
			matched := submitted && event.Kind == LinkEventPong && event.KeepaliveID == pingID
			keepalive := event.Kind == LinkEventPing || event.Kind == LinkEventPong
			clearLinkEventPacket(&event)
			if err != nil || !keepalive {
				return fmt.Errorf("%w: unexpected refresh probe event", ErrFixedBindingProtocol)
			}
			if matched {
				return nil
			}
		}
	}
}

func (m *fixedBindingManager) finishSlotRefresh(attempt *slotRefreshAttempt, success, canceled bool) {
	m.mu.Lock()
	old := attempt.old
	delta := FixedBindingDCSnapshot{DCID: old.dcID}
	counters := m.dcCounters[old.dcID]
	switch {
	case success:
		counters.SlotRefreshSuccesses++
		delta.SlotRefreshSuccesses = 1
	case canceled:
		counters.SlotRefreshCanceled++
		delta.SlotRefreshCanceled = 1
	default:
		counters.SlotRefreshFailures++
		delta.SlotRefreshFailures = 1
	}
	m.dcCounters[old.dcID] = counters
	if old.events == attempt.oldEvents {
		old.refreshing = false
		if !success && !old.unusedSince.IsZero() && old.bindEpoch == attempt.bindEpoch {
			old.refreshAfter = time.Now().Add(jitteredRetryDelay(old.refreshRetry))
			old.refreshRetry = nextRepairBackoff(old.refreshRetry, slotRefreshRetryMaximum)
		}
	}
	observer := m.dcObserver
	m.mu.Unlock()
	if observer != nil {
		observer(delta)
	}
	m.mu.Lock()
	delete(m.refreshDCs, old.dcID)
	m.refreshes--
	m.publishDrainedLocked()
	m.mu.Unlock()
}
