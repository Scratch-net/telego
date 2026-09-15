package middleend

import (
	"time"
	"unsafe"
)

// These ages only rank victims after admission exhausts the shared pool.
// They do not replace the client's independent no-progress timeout.
const (
	responsePressureStallAge       = time.Second
	responsePressureObservationAge = 2 * time.Second
)

type responsePressureTarget interface {
	evictResponsePressure(responsePressureEvidence) bool
}

// ResponseParticipant records one binding's allocation ownership independently
// of manager residency. Its target points to an existing binding, not a closure.
// Detach clears that reference before historical output can retain the record.
type ResponseParticipant struct {
	budget         *ResponseBudget
	previous, next *ResponseParticipant
	target         responsePressureTarget
	id             int64
	stages         [responseMemoryStageCount]int
	ordinaryBytes  int
	allocations    int
	observedAt     time.Time
	lastProgressAt time.Time
	unreadBytes    int
	wait           ResponseOutputWait
	registered     bool
	detached       bool
	pending        bool
	asyncPending   bool
	selection      uint64
	invoked        bool
}

const ResponseParticipantBytes = int(unsafe.Sizeof(ResponseParticipant{}))

// registerParticipant charges metadata before allocation. Call lazily on the
// first response. Global connection IDs must already be unique. A registration
// failure uses the same pressure/retry path as payload admission.
func (b *ResponseBudget) registerParticipant(id int64, target responsePressureTarget) (*ResponseParticipant, bool) {
	if b == nil {
		return nil, true
	}
	if target == nil {
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if ResponseParticipantBytes > b.classLimits[ResponseMemoryOrdinary]-b.classes[ResponseMemoryOrdinary] {
		return nil, false
	}
	p := &ResponseParticipant{budget: b, target: target, id: id, registered: true, next: b.participants, ordinaryBytes: ResponseParticipantBytes}
	p.stages[ResponseMemoryOwnerMetadata] = ResponseParticipantBytes
	if b.participants != nil {
		b.participants.previous = p
	}
	b.participants = p
	b.participantCount++
	b.classes[ResponseMemoryOrdinary] += ResponseParticipantBytes
	b.stages[ResponseMemoryOwnerMetadata] += ResponseParticipantBytes
	b.used += ResponseParticipantBytes
	b.highWater = max(b.highWater, b.used)
	b.allocations++
	return p, true
}

// Detach ends the binding lifetime and removes its lifecycle target. Retained
// allocations keep the charged record alive until their actual release.
func (p *ResponseParticipant) Detach() {
	p.detachBytes()
}

func (p *ResponseParticipant) detachBytes() int {
	if p == nil || p.budget == nil {
		return 0
	}
	b := p.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if p.detached || !p.registered {
		return 0
	}
	if p.backloggedLocked() {
		b.backloggedParticipants--
	}
	p.detached = true
	p.target = nil
	if p.previous == nil {
		b.participants = p.next
	} else {
		p.previous.next = p.next
	}
	if p.next != nil {
		p.next.previous = p.previous
	}
	p.previous, p.next = nil, nil
	before := b.used
	p.retireLocked()
	return before - b.used
}

func (p *ResponseParticipant) retireLocked() {
	if !p.registered || !p.detached || p.allocations != 0 {
		return
	}
	b := p.budget
	p.registered = false
	p.clearPendingLocked()
	p.ordinaryBytes -= ResponseParticipantBytes
	p.stages[ResponseMemoryOwnerMetadata] -= ResponseParticipantBytes
	b.classes[ResponseMemoryOrdinary] -= ResponseParticipantBytes
	b.stages[ResponseMemoryOwnerMetadata] -= ResponseParticipantBytes
	b.used -= ResponseParticipantBytes
	b.allocations--
	b.participantCount--
}

func (p *ResponseParticipant) addAllocationLocked(a *ResponseAllocation) {
	p.allocations++
	p.adjustLocked(a.class, a.stage, a.bytes)
}

func (p *ResponseParticipant) removeAllocationLocked(a *ResponseAllocation) {
	p.adjustLocked(a.class, a.stage, -a.bytes)
	p.allocations--
	if p.allocations == 0 {
		p.clearPendingLocked()
	}
	p.retireLocked()
}

func (p *ResponseParticipant) adjustLocked(class ResponseMemoryClass, stage ResponseMemoryStage, delta int) {
	wasBacklogged := p.backloggedLocked()
	p.stages[stage] += delta
	if class == ResponseMemoryOrdinary {
		p.ordinaryBytes += delta
	}
	if backlogged := p.backloggedLocked(); wasBacklogged != backlogged {
		if backlogged {
			p.budget.backloggedParticipants++
		} else {
			p.budget.backloggedParticipants--
		}
	}
}

func (p *ResponseParticipant) backloggedLocked() bool {
	return p.registered && !p.detached && (p.stages[ResponseMemoryQueuePayload] > 0 ||
		p.stages[ResponseMemoryInflight] > 0 || p.stages[ResponseMemoryOutput] > 0)
}

// ReportProgress records owner observations, never accepted-write timestamps.
// A new backlog or a gap in observations starts a fresh progress baseline.
func (p *ResponseParticipant) ReportProgress(observedAt, lastProgress time.Time, unreadBytes int, wait ResponseOutputWait) {
	if p == nil || p.budget == nil || observedAt.IsZero() || unreadBytes < 0 {
		return
	}
	p.budget.mu.Lock()
	defer p.budget.mu.Unlock()
	if !p.registered || p.detached || observedAt.Before(p.observedAt) {
		return
	}
	if unreadBytes == 0 {
		p.lastProgressAt = time.Time{}
	} else if p.unreadBytes == 0 || observedAt.Sub(p.observedAt) > responsePressureObservationAge {
		p.lastProgressAt = observedAt
	} else {
		if unreadBytes < p.unreadBytes {
			p.lastProgressAt = observedAt
		}
		if lastProgress.After(p.lastProgressAt) && !lastProgress.After(observedAt) {
			p.lastProgressAt = lastProgress
		}
	}
	p.observedAt, p.unreadBytes, p.wait = observedAt, unreadBytes, wait
}

// ResponseParticipantSnapshot separates retained allocations from unread bytes.
// QueuedBytes is an upper bound on reclamation until the manager revalidates it.
type ResponseParticipantSnapshot struct {
	ConnectionID    int64
	RetainedBytes   int
	OrdinaryBytes   int
	QueuedBytes     int
	InflightBytes   int
	OutputBytes     int
	Allocations     int
	StageBytes      [responseMemoryStageCount]int
	ObservedAt      time.Time
	LastProgressAt  time.Time
	UnreadBytes     int
	Wait            ResponseOutputWait
	Detached        bool
	PendingEviction bool
}

func (p *ResponseParticipant) Snapshot() ResponseParticipantSnapshot {
	if p == nil || p.budget == nil {
		return ResponseParticipantSnapshot{}
	}
	p.budget.mu.Lock()
	defer p.budget.mu.Unlock()
	return p.snapshotLocked()
}

func (p *ResponseParticipant) snapshotLocked() ResponseParticipantSnapshot {
	retained := 0
	for _, bytes := range p.stages {
		retained += bytes
	}
	return ResponseParticipantSnapshot{
		ConnectionID: p.id, RetainedBytes: retained, OrdinaryBytes: p.ordinaryBytes,
		QueuedBytes:   p.stages[ResponseMemoryQueuePayload] + p.stages[ResponseMemoryQueueMetadata],
		InflightBytes: p.stages[ResponseMemoryInflight], OutputBytes: p.stages[ResponseMemoryOutput],
		Allocations: p.allocations, StageBytes: p.stages, ObservedAt: p.observedAt,
		LastProgressAt: p.lastProgressAt, UnreadBytes: p.unreadBytes, Wait: p.wait,
		Detached: p.detached, PendingEviction: p.pending,
	}
}

type ResponsePressureSelectionReason uint8

const (
	ResponsePressureLargestBacklog ResponsePressureSelectionReason = iota
	ResponsePressureAboveFairShare
	ResponsePressureStalled
	ResponsePressureIncomingFallback
	ResponsePressureSelectionReasonCount
)

func (r ResponsePressureSelectionReason) String() string {
	switch r {
	case ResponsePressureAboveFairShare:
		return "above_fair_share"
	case ResponsePressureStalled:
		return "stalled"
	case ResponsePressureIncomingFallback:
		return "incoming_fallback"
	default:
		return "largest_backlog"
	}
}

// ResponsePressureVictim holds a selection, not reclaimed byte credit.
// Call TryEvict only after releasing every manager and owner lock.
type ResponsePressureVictim struct {
	Participant             *ResponseParticipant
	Snapshot                ResponseParticipantSnapshot
	Reason                  ResponsePressureSelectionReason
	FairShareBytes          int
	RequiredReclaimBytes    int
	Scanned                 int
	Budget                  ResponseBudgetSnapshot
	SelectedAt              time.Time
	RequiredAdditionalBytes int
	selection               uint64
}

// SelectPressureVictim first rechecks ordinary capacity under the budget lock.
// requiredAdditional is the complete additional charge for incoming admission,
// before subtracting currently free capacity. If it fits, no owner is selected.
// Otherwise it scans active charged participants once. Detached records remain
// charged until release but leave the scan list immediately. Its maximum size is
// OrdinaryLimitBytes/ResponseParticipantBytes, independent of historical churn.
// A queue that can cover the deficit ranks before one that cannot. Within that
// group, fresh stalled output precedes consumers above their soft fair share.
func (b *ResponseBudget) SelectPressureVictim(now time.Time, requiredAdditional int) ResponsePressureVictim {
	if b == nil {
		return ResponsePressureVictim{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	result := ResponsePressureVictim{Budget: b.snapshotLocked(), SelectedAt: now, RequiredAdditionalBytes: requiredAdditional}
	if requiredAdditional > b.classLimits[ResponseMemoryOrdinary] {
		return result
	}
	available := b.classLimits[ResponseMemoryOrdinary] - b.classes[ResponseMemoryOrdinary]
	if requiredAdditional <= available {
		return result
	}
	result.RequiredReclaimBytes = requiredAdditional - available
	result.FairShareBytes = b.classLimits[ResponseMemoryOrdinary] / max(1, b.backloggedParticipants)
	bestFit, bestQueued := false, false
	for p := b.participants; p != nil; p = p.next {
		result.Scanned++
		if !p.backloggedLocked() || p.pending || p.target == nil {
			continue
		}
		snapshot := p.snapshotLocked()
		queued := p.stages[ResponseMemoryQueuePayload] > 0
		if !queued && snapshot.OutputBytes == 0 {
			continue
		}
		if !queued && b.asyncPressureEvictions != 0 {
			continue
		}
		fits := queued && snapshot.QueuedBytes >= result.RequiredReclaimBytes
		reason := ResponsePressureLargestBacklog
		if snapshot.OrdinaryBytes > result.FairShareBytes {
			reason = ResponsePressureAboveFairShare
		}
		if p.unreadBytes > 0 && !p.observedAt.IsZero() && !p.observedAt.After(now) &&
			now.Sub(p.observedAt) <= responsePressureObservationAge && !p.lastProgressAt.IsZero() &&
			now.Sub(p.lastProgressAt) >= responsePressureStallAge {
			reason = ResponsePressureStalled
		}
		better := result.Participant == nil
		if !better && fits != bestFit {
			better = fits
		} else if !better && fits == bestFit && queued != bestQueued {
			better = queued
		} else if !better && fits == bestFit && queued == bestQueued {
			better = reason > result.Reason || (reason == result.Reason &&
				(snapshot.OrdinaryBytes > result.Snapshot.OrdinaryBytes ||
					(snapshot.OrdinaryBytes == result.Snapshot.OrdinaryBytes && snapshot.ConnectionID < result.Snapshot.ConnectionID)))
		}
		if better {
			result.Participant, result.Snapshot, result.Reason = p, snapshot, reason
			bestFit, bestQueued = fits, queued
		}
	}
	if p := result.Participant; p != nil {
		p.selection++
		p.pending = true
		p.invoked = false
		p.asyncPending = !bestQueued
		if p.asyncPending {
			b.asyncPressureEvictions++
		}
		result.Snapshot.PendingEviction = true
		result.selection = p.selection
	}
	return result
}

// TryEvict invokes a revalidating lifecycle target outside the budget lock.
// A false result cancels selection. Success leaves ownership charged until the
// manager and output callbacks release their actual allocations.
func (v ResponsePressureVictim) TryEvict() bool {
	return v.tryEvict(responsePressureIncoming{})
}

func (v ResponsePressureVictim) tryEvict(incoming responsePressureIncoming) bool {
	p := v.Participant
	if p == nil || p.budget == nil {
		return false
	}
	b := p.budget
	b.mu.Lock()
	target := p.target
	valid := p.registered && !p.detached && p.pending && !p.invoked && p.selection == v.selection && target != nil
	if valid {
		p.invoked = true
	}
	b.mu.Unlock()
	if !valid {
		return false
	}
	if target.evictResponsePressure(responsePressureEvidence{
		incoming: incoming, budget: v.Budget, selectedAt: v.SelectedAt, reason: v.Reason,
		requiredAdditional: v.RequiredAdditionalBytes, requiredReclaim: v.RequiredReclaimBytes,
		fairShare: v.FairShareBytes, scanned: v.Scanned, victim: v.Snapshot,
	}) {
		return true
	}
	v.cancel(true)
	return false
}

// Cancel abandons a selection before its lifecycle callback begins.
// Once invoked, only callback failure or actual ownership release ends it.
func (v ResponsePressureVictim) Cancel() {
	v.cancel(false)
}

func (v ResponsePressureVictim) cancel(invoked bool) {
	if p := v.Participant; p != nil && p.budget != nil {
		p.budget.mu.Lock()
		if p.selection == v.selection && (!p.invoked || invoked) {
			p.clearPendingLocked()
		}
		p.budget.mu.Unlock()
	}
}

func (p *ResponseParticipant) clearPendingLocked() {
	if p.asyncPending {
		p.budget.asyncPressureEvictions--
	}
	p.pending, p.asyncPending, p.invoked = false, false, false
}
