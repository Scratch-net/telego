package middleend

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"unsafe"
)

// ErrInvalidResponseBudget reports an invalid allocation bound or reserve.
var ErrInvalidResponseBudget = errors.New("invalid Middle-End response budget")

// ResponseQueueEntryBytes is the retained metadata capacity of one queue slot.
const ResponseQueueEntryBytes = int(unsafe.Sizeof(LinkEvent{}))

// ResponseMemoryClass identifies protected portions of one response budget.
// Processing and control capacity cannot be borrowed by ordinary queues/output.
type ResponseMemoryClass uint8

const (
	ResponseMemoryOrdinary ResponseMemoryClass = iota
	ResponseMemoryProcessing
	ResponseMemoryControl
	responseMemoryClassCount
)

// ResponseMemoryStage identifies the current owner without changing its class.
type ResponseMemoryStage uint8

const (
	ResponseMemoryQueuePayload ResponseMemoryStage = iota
	ResponseMemoryQueueMetadata
	ResponseMemoryDecode
	ResponseMemoryEncode
	ResponseMemoryOutput
	ResponseMemoryInflight
	ResponseMemoryOwnerMetadata
	responseMemoryStageCount
)

// ResponseBudgetConfig bounds retained response allocations, not process RSS.
// Reserve sizes include allocation handles and must cover the largest permitted
// operation. Byte permits bound concurrent processing independently of CPU count.
type ResponseBudgetConfig struct {
	LimitBytes             int
	ProcessingReserveBytes int
	ControlReserveBytes    int
}

// Validate requires nonnegative reserves and positive ordinary capacity.
func (c ResponseBudgetConfig) Validate() error {
	if c.LimitBytes <= 0 || c.ProcessingReserveBytes < 0 || c.ControlReserveBytes < 0 ||
		c.ProcessingReserveBytes >= c.LimitBytes || c.ControlReserveBytes >= c.LimitBytes-c.ProcessingReserveBytes {
		return fmt.Errorf("%w: reserves must leave positive ordinary capacity", ErrInvalidResponseBudget)
	}
	return nil
}

// ResponseBudget is shared by every response owner in one service, including
// overlapping generations. Reserve before allocation and release only after the
// allocation is no longer retained. Charges include allocation-handle storage.
//
// Lock order is manager/owner lock, then budget lock. Budget operations never
// invoke callbacks, acquire manager/owner locks, or wait for lifecycle work.
// Processing allocations must be promoted before retention by client output.
type ResponseBudget struct {
	mu                     sync.Mutex
	config                 ResponseBudgetConfig
	classLimits            [responseMemoryClassCount]int
	classes                [responseMemoryClassCount]int
	stages                 [responseMemoryStageCount]int
	used                   int
	highWater              int
	allocations            int
	participants           *ResponseParticipant
	participantCount       int
	backloggedParticipants int
	asyncPressureEvictions int
}

// ResponseAllocation is an exact-once charge obtained from TryReserve. Do not
// copy its value. Copies of its pointer share the same charge. Release remains
// safe when a synchronous write callback reenters its caller. The caller retains
// exclusive ownership of the actual byte slice. Its zero value owns no bytes.
type ResponseAllocation struct {
	_        responseAllocationNoCopy
	budget   *ResponseBudget
	bytes    int
	class    ResponseMemoryClass
	stage    ResponseMemoryStage
	released bool
	owner    *ResponseParticipant
}

type responseAllocationNoCopy struct{}

func (*responseAllocationNoCopy) Lock()   {}
func (*responseAllocationNoCopy) Unlock() {}

// ResponseBudgetSnapshot contains bounded, payload-free allocation counters.
// Stage and class byte counters include handles and sum to UsedBytes.
type ResponseBudgetSnapshot struct {
	LimitBytes             int
	OrdinaryLimitBytes     int
	ProcessingReserveBytes int
	ControlReserveBytes    int
	UsedBytes              int
	HighWaterBytes         int
	Allocations            int
	ClassBytes             [responseMemoryClassCount]int
	StageBytes             [responseMemoryStageCount]int
	Participants           int
	BackloggedParticipants int
}

// NewResponseBudget constructs an empty pool. Construct it once per service.
func NewResponseBudget(config ResponseBudgetConfig) (*ResponseBudget, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &ResponseBudget{
		config: config,
		classLimits: [responseMemoryClassCount]int{
			config.LimitBytes - config.ProcessingReserveBytes - config.ControlReserveBytes,
			config.ProcessingReserveBytes,
			config.ControlReserveBytes,
		},
	}, nil
}

// ResponseAllocationCharge adds the handle cost to an allocation capacity.
// A negative result reports an invalid capacity or integer overflow.
func ResponseAllocationCharge(capacity int) int {
	const overhead = int(unsafe.Sizeof(ResponseAllocation{}))
	if capacity < 0 || capacity > math.MaxInt-overhead {
		return -1
	}
	return capacity + overhead
}

// TryReserve charges capacity before allocation. Failure changes no counters.
// A nil budget represents legacy unaccounted ownership and succeeds with nil.
func (b *ResponseBudget) TryReserve(capacity int, class ResponseMemoryClass, stage ResponseMemoryStage) (*ResponseAllocation, bool) {
	return b.TryReserveFor(nil, capacity, class, stage)
}

// TryReserveFor assigns a charge to a binding before allocating its handle.
// Detached participants cannot accept new allocations.
func (b *ResponseBudget) TryReserveFor(owner *ResponseParticipant, capacity int, class ResponseMemoryClass, stage ResponseMemoryStage) (*ResponseAllocation, bool) {
	charge := ResponseAllocationCharge(capacity)
	if charge < 0 || class >= responseMemoryClassCount || stage >= responseMemoryStageCount {
		return nil, false
	}
	if b == nil {
		return nil, owner == nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if owner != nil && (owner.budget != b || !owner.registered || owner.detached) {
		return nil, false
	}
	if charge > b.classLimits[class]-b.classes[class] {
		return nil, false
	}
	b.classes[class] += charge
	b.stages[stage] += charge
	b.used += charge
	b.highWater = max(b.highWater, b.used)
	b.allocations++
	allocation := &ResponseAllocation{budget: b, bytes: charge, class: class, stage: stage, owner: owner}
	if owner != nil {
		owner.addAllocationLocked(allocation)
	}
	return allocation, true
}

// TryReservePair reserves one complete encoding operation atomically. Two
// contenders cannot each retain half of the same processing reserve.
func (b *ResponseBudget) TryReservePair(firstCapacity, secondCapacity int, class ResponseMemoryClass, stage ResponseMemoryStage) (*ResponseAllocation, *ResponseAllocation, bool) {
	firstCharge, secondCharge := ResponseAllocationCharge(firstCapacity), ResponseAllocationCharge(secondCapacity)
	if firstCharge < 0 || secondCharge < 0 || class >= responseMemoryClassCount || stage >= responseMemoryStageCount {
		return nil, nil, false
	}
	if b == nil {
		return nil, nil, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	available := b.classLimits[class] - b.classes[class]
	if firstCharge > available || secondCharge > available-firstCharge {
		return nil, nil, false
	}
	charge := firstCharge + secondCharge
	b.classes[class] += charge
	b.stages[stage] += charge
	b.used += charge
	b.highWater = max(b.highWater, b.used)
	b.allocations += 2
	return &ResponseAllocation{budget: b, bytes: firstCharge, class: class, stage: stage},
		&ResponseAllocation{budget: b, bytes: secondCharge, class: class, stage: stage}, true
}

// Snapshot returns consistent current counters and the retained high-water mark.
func (b *ResponseBudget) Snapshot() ResponseBudgetSnapshot {
	if b == nil {
		return ResponseBudgetSnapshot{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.snapshotLocked()
}

func (b *ResponseBudget) snapshotLocked() ResponseBudgetSnapshot {
	return ResponseBudgetSnapshot{
		LimitBytes: b.config.LimitBytes, OrdinaryLimitBytes: b.classLimits[ResponseMemoryOrdinary],
		ProcessingReserveBytes: b.config.ProcessingReserveBytes, ControlReserveBytes: b.config.ControlReserveBytes,
		UsedBytes: b.used, HighWaterBytes: b.highWater, Allocations: b.allocations,
		ClassBytes: b.classes, StageBytes: b.stages,
		Participants: b.participantCount, BackloggedParticipants: b.backloggedParticipants,
	}
}

// Bytes returns the retained charge, including its handle, or zero after release.
func (a *ResponseAllocation) Bytes() int {
	if a == nil || a.budget == nil {
		return 0
	}
	a.budget.mu.Lock()
	defer a.budget.mu.Unlock()
	return a.bytes
}

// OrdinaryBytes returns credit already held in the ordinary response pool.
// Processing and control charges cannot reduce an ordinary admission deficit.
func (a *ResponseAllocation) OrdinaryBytes() int {
	if a == nil || a.budget == nil {
		return 0
	}
	a.budget.mu.Lock()
	defer a.budget.mu.Unlock()
	if a.class != ResponseMemoryOrdinary {
		return 0
	}
	return a.bytes
}

// Release returns the charge exactly once. It never calls the allocation owner.
// Clear sensitive bytes and stop retaining the allocation before this call.
func (a *ResponseAllocation) Release() {
	a.releaseBytes()
}

// releaseBytes counts only charges returned by this operation, including an
// owner record retired by its final allocation. The lock excludes other owners.
func (a *ResponseAllocation) releaseBytes() int {
	if a == nil || a.budget == nil {
		return 0
	}
	a.budget.mu.Lock()
	before := a.budget.used
	a.releaseLocked()
	released := before - a.budget.used
	a.budget.mu.Unlock()
	return released
}

func (a *ResponseAllocation) releaseLocked() {
	if a.released {
		return
	}
	b := a.budget
	b.classes[a.class] -= a.bytes
	b.stages[a.stage] -= a.bytes
	b.used -= a.bytes
	b.allocations--
	if a.owner != nil {
		a.owner.removeAllocationLocked(a)
		a.owner = nil
	}
	a.bytes = 0
	a.released = true
}

// Shrink returns unused reservation capacity. It cannot grow an allocation.
// Do not shrink a partially drained allocation whose backing array is retained.
func (a *ResponseAllocation) Shrink(capacity int) bool {
	charge := ResponseAllocationCharge(capacity)
	if charge < 0 {
		return false
	}
	if a == nil {
		return true
	}
	if a.budget == nil {
		return false
	}
	b := a.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if a.released || charge > a.bytes {
		return false
	}
	delta := a.bytes - charge
	if a.owner != nil {
		a.owner.adjustLocked(a.class, a.stage, -delta)
	}
	b.classes[a.class] -= delta
	b.stages[a.stage] -= delta
	b.used -= delta
	a.bytes = charge
	return true
}

// TryMove changes ownership without releasing the allocation charge.
func (a *ResponseAllocation) TryMove(class ResponseMemoryClass, stage ResponseMemoryStage) bool {
	return a.TryMoveAtLeast(0, class, stage)
}

// AssignOwner associates an adopted allocation without changing its charge.
// An allocation cannot move between participants.
func (a *ResponseAllocation) AssignOwner(owner *ResponseParticipant) bool {
	if a == nil {
		return owner == nil
	}
	if a.budget == nil {
		return false
	}
	b := a.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if a.released {
		return false
	}
	if a.owner == owner {
		return true
	}
	if a.owner != nil || owner == nil || owner.budget != b || !owner.registered || owner.detached {
		return false
	}
	a.owner = owner
	owner.addAllocationLocked(a)
	return true
}

// TryMoveAtLeast changes ownership and reserves at least capacity bytes.
// It never shrinks an existing charge. Extra capacity can reserve future output
// expansion while retaining the original packet. Such headroom is a reservation,
// not a claim that the allocation physically retains that many bytes.
// Failure leaves the charge and its class/stage unchanged.
func (a *ResponseAllocation) TryMoveAtLeast(capacity int, class ResponseMemoryClass, stage ResponseMemoryStage) bool {
	return a.tryMoveReplacing(capacity, class, stage, nil)
}

// TryMoveReplacing atomically releases consumed allocations and moves a to its
// next owner. All supplied handles must be distinct, live, and from this pool.
// Nil handles are ignored. Failure leaves every charge unchanged.
//
// The caller must stop retaining consumed buffers before this operation. On
// failure they remain conservatively charged. A failed output promotion must
// lead to bounded retry or cancellation that releases processing capacity. It
// must never leave processing capacity attached to stalled client output.
func (a *ResponseAllocation) TryMoveReplacing(class ResponseMemoryClass, stage ResponseMemoryStage, consumed ...*ResponseAllocation) bool {
	return a.tryMoveReplacing(0, class, stage, consumed)
}

func (a *ResponseAllocation) tryMoveReplacing(capacity int, class ResponseMemoryClass, stage ResponseMemoryStage, consumed []*ResponseAllocation) bool {
	minimumCharge := ResponseAllocationCharge(capacity)
	if minimumCharge < 0 || class >= responseMemoryClassCount || stage >= responseMemoryStageCount {
		return false
	}
	if a == nil {
		for _, other := range consumed {
			if other != nil {
				return false
			}
		}
		return true
	}
	if a.budget == nil {
		return false
	}
	b := a.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if a.released {
		return false
	}
	charge := max(a.bytes, minimumCharge)
	available := b.classLimits[class] - b.classes[class]
	owner := a.owner
	if a.class == class {
		available += a.bytes
	}
	for index, other := range consumed {
		if other == nil {
			continue
		}
		if other == a || other.budget != b || other.released {
			return false
		}
		if other.owner != nil {
			if owner != nil && owner != other.owner {
				return false
			}
			owner = other.owner
		}
		for _, earlier := range consumed[:index] {
			if earlier == other {
				return false
			}
		}
		if other.class == class {
			available += other.bytes
		}
	}
	if charge > available {
		return false
	}
	// Pin the inherited participant before releasing consumed allocations.
	// Its binding can already be detached with only those allocations alive.
	if a.owner == nil && owner != nil {
		a.owner = owner
		owner.addAllocationLocked(a)
	}
	for _, other := range consumed {
		if other != nil {
			other.releaseLocked()
		}
	}
	b.classes[a.class] -= a.bytes
	b.stages[a.stage] -= a.bytes
	b.used += charge - a.bytes
	b.highWater = max(b.highWater, b.used)
	if owner != nil {
		owner.adjustLocked(a.class, a.stage, -a.bytes)
		owner.adjustLocked(class, stage, charge)
	}
	a.bytes = charge
	a.class, a.stage = class, stage
	b.classes[a.class] += a.bytes
	b.stages[a.stage] += a.bytes
	return true
}
