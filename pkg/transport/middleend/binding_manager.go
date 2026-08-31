package middleend

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
)

var (
	// ErrInvalidFixedBindingManager reports invalid slots or limits.
	ErrInvalidFixedBindingManager = errors.New("invalid fixed-binding manager")
	// ErrFixedBindingManagerNotStarted reports work attempted before Start succeeds.
	ErrFixedBindingManagerNotStarted = errors.New("fixed-binding manager is not started")
	// ErrFixedBindingManagerClosed reports work attempted during or after manager shutdown.
	ErrFixedBindingManagerClosed = errors.New("fixed-binding manager is closed")
	// ErrFixedBindingManagerQuiesced reports a Bind after new admission stops.
	ErrFixedBindingManagerQuiesced = errors.New("fixed-binding manager is not admitting new bindings")
	// ErrFixedBindingInitialFailure reports a permanent failure while starting the fixed slots.
	ErrFixedBindingInitialFailure = errors.New("start fixed-binding manager")
	// ErrFixedBindingUnknownDC reports a Bind for an exact signed DCID absent from the fixed slots.
	ErrFixedBindingUnknownDC = errors.New("unknown fixed-binding DC")
	// ErrFixedBindingSlotFailed reports the permanent loss of one exact source slot.
	ErrFixedBindingSlotFailed = errors.New("fixed-binding slot failed")
	// ErrFixedBindingSlotRepair reports a failed or unavailable physical-link replacement.
	ErrFixedBindingSlotRepair = errors.New("repair fixed-binding slot")
	// ErrFixedBindingLimit reports a global or per-slot resident-binding limit.
	ErrFixedBindingLimit = errors.New("fixed-binding resident-binding limit reached")
	// ErrFixedBindingRequestPending reports a second request before the first
	// request's waiting, reservation, submission, or result state is consumed.
	ErrFixedBindingRequestPending = errors.New("fixed-binding request is already pending")
	// ErrFixedBindingRequestRejected reports a permanent request validation or
	// size failure. Retrying the same request cannot succeed.
	ErrFixedBindingRequestRejected = errors.New("fixed-binding request is permanently rejected")
	// ErrFixedBindingResponseBackpressure reports a bounded response queue that cannot accept an event.
	ErrFixedBindingResponseBackpressure = errors.New("fixed-binding response queue is full")
	// ErrFixedBindingProtocol reports an event with an invalid connection identity or source slot.
	ErrFixedBindingProtocol = errors.New("fixed-binding routing protocol failure")
	// ErrFixedBindingConnectionIDExhausted reports permanent exhaustion of positive connection IDs.
	ErrFixedBindingConnectionIDExhausted = errors.New("fixed-binding connection IDs exhausted")
	// ErrFixedBindingSubmissionIDExhausted reports permanent exhaustion of nonzero submission IDs.
	ErrFixedBindingSubmissionIDExhausted = errors.New("fixed-binding submission IDs exhausted")
	// ErrFixedBindingWaitTicketExhausted reports permanent exhaustion of FIFO
	// waiter tickets before wraparound.
	ErrFixedBindingWaitTicketExhausted = errors.New("fixed-binding wait tickets exhausted")
	// ErrFixedBindingEpochExhausted reports permanent exhaustion of an opaque
	// binding readiness or reservation epoch before wraparound.
	ErrFixedBindingEpochExhausted = errors.New("fixed-binding epochs exhausted")
	// ErrFixedBindingReadyToken reports a stale, duplicate, or foreign token.
	ErrFixedBindingReadyToken = errors.New("invalid fixed-binding ready token")
	// ErrFixedBindingConsumerMode reports mixed blocking and readiness-token
	// event consumption for one binding.
	ErrFixedBindingConsumerMode = errors.New("fixed-binding event consumer mode conflict")
	// ErrFixedBindingControlBackpressure reports exhaustion of the bounded
	// manager-owned control queue.
	ErrFixedBindingControlBackpressure = errors.New("fixed-binding control queue is full")
	// ErrFixedBindingProbePending reports a second concurrent liveness probe for
	// one exact source slot.
	ErrFixedBindingProbePending = errors.New("fixed-binding slot probe is already pending")
	// ErrFixedBindingProbeIDExhausted reports permanent exhaustion of a manager's
	// nonzero keepalive IDs before wraparound.
	ErrFixedBindingProbeIDExhausted = errors.New("fixed-binding probe IDs exhausted")
	// ErrClientBindingClosed reports work attempted after a binding starts closing.
	ErrClientBindingClosed = errors.New("Middle-End client binding is closed")
)

const (
	// MaxFixedBindingResidents matches Telegram's official process-wide
	// MAX_CONNECTIONS table bound at the pinned MTProxy commit. It is separate
	// from per-link queue metadata because resident bindings do not eagerly
	// allocate request or response payload capacity.
	MaxFixedBindingResidents = 65536
)

// FixedBindingSlot fixes one exact signed DCID and source IP to one unstarted
// ClientLink. SourceIP is the public source IP used by the link bootstrap.
// A zero SourceIP is valid only for manager users that construct ProxyRequest
// values with independent address metadata. The manager takes ownership of
// every link only when construction succeeds.
// A supplied ClientLink method must not synchronously call manager Start, Bind,
// or Close, or binding PrepareProxyRequest, PrepareReservedProxyRequest,
// Probe, NextEvent, BeginClose, or Close. Those callbacks can deadlock lifecycle
// barriers or the sole Events consumer. Read-only Err, Done, Ready, String,
// GoString, ConnectionID, DCID, CloseDone, and CloseResult calls are supported,
// but a callback must not wait for Done or CloseDone to close. The built-in
// link engines do not reenter their owner.
type FixedBindingSlot struct {
	DCID     DCID
	SourceIP netip.Addr
	Link     ClientLink
}

// FixedBindingLimits bounds resident bindings and all manager-retained request,
// response, probe, and CloseConnection state. Every field is required; this API has
// no operational defaults.
type FixedBindingLimits struct {
	MaxResidentBindings        int
	MaxResidentBindingsPerSlot int

	MaxPendingRequestItemsPerBinding int
	MaxPendingRequestBytesPerBinding int
	MaxPendingRequestItemsPerSlot    int
	MaxPendingRequestBytesPerSlot    int
	MaxPendingRequestItems           int
	MaxPendingRequestBytes           int
	MaxPendingControlItemsPerSlot    int
	MaxPendingControlBytesPerSlot    int
	MaxPendingControlItems           int
	MaxPendingControlBytes           int

	MaxPendingResponseItemsPerBinding int
	MaxPendingResponseBytesPerBinding int
	MaxPendingResponseItemsPerSlot    int
	MaxPendingResponseBytesPerSlot    int
	MaxPendingResponseItems           int
	MaxPendingResponseBytes           int
}

// Validate rejects zero, excessive, or inconsistent nested limits.
func (l FixedBindingLimits) Validate() error {
	values := [...]int{
		l.MaxResidentBindings,
		l.MaxResidentBindingsPerSlot,
		l.MaxPendingRequestItemsPerBinding,
		l.MaxPendingRequestBytesPerBinding,
		l.MaxPendingRequestItemsPerSlot,
		l.MaxPendingRequestBytesPerSlot,
		l.MaxPendingRequestItems,
		l.MaxPendingRequestBytes,
		l.MaxPendingControlItemsPerSlot,
		l.MaxPendingControlBytesPerSlot,
		l.MaxPendingControlItems,
		l.MaxPendingControlBytes,
		l.MaxPendingResponseItemsPerBinding,
		l.MaxPendingResponseBytesPerBinding,
		l.MaxPendingResponseItemsPerSlot,
		l.MaxPendingResponseBytesPerSlot,
		l.MaxPendingResponseItems,
		l.MaxPendingResponseBytes,
	}
	for _, value := range values {
		if value <= 0 {
			return fmt.Errorf("%w: every limit must be positive", ErrInvalidFixedBindingManager)
		}
	}
	if l.MaxResidentBindings > MaxFixedBindingResidents || l.MaxResidentBindingsPerSlot > MaxFixedBindingResidents {
		return fmt.Errorf("%w: resident-binding limits must not exceed %d", ErrInvalidFixedBindingManager, MaxFixedBindingResidents)
	}
	if l.MaxPendingRequestItemsPerBinding > MaxLinkQueueItems || l.MaxPendingRequestItemsPerSlot > MaxLinkQueueItems ||
		l.MaxPendingRequestItems > MaxLinkQueueItems ||
		l.MaxPendingControlItemsPerSlot > MaxLinkQueueItems || l.MaxPendingControlItems > MaxLinkQueueItems ||
		l.MaxPendingResponseItemsPerBinding > MaxLinkQueueItems || l.MaxPendingResponseItemsPerSlot > MaxLinkQueueItems ||
		l.MaxPendingResponseItems > MaxLinkQueueItems {
		return fmt.Errorf("%w: item limits must not exceed %d", ErrInvalidFixedBindingManager, MaxLinkQueueItems)
	}
	if l.MaxPendingRequestBytesPerBinding > MaxLinkQueueBytes ||
		l.MaxPendingRequestBytesPerSlot > MaxLinkQueueBytes || l.MaxPendingRequestBytes > MaxLinkQueueBytes ||
		l.MaxPendingControlBytesPerSlot > MaxLinkQueueBytes || l.MaxPendingControlBytes > MaxLinkQueueBytes ||
		l.MaxPendingResponseBytesPerBinding > MaxLinkQueueBytes ||
		l.MaxPendingResponseBytesPerSlot > MaxLinkQueueBytes ||
		l.MaxPendingResponseBytes > MaxLinkQueueBytes {
		return fmt.Errorf("%w: byte limits must not exceed %d", ErrInvalidFixedBindingManager, MaxLinkQueueBytes)
	}
	if l.MaxResidentBindingsPerSlot > l.MaxResidentBindings {
		return fmt.Errorf("%w: per-slot resident bindings exceed the global limit", ErrInvalidFixedBindingManager)
	}
	if l.MaxPendingRequestItemsPerBinding != 1 {
		return fmt.Errorf("%w: per-binding pending request items must equal 1", ErrInvalidFixedBindingManager)
	}
	if l.MaxPendingRequestItemsPerBinding > l.MaxPendingRequestItemsPerSlot ||
		l.MaxPendingRequestItemsPerSlot > l.MaxPendingRequestItems {
		return fmt.Errorf("%w: request item limits must be nested binding <= slot <= global", ErrInvalidFixedBindingManager)
	}
	if l.MaxPendingRequestBytesPerBinding > l.MaxPendingRequestBytesPerSlot ||
		l.MaxPendingRequestBytesPerSlot > l.MaxPendingRequestBytes {
		return fmt.Errorf("%w: request byte limits must be nested binding <= slot <= global", ErrInvalidFixedBindingManager)
	}
	if l.MaxPendingControlItemsPerSlot > l.MaxPendingControlItems {
		return fmt.Errorf("%w: per-slot control items exceed the global limit", ErrInvalidFixedBindingManager)
	}
	if l.MaxPendingControlBytesPerSlot > l.MaxPendingControlBytes {
		return fmt.Errorf("%w: per-slot control bytes exceed the global limit", ErrInvalidFixedBindingManager)
	}
	if l.MaxPendingResponseItemsPerBinding > l.MaxPendingResponseItemsPerSlot ||
		l.MaxPendingResponseItemsPerSlot > l.MaxPendingResponseItems {
		return fmt.Errorf("%w: response item limits must be nested binding <= slot <= global", ErrInvalidFixedBindingManager)
	}
	if l.MaxPendingResponseBytesPerBinding > l.MaxPendingResponseBytesPerSlot ||
		l.MaxPendingResponseBytesPerSlot > l.MaxPendingResponseBytes {
		return fmt.Errorf("%w: response byte limits must be nested binding <= slot <= global", ErrInvalidFixedBindingManager)
	}
	const minimumRequestBytes = ProxyRequestBaseSize + UnencryptedMessageHeaderSize + MinimumUnencryptedBodySize
	if l.MaxPendingRequestBytesPerBinding < minimumRequestBytes ||
		l.MaxPendingRequestBytesPerSlot < minimumRequestBytes || l.MaxPendingRequestBytes < minimumRequestBytes {
		return fmt.Errorf("%w: request byte limits must admit the smallest valid %d-byte proxy request", ErrInvalidFixedBindingManager, minimumRequestBytes)
	}
	if l.MaxPendingControlBytesPerSlot < ClosePayloadSize || l.MaxPendingControlBytes < ClosePayloadSize {
		return fmt.Errorf("%w: control byte limits must admit one %d-byte control payload", ErrInvalidFixedBindingManager, ClosePayloadSize)
	}
	if l.MaxPendingResponseBytesPerBinding < ClosePayloadSize ||
		l.MaxPendingResponseBytesPerSlot < ClosePayloadSize || l.MaxPendingResponseBytes < ClosePayloadSize {
		return fmt.Errorf("%w: response byte limits must admit one %d-byte close event", ErrInvalidFixedBindingManager, ClosePayloadSize)
	}
	return nil
}

type fixedBindingManagerState uint8

const (
	fixedBindingManagerCreated fixedBindingManagerState = iota
	fixedBindingManagerStarting
	fixedBindingManagerReady
	fixedBindingManagerClosing
	fixedBindingManagerClosed
)

type fixedBindingSlot struct {
	dcID        DCID
	sourceIP    netip.Addr
	link        ClientLink
	events      <-chan LinkEvent
	capacity    <-chan struct{}
	requestWake chan struct{}

	bindings map[*clientBinding]struct{}
	resident int
	pending  int
	bytes    int

	requestItems int
	requestBytes int
	controlItems int
	controlBytes int

	requestItemsHighWater  int
	requestBytesHighWater  int
	controlItemsHighWater  int
	controlBytesHighWater  int
	responseItemsHighWater int
	responseBytesHighWater int

	waitHead *preparedRequest
	waitTail *preparedRequest
	outHead  *outboundItem
	outTail  *outboundItem

	failed       bool
	repairing    bool
	err          error
	probe        *fixedBindingProbe
	consumerDone chan struct{}
}

type fixedBindingSlotRepair func(context.Context, DCID) (FixedBindingSlot, error)

type fixedBindingManager struct {
	mu     sync.Mutex
	limits FixedBindingLimits
	state  fixedBindingManagerState
	// slots retains the first configured slot for focused diagnostics and
	// compatibility with single-link generations. slotGroups owns the complete
	// per-DC pool used for admission and probing.
	slots      map[DCID]*fixedBindingSlot
	slotGroups map[DCID][]*fixedBindingSlot
	bindNext   map[DCID]int
	order      []*fixedBindingSlot
	byID       map[int64]*clientBinding

	residentBindings int
	accepting        bool
	drained          chan struct{}
	drainedSet       bool
	pending          int
	pendingBytes     int
	requestItems     int
	requestBytes     int
	controlItems     int
	controlBytes     int

	requestItemsHighWater  int
	requestBytesHighWater  int
	controlItemsHighWater  int
	controlBytesHighWater  int
	responseItemsHighWater int
	responseBytesHighWater int

	responseBackpressureEvents  uint64
	controlBackpressureEvents   uint64
	slotFailures                uint64
	slotFailureAffectedBindings uint64
	lastSlotFailure             FixedBindingSlotFailureSnapshot
	slotFailureObserver         func(FixedBindingSlotFailureSnapshot)
	slotRepairSuccesses         uint64
	slotRepairFailures          uint64
	repairLink                  fixedBindingSlotRepair
	repairContext               context.Context
	cancelRepairs               context.CancelCauseFunc
	operations                  sync.WaitGroup

	ready      chan struct{}
	readyHead  *clientBinding
	readyTail  *clientBinding
	waitTicket uint64
	probeID    uint64

	consumersOnce sync.Once
	consumers     sync.WaitGroup
	closeOnce     sync.Once
	startDone     chan struct{}
	done          chan struct{}
	startResult   error
	startSet      bool
	terminalErr   error
	closeResult   error

	materializeHookForTest func()
}

type clientBinding struct {
	manager      *fixedBindingManager
	slot         *fixedBindingSlot
	sourceIP     netip.Addr
	connectionID int64

	nextMu sync.Mutex
	queue  []LinkEvent
	head   int
	items  int
	bytes  int
	notify chan struct{}
	ops    sync.WaitGroup

	request *preparedRequest
	result  *ClientRequestResult

	readyPrev        *clientBinding
	readyNext        *clientBinding
	readyQueued      bool
	readyLeased      bool
	readyEpoch       uint64
	reservationEpoch uint64
	consumerMode     fixedBindingConsumerMode
	terminalObserved bool
	resident         bool
	active           bool
	localClosing     bool
	remoteClosed     bool
	terminal         bool
	terminalErr      error
	closeStarted     bool
	closeDone        chan struct{}
	closeResult      error
	closeSet         bool
}

type fixedBindingConsumerMode uint8

const (
	fixedBindingConsumerUnset fixedBindingConsumerMode = iota
	fixedBindingConsumerBlocking
	fixedBindingConsumerToken
)

type preparedRequestPhase uint8

const (
	preparedRequestWaiting preparedRequestPhase = iota + 1
	preparedRequestReserved
	preparedRequestMaterializing
	preparedRequestMaterialized
	preparedRequestAttempting
)

type preparedRequest struct {
	binding     *clientBinding
	size        int
	fingerprint [sha256.Size]byte
	ticket      uint64
	epoch       uint64
	phase       preparedRequestPhase
	handed      bool
	canceled    bool
	submission  LinkSubmission
	waitPrev    *preparedRequest
	waitNext    *preparedRequest
	outbound    *outboundItem
}

type outboundItemKind uint8

const (
	outboundRequest outboundItemKind = iota + 1
	outboundControl
	outboundProbe
)

type outboundItem struct {
	kind       outboundItemKind
	request    *preparedRequest
	binding    *clientBinding
	submission LinkSubmission
	probe      *fixedBindingProbe
	attempting bool
	canceled   bool
	prev       *outboundItem
	next       *outboundItem
}

type fixedBindingProbe struct {
	slot      *fixedBindingSlot
	id        uint64
	done      chan struct{}
	result    error
	complete  bool
	submitted bool
	outbound  *outboundItem
}

// FixedBindingManager owns a fixed set of signed-DC-to-link bindings. Its
// pointer-backed representation is safe to copy and does not expose links,
// locks, queues, or retained payloads through formatting. It does not own
// endpoint selection, dialing, bootstraps, engine runtimes, retries,
// migrations, or frontend state.
type FixedBindingManager struct {
	state *fixedBindingManager
}

// FixedBindingSlotSnapshot is a payload-free operational view of one physical
// link in a signed-DC pool.
type FixedBindingSlotSnapshot struct {
	DCID DCID

	Failed           bool
	Repairing        bool
	ResidentBindings int
	RequestItems     int
	RequestBytes     int
	ControlItems     int
	ControlBytes     int
	ResponseItems    int
	ResponseBytes    int

	RequestItemsHighWater  int
	RequestBytesHighWater  int
	ControlItemsHighWater  int
	ControlBytesHighWater  int
	ResponseItemsHighWater int
	ResponseBytesHighWater int
	Link                   LinkSnapshot
}

// FixedBindingSlotFailureReason identifies the manager operation that caused
// one physical link to fail.
type FixedBindingSlotFailureReason string

const (
	FixedBindingSlotFailureProbeTimeout      FixedBindingSlotFailureReason = "probe_timeout"
	FixedBindingSlotFailureControlSubmission FixedBindingSlotFailureReason = "control_submission"
	FixedBindingSlotFailureEventRouting      FixedBindingSlotFailureReason = "event_routing"
	FixedBindingSlotFailureLinkTerminal      FixedBindingSlotFailureReason = "link_terminal"
	FixedBindingSlotFailureSubmission        FixedBindingSlotFailureReason = "submission"
)

// FixedBindingSlotFailureSnapshot describes the last physical-link failure.
// Sequence is manager-local in FixedBindingManagerSnapshot and service-local
// in GenerationSupervisorSnapshot.
type FixedBindingSlotFailureSnapshot struct {
	Sequence         uint64
	DCID             DCID
	Reason           FixedBindingSlotFailureReason
	AffectedBindings int
	Error            error
}

// FixedBindingManagerSnapshot is a concurrency-safe payload-free view of one
// generation manager and all of its physical links.
type FixedBindingManagerSnapshot struct {
	Ready     bool
	Accepting bool
	Closed    bool

	ResidentBindings int
	RequestItems     int
	RequestBytes     int
	ControlItems     int
	ControlBytes     int
	ResponseItems    int
	ResponseBytes    int

	RequestItemsHighWater  int
	RequestBytesHighWater  int
	ControlItemsHighWater  int
	ControlBytesHighWater  int
	ResponseItemsHighWater int
	ResponseBytesHighWater int

	ResponseBackpressureEvents  uint64
	ControlBackpressureEvents   uint64
	SlotFailures                uint64
	SlotFailureAffectedBindings uint64
	LastSlotFailure             FixedBindingSlotFailureSnapshot
	SlotRepairSuccesses         uint64
	SlotRepairFailures          uint64
	RepairingSlots              int
	Slots                       []FixedBindingSlotSnapshot
}

// ClientBinding is one positive connection identity fixed permanently to the
// slot selected by Bind. Its pointer-backed representation is safe to copy and
// does not expose retained packets through formatting. It has one NextEvent
// consumer and no goroutine.
type ClientBinding struct {
	state *clientBinding
}

// PrepareProxyRequestStatus reports whether one validated request was
// materialized immediately or registered as a payload-free capacity waiter.
type PrepareProxyRequestStatus uint8

const (
	// PrepareProxyRequestQueued means the manager marshaled and queued the
	// request. The caller may release the source request but must wait for its
	// accepted result before reading another frontend packet.
	PrepareProxyRequestQueued PrepareProxyRequestStatus = iota + 1
	// PrepareProxyRequestWaiting means the caller must retain the unchanged
	// request until a readiness token yields its exact reservation.
	PrepareProxyRequestWaiting
)

// ClientRequestResult is the stored terminal result of one prepared request.
// Accepted transfers the marshaled payload to the fixed ClientLink exactly
// once. An error is permanent for this request.
type ClientRequestResult struct {
	SubmissionID uint64
	Accepted     bool
	Err          error
}

// ClientPrepareReservation is an opaque, payload-free handoff for one
// capacity reservation. It is bound to one binding, epoch, size, and request
// fingerprint.
type ClientPrepareReservation struct {
	state *clientPrepareReservation
}

type clientPrepareReservation struct {
	binding *clientBinding
	epoch   uint64
}

// ClientReadyToken is one opaque lease for coalesced binding readiness. The
// token contains no request or response payload.
type ClientReadyToken struct {
	state *clientReadyToken
}

type clientReadyToken struct {
	manager *fixedBindingManager
	binding *clientBinding
	epoch   uint64
}

// String redacts reservation identity and request metadata.
func (ClientPrepareReservation) String() string {
	return "middleend.ClientPrepareReservation{redacted}"
}

// GoString redacts reservation identity and request metadata.
func (r ClientPrepareReservation) GoString() string { return r.String() }

// String reports only public routing identities and redacts lease state.
func (t ClientReadyToken) String() string {
	if t.state == nil || t.state.binding == nil || t.state.binding.slot == nil {
		return "middleend.ClientReadyToken{redacted}"
	}
	return fmt.Sprintf("middleend.ClientReadyToken{DCID:%d, ConnectionID:%d, state:<redacted>}", t.state.binding.slot.dcID, t.state.binding.connectionID)
}

// GoString reports only public routing identities and redacts lease state.
func (t ClientReadyToken) GoString() string { return t.String() }

var (
	fixedBindingConnectionIDs atomic.Int64
	fixedBindingSubmissionIDs atomic.Uint64
	fixedBindingAllocatorMu   sync.Mutex
)

// NewFixedBindingManager validates and takes ownership of exact unstarted
// links. Multiple links may share one signed DCID and form its fixed pool. It
// calls Events exactly once per accepted link and retains that
// channel for the sole consumer. Validation failure leaves every link owned by
// the caller and starts no goroutine. Supplied ClientLink methods have the
// synchronous reentry restrictions documented on FixedBindingSlot.
func NewFixedBindingManager(slots []FixedBindingSlot, limits FixedBindingLimits) (*FixedBindingManager, error) {
	return newFixedBindingManager(slots, limits, nil)
}

func newFixedBindingManager(
	slots []FixedBindingSlot,
	limits FixedBindingLimits,
	repairLink fixedBindingSlotRepair,
) (*FixedBindingManager, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if len(slots) == 0 || len(slots) > MaxProxyTargets {
		return nil, fmt.Errorf("%w: slot count must be in [1,%d]", ErrInvalidFixedBindingManager, MaxProxyTargets)
	}
	if err := validateFixedBindingControlReserve(limits, len(slots)); err != nil {
		return nil, err
	}
	for index, configured := range slots {
		if nilClientLink(configured.Link) {
			return nil, fmt.Errorf("%w: slot %d has a nil or typed-nil link", ErrInvalidFixedBindingManager, index)
		}
		if configured.SourceIP.IsValid() {
			sourceIP := configured.SourceIP.Unmap()
			if err := validatePublicEndpoint("slot source", netip.AddrPortFrom(sourceIP, 1)); err != nil {
				return nil, fmt.Errorf("%w: slot %d source IP: %v", ErrInvalidFixedBindingManager, index, err)
			}
		}
	}

	manager := &fixedBindingManager{
		limits:     limits,
		state:      fixedBindingManagerCreated,
		accepting:  true,
		drained:    make(chan struct{}),
		slots:      make(map[DCID]*fixedBindingSlot, len(slots)),
		slotGroups: make(map[DCID][]*fixedBindingSlot, len(slots)),
		bindNext:   make(map[DCID]int, len(slots)),
		order:      make([]*fixedBindingSlot, 0, len(slots)),
		byID:       make(map[int64]*clientBinding),
		startDone:  make(chan struct{}),
		done:       make(chan struct{}),
		ready:      make(chan struct{}, 1),
		repairLink: repairLink,
	}
	seenEvents := make(map[<-chan LinkEvent]struct{}, len(slots))
	seenCapacity := make(map[<-chan struct{}]struct{}, len(slots))
	for index, configured := range slots {
		events := configured.Link.Events()
		if events == nil {
			return nil, fmt.Errorf("%w: slot %d has a nil Events channel", ErrInvalidFixedBindingManager, index)
		}
		if _, exists := seenEvents[events]; exists {
			return nil, fmt.Errorf("%w: duplicate Events channel identity", ErrInvalidFixedBindingManager)
		}
		seenEvents[events] = struct{}{}
		capacity := configured.Link.SubmissionReady()
		if capacity == nil {
			return nil, fmt.Errorf("%w: slot %d has a nil SubmissionReady channel", ErrInvalidFixedBindingManager, index)
		}
		if _, exists := seenCapacity[capacity]; exists {
			return nil, fmt.Errorf("%w: duplicate SubmissionReady channel identity", ErrInvalidFixedBindingManager)
		}
		seenCapacity[capacity] = struct{}{}
		slot := &fixedBindingSlot{
			dcID:         configured.DCID,
			sourceIP:     configured.SourceIP.Unmap(),
			link:         configured.Link,
			events:       events,
			capacity:     capacity,
			requestWake:  make(chan struct{}, 1),
			bindings:     make(map[*clientBinding]struct{}),
			consumerDone: make(chan struct{}),
		}
		if manager.slots[configured.DCID] == nil {
			manager.slots[configured.DCID] = slot
		}
		manager.slotGroups[configured.DCID] = append(manager.slotGroups[configured.DCID], slot)
		manager.order = append(manager.order, slot)
	}
	manager.repairContext, manager.cancelRepairs = context.WithCancelCause(context.Background())
	return &FixedBindingManager{state: manager}, nil
}

func validateFixedBindingControlReserve(limits FixedBindingLimits, slotCount int) error {
	minimumPerSlotItems := 2
	minimumPerSlotBytes := KeepalivePayloadSize + ClosePayloadSize
	minimumGlobalItems := slotCount + 1
	minimumGlobalBytes := slotCount*KeepalivePayloadSize + ClosePayloadSize
	if limits.MaxPendingControlItemsPerSlot < minimumPerSlotItems ||
		limits.MaxPendingControlBytesPerSlot < minimumPerSlotBytes ||
		limits.MaxPendingControlItems < minimumGlobalItems ||
		limits.MaxPendingControlBytes < minimumGlobalBytes {
		return fmt.Errorf(
			"%w: control limits must reserve one liveness probe per slot and one close (need slot %d items/%d bytes, global %d items/%d bytes)",
			ErrInvalidFixedBindingManager,
			minimumPerSlotItems,
			minimumPerSlotBytes,
			minimumGlobalItems,
			minimumGlobalBytes,
		)
	}
	return nil
}

func nilClientLink(link ClientLink) bool {
	if link == nil {
		return true
	}
	value := reflect.ValueOf(link)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// String redacts links, queues, and retained response packets.
func (FixedBindingManager) String() string {
	return "middleend.FixedBindingManager{redacted}"
}

// GoString redacts links, queues, and retained response packets.
func (FixedBindingManager) GoString() string {
	return "middleend.FixedBindingManager{redacted}"
}

// String reports only the fixed signed DC and connection identity.
func (b ClientBinding) String() string {
	if b.state == nil || b.state.slot == nil {
		return "middleend.ClientBinding{redacted}"
	}
	return fmt.Sprintf("middleend.ClientBinding{DCID:%d, ConnectionID:%d, state:<redacted>}", b.state.slot.dcID, b.state.connectionID)
}

// GoString reports only the fixed signed DC and connection identity.
func (b ClientBinding) GoString() string {
	return b.String()
}

// Start starts exactly one Events consumer per link, then starts all fixed
// links concurrently. Concurrent calls share one result. A successful call
// does not retain ctx.
func (m *FixedBindingManager) Start(ctx context.Context) error {
	if m == nil || m.state == nil {
		return ErrFixedBindingManagerClosed
	}
	return m.state.start(ctx)
}

func (m *fixedBindingManager) start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil start context", ErrInvalidFixedBindingManager)
	}

	m.mu.Lock()
	switch m.state {
	case fixedBindingManagerCreated:
		m.state = fixedBindingManagerStarting
		m.mu.Unlock()
		return m.startFirst(ctx)
	case fixedBindingManagerStarting:
		startDone := m.startDone
		m.mu.Unlock()
		<-startDone
		return m.waitStartResult()
	case fixedBindingManagerReady:
		result := m.startResult
		m.mu.Unlock()
		return result
	case fixedBindingManagerClosing, fixedBindingManagerClosed:
		startDone := m.startDone
		m.mu.Unlock()
		<-startDone
		return m.waitStartResult()
	default:
		m.mu.Unlock()
		return ErrFixedBindingManagerClosed
	}
}

func (m *fixedBindingManager) startFirst(ctx context.Context) error {
	m.ensureConsumers()
	m.mu.Lock()
	starting := m.state == fixedBindingManagerStarting
	m.mu.Unlock()
	if !starting {
		<-m.done
		return m.waitStartResult()
	}

	results := make([]error, len(m.order))
	var starts sync.WaitGroup
	for index, slot := range m.order {
		starts.Go(func() {
			results[index] = slot.link.Start(ctx)
		})
	}
	starts.Wait()
	for index, err := range results {
		if err == nil {
			continue
		}
		m.beginTerminal(fmt.Errorf("%w: DC %d: %w", ErrFixedBindingInitialFailure, m.order[index].dcID, err))
		<-m.done
		return m.waitStartResult()
	}

	m.mu.Lock()
	if m.state == fixedBindingManagerStarting {
		m.state = fixedBindingManagerReady
		m.publishStartLocked(nil)
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	<-m.done
	return m.waitStartResult()
}

func (m *fixedBindingManager) waitStartResult() error {
	m.mu.Lock()
	result := m.startResult
	m.mu.Unlock()
	if result != nil {
		<-m.done
	}
	return result
}

func (m *fixedBindingManager) publishStartLocked(result error) {
	if m.startSet {
		return
	}
	m.startResult = result
	m.startSet = true
	close(m.startDone)
}

func (m *fixedBindingManager) ensureConsumers() {
	m.consumersOnce.Do(func() {
		for _, slot := range m.order {
			m.consumers.Go(func() {
				m.consumeSlot(slot)
			})
		}
	})
}

// DCIDs returns the complete sorted set of exact signed DCIDs owned by the
// manager. The returned slice does not alias manager state.
func (m *FixedBindingManager) DCIDs() []DCID {
	if m == nil || m.state == nil {
		return nil
	}
	m.state.mu.Lock()
	dcIDs := make([]DCID, 0, len(m.state.slotGroups))
	for dcID := range m.state.slotGroups {
		dcIDs = append(dcIDs, dcID)
	}
	m.state.mu.Unlock()
	slices.Sort(dcIDs)
	return dcIDs
}

// Snapshot returns current manager, queue, binding, and physical-link state.
// It never exposes payloads, endpoints, credentials, or connection IDs.
func (m *FixedBindingManager) Snapshot() FixedBindingManagerSnapshot {
	if m == nil || m.state == nil {
		return FixedBindingManagerSnapshot{Closed: true}
	}
	state := m.state
	state.mu.Lock()
	snapshot := FixedBindingManagerSnapshot{
		Ready:                       state.state == fixedBindingManagerReady,
		Accepting:                   state.accepting,
		Closed:                      state.state == fixedBindingManagerClosing || state.state == fixedBindingManagerClosed,
		ResidentBindings:            state.residentBindings,
		RequestItems:                state.requestItems,
		RequestBytes:                state.requestBytes,
		ControlItems:                state.controlItems,
		ControlBytes:                state.controlBytes,
		ResponseItems:               state.pending,
		ResponseBytes:               state.pendingBytes,
		RequestItemsHighWater:       state.requestItemsHighWater,
		RequestBytesHighWater:       state.requestBytesHighWater,
		ControlItemsHighWater:       state.controlItemsHighWater,
		ControlBytesHighWater:       state.controlBytesHighWater,
		ResponseItemsHighWater:      state.responseItemsHighWater,
		ResponseBytesHighWater:      state.responseBytesHighWater,
		ResponseBackpressureEvents:  state.responseBackpressureEvents,
		ControlBackpressureEvents:   state.controlBackpressureEvents,
		SlotFailures:                state.slotFailures,
		SlotFailureAffectedBindings: state.slotFailureAffectedBindings,
		LastSlotFailure:             state.lastSlotFailure,
		SlotRepairSuccesses:         state.slotRepairSuccesses,
		SlotRepairFailures:          state.slotRepairFailures,
		Slots:                       make([]FixedBindingSlotSnapshot, len(state.order)),
	}
	links := make([]ClientLink, len(state.order))
	for index, slot := range state.order {
		snapshot.Slots[index] = FixedBindingSlotSnapshot{
			DCID:                   slot.dcID,
			Failed:                 slot.failed,
			Repairing:              slot.repairing,
			ResidentBindings:       slot.resident,
			RequestItems:           slot.requestItems,
			RequestBytes:           slot.requestBytes,
			ControlItems:           slot.controlItems,
			ControlBytes:           slot.controlBytes,
			ResponseItems:          slot.pending,
			ResponseBytes:          slot.bytes,
			RequestItemsHighWater:  slot.requestItemsHighWater,
			RequestBytesHighWater:  slot.requestBytesHighWater,
			ControlItemsHighWater:  slot.controlItemsHighWater,
			ControlBytesHighWater:  slot.controlBytesHighWater,
			ResponseItemsHighWater: slot.responseItemsHighWater,
			ResponseBytesHighWater: slot.responseBytesHighWater,
		}
		if slot.repairing {
			snapshot.RepairingSlots++
		}
		links[index] = slot.link
	}
	state.mu.Unlock()
	for index, link := range links {
		snapshot.Slots[index].Link = link.Snapshot()
	}
	return snapshot
}

// Quiesce permanently stops new Bind admission and returns a stable channel
// that closes when every binding resident at the admission boundary has left
// the manager. Existing bindings, probes, and link consumers remain active.
// Quiesce is concurrent and idempotent and may be called before Start.
func (m *FixedBindingManager) Quiesce() <-chan struct{} {
	if m == nil || m.state == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	m.state.mu.Lock()
	m.state.accepting = false
	m.state.publishDrainedLocked()
	drained := m.state.drained
	m.state.mu.Unlock()
	return drained
}

// Bind creates a positive process-unique connection identity fixed to one
// healthy link in the exact signed DC pool. Selection prefers the least-loaded
// eligible link and rotates deterministic ties. A returned binding never moves.
func (m *FixedBindingManager) Bind(dcID DCID) (*ClientBinding, error) {
	if m == nil || m.state == nil {
		return nil, ErrFixedBindingManagerClosed
	}
	return m.state.bind(dcID, fixedBindingConsumerUnset)
}

// BindReady creates the same sticky binding as Bind and selects
// ClientReadyToken as its exclusive response consumer. Manager shutdown keeps
// a payload-free terminal token available after the resident binding and its
// physical link resources have been released.
func (m *FixedBindingManager) BindReady(dcID DCID) (*ClientBinding, error) {
	if m == nil || m.state == nil {
		return nil, ErrFixedBindingManagerClosed
	}
	return m.state.bind(dcID, fixedBindingConsumerToken)
}

func (m *fixedBindingManager) bind(dcID DCID, consumerMode fixedBindingConsumerMode) (*ClientBinding, error) {
	m.mu.Lock()
	switch m.state {
	case fixedBindingManagerCreated, fixedBindingManagerStarting:
		m.mu.Unlock()
		return nil, ErrFixedBindingManagerNotStarted
	case fixedBindingManagerClosing, fixedBindingManagerClosed:
		err := m.closedWorkErrorLocked()
		m.mu.Unlock()
		return nil, err
	case fixedBindingManagerReady:
	}
	if !m.accepting {
		m.mu.Unlock()
		return nil, ErrFixedBindingManagerQuiesced
	}
	if fixedBindingSubmissionIDs.Load() == math.MaxUint64 {
		m.mu.Unlock()
		m.exhaustSubmissionIDs()
		return nil, ErrFixedBindingSubmissionIDExhausted
	}
	group, exists := m.slotGroups[dcID]
	if !exists {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: signed DCID %d", ErrFixedBindingUnknownDC, dcID)
	}
	if m.residentBindings >= m.limits.MaxResidentBindings {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: global", ErrFixedBindingLimit)
	}
	slot, healthy := m.selectBindingSlotLocked(dcID, group)
	if slot == nil && !healthy {
		err := firstSlotFailure(group)
		m.mu.Unlock()
		return nil, err
	}
	if slot == nil {
		m.mu.Unlock()
		return nil, fmt.Errorf("%w: every link for DC %d", ErrFixedBindingLimit, dcID)
	}
	connectionID, err := allocateFixedBindingConnectionID()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	state := &clientBinding{
		manager:      m,
		slot:         slot,
		sourceIP:     slot.sourceIP,
		connectionID: connectionID,
		consumerMode: consumerMode,
		notify:       make(chan struct{}, 1),
		resident:     true,
		active:       true,
		closeDone:    make(chan struct{}),
	}
	m.byID[connectionID] = state
	slot.bindings[state] = struct{}{}
	slot.resident++
	m.residentBindings++
	m.mu.Unlock()
	return &ClientBinding{state: state}, nil
}

func (m *fixedBindingManager) selectBindingSlotLocked(dcID DCID, group []*fixedBindingSlot) (*fixedBindingSlot, bool) {
	start := m.bindNext[dcID] % len(group)
	var selected *fixedBindingSlot
	selectedIndex := -1
	healthy := false
	for offset := range len(group) {
		index := (start + offset) % len(group)
		candidate := group[index]
		if candidate.failed {
			continue
		}
		healthy = true
		if candidate.resident >= m.limits.MaxResidentBindingsPerSlot {
			continue
		}
		if selected == nil || lessLoadedFixedBindingSlot(candidate, selected) {
			selected = candidate
			selectedIndex = index
		}
	}
	if selected != nil {
		m.bindNext[dcID] = (selectedIndex + 1) % len(group)
	}
	return selected, healthy
}

func lessLoadedFixedBindingSlot(left, right *fixedBindingSlot) bool {
	if left.resident != right.resident {
		return left.resident < right.resident
	}
	leftItems := left.requestItems + left.controlItems + left.pending
	rightItems := right.requestItems + right.controlItems + right.pending
	if leftItems != rightItems {
		return leftItems < rightItems
	}
	leftBytes := left.requestBytes + left.controlBytes + left.bytes
	rightBytes := right.requestBytes + right.controlBytes + right.bytes
	return leftBytes < rightBytes
}

func firstSlotFailure(group []*fixedBindingSlot) error {
	for _, slot := range group {
		if slot.err != nil {
			return slot.err
		}
	}
	return ErrFixedBindingSlotFailed
}

// Probe submits one manager-owned RPC ping to every link in the exact signed DC
// pool and waits for every matching pong. At most one probe may wait on each
// link. Probes use the manager's bounded control FIFOs, so they never bypass an
// earlier request or CloseConnection. The caller supplies every deadline;
// Probe creates no timer and performs no retry. Errors are returned in stable
// slot order after every concurrent probe has stopped.
func (m *FixedBindingManager) Probe(ctx context.Context, dcID DCID) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil probe context", ErrInvalidFixedBindingManager)
	}
	if cause := context.Cause(ctx); cause != nil {
		return fmt.Errorf("probe fixed-binding DC %d: %w", dcID, cause)
	}
	if m == nil || m.state == nil {
		return ErrFixedBindingManagerClosed
	}
	return m.state.probeDC(ctx, dcID)
}

func (m *fixedBindingManager) probeDC(ctx context.Context, dcID DCID) error {
	m.mu.Lock()
	switch m.state {
	case fixedBindingManagerCreated, fixedBindingManagerStarting:
		m.mu.Unlock()
		return ErrFixedBindingManagerNotStarted
	case fixedBindingManagerClosing, fixedBindingManagerClosed:
		err := m.closedWorkErrorLocked()
		m.mu.Unlock()
		return err
	case fixedBindingManagerReady:
	}
	group, exists := m.slotGroups[dcID]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("%w: signed DCID %d", ErrFixedBindingUnknownDC, dcID)
	}
	group = slices.Clone(group)
	m.mu.Unlock()

	results := make([]error, len(group))
	var probes sync.WaitGroup
	for index, slot := range group {
		probes.Go(func() {
			results[index] = m.probeSlot(ctx, dcID, slot)
		})
	}
	probes.Wait()
	for _, err := range results {
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *fixedBindingManager) probeSlot(ctx context.Context, dcID DCID, slot *fixedBindingSlot) error {
	m.mu.Lock()
	if m.state == fixedBindingManagerClosing || m.state == fixedBindingManagerClosed {
		err := m.closedWorkErrorLocked()
		m.mu.Unlock()
		return err
	}
	if slot.failed {
		err := slot.err
		m.mu.Unlock()
		return err
	}
	if slot.probe != nil {
		m.mu.Unlock()
		return fmt.Errorf("%w: DC %d", ErrFixedBindingProbePending, dcID)
	}
	if slot.controlItems >= m.limits.MaxPendingControlItemsPerSlot ||
		KeepalivePayloadSize > m.limits.MaxPendingControlBytesPerSlot-slot.controlBytes ||
		m.controlItems >= m.limits.MaxPendingControlItems ||
		KeepalivePayloadSize > m.limits.MaxPendingControlBytes-m.controlBytes {
		m.mu.Unlock()
		return fmt.Errorf("%w: DC %d", ErrFixedBindingControlBackpressure, dcID)
	}
	pingID, err := m.allocateProbeIDLocked()
	if err != nil {
		m.mu.Unlock()
		m.beginTerminal(err)
		return err
	}
	submissionID, err := allocateFixedBindingSubmissionID()
	if err != nil {
		m.mu.Unlock()
		m.exhaustSubmissionIDs()
		return err
	}
	payload := (Ping{ID: pingID}).MarshalBinary()
	if len(payload) != KeepalivePayloadSize {
		clear(payload)
		m.mu.Unlock()
		err := fmt.Errorf("%w: ping payload size %d", ErrFixedBindingProtocol, len(payload))
		m.beginTerminal(err)
		return err
	}
	payload = payload[:len(payload):len(payload)]
	probe := &fixedBindingProbe{slot: slot, id: pingID, done: make(chan struct{})}
	item := &outboundItem{
		kind:  outboundProbe,
		probe: probe,
		submission: LinkSubmission{
			SubmissionID: submissionID,
			Payload:      payload,
		},
	}
	probe.outbound = item
	slot.probe = probe
	wasEmpty := slot.outHead == nil
	m.appendOutboundLocked(slot, item)
	slot.controlItems++
	slot.controlBytes += len(payload)
	m.controlItems++
	m.controlBytes += len(payload)
	m.recordControlHighWaterLocked(slot)
	if wasEmpty {
		m.signalSlotLocked(slot)
	}
	m.mu.Unlock()

	select {
	case <-probe.done:
		return m.probeResult(probe)
	case <-ctx.Done():
		probeErr := m.cancelProbe(probe, fmt.Errorf("probe fixed-binding DC %d: %w", dcID, context.Cause(ctx)))
		if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			m.failSlot(slot, probeErr, FixedBindingSlotFailureProbeTimeout)
		}
		return probeErr
	}
}

func (m *fixedBindingManager) allocateProbeIDLocked() (uint64, error) {
	if m.probeID == math.MaxUint64 {
		return 0, ErrFixedBindingProbeIDExhausted
	}
	m.probeID++
	return m.probeID, nil
}

func (m *fixedBindingManager) probeResult(probe *fixedBindingProbe) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return probe.result
}

func (m *fixedBindingManager) canRepairSlots() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state == fixedBindingManagerReady && m.repairLink != nil
}

func (m *fixedBindingManager) slotRepairCounts() (successes, failures uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.slotRepairSuccesses, m.slotRepairFailures
}

func (m *fixedBindingManager) repairFailedSlots(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil repair context", ErrFixedBindingSlotRepair)
	}
	if cause := context.Cause(ctx); cause != nil {
		return fmt.Errorf("%w: %w", ErrFixedBindingSlotRepair, cause)
	}
	repairContext, cancelRepair := context.WithCancelCause(ctx)
	stopManagerCancel := context.AfterFunc(m.repairContext, func() {
		cancelRepair(context.Cause(m.repairContext))
	})
	defer func() {
		stopManagerCancel()
		cancelRepair(nil)
	}()
	m.mu.Lock()
	if m.state != fixedBindingManagerReady {
		err := m.closedWorkErrorLocked()
		m.mu.Unlock()
		return fmt.Errorf("%w: %w", ErrFixedBindingSlotRepair, err)
	}
	if m.repairLink == nil {
		m.mu.Unlock()
		return fmt.Errorf("%w: no replacement factory", ErrFixedBindingSlotRepair)
	}
	targets := make([]*fixedBindingSlot, 0, len(m.order))
	failedSlots := 0
	for _, slot := range m.order {
		if !slot.failed {
			continue
		}
		failedSlots++
		if slot.repairing {
			continue
		}
		slot.repairing = true
		targets = append(targets, slot)
	}
	if len(targets) == 0 {
		m.mu.Unlock()
		if failedSlots == 0 {
			return nil
		}
		return fmt.Errorf("%w: replacement already in progress", ErrFixedBindingSlotRepair)
	}
	m.operations.Add(len(targets))
	m.mu.Unlock()

	results := make([]error, len(targets))
	var repairs sync.WaitGroup
	for index, slot := range targets {
		repairs.Go(func() {
			defer m.operations.Done()
			results[index] = m.repairSlot(repairContext, slot)
		})
	}
	repairs.Wait()
	return errors.Join(results...)
}

func (m *fixedBindingManager) repairSlot(ctx context.Context, slot *fixedBindingSlot) (result error) {
	repaired := false
	defer func() {
		if !repaired {
			m.finishSlotRepairFailure(slot)
		}
	}()

	select {
	case <-slot.consumerDone:
	case <-ctx.Done():
		return fmt.Errorf("%w: DC %d wait for failed consumer: %w", ErrFixedBindingSlotRepair, slot.dcID, context.Cause(ctx))
	}

	replacement, err := m.repairLink(ctx, slot.dcID)
	if err != nil {
		return fmt.Errorf("%w: DC %d construct replacement: %w", ErrFixedBindingSlotRepair, slot.dcID, err)
	}
	link := replacement.Link
	if nilClientLink(link) {
		return fmt.Errorf("%w: DC %d replacement factory returned a nil link", ErrFixedBindingSlotRepair, slot.dcID)
	}
	if replacement.DCID != slot.dcID {
		_ = link.Close()
		return fmt.Errorf("%w: DC %d replacement returned signed DC %d", ErrFixedBindingSlotRepair, slot.dcID, replacement.DCID)
	}
	replacement.SourceIP = replacement.SourceIP.Unmap()
	if err := validatePublicEndpoint("replacement source", netip.AddrPortFrom(replacement.SourceIP, 1)); err != nil {
		_ = link.Close()
		return fmt.Errorf("%w: DC %d replacement source IP: %v", ErrFixedBindingSlotRepair, slot.dcID, err)
	}
	events := link.Events()
	capacity := link.SubmissionReady()
	if events == nil || capacity == nil {
		_ = link.Close()
		return fmt.Errorf("%w: DC %d replacement has a nil notification channel", ErrFixedBindingSlotRepair, slot.dcID)
	}
	if err := link.Start(ctx); err != nil {
		_ = link.Close()
		return fmt.Errorf("%w: DC %d start replacement: %w", ErrFixedBindingSlotRepair, slot.dcID, err)
	}
	select {
	case <-link.Done():
		err := link.Err()
		if err == nil {
			err = ErrLinkClosed
		}
		_ = link.Close()
		return fmt.Errorf("%w: DC %d replacement closed before publication: %w", ErrFixedBindingSlotRepair, slot.dcID, err)
	default:
	}

	m.mu.Lock()
	if m.state != fixedBindingManagerReady || !slot.failed || !slot.repairing {
		m.mu.Unlock()
		_ = link.Close()
		return fmt.Errorf("%w: DC %d manager changed during replacement", ErrFixedBindingSlotRepair, slot.dcID)
	}
	if events == slot.events || capacity == slot.capacity {
		m.mu.Unlock()
		_ = link.Close()
		return fmt.Errorf("%w: DC %d replacement reused a failed notification channel", ErrFixedBindingSlotRepair, slot.dcID)
	}
	for _, other := range m.order {
		if other == slot {
			continue
		}
		if events == other.events || capacity == other.capacity {
			m.mu.Unlock()
			_ = link.Close()
			return fmt.Errorf("%w: DC %d replacement duplicated another slot notification channel", ErrFixedBindingSlotRepair, slot.dcID)
		}
	}
	if slot.outHead != nil || slot.requestItems != 0 || slot.requestBytes != 0 ||
		slot.controlItems != 0 || slot.controlBytes != 0 || slot.probe != nil {
		m.mu.Unlock()
		_ = link.Close()
		return fmt.Errorf("%w: DC %d failed slot retained outbound work", ErrFixedBindingSlotRepair, slot.dcID)
	}
	slot.link = link
	slot.sourceIP = replacement.SourceIP
	slot.events = events
	slot.capacity = capacity
	slot.requestWake = make(chan struct{}, 1)
	slot.failed = false
	slot.repairing = false
	slot.err = nil
	slot.consumerDone = make(chan struct{})
	m.slotRepairSuccesses++
	m.consumers.Go(func() { m.consumeSlot(slot) })
	m.mu.Unlock()
	repaired = true
	return nil
}

func (m *fixedBindingManager) finishSlotRepairFailure(slot *fixedBindingSlot) {
	m.mu.Lock()
	if m.state == fixedBindingManagerReady && slot.failed && slot.repairing {
		slot.repairing = false
		m.slotRepairFailures++
	}
	m.mu.Unlock()
}

func (m *fixedBindingManager) cancelProbe(probe *fixedBindingProbe, cause error) error {
	m.mu.Lock()
	m.completeProbeLocked(probe, cause)
	result := probe.result
	m.mu.Unlock()
	return result
}

func (m *fixedBindingManager) completeProbeLocked(probe *fixedBindingProbe, result error) {
	if probe == nil || probe.complete {
		return
	}
	probe.complete = true
	probe.result = result
	if probe.slot.probe == probe {
		probe.slot.probe = nil
	}
	item := probe.outbound
	if item != nil {
		item.canceled = true
		if !item.attempting {
			wasHead := probe.slot.outHead == item
			m.removeOutboundLocked(probe.slot, item)
			m.releaseControlLocked(probe.slot, item)
			clear(item.submission.Payload)
			item.submission = LinkSubmission{}
			probe.outbound = nil
			if wasHead {
				m.signalSlotLocked(probe.slot)
			}
		}
	}
	close(probe.done)
}

// ConnectionID returns the positive process-lifetime identity of the binding.
func (b *ClientBinding) ConnectionID() int64 {
	if b == nil || b.state == nil {
		return 0
	}
	return b.state.connectionID
}

// DCID returns the exact signed slot selected at Bind time.
func (b *ClientBinding) DCID() DCID {
	if b == nil || b.state == nil || b.state.slot == nil {
		return 0
	}
	return b.state.slot.dcID
}

// SourceIP returns the authoritative public source IP selected for the fixed
// physical link. It returns an invalid address when a manager-only caller did
// not configure source metadata.
func (b *ClientBinding) SourceIP() netip.Addr {
	if b == nil || b.state == nil {
		return netip.Addr{}
	}
	return b.state.sourceIP
}

// PrepareProxyRequest validates one frontend request without request-sized
// allocation. It either marshals the request once into the fixed slot FIFO or
// registers one payload-free capacity waiter. Each call is a new request; a
// binding cannot prepare another until it consumes the stored result.
func (b *ClientBinding) PrepareProxyRequest(request ProxyRequest) (PrepareProxyRequestStatus, error) {
	if b == nil || b.state == nil {
		return 0, ErrClientBindingClosed
	}
	return b.state.prepareProxyRequest(request)
}

func (b *clientBinding) prepareProxyRequest(request ProxyRequest) (PrepareProxyRequestStatus, error) {
	size, fingerprint, err := proxyRequestIdentity(request)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrFixedBindingRequestRejected, err)
	}
	m := b.manager
	m.mu.Lock()
	if m.state != fixedBindingManagerReady || !b.active || b.slot.failed {
		err := b.workErrorLocked()
		m.mu.Unlock()
		return 0, err
	}
	if b.request != nil || b.result != nil {
		m.mu.Unlock()
		return 0, fmt.Errorf("%w: binding %d", ErrFixedBindingRequestPending, b.connectionID)
	}
	if size > m.limits.MaxPendingRequestBytesPerBinding ||
		size > m.limits.MaxPendingRequestBytesPerSlot || size > m.limits.MaxPendingRequestBytes {
		m.mu.Unlock()
		return 0, fmt.Errorf("%w: encoded request size %d exceeds retained limit", ErrFixedBindingRequestRejected, size)
	}
	requestState := &preparedRequest{binding: b, size: size, fingerprint: fingerprint}
	item := &outboundItem{kind: outboundRequest, request: requestState, binding: b}
	requestState.outbound = item
	b.request = requestState
	m.appendOutboundLocked(b.slot, item)

	if item == b.slot.outHead && !m.hasWaitersLocked() && m.canReserveRequestLocked(b.slot, size) {
		if err := m.reserveRequestLocked(requestState); err != nil {
			m.removeOutboundLocked(b.slot, item)
			b.request = nil
			m.mu.Unlock()
			m.terminalizeBinding(b, err)
			return 0, err
		}
		m.claimMaterializationLocked(requestState)
		m.mu.Unlock()
		if err := b.materializePreparedRequest(requestState, request); err != nil {
			return 0, err
		}
		return PrepareProxyRequestQueued, nil
	}
	ticket, err := m.allocateWaitTicketLocked()
	if err != nil {
		m.removeOutboundLocked(b.slot, item)
		b.request = nil
		m.mu.Unlock()
		m.beginTerminal(err)
		return 0, err
	}
	requestState.phase = preparedRequestWaiting
	requestState.ticket = ticket
	m.appendWaitLocked(b.slot, requestState)
	m.promoteRequestsLocked()
	m.mu.Unlock()
	return PrepareProxyRequestWaiting, nil
}

func proxyRequestEncodedSize(request ProxyRequest) (int, error) {
	hasTag := request.Tag != nil
	if err := validateProxyRequestFlags(request.Flags, hasTag); err != nil {
		return 0, err
	}
	if err := validateProxyPacket(request.Packet, request.Flags); err != nil {
		return 0, err
	}
	if err := validateProxyAddress(request.RemoteAddr, true); err != nil {
		return 0, fmt.Errorf("encode remote address: %w", err)
	}
	if err := validateProxyAddress(request.ProxyAddr, false); err != nil {
		return 0, fmt.Errorf("encode proxy address: %w", err)
	}
	headerSize := ProxyRequestBaseSize
	if hasTag {
		headerSize = ProxyRequestTaggedHeaderSize
	}
	return headerSize + len(request.Packet), nil
}

func proxyRequestIdentity(request ProxyRequest) (int, [sha256.Size]byte, error) {
	size, err := proxyRequestEncodedSize(request)
	if err != nil {
		return 0, [sha256.Size]byte{}, err
	}
	var canonical [4 + 20 + 20 + 1 + len(ProxyTag{}) + sha256.Size]byte
	binary.LittleEndian.PutUint32(canonical[0:4], uint32(request.Flags))
	if err := putProxyAddress(canonical[4:24], request.RemoteAddr, true); err != nil {
		return 0, [sha256.Size]byte{}, fmt.Errorf("encode remote address: %w", err)
	}
	if err := putProxyAddress(canonical[24:44], request.ProxyAddr, false); err != nil {
		return 0, [sha256.Size]byte{}, fmt.Errorf("encode proxy address: %w", err)
	}
	if request.Tag != nil {
		canonical[44] = 1
		copy(canonical[45:61], request.Tag[:])
	}
	packetDigest := sha256.Sum256(request.Packet)
	copy(canonical[61:], packetDigest[:])
	return size, sha256.Sum256(canonical[:]), nil
}

func (m *fixedBindingManager) canReserveRequestLocked(slot *fixedBindingSlot, size int) bool {
	return slot.requestItems < m.limits.MaxPendingRequestItemsPerSlot &&
		size <= m.limits.MaxPendingRequestBytesPerSlot-slot.requestBytes &&
		m.requestItems < m.limits.MaxPendingRequestItems &&
		size <= m.limits.MaxPendingRequestBytes-m.requestBytes
}

func (m *fixedBindingManager) reserveRequestLocked(request *preparedRequest) error {
	if request.binding.reservationEpoch == math.MaxUint64 {
		return ErrFixedBindingEpochExhausted
	}
	request.binding.reservationEpoch++
	request.epoch = request.binding.reservationEpoch
	request.phase = preparedRequestReserved
	request.binding.slot.requestItems++
	request.binding.slot.requestBytes += request.size
	m.requestItems++
	m.requestBytes += request.size
	m.recordRequestHighWaterLocked(request.binding.slot)
	return nil
}

func (b *clientBinding) materializePreparedRequest(state *preparedRequest, request ProxyRequest) error {
	m := b.manager
	defer func() {
		b.ops.Done()
		m.operations.Done()
	}()
	if hook := m.materializeHookForTest; hook != nil {
		hook()
	}
	submissionID, err := allocateFixedBindingSubmissionID()
	if err != nil {
		m.mu.Lock()
		m.finishMaterializationFailureLocked(state)
		m.mu.Unlock()
		m.exhaustSubmissionIDs()
		return err
	}
	request.ConnectionID = b.connectionID
	payload, marshalErr := request.MarshalBinary()
	if marshalErr != nil {
		m.mu.Lock()
		m.finishMaterializationFailureLocked(state)
		m.mu.Unlock()
		m.terminalizeBinding(b, marshalErr)
		return fmt.Errorf("%w: %v", ErrFixedBindingRequestRejected, marshalErr)
	}
	payload = payload[:len(payload):len(payload)]

	m.mu.Lock()
	if m.state != fixedBindingManagerReady || b.request != state || state.canceled || state.phase != preparedRequestMaterializing {
		clear(payload)
		m.finishMaterializationFailureLocked(state)
		err := b.workErrorLocked()
		m.mu.Unlock()
		return err
	}
	state.submission = LinkSubmission{SubmissionID: submissionID, ConnectionID: b.connectionID, Payload: payload}
	state.phase = preparedRequestMaterialized
	state.handed = true
	if b.slot.outHead == state.outbound {
		m.signalSlotLocked(b.slot)
	}
	m.mu.Unlock()
	return nil
}

func (m *fixedBindingManager) claimMaterializationLocked(request *preparedRequest) {
	request.phase = preparedRequestMaterializing
	request.binding.ops.Add(1)
	m.operations.Add(1)
}

func (m *fixedBindingManager) finishMaterializationFailureLocked(request *preparedRequest) {
	if request.phase == preparedRequestMaterializing {
		m.releaseRequestChargeLocked(request)
	}
	wasHead := request.binding.slot.outHead == request.outbound
	if request.outbound != nil && !request.outbound.attempting {
		m.removeOutboundLocked(request.binding.slot, request.outbound)
	}
	clear(request.submission.Payload)
	request.submission = LinkSubmission{}
	request.canceled = true
	if request.binding.request == request {
		request.binding.request = nil
	}
	m.promoteRequestsLocked()
	if wasHead {
		m.signalSlotLocked(request.binding.slot)
	}
}

func (b *clientBinding) workErrorLocked() error {
	if b.terminalErr != nil {
		return b.terminalErr
	}
	if b.slot.failed {
		return b.slot.err
	}
	if b.manager.terminalErr != nil {
		return b.manager.terminalErr
	}
	if b.manager.state == fixedBindingManagerCreated || b.manager.state == fixedBindingManagerStarting {
		return ErrFixedBindingManagerNotStarted
	}
	if b.manager.state != fixedBindingManagerReady {
		return ErrFixedBindingManagerClosed
	}
	return ErrClientBindingClosed
}

func (m *fixedBindingManager) closedWorkErrorLocked() error {
	if m.terminalErr != nil {
		return m.terminalErr
	}
	return ErrFixedBindingManagerClosed
}

func (m *fixedBindingManager) allocateWaitTicketLocked() (uint64, error) {
	if m.waitTicket == math.MaxUint64 {
		return 0, ErrFixedBindingWaitTicketExhausted
	}
	m.waitTicket++
	return m.waitTicket, nil
}

func (m *fixedBindingManager) appendWaitLocked(slot *fixedBindingSlot, request *preparedRequest) {
	request.waitPrev = slot.waitTail
	if slot.waitTail == nil {
		slot.waitHead = request
	} else {
		slot.waitTail.waitNext = request
	}
	slot.waitTail = request
}

func (m *fixedBindingManager) removeWaitLocked(slot *fixedBindingSlot, request *preparedRequest) {
	if request.phase != preparedRequestWaiting {
		return
	}
	if request.waitPrev == nil {
		slot.waitHead = request.waitNext
	} else {
		request.waitPrev.waitNext = request.waitNext
	}
	if request.waitNext == nil {
		slot.waitTail = request.waitPrev
	} else {
		request.waitNext.waitPrev = request.waitPrev
	}
	request.waitPrev = nil
	request.waitNext = nil
}

func (m *fixedBindingManager) appendOutboundLocked(slot *fixedBindingSlot, item *outboundItem) {
	item.prev = slot.outTail
	if slot.outTail == nil {
		slot.outHead = item
	} else {
		slot.outTail.next = item
	}
	slot.outTail = item
}

func (m *fixedBindingManager) removeOutboundLocked(slot *fixedBindingSlot, item *outboundItem) {
	if item == nil {
		return
	}
	if item.prev == nil {
		if slot.outHead != item {
			return
		}
		slot.outHead = item.next
	} else {
		item.prev.next = item.next
	}
	if item.next == nil {
		if slot.outTail == item {
			slot.outTail = item.prev
		}
	} else {
		item.next.prev = item.prev
	}
	item.prev = nil
	item.next = nil
}

func (m *fixedBindingManager) hasWaitersLocked() bool {
	for _, slot := range m.order {
		if slot.waitHead != nil {
			return true
		}
	}
	return false
}

func (m *fixedBindingManager) promoteRequestsLocked() {
	for m.state == fixedBindingManagerReady {
		var candidate *preparedRequest
		for _, slot := range m.order {
			request := slot.waitHead
			if request == nil {
				continue
			}
			if slot.requestItems >= m.limits.MaxPendingRequestItemsPerSlot ||
				request.size > m.limits.MaxPendingRequestBytesPerSlot-slot.requestBytes {
				continue
			}
			if candidate == nil || request.ticket < candidate.ticket {
				candidate = request
			}
		}
		if candidate == nil {
			return
		}
		if m.requestItems >= m.limits.MaxPendingRequestItems ||
			candidate.size > m.limits.MaxPendingRequestBytes-m.requestBytes {
			return
		}
		m.removeWaitLocked(candidate.binding.slot, candidate)
		if err := m.reserveRequestLocked(candidate); err != nil {
			wasHead := candidate.binding.slot.outHead == candidate.outbound
			m.removeOutboundLocked(candidate.binding.slot, candidate.outbound)
			candidate.canceled = true
			candidate.binding.request = nil
			m.publishBindingTerminalLocked(candidate.binding, err)
			m.detachActiveBindingLocked(candidate.binding)
			if wasHead {
				m.signalSlotLocked(candidate.binding.slot)
			}
			continue
		}
		m.signalBindingLocked(candidate.binding)
	}
}

func (m *fixedBindingManager) releaseRequestChargeLocked(request *preparedRequest) {
	if request.phase != preparedRequestReserved && request.phase != preparedRequestMaterializing &&
		request.phase != preparedRequestMaterialized && request.phase != preparedRequestAttempting {
		return
	}
	slot := request.binding.slot
	slot.requestItems--
	slot.requestBytes -= request.size
	m.requestItems--
	m.requestBytes -= request.size
}

func (m *fixedBindingManager) cancelRequestLocked(request *preparedRequest, removeOutbound bool) {
	if request == nil || request.canceled {
		return
	}
	request.canceled = true
	if request.phase == preparedRequestMaterializing || request.phase == preparedRequestAttempting {
		if request.binding.request == request {
			request.binding.request = nil
		}
		return
	}
	if request.phase == preparedRequestWaiting {
		m.removeWaitLocked(request.binding.slot, request)
	} else {
		m.releaseRequestChargeLocked(request)
	}
	wasHead := request.binding.slot.outHead == request.outbound
	if removeOutbound && !request.outbound.attempting {
		m.removeOutboundLocked(request.binding.slot, request.outbound)
	}
	if !request.outbound.attempting {
		clear(request.submission.Payload)
		request.submission = LinkSubmission{}
	}
	if request.binding.request == request {
		request.binding.request = nil
	}
	m.promoteRequestsLocked()
	if wasHead && removeOutbound {
		m.signalSlotLocked(request.binding.slot)
	}
}

const closeConnectionEncodedSize = ClosePayloadSize

func (m *fixedBindingManager) queueControlLocked(slot *fixedBindingSlot, binding *clientBinding, connectionID int64) error {
	reservedGlobalItems := len(m.order)
	reservedGlobalBytes := len(m.order) * KeepalivePayloadSize
	if slot.controlItems >= m.limits.MaxPendingControlItemsPerSlot-1 ||
		closeConnectionEncodedSize > m.limits.MaxPendingControlBytesPerSlot-KeepalivePayloadSize-slot.controlBytes ||
		m.controlItems >= m.limits.MaxPendingControlItems-reservedGlobalItems ||
		closeConnectionEncodedSize > m.limits.MaxPendingControlBytes-reservedGlobalBytes-m.controlBytes {
		m.controlBackpressureEvents++
		return fmt.Errorf("%w: DC %d", ErrFixedBindingControlBackpressure, slot.dcID)
	}
	submissionID, err := allocateFixedBindingSubmissionID()
	if err != nil {
		return err
	}
	payload := (CloseConnection{ConnectionID: connectionID}).MarshalBinary()
	if len(payload) != closeConnectionEncodedSize {
		clear(payload)
		return fmt.Errorf("%w: close payload size %d", ErrFixedBindingProtocol, len(payload))
	}
	payload = payload[:len(payload):len(payload)]
	item := &outboundItem{
		kind:    outboundControl,
		binding: binding,
		submission: LinkSubmission{
			SubmissionID: submissionID,
			ConnectionID: connectionID,
			Payload:      payload,
		},
	}
	wasEmpty := slot.outHead == nil
	m.appendOutboundLocked(slot, item)
	slot.controlItems++
	slot.controlBytes += len(payload)
	m.controlItems++
	m.controlBytes += len(payload)
	m.recordControlHighWaterLocked(slot)
	if wasEmpty {
		m.signalSlotLocked(slot)
	}
	return nil
}

func (m *fixedBindingManager) recordRequestHighWaterLocked(slot *fixedBindingSlot) {
	slot.requestItemsHighWater = max(slot.requestItemsHighWater, slot.requestItems)
	slot.requestBytesHighWater = max(slot.requestBytesHighWater, slot.requestBytes)
	m.requestItemsHighWater = max(m.requestItemsHighWater, m.requestItems)
	m.requestBytesHighWater = max(m.requestBytesHighWater, m.requestBytes)
}

func (m *fixedBindingManager) recordControlHighWaterLocked(slot *fixedBindingSlot) {
	slot.controlItemsHighWater = max(slot.controlItemsHighWater, slot.controlItems)
	slot.controlBytesHighWater = max(slot.controlBytesHighWater, slot.controlBytes)
	m.controlItemsHighWater = max(m.controlItemsHighWater, m.controlItems)
	m.controlBytesHighWater = max(m.controlBytesHighWater, m.controlBytes)
}

func (m *fixedBindingManager) recordResponseHighWaterLocked(slot *fixedBindingSlot) {
	slot.responseItemsHighWater = max(slot.responseItemsHighWater, slot.pending)
	slot.responseBytesHighWater = max(slot.responseBytesHighWater, slot.bytes)
	m.responseItemsHighWater = max(m.responseItemsHighWater, m.pending)
	m.responseBytesHighWater = max(m.responseBytesHighWater, m.pendingBytes)
}

// Ready returns the stable, coalesced manager readiness channel. It is never
// closed; select it together with Done. It has one consumer and carries no
// request or response payload.
func (m *FixedBindingManager) Ready() <-chan struct{} {
	if m == nil || m.state == nil {
		return nil
	}
	return m.state.ready
}

func (m *FixedBindingManager) hasReady() bool {
	if m == nil || m.state == nil {
		return false
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	return m.state.readyHead != nil
}

// TryNextReady leases the next binding with one or more coalesced reasons.
// The caller must Ack the token after nonblocking reason inspection.
func (m *FixedBindingManager) TryNextReady() *ClientReadyToken {
	if m == nil || m.state == nil {
		return nil
	}
	state := m.state
	state.mu.Lock()
	binding := state.readyHead
	if binding == nil {
		state.mu.Unlock()
		return nil
	}
	state.unlinkReadyLocked(binding)
	if binding.readyEpoch == math.MaxUint64 {
		state.mu.Unlock()
		state.beginTerminal(ErrFixedBindingEpochExhausted)
		return nil
	}
	binding.readyEpoch++
	binding.readyLeased = true
	token := &ClientReadyToken{state: &clientReadyToken{manager: state, binding: binding, epoch: binding.readyEpoch}}
	state.mu.Unlock()
	return token
}

// ConnectionID returns the token's public binding identity.
func (t *ClientReadyToken) ConnectionID() int64 {
	if t == nil || t.state == nil || t.state.binding == nil {
		return 0
	}
	return t.state.binding.connectionID
}

// DCID returns the token's exact signed source slot.
func (t *ClientReadyToken) DCID() DCID {
	if t == nil || t.state == nil || t.state.binding == nil || t.state.binding.slot == nil {
		return 0
	}
	return t.state.binding.slot.dcID
}

func (t *ClientReadyToken) validateLocked() (*fixedBindingManager, *clientBinding, error) {
	if t == nil || t.state == nil || t.state.manager == nil || t.state.binding == nil {
		return nil, nil, ErrFixedBindingReadyToken
	}
	m := t.state.manager
	binding := t.state.binding
	if !binding.readyLeased || binding.readyEpoch != t.state.epoch {
		return m, binding, ErrFixedBindingReadyToken
	}
	return m, binding, nil
}

// TryTakePrepareReservation takes the current payload-free reservation once.
func (t *ClientReadyToken) TryTakePrepareReservation() (*ClientPrepareReservation, bool, error) {
	if t == nil || t.state == nil || t.state.manager == nil {
		return nil, false, ErrFixedBindingReadyToken
	}
	m := t.state.manager
	m.mu.Lock()
	_, binding, err := t.validateLocked()
	if err != nil {
		m.mu.Unlock()
		return nil, false, err
	}
	request := binding.request
	if request == nil || request.phase != preparedRequestReserved || request.handed {
		m.mu.Unlock()
		return nil, false, nil
	}
	request.handed = true
	reservation := &ClientPrepareReservation{state: &clientPrepareReservation{binding: binding, epoch: request.epoch}}
	m.mu.Unlock()
	return reservation, true, nil
}

// PrepareReservedProxyRequest verifies and materializes the exact request for
// a previously taken reservation. A mismatch permanently retires the binding.
func (b *ClientBinding) PrepareReservedProxyRequest(reservation *ClientPrepareReservation, request ProxyRequest) error {
	if b == nil || b.state == nil || reservation == nil || reservation.state == nil {
		return ErrFixedBindingRequestRejected
	}
	if reservation.state.binding != b.state {
		origin := reservation.state.binding
		if origin != nil && origin.manager != nil {
			originManager := origin.manager
			foreignErr := fmt.Errorf("%w: reservation belongs to another binding", ErrFixedBindingRequestRejected)
			originManager.mu.Lock()
			prepared := origin.request
			if prepared != nil && prepared.phase == preparedRequestReserved && prepared.handed &&
				prepared.epoch == reservation.state.epoch {
				originManager.cancelRequestLocked(prepared, true)
				originManager.detachActiveBindingLocked(origin)
				originManager.publishBindingTerminalLocked(origin, foreignErr)
				originManager.releaseTerminalBindingLocked(origin)
			}
			originManager.mu.Unlock()
		}
		return fmt.Errorf("%w: foreign reservation", ErrFixedBindingRequestRejected)
	}
	size, fingerprint, err := proxyRequestIdentity(request)
	if err != nil {
		b.state.manager.terminalizeBinding(b.state, fmt.Errorf("%w: %v", ErrFixedBindingRequestRejected, err))
		return fmt.Errorf("%w: %v", ErrFixedBindingRequestRejected, err)
	}
	state := b.state
	m := state.manager
	m.mu.Lock()
	prepared := state.request
	if prepared == nil || prepared.phase != preparedRequestReserved ||
		!prepared.handed || prepared.epoch != reservation.state.epoch || prepared.size != size || prepared.fingerprint != fingerprint {
		if prepared != nil && prepared.phase == preparedRequestReserved {
			m.cancelRequestLocked(prepared, true)
		}
		m.mu.Unlock()
		err := fmt.Errorf("%w: reservation does not match request", ErrFixedBindingRequestRejected)
		m.terminalizeBinding(state, err)
		return err
	}
	m.claimMaterializationLocked(prepared)
	m.mu.Unlock()
	return state.materializePreparedRequest(prepared, request)
}

// TryTakeRequestResult takes one stored request result exactly once.
func (t *ClientReadyToken) TryTakeRequestResult() (ClientRequestResult, bool, error) {
	if t == nil || t.state == nil || t.state.manager == nil {
		return ClientRequestResult{}, false, ErrFixedBindingReadyToken
	}
	m := t.state.manager
	m.mu.Lock()
	_, binding, err := t.validateLocked()
	if err != nil {
		m.mu.Unlock()
		return ClientRequestResult{}, false, err
	}
	if binding.result == nil {
		m.mu.Unlock()
		return ClientRequestResult{}, false, nil
	}
	result := *binding.result
	binding.result = nil
	m.releaseTerminalBindingLocked(binding)
	m.mu.Unlock()
	return result, true, nil
}

// TryNextEvent takes at most one retained response without blocking.
func (t *ClientReadyToken) TryNextEvent() (LinkEvent, bool, error) {
	if t == nil || t.state == nil || t.state.manager == nil {
		return LinkEvent{}, false, ErrFixedBindingReadyToken
	}
	m := t.state.manager
	m.mu.Lock()
	_, binding, err := t.validateLocked()
	if err != nil {
		m.mu.Unlock()
		return LinkEvent{}, false, err
	}
	if binding.consumerMode == fixedBindingConsumerBlocking {
		m.mu.Unlock()
		return LinkEvent{}, false, ErrFixedBindingConsumerMode
	}
	binding.consumerMode = fixedBindingConsumerToken
	event, ok := m.popBindingEventLocked(binding)
	m.mu.Unlock()
	return event, ok, nil
}

// TryTerminal observes a terminal binding state without blocking, after all
// earlier response, request-result, and reservation reasons are consumed.
func (t *ClientReadyToken) TryTerminal() (error, bool, error) {
	if t == nil || t.state == nil || t.state.manager == nil {
		return nil, false, ErrFixedBindingReadyToken
	}
	m := t.state.manager
	m.mu.Lock()
	_, binding, err := t.validateLocked()
	if err != nil {
		m.mu.Unlock()
		return nil, false, err
	}
	if !binding.terminal {
		m.mu.Unlock()
		return nil, false, nil
	}
	if binding.items != 0 || binding.result != nil || binding.request != nil {
		m.mu.Unlock()
		return nil, false, nil
	}
	binding.terminalObserved = true
	terminalErr := binding.terminalErr
	m.releaseTerminalBindingLocked(binding)
	m.mu.Unlock()
	return terminalErr, true, nil
}

// Ack releases one readiness lease. Remaining reasons are requeued without
// loss. Duplicate, stale, and foreign acknowledgements are rejected.
func (t *ClientReadyToken) Ack() error {
	if t == nil || t.state == nil || t.state.manager == nil {
		return ErrFixedBindingReadyToken
	}
	m := t.state.manager
	m.mu.Lock()
	_, binding, err := t.validateLocked()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	binding.readyLeased = false
	if m.bindingHasReadyReasonLocked(binding) {
		m.enqueueReadyLocked(binding)
	}
	m.releaseTerminalBindingLocked(binding)
	m.mu.Unlock()
	return nil
}

func (m *fixedBindingManager) bindingHasReadyReasonLocked(binding *clientBinding) bool {
	tokenEvents := binding.consumerMode != fixedBindingConsumerBlocking && binding.items > 0
	tokenTerminal := binding.consumerMode != fixedBindingConsumerBlocking && binding.terminal && !binding.terminalObserved
	return tokenEvents || tokenTerminal || binding.result != nil ||
		(binding.request != nil && binding.request.phase == preparedRequestReserved && !binding.request.handed)
}

func (m *fixedBindingManager) refreshReadyLocked(binding *clientBinding) {
	if binding.readyLeased {
		return
	}
	m.unlinkReadyLocked(binding)
	m.enqueueReadyLocked(binding)
}

func (m *fixedBindingManager) enqueueReadyLocked(binding *clientBinding) {
	if binding.readyQueued || binding.readyLeased || !m.bindingHasReadyReasonLocked(binding) {
		return
	}
	binding.readyPrev = m.readyTail
	if m.readyTail == nil {
		m.readyHead = binding
	} else {
		m.readyTail.readyNext = binding
	}
	m.readyTail = binding
	binding.readyQueued = true
	select {
	case m.ready <- struct{}{}:
	default:
	}
}

func (m *fixedBindingManager) unlinkReadyLocked(binding *clientBinding) {
	if !binding.readyQueued {
		return
	}
	if binding.readyPrev == nil {
		m.readyHead = binding.readyNext
	} else {
		binding.readyPrev.readyNext = binding.readyNext
	}
	if binding.readyNext == nil {
		m.readyTail = binding.readyPrev
	} else {
		binding.readyNext.readyPrev = binding.readyPrev
	}
	binding.readyPrev = nil
	binding.readyNext = nil
	binding.readyQueued = false
	if m.readyHead != nil {
		select {
		case m.ready <- struct{}{}:
		default:
		}
	}
}

// NextEvent returns the next retained response in order and releases its exact
// item and ByteSize charge. It returns io.EOF after an orderly local, remote,
// or manager close once the response queue is empty. Slot failures are sticky.
// One goroutine may call NextEvent for a binding.
func (b *ClientBinding) NextEvent(ctx context.Context) (LinkEvent, error) {
	if b == nil || b.state == nil {
		return LinkEvent{}, ErrClientBindingClosed
	}
	return b.state.nextEvent(ctx)
}

func (b *clientBinding) nextEvent(ctx context.Context) (LinkEvent, error) {
	if ctx == nil {
		return LinkEvent{}, fmt.Errorf("%w: nil event context", ErrInvalidFixedBindingManager)
	}
	b.nextMu.Lock()
	defer b.nextMu.Unlock()

	for {
		m := b.manager
		m.mu.Lock()
		if b.consumerMode == fixedBindingConsumerToken {
			m.mu.Unlock()
			return LinkEvent{}, ErrFixedBindingConsumerMode
		}
		if b.consumerMode == fixedBindingConsumerUnset {
			b.consumerMode = fixedBindingConsumerBlocking
			m.refreshReadyLocked(b)
		}
		if event, ok := m.popBindingEventLocked(b); ok {
			m.mu.Unlock()
			return event, nil
		}
		if b.terminal {
			b.terminalObserved = true
			err := b.terminalErr
			m.releaseTerminalBindingLocked(b)
			m.mu.Unlock()
			if err != nil {
				return LinkEvent{}, err
			}
			return LinkEvent{}, io.EOF
		}
		notify := b.notify
		m.mu.Unlock()

		select {
		case <-notify:
		case <-ctx.Done():
			return LinkEvent{}, context.Cause(ctx)
		}
	}
}

func (m *fixedBindingManager) popBindingEventLocked(binding *clientBinding) (LinkEvent, bool) {
	if binding.items == 0 {
		return LinkEvent{}, false
	}
	event := binding.queue[binding.head]
	binding.queue[binding.head] = LinkEvent{}
	binding.head = (binding.head + 1) % len(binding.queue)
	size := event.ByteSize()
	binding.items--
	binding.bytes -= size
	binding.slot.pending--
	binding.slot.bytes -= size
	m.pending--
	m.pendingBytes -= size
	if binding.items == 0 {
		binding.head = 0
	}
	m.releaseTerminalBindingLocked(binding)
	return event, true
}

// BeginClose starts an idempotent local close without waiting. CloseDone closes
// when its ordered CloseConnection is accepted or a terminal state wins.
// An already received CloseExternal completes without a reciprocal submission.
func (b *ClientBinding) BeginClose() <-chan struct{} {
	if b == nil || b.state == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	b.state.beginClose()
	return b.state.closeDone
}

// CloseDone returns the stable local-close completion channel.
func (b *ClientBinding) CloseDone() <-chan struct{} {
	if b == nil || b.state == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return b.state.closeDone
}

// CloseResult returns the exact stored close result after completion.
func (b *ClientBinding) CloseResult() (error, bool) {
	if b == nil || b.state == nil {
		return nil, true
	}
	m := b.state.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	return b.state.closeResult, b.state.closeSet
}

// Close starts local close and waits for the same stored result returned to
// every concurrent caller.
func (b *ClientBinding) Close() error {
	if b == nil || b.state == nil {
		return nil
	}
	done := b.BeginClose()
	<-done
	result, _ := b.CloseResult()
	return result
}

func (b *clientBinding) beginClose() {
	m := b.manager
	m.mu.Lock()
	if b.closeStarted {
		m.mu.Unlock()
		return
	}
	b.closeStarted = true
	b.localClosing = true
	m.detachActiveBindingLocked(b)
	m.clearBindingQueueLocked(b)
	b.result = nil
	m.invalidateReadyLocked(b)
	if b.request != nil {
		switch b.request.phase {
		case preparedRequestWaiting, preparedRequestReserved:
			m.cancelRequestLocked(b.request, true)
		case preparedRequestMaterializing, preparedRequestMaterialized, preparedRequestAttempting:
			// PrepareProxyRequestQueued transferred ownership to the manager.
			// Keep the exact request ahead of the ordered local close.
		}
	}
	if b.remoteClosed {
		m.publishBindingTerminalLocked(b, nil)
		m.publishBindingCloseLocked(b, nil)
		b.terminalObserved = true
		m.invalidateReadyLocked(b)
		m.releaseTerminalBindingLocked(b)
		m.mu.Unlock()
		return
	}
	if b.terminal || b.slot.failed || m.state != fixedBindingManagerReady {
		result := b.terminalErr
		if result == nil && b.slot.failed {
			result = b.slot.err
		}
		if result == nil && m.state != fixedBindingManagerReady {
			result = m.terminalErr
		}
		m.publishBindingTerminalLocked(b, result)
		m.publishBindingCloseLocked(b, result)
		b.terminalObserved = true
		m.invalidateReadyLocked(b)
		m.releaseTerminalBindingLocked(b)
		m.mu.Unlock()
		return
	}
	if err := m.queueControlLocked(b.slot, b, b.connectionID); err != nil {
		if errors.Is(err, ErrFixedBindingControlBackpressure) {
			// The external connection is already gone. Treat its ME-side close as
			// best effort, matching Telegram-compatible implementations: bounded
			// control pressure must not poison every binding on this link.
			m.publishBindingTerminalLocked(b, nil)
			m.publishBindingCloseLocked(b, nil)
			b.terminalObserved = true
			m.invalidateReadyLocked(b)
			m.releaseTerminalBindingLocked(b)
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
		if errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
			m.exhaustSubmissionIDs()
		} else {
			m.failSlot(b.slot, err, FixedBindingSlotFailureControlSubmission)
		}
		return
	}
	m.mu.Unlock()
}

// Close rejects new work, closes every owned link while its sole consumer is
// alive, drains link Events to closure, clears retained packets, and joins all
// consumers before Done closes. Calls are concurrent and idempotent.
func (m *FixedBindingManager) Close() error {
	if m == nil || m.state == nil {
		return nil
	}
	return m.state.close()
}

func (m *fixedBindingManager) close() error {
	m.beginTerminal(nil)
	<-m.done
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closeResult
}

// Done closes after every link and sole Events consumer has terminated.
func (m *FixedBindingManager) Done() <-chan struct{} {
	if m == nil || m.state == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return m.state.done
}

// Err returns the permanent initial or allocator failure, or nil after a
// successful Start and after an orderly manager Close. Per-slot failures are
// binding-local.
func (m *FixedBindingManager) Err() error {
	if m == nil || m.state == nil {
		return nil
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	return m.state.terminalErr
}

func (m *fixedBindingManager) exhaustSubmissionIDs() {
	m.beginTerminal(ErrFixedBindingSubmissionIDExhausted)
}

func (m *fixedBindingManager) beginTerminal(err error) {
	m.mu.Lock()
	if m.state == fixedBindingManagerClosing || m.state == fixedBindingManagerClosed {
		m.mu.Unlock()
		return
	}
	if err != nil && m.terminalErr == nil {
		m.terminalErr = err
	}
	m.state = fixedBindingManagerClosing
	m.cancelRepairs(m.closedWorkErrorLocked())
	for _, slot := range m.order {
		m.cancelSlotOutboundLocked(slot, m.closedWorkErrorLocked())
		for binding := range slot.bindings {
			m.detachActiveBindingLocked(binding)
			m.clearBindingQueueLocked(binding)
			binding.result = nil
			m.invalidateReadyLocked(binding)
			if binding.request != nil {
				m.cancelRequestLocked(binding.request, true)
			}
			bindingErr := binding.terminalErr
			if bindingErr == nil {
				bindingErr = m.terminalErr
			}
			m.publishBindingTerminalLocked(binding, bindingErr)
			m.publishBindingCloseLocked(binding, bindingErr)
			m.releaseManagerClosedBindingLocked(binding)
		}
	}
	startResult := ErrFixedBindingManagerClosed
	if m.terminalErr != nil {
		startResult = m.terminalErr
	}
	m.publishStartLocked(startResult)
	m.mu.Unlock()

	m.ensureConsumers()
	m.closeOnce.Do(func() {
		go m.closeAll()
	})
}

func (m *fixedBindingManager) closeAll() {
	m.operations.Wait()
	closeErrors := make([]error, 0, len(m.order))
	for _, slot := range m.order {
		if err := slot.link.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close fixed-binding DC %d: %w", slot.dcID, err))
		}
	}
	m.consumers.Wait()

	m.mu.Lock()
	for _, slot := range m.order {
		for binding := range slot.bindings {
			m.clearBindingQueueLocked(binding)
			terminalErr := binding.terminalErr
			if terminalErr == nil && !binding.remoteClosed && m.terminalErr != nil {
				terminalErr = m.terminalErr
			}
			m.publishBindingTerminalLocked(binding, terminalErr)
			m.publishBindingCloseLocked(binding, terminalErr)
			binding.result = nil
			m.releaseManagerClosedBindingLocked(binding)
		}
		slot.requestItems = 0
		slot.requestBytes = 0
		slot.controlItems = 0
		slot.controlBytes = 0
	}
	m.pending = 0
	m.pendingBytes = 0
	m.requestItems = 0
	m.requestBytes = 0
	m.controlItems = 0
	m.controlBytes = 0
	m.closeResult = errors.Join(closeErrors...)
	m.state = fixedBindingManagerClosed
	close(m.done)
	m.mu.Unlock()
}

func (m *fixedBindingManager) consumeSlot(slot *fixedBindingSlot) {
	consumerDone := slot.consumerDone
	defer close(consumerDone)
	events := slot.events
	for events != nil {
		select {
		case event, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			m.mu.Lock()
			state := m.state
			m.mu.Unlock()
			if state == fixedBindingManagerClosing || state == fixedBindingManagerClosed {
				clearLinkEventPacket(&event)
				continue
			}
			if err := m.routeEvent(slot, event); err != nil {
				m.failSlot(slot, err, FixedBindingSlotFailureEventRouting)
			}
		case <-slot.requestWake:
			m.dispatchSlotOnce(slot)
		case <-slot.capacity:
			m.dispatchSlotOnce(slot)
		}
	}

	linkErr := slot.link.Err()
	m.mu.Lock()
	state := m.state
	failed := slot.failed
	m.mu.Unlock()
	if state != fixedBindingManagerClosing && state != fixedBindingManagerClosed && !failed {
		if linkErr == nil {
			linkErr = ErrLinkClosed
		}
		m.failSlot(slot, linkErr, FixedBindingSlotFailureLinkTerminal)
	}
}

func (m *fixedBindingManager) dispatchSlotOnce(slot *fixedBindingSlot) {
	m.mu.Lock()
	if m.state != fixedBindingManagerReady || slot.failed {
		m.mu.Unlock()
		return
	}
	item := slot.outHead
	if item == nil || item.attempting {
		m.mu.Unlock()
		return
	}
	if item.kind == outboundRequest {
		if item.request.phase != preparedRequestMaterialized {
			m.mu.Unlock()
			return
		}
		item.request.phase = preparedRequestAttempting
	}
	item.attempting = true
	submission := item.submission
	if item.kind == outboundRequest {
		submission = item.request.submission
	}
	m.operations.Add(1)
	m.mu.Unlock()

	err := slot.link.TrySubmit(submission)

	m.mu.Lock()
	item.attempting = false
	switch item.kind {
	case outboundRequest:
		m.finishRequestAttemptLocked(slot, item, err)
	case outboundControl:
		m.finishControlAttemptLocked(slot, item, err)
	case outboundProbe:
		m.finishProbeAttemptLocked(slot, item, err)
	}
	m.operations.Done()
	state := m.state
	m.mu.Unlock()

	if err != nil && !errors.Is(err, ErrLinkBackpressure) &&
		(!errors.Is(err, ErrLinkSubmissionTooLarge) || item.kind != outboundRequest) &&
		state != fixedBindingManagerClosing && state != fixedBindingManagerClosed {
		m.failSlot(slot, err, FixedBindingSlotFailureSubmission)
	}
}

func (m *fixedBindingManager) finishProbeAttemptLocked(slot *fixedBindingSlot, item *outboundItem, err error) {
	probe := item.probe
	if errors.Is(err, ErrLinkBackpressure) && !item.canceled && m.state == fixedBindingManagerReady {
		return
	}
	m.removeOutboundLocked(slot, item)
	m.releaseControlLocked(slot, item)
	probe.outbound = nil
	if err == nil {
		item.submission = LinkSubmission{}
		if !probe.complete {
			probe.submitted = true
		}
	} else {
		clear(item.submission.Payload)
		item.submission = LinkSubmission{}
	}
	m.signalSlotLocked(slot)
}

func (m *fixedBindingManager) finishRequestAttemptLocked(slot *fixedBindingSlot, item *outboundItem, err error) {
	request := item.request
	binding := request.binding
	if err == nil {
		submissionID := request.submission.SubmissionID
		m.removeOutboundLocked(slot, item)
		m.releaseRequestChargeLocked(request)
		request.submission = LinkSubmission{}
		if binding.request == request {
			binding.request = nil
		}
		if !request.canceled && m.state == fixedBindingManagerReady && !binding.localClosing && !binding.terminal {
			binding.result = &ClientRequestResult{SubmissionID: submissionID, Accepted: true}
			m.signalBindingLocked(binding)
		}
		m.promoteRequestsLocked()
		m.signalSlotLocked(slot)
		return
	}
	if errors.Is(err, ErrLinkBackpressure) && !request.canceled && m.state == fixedBindingManagerReady {
		request.phase = preparedRequestMaterialized
		return
	}
	m.removeOutboundLocked(slot, item)
	m.releaseRequestChargeLocked(request)
	clear(request.submission.Payload)
	submissionID := request.submission.SubmissionID
	request.submission = LinkSubmission{}
	if binding.request == request {
		binding.request = nil
	}
	if !request.canceled && errors.Is(err, ErrLinkSubmissionTooLarge) {
		permanent := fmt.Errorf("%w: %w", ErrFixedBindingRequestRejected, err)
		if !binding.localClosing {
			binding.result = &ClientRequestResult{SubmissionID: submissionID, Err: permanent}
		}
		m.detachActiveBindingLocked(binding)
		m.publishBindingTerminalLocked(binding, permanent)
	}
	m.promoteRequestsLocked()
	m.signalSlotLocked(slot)
}

func (m *fixedBindingManager) finishControlAttemptLocked(slot *fixedBindingSlot, item *outboundItem, err error) {
	if errors.Is(err, ErrLinkBackpressure) && !item.canceled && m.state == fixedBindingManagerReady {
		return
	}
	m.removeOutboundLocked(slot, item)
	m.releaseControlLocked(slot, item)
	if err == nil {
		item.submission = LinkSubmission{}
	} else {
		clear(item.submission.Payload)
		item.submission = LinkSubmission{}
	}
	if item.binding != nil && !item.canceled {
		if err == nil {
			result := item.binding.terminalErr
			m.publishBindingTerminalLocked(item.binding, result)
			m.publishBindingCloseLocked(item.binding, result)
			item.binding.terminalObserved = true
			m.invalidateReadyLocked(item.binding)
			m.releaseTerminalBindingLocked(item.binding)
		}
	}
	m.signalSlotLocked(slot)
}

func (m *fixedBindingManager) releaseControlLocked(slot *fixedBindingSlot, item *outboundItem) {
	size := len(item.submission.Payload)
	slot.controlItems--
	slot.controlBytes -= size
	m.controlItems--
	m.controlBytes -= size
}

func (m *fixedBindingManager) signalSlotLocked(slot *fixedBindingSlot) {
	select {
	case slot.requestWake <- struct{}{}:
	default:
	}
}

func (m *fixedBindingManager) routeEvent(slot *fixedBindingSlot, event LinkEvent) error {
	if err := validateFixedBindingLinkEvent(event); err != nil {
		clearLinkEventPacket(&event)
		return fmt.Errorf("%w: DC %d: %v", ErrFixedBindingProtocol, slot.dcID, err)
	}
	switch event.Kind {
	case LinkEventPing:
		return nil
	case LinkEventPong:
		m.mu.Lock()
		if m.state != fixedBindingManagerClosing && m.state != fixedBindingManagerClosed && !slot.failed {
			probe := slot.probe
			if probe != nil && probe.submitted && probe.id == event.KeepaliveID {
				m.completeProbeLocked(probe, nil)
			}
		}
		m.mu.Unlock()
		return nil
	case LinkEventProxyAnswer, LinkEventSimpleAck, LinkEventCloseExternal:
	default:
		return fmt.Errorf("%w: DC %d emitted event kind %d", ErrFixedBindingProtocol, slot.dcID, event.Kind)
	}
	m.mu.Lock()
	if m.state == fixedBindingManagerClosing || m.state == fixedBindingManagerClosed || slot.failed {
		m.mu.Unlock()
		clearLinkEventPacket(&event)
		return nil
	}
	binding := m.byID[event.ConnectionID]
	if binding != nil && binding.slot != slot {
		m.mu.Unlock()
		clearLinkEventPacket(&event)
		return fmt.Errorf("%w: connection %d belongs to DC %d, arrived on DC %d", ErrFixedBindingProtocol, event.ConnectionID, binding.slot.dcID, slot.dcID)
	}
	if binding == nil {
		if event.Kind == LinkEventCloseExternal {
			m.mu.Unlock()
			clearLinkEventPacket(&event)
			return nil
		}
		connectionID := event.ConnectionID
		clearLinkEventPacket(&event)
		err := m.queueControlLocked(slot, nil, connectionID)
		m.mu.Unlock()
		if errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
			m.exhaustSubmissionIDs()
			return nil
		}
		if errors.Is(err, ErrFixedBindingControlBackpressure) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("close stale connection %d on DC %d: %w", connectionID, slot.dcID, err)
		}
		return nil
	}
	if binding.terminal || (binding.localClosing && event.Kind != LinkEventCloseExternal) {
		m.mu.Unlock()
		clearLinkEventPacket(&event)
		return nil
	}
	if binding.localClosing && event.Kind == LinkEventCloseExternal {
		clearLinkEventPacket(&event)
		binding.remoteClosed = true
		if binding.request != nil {
			m.cancelRequestLocked(binding.request, true)
		}
		m.cancelBindingControlsLocked(binding)
		m.publishBindingTerminalLocked(binding, nil)
		m.publishBindingCloseLocked(binding, nil)
		binding.terminalObserved = true
		m.invalidateReadyLocked(binding)
		m.releaseTerminalBindingLocked(binding)
		m.mu.Unlock()
		return nil
	}
	if err := m.enqueueEventLocked(binding, event); err != nil {
		if errors.Is(err, ErrFixedBindingResponseBackpressure) {
			victim := m.responsePressureVictimLocked(binding, event.ByteSize())
			m.evictBackpressuredBindingLocked(victim, err)
			controlErr := m.queueControlLocked(victim.slot, nil, victim.connectionID)
			if victim != binding {
				// Shared slot/global pressure belongs to an already buffered
				// client. Its released charge is sufficient for this exact event,
				// so preserve the incoming healthy response.
				if retryErr := m.enqueueEventLocked(binding, event); retryErr != nil {
					m.evictBackpressuredBindingLocked(binding, retryErr)
					clearLinkEventPacket(&event)
				}
			} else {
				clearLinkEventPacket(&event)
			}
			m.mu.Unlock()
			if errors.Is(controlErr, ErrFixedBindingSubmissionIDExhausted) {
				m.exhaustSubmissionIDs()
			}
			if controlErr != nil && !errors.Is(controlErr, ErrFixedBindingControlBackpressure) &&
				!errors.Is(controlErr, ErrFixedBindingSubmissionIDExhausted) {
				return fmt.Errorf("close backpressured connection %d on DC %d: %w", binding.connectionID, slot.dcID, controlErr)
			}
			return nil
		}
		m.mu.Unlock()
		clearLinkEventPacket(&event)
		return err
	}
	if event.Kind == LinkEventCloseExternal {
		binding.remoteClosed = true
		m.detachActiveBindingLocked(binding)
		m.publishBindingTerminalLocked(binding, nil)
	}
	m.mu.Unlock()
	return nil
}

func (m *fixedBindingManager) evictBackpressuredBindingLocked(binding *clientBinding, cause error) {
	m.detachActiveBindingLocked(binding)
	m.clearBindingQueueLocked(binding)
	binding.result = nil
	m.invalidateReadyLocked(binding)
	if binding.request != nil {
		m.cancelRequestLocked(binding.request, true)
	}
	m.publishBindingTerminalLocked(binding, cause)
	m.releaseTerminalBindingLocked(binding)
}

func (m *fixedBindingManager) responsePressureVictimLocked(incoming *clientBinding, incomingBytes int) *clientBinding {
	if incoming.items >= m.limits.MaxPendingResponseItemsPerBinding ||
		incomingBytes > m.limits.MaxPendingResponseBytesPerBinding-incoming.bytes {
		return incoming
	}

	neededItems := 0
	neededBytes := 0
	slotPressure := false
	if incoming.slot.pending >= m.limits.MaxPendingResponseItemsPerSlot ||
		incomingBytes > m.limits.MaxPendingResponseBytesPerSlot-incoming.slot.bytes {
		slotPressure = true
		neededItems = max(0, incoming.slot.pending+1-m.limits.MaxPendingResponseItemsPerSlot)
		neededBytes = max(0, incoming.slot.bytes+incomingBytes-m.limits.MaxPendingResponseBytesPerSlot)
	} else {
		neededItems = max(0, m.pending+1-m.limits.MaxPendingResponseItems)
		neededBytes = max(0, m.pendingBytes+incomingBytes-m.limits.MaxPendingResponseBytes)
	}

	var victim *clientBinding
	consider := func(candidate *clientBinding) {
		if candidate == incoming || candidate.terminal || candidate.items < neededItems || candidate.bytes < neededBytes {
			return
		}
		if victim == nil || candidate.bytes > victim.bytes ||
			candidate.bytes == victim.bytes && candidate.items > victim.items ||
			candidate.bytes == victim.bytes && candidate.items == victim.items && candidate.connectionID < victim.connectionID {
			victim = candidate
		}
	}
	if slotPressure {
		for candidate := range incoming.slot.bindings {
			consider(candidate)
		}
	} else {
		for _, candidate := range m.byID {
			consider(candidate)
		}
	}
	if victim != nil {
		return victim
	}
	return incoming
}

func (m *fixedBindingManager) cancelBindingControlsLocked(binding *clientBinding) {
	slot := binding.slot
	for item := slot.outHead; item != nil; item = item.next {
		if item.kind != outboundControl || item.binding != binding {
			continue
		}
		item.canceled = true
		if item.attempting {
			continue
		}
		wasHead := slot.outHead == item
		m.removeOutboundLocked(slot, item)
		m.releaseControlLocked(slot, item)
		clear(item.submission.Payload)
		item.submission = LinkSubmission{}
		if wasHead {
			m.signalSlotLocked(slot)
		}
		return
	}
}

func validateFixedBindingLinkEvent(event LinkEvent) error {
	switch event.Kind {
	case LinkEventProxyAnswer:
		if err := validateProxyAnswerFlags(event.AnswerFlags); err != nil {
			return err
		}
		if event.ConfirmKey != 0 || event.KeepaliveID != 0 {
			return fmt.Errorf("proxy answer carries acknowledgement or keepalive metadata")
		}
		if len(event.Packet)%4 != 0 {
			return fmt.Errorf("proxy answer packet length %d is not word-aligned", len(event.Packet))
		}
		if len(event.Packet) > MaxClientPacketSize {
			return fmt.Errorf("proxy answer packet %d exceeds %d", len(event.Packet), MaxClientPacketSize)
		}
	case LinkEventSimpleAck:
		if event.AnswerFlags != 0 || event.KeepaliveID != 0 || event.Packet != nil {
			return fmt.Errorf("simple acknowledgement carries answer, keepalive, or packet data")
		}
	case LinkEventCloseExternal:
		if event.AnswerFlags != 0 || event.ConfirmKey != 0 || event.KeepaliveID != 0 || event.Packet != nil {
			return fmt.Errorf("external close carries answer, acknowledgement, keepalive, or packet data")
		}
	case LinkEventPing, LinkEventPong:
		if event.ConnectionID != 0 || event.AnswerFlags != 0 || event.ConfirmKey != 0 || event.Packet != nil {
			return fmt.Errorf("keepalive carries connection, answer, acknowledgement, or packet data")
		}
	default:
		return fmt.Errorf("unsupported event kind %d", event.Kind)
	}
	return nil
}

func (m *fixedBindingManager) enqueueEventLocked(binding *clientBinding, event LinkEvent) error {
	size := event.ByteSize()
	if size <= 0 {
		return fmt.Errorf("%w: invalid event size", ErrFixedBindingProtocol)
	}
	if binding.items >= m.limits.MaxPendingResponseItemsPerBinding ||
		size > m.limits.MaxPendingResponseBytesPerBinding-binding.bytes {
		m.responseBackpressureEvents++
		return fmt.Errorf("%w: binding %d", ErrFixedBindingResponseBackpressure, binding.connectionID)
	}
	if binding.slot.pending >= m.limits.MaxPendingResponseItemsPerSlot ||
		size > m.limits.MaxPendingResponseBytesPerSlot-binding.slot.bytes {
		m.responseBackpressureEvents++
		return fmt.Errorf("%w: DC %d", ErrFixedBindingResponseBackpressure, binding.slot.dcID)
	}
	if m.pending >= m.limits.MaxPendingResponseItems ||
		size > m.limits.MaxPendingResponseBytes-m.pendingBytes {
		m.responseBackpressureEvents++
		return fmt.Errorf("%w: global", ErrFixedBindingResponseBackpressure)
	}
	if err := m.growBindingQueueLocked(binding); err != nil {
		return err
	}
	if event.Kind == LinkEventProxyAnswer && event.Packet != nil {
		// ByteSize charges len(Packet). Detach from any oversized backing array
		// before retention so the manager-owned capacity has the same bound.
		packet := make([]byte, len(event.Packet))
		copy(packet, event.Packet)
		clear(event.Packet)
		event.Packet = packet
	}
	index := (binding.head + binding.items) % len(binding.queue)
	binding.queue[index] = event
	binding.items++
	binding.bytes += size
	binding.slot.pending++
	binding.slot.bytes += size
	m.pending++
	m.pendingBytes += size
	m.recordResponseHighWaterLocked(binding.slot)
	m.signalBindingLocked(binding)
	return nil
}

func (m *fixedBindingManager) growBindingQueueLocked(binding *clientBinding) error {
	if binding.items < len(binding.queue) {
		return nil
	}
	limit := m.limits.MaxPendingResponseItemsPerBinding
	if len(binding.queue) >= limit {
		return fmt.Errorf("%w: binding %d", ErrFixedBindingResponseBackpressure, binding.connectionID)
	}
	newLength := min(limit, max(1, len(binding.queue)*2))
	queue := make([]LinkEvent, newLength)
	for index := range binding.items {
		queue[index] = binding.queue[(binding.head+index)%len(binding.queue)]
	}
	clear(binding.queue)
	binding.queue = queue
	binding.head = 0
	return nil
}

func (m *fixedBindingManager) failSlot(
	slot *fixedBindingSlot,
	cause error,
	reason FixedBindingSlotFailureReason,
) {
	if cause == nil {
		cause = ErrLinkClosed
	}
	wrapped := fmt.Errorf("%w: DC %d: %w", ErrFixedBindingSlotFailed, slot.dcID, cause)
	m.mu.Lock()
	if slot.failed {
		m.mu.Unlock()
		return
	}
	if m.state == fixedBindingManagerClosing || m.state == fixedBindingManagerClosed {
		m.mu.Unlock()
		return
	}
	slot.failed = true
	slot.err = wrapped
	starting := m.state == fixedBindingManagerStarting
	affectedBindings := 0
	if !starting {
		m.cancelSlotOutboundLocked(slot, wrapped)
		for binding := range slot.bindings {
			if binding.remoteClosed {
				continue
			}
			if !binding.terminal {
				affectedBindings++
			}
			m.detachActiveBindingLocked(binding)
			m.publishBindingTerminalLocked(binding, wrapped)
			if binding.closeStarted {
				m.publishBindingCloseLocked(binding, wrapped)
				binding.terminalObserved = true
				m.invalidateReadyLocked(binding)
			}
			m.releaseTerminalBindingLocked(binding)
		}
	}
	m.slotFailures++
	m.slotFailureAffectedBindings += uint64(affectedBindings)
	failure := FixedBindingSlotFailureSnapshot{
		Sequence:         m.slotFailures,
		DCID:             slot.dcID,
		Reason:           reason,
		AffectedBindings: affectedBindings,
		Error:            wrapped,
	}
	m.lastSlotFailure = failure
	observer := m.slotFailureObserver
	m.mu.Unlock()
	if observer != nil {
		observer(failure)
	}
	if starting {
		m.beginTerminal(fmt.Errorf("%w: %w", ErrFixedBindingInitialFailure, wrapped))
		return
	}
	_ = slot.link.Close()
}

func (m *fixedBindingManager) terminalizeBinding(binding *clientBinding, cause error) {
	m.mu.Lock()
	if binding.resident {
		m.detachActiveBindingLocked(binding)
		if binding.request != nil {
			m.cancelRequestLocked(binding.request, true)
		}
		m.publishBindingTerminalLocked(binding, cause)
		if binding.closeStarted {
			m.publishBindingCloseLocked(binding, cause)
			binding.terminalObserved = true
			m.invalidateReadyLocked(binding)
		}
		m.releaseTerminalBindingLocked(binding)
	}
	m.mu.Unlock()
}

func (m *fixedBindingManager) cancelSlotOutboundLocked(slot *fixedBindingSlot, cause error) {
	m.completeProbeLocked(slot.probe, cause)
	for item := slot.outHead; item != nil; {
		next := item.next
		item.canceled = true
		switch item.kind {
		case outboundRequest:
			m.cancelRequestLocked(item.request, !item.attempting)
		case outboundProbe:
			m.completeProbeLocked(item.probe, cause)
		case outboundControl:
			if !item.attempting {
				m.removeOutboundLocked(slot, item)
				m.releaseControlLocked(slot, item)
				clear(item.submission.Payload)
				item.submission = LinkSubmission{}
			}
		}
		item = next
	}
}

func (m *fixedBindingManager) detachActiveBindingLocked(binding *clientBinding) {
	if !binding.active {
		return
	}
	binding.active = false
}

func (m *fixedBindingManager) clearBindingQueueLocked(binding *clientBinding) {
	for index := range binding.items {
		queueIndex := (binding.head + index) % len(binding.queue)
		clearLinkEventPacket(&binding.queue[queueIndex])
		binding.queue[queueIndex] = LinkEvent{}
	}
	binding.slot.pending -= binding.items
	binding.slot.bytes -= binding.bytes
	m.pending -= binding.items
	m.pendingBytes -= binding.bytes
	binding.head = 0
	binding.items = 0
	binding.bytes = 0
}

func (m *fixedBindingManager) publishBindingTerminalLocked(binding *clientBinding, err error) {
	if binding.terminal {
		if binding.terminalErr == nil && err != nil {
			binding.terminalErr = err
		}
		m.signalBindingLocked(binding)
		return
	}
	binding.terminal = true
	binding.terminalErr = err
	m.signalBindingLocked(binding)
}

func (m *fixedBindingManager) publishBindingCloseLocked(binding *clientBinding, result error) {
	if binding.closeSet {
		return
	}
	binding.closeResult = result
	binding.closeSet = true
	close(binding.closeDone)
}

func (m *fixedBindingManager) releaseTerminalBindingLocked(binding *clientBinding) {
	if !binding.resident || !binding.terminal || binding.items != 0 || binding.request != nil || binding.result != nil ||
		binding.readyQueued || binding.readyLeased || (!binding.terminalObserved && !binding.closeSet) {
		return
	}
	m.releaseBindingResidentLocked(binding)
}

func (m *fixedBindingManager) releaseManagerClosedBindingLocked(binding *clientBinding) {
	if binding.consumerMode != fixedBindingConsumerToken {
		binding.terminalObserved = true
		m.invalidateReadyLocked(binding)
	}
	m.releaseBindingResidentLocked(binding)
}

func (m *fixedBindingManager) releaseBindingResidentLocked(binding *clientBinding) {
	if !binding.resident {
		return
	}
	delete(m.byID, binding.connectionID)
	delete(binding.slot.bindings, binding)
	binding.resident = false
	binding.slot.resident--
	m.residentBindings--
	m.publishDrainedLocked()
}

func (m *fixedBindingManager) publishDrainedLocked() {
	if m.accepting || m.residentBindings != 0 || m.drainedSet {
		return
	}
	m.drainedSet = true
	close(m.drained)
}

func (m *fixedBindingManager) signalBindingLocked(binding *clientBinding) {
	select {
	case binding.notify <- struct{}{}:
	default:
	}
	if m.bindingHasReadyReasonLocked(binding) {
		m.enqueueReadyLocked(binding)
	}
}

func (m *fixedBindingManager) invalidateReadyLocked(binding *clientBinding) {
	m.unlinkReadyLocked(binding)
	binding.readyLeased = false
}

func clearLinkEventPacket(event *LinkEvent) {
	if event == nil {
		return
	}
	clear(event.Packet)
	event.Packet = nil
}

func allocateFixedBindingConnectionID() (int64, error) {
	for {
		current := fixedBindingConnectionIDs.Load()
		if current == math.MaxInt64 {
			return 0, ErrFixedBindingConnectionIDExhausted
		}
		next := current + 1
		if fixedBindingConnectionIDs.CompareAndSwap(current, next) {
			return next, nil
		}
	}
}

func allocateFixedBindingSubmissionID() (uint64, error) {
	for {
		current := fixedBindingSubmissionIDs.Load()
		if current == math.MaxUint64 {
			return 0, ErrFixedBindingSubmissionIDExhausted
		}
		next := current + 1
		if next == 0 {
			return 0, ErrFixedBindingSubmissionIDExhausted
		}
		if fixedBindingSubmissionIDs.CompareAndSwap(current, next) {
			return next, nil
		}
	}
}

// setFixedBindingAllocatorStateForTest is an unexported serial test seam.
func setFixedBindingAllocatorStateForTest(connectionID int64, submissionID uint64) func() {
	fixedBindingAllocatorMu.Lock()
	previousConnectionID := fixedBindingConnectionIDs.Swap(connectionID)
	previousSubmissionID := fixedBindingSubmissionIDs.Swap(submissionID)
	return sync.OnceFunc(func() {
		fixedBindingConnectionIDs.Store(previousConnectionID)
		fixedBindingSubmissionIDs.Store(previousSubmissionID)
		fixedBindingAllocatorMu.Unlock()
	})
}

// setFixedBindingProbeIDForTest is an unexported serial test seam.
func setFixedBindingProbeIDForTest(manager *FixedBindingManager, probeID uint64) func() {
	if manager == nil || manager.state == nil {
		return func() {}
	}
	manager.state.mu.Lock()
	previous := manager.state.probeID
	manager.state.probeID = probeID
	manager.state.mu.Unlock()
	return sync.OnceFunc(func() {
		manager.state.mu.Lock()
		manager.state.probeID = previous
		manager.state.mu.Unlock()
	})
}
