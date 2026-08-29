package middleend

import (
	"context"
	"errors"
	"fmt"
)

var (
	// ErrLinkNotReady reports a submission made before Start completes.
	ErrLinkNotReady = errors.New("Middle-End link is not ready")
	// ErrLinkBackpressure reports that a bounded submission queue cannot accept
	// an item at present. The caller retains ownership and may retry after a
	// SubmissionReady signal.
	ErrLinkBackpressure = errors.New("Middle-End link submission queue is full")
	// ErrLinkSubmissionTooLarge reports a valid submission whose payload can
	// never fit this link's configured submission-byte limit. Unlike
	// ErrLinkBackpressure, retrying the same submission cannot succeed.
	ErrLinkSubmissionTooLarge = errors.New("Middle-End link submission exceeds byte limit")
	// ErrLinkClosed reports an operation on a link that is closing or closed.
	ErrLinkClosed = errors.New("Middle-End link is closed")
	// ErrLinkEventBackpressure is terminal. A link must close instead of
	// dropping a response when its bounded event queue is full.
	ErrLinkEventBackpressure = errors.New("Middle-End link event queue is full")
	// ErrInvalidLinkLimits reports nonpositive queue limits, values above the
	// local safety ceilings, or unsafe derived queue arithmetic.
	ErrInvalidLinkLimits = errors.New("invalid Middle-End link limits")
	// ErrInvalidLinkSubmission reports an unsupported or inconsistent outbound
	// RPC payload.
	ErrInvalidLinkSubmission = errors.New("invalid Middle-End link submission")
	// ErrUnexpectedLinkRPC reports a valid RPC operation in the wrong direction
	// for a Middle-End client link.
	ErrUnexpectedLinkRPC = errors.New("unexpected Middle-End link RPC")
)

const (
	// MaxLinkQueueItems is the local memory-safety ceiling for either queue on
	// one Middle-End link. It is not a Telegram protocol limit. The 4,096-item
	// cap matches the web-proxy bridge frame cap. With the current amd64 engine
	// layouts, it limits eager per-link queue metadata to 360,480 bytes for the
	// blocking engine and 229,376 bytes for the gnet engine.
	MaxLinkQueueItems = 4096
	// MaxLinkQueueBytes is the local payload-memory ceiling for either queue on
	// one Middle-End link. It follows the existing 512 MiB global pending-byte
	// policy. It is not a Telegram protocol limit.
	MaxLinkQueueBytes = 512 * 1024 * 1024

	// A full frame adds its header and CBC alignment adds at most three
	// four-byte no-op frames to each accepted submission.
	maxLinkSubmissionWireOverhead = FullFrameOverhead + 3*NoopFrameSize
)

// LinkLimits are hard application-level queue limits for one Middle-End link.
// Pending submissions include accepted work in the application queue and work
// in an application-visible transport buffer. Every engine must enforce both
// the item and byte limits. Values cannot exceed MaxLinkQueueItems or
// MaxLinkQueueBytes. A zero value is invalid; callers must choose limits
// deliberately.
type LinkLimits struct {
	MaxPendingSubmissions     int
	MaxPendingSubmissionBytes int
	MaxPendingEvents          int
	MaxPendingEventBytes      int
}

// Validate rejects limits that cannot bound every queue dimension. Engine
// constructors must call it before they allocate queue storage.
func (l LinkLimits) Validate() error {
	if l.MaxPendingSubmissions <= 0 || l.MaxPendingSubmissionBytes <= 0 ||
		l.MaxPendingEvents <= 0 || l.MaxPendingEventBytes <= 0 {
		return fmt.Errorf("%w: every item and byte limit must be positive", ErrInvalidLinkLimits)
	}
	if l.MaxPendingSubmissions > MaxLinkQueueItems || l.MaxPendingEvents > MaxLinkQueueItems {
		return fmt.Errorf("%w: item limits must not exceed the local ceiling %d", ErrInvalidLinkLimits, MaxLinkQueueItems)
	}
	if l.MaxPendingSubmissionBytes > MaxLinkQueueBytes || l.MaxPendingEventBytes > MaxLinkQueueBytes {
		return fmt.Errorf("%w: byte limits must not exceed the local ceiling %d", ErrInvalidLinkLimits, MaxLinkQueueBytes)
	}
	maximumInt := int(^uint(0) >> 1)
	if l.MaxPendingSubmissions > (maximumInt-l.MaxPendingSubmissionBytes)/maxLinkSubmissionWireOverhead {
		return fmt.Errorf("%w: derived encoded submission byte limit overflows int", ErrInvalidLinkLimits)
	}
	return nil
}

// LinkSubmission is one complete outbound RPC payload and its stable local
// identity. SubmissionID is not sent to Telegram. It identifies the queued
// work item in diagnostics. ConnectionID must match the RPC payload; it is
// zero only for link-scoped ping traffic.
//
// If TrySubmit returns nil, ownership of Payload transfers to the link and the
// caller must not read or modify it. On error, ownership remains with the
// caller.
type LinkSubmission struct {
	SubmissionID uint64
	ConnectionID int64
	Payload      []byte
}

// String reports routing metadata without disclosing the RPC payload.
func (s LinkSubmission) String() string {
	return fmt.Sprintf("middleend.LinkSubmission{SubmissionID:%d, ConnectionID:%d, Payload:<redacted %d bytes>}", s.SubmissionID, s.ConnectionID, len(s.Payload))
}

// GoString reports routing metadata without disclosing the RPC payload.
func (s LinkSubmission) GoString() string {
	return s.String()
}

// ByteSize is the exact charge applied to MaxPendingSubmissionBytes. The
// common quantity is the complete RPC payload before frame and CBC encoding.
func (s LinkSubmission) ByteSize() int {
	return len(s.Payload)
}

// Validate checks the submission identity, direction, and duplicated
// ConnectionID metadata. Client links may submit proxy requests, external
// connection closes, and pings. Pongs are generated internally in response to
// peer pings.
func (s LinkSubmission) Validate() error {
	if s.SubmissionID == 0 {
		return fmt.Errorf("%w: submission ID is zero", ErrInvalidLinkSubmission)
	}
	operation, err := ParseRPCOperation(s.Payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidLinkSubmission, err)
	}
	switch operation {
	case OperationProxyRequest:
		request, err := parseProxyRequest(s.Payload, false)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidLinkSubmission, err)
		}
		return validateSubmissionConnectionID(s.ConnectionID, request.ConnectionID)
	case OperationCloseConnection:
		closeRequest, err := ParseCloseConnection(s.Payload)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidLinkSubmission, err)
		}
		return validateSubmissionConnectionID(s.ConnectionID, closeRequest.ConnectionID)
	case OperationPing:
		if _, err := ParsePing(s.Payload); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidLinkSubmission, err)
		}
		if s.ConnectionID != 0 {
			return fmt.Errorf("%w: link ping has connection ID %d", ErrInvalidLinkSubmission, s.ConnectionID)
		}
		return nil
	default:
		return fmt.Errorf("%w: outbound operation %08x", ErrUnexpectedLinkRPC, operation)
	}
}

func validateSubmissionConnectionID(metadata int64, payload int64) error {
	if metadata == 0 {
		return fmt.Errorf("%w: connection ID is zero", ErrInvalidLinkSubmission)
	}
	if metadata != payload {
		return fmt.Errorf("%w: connection ID %d does not match payload %d", ErrInvalidLinkSubmission, metadata, payload)
	}
	return nil
}

// LinkEventKind identifies one validated peer RPC.
type LinkEventKind uint8

const (
	LinkEventProxyAnswer LinkEventKind = iota + 1
	LinkEventSimpleAck
	LinkEventCloseExternal
	LinkEventPing
	LinkEventPong
)

// LinkEvent is one validated peer RPC. ConnectionID is nonzero for proxy
// answers, acknowledgements, and external closes. KeepaliveID is set for ping
// and pong. Packet is set only for a proxy answer and transfers to the event
// consumer, which may retain or modify it.
//
// Telegram's wire protocol does not carry the local SubmissionID in answers,
// acknowledgements, or closes. Engines must not invent one-to-one request and
// response correlation; inbound traffic is owned by ConnectionID.
type LinkEvent struct {
	Kind         LinkEventKind
	ConnectionID int64
	AnswerFlags  ProxyAnswerFlags
	ConfirmKey   uint32
	KeepaliveID  uint64
	Packet       []byte
}

// String reports routing metadata without disclosing the answer packet.
func (e LinkEvent) String() string {
	return fmt.Sprintf("middleend.LinkEvent{Kind:%d, ConnectionID:%d, AnswerFlags:%d, ConfirmKey:%d, KeepaliveID:%d, Packet:<redacted %d bytes>}",
		e.Kind, e.ConnectionID, e.AnswerFlags, e.ConfirmKey, e.KeepaliveID, len(e.Packet))
}

// GoString reports routing metadata without disclosing the answer packet.
func (e LinkEvent) GoString() string {
	return e.String()
}

// ByteSize reports the decoded application bytes charged to the bounded event
// queue. Fixed metadata is accounted as its exact RPC payload size.
func (e LinkEvent) ByteSize() int {
	switch e.Kind {
	case LinkEventProxyAnswer:
		return ProxyAnswerHeaderSize + len(e.Packet)
	case LinkEventSimpleAck:
		return SimpleAckPayloadSize
	case LinkEventCloseExternal:
		return ClosePayloadSize
	case LinkEventPing, LinkEventPong:
		return KeepalivePayloadSize
	default:
		return 0
	}
}

// LinkState is the lifecycle state of one engine instance.
type LinkState uint8

const (
	LinkStateCreated LinkState = iota
	LinkStateBootstrapping
	LinkStateReady
	LinkStateClosing
	LinkStateClosed
)

// LinkSnapshot is a concurrency-safe instantaneous view used by operational
// metrics and the common engine comparison harness. Pending submission values
// include accepted work that the underlying socket has not consumed.
// High-water fields are monotonic for the lifetime of a link.
type LinkSnapshot struct {
	State                    LinkState
	PendingSubmissions       int
	PendingSubmissionBytes   int
	SubmissionHighWater      int
	SubmissionBytesHighWater int
	PendingEvents            int
	PendingEventBytes        int
	EventHighWater           int
	EventBytesHighWater      int
}

// ClientLink is the common contract for one already-selected Middle-End
// endpoint and stream. Implementations own their ClientBootstrap and are the
// sole callers of its Start, Feed, Encode, and Finish methods. This preserves
// the single owner of CBC and full-frame sequence state.
//
// Start performs the bilateral bootstrap exactly once and returns only after
// the link is ready or permanently failed. Concurrent and repeated Start calls
// return the first start result. Start returns ErrLinkClosed if Close wins
// before bootstrap starts. If Close interrupts an active bootstrap, Start
// returns ErrLinkClosed unless Start already published the ready state. A
// successful Start does not retain its context. Canceling that context does
// not close the ready link. TrySubmit is non-blocking and safe for concurrent
// callers. Events has one consumer. Snapshot, Done, Err, and Close are safe for
// concurrent use. Close is idempotent and every call returns the same result.
//
// An implementation must encode a pong on its owner when it receives a peer
// ping. It publishes the ping event only after it accepts that pong for write.
//
// Implementations must use bounded submission and event queues. They return
// ErrLinkSubmissionTooLarge without accepting a valid item whose byte charge
// exceeds MaxPendingSubmissionBytes. They return ErrLinkBackpressure without
// accepting an item when the current pending item or byte charge would exceed
// a limit. If an accepted response cannot fit in the event queue, they must
// fail the entire link with ErrLinkEventBackpressure. Any bootstrap, protocol,
// transport, or owner-loop failure must close the stream, stop accepting
// submissions, close every link-owned queue, and preserve the first terminal
// error for Err. They must never retry, migrate a connection, or drop an
// accepted response.

// If Close races a protocol failure, the first terminal action wins. Err is
// nil if Close wins. Err retains the protocol error if the failure wins.
//
// A submission remains charged until the engine observes that the underlying
// socket consumed its encoded bytes. A gnet asynchronous write callback only
// confirms queueing and does not release this charge. The gnet owner loop must
// observe its outbound buffer before it releases the charge.
//
// Terminal publication has this order:
//
//  1. The link stops accepting submissions and closes its stream.
//  2. The link preserves the first terminal error and clears pending work.
//  3. The link closes Events. Buffered events remain available to its consumer.
//  4. The link publishes LinkStateClosed with all pending counters at zero.
//  5. The link closes Done.
//
// High-water counters never decrease. Err returns the first terminal error
// after a failure and nil after an explicit orderly Close. TrySubmit returns
// ErrLinkNotReady before Start completes. It returns ErrLinkClosed during and
// after terminal publication. Neither rejection takes payload ownership.
//
// SubmissionReady returns one stable, single-consumer notification channel.
// The channel receives a nonblocking coalesced signal after pending submission
// item or byte charge is released while the link remains ready. A signal means
// a previously backpressured submission may now fit; it is not a reservation,
// and false positives are allowed. Consumers must retry TrySubmit and wait for
// a later signal after another ErrLinkBackpressure. The channel carries no
// payload and is never closed. Consumers must select it together with Done;
// after terminal publication, at most one already-coalesced signal remains and
// no new signals are sent.
type ClientLink interface {
	Start(context.Context) error
	TrySubmit(LinkSubmission) error
	SubmissionReady() <-chan struct{}
	Events() <-chan LinkEvent
	Snapshot() LinkSnapshot
	Done() <-chan struct{}
	Err() error
	Close() error
}

func signalSubmissionReady(ready chan<- struct{}) {
	select {
	case ready <- struct{}{}:
	default:
	}
}

func parseLinkEvent(payload []byte) (LinkEvent, error) {
	operation, err := ParseRPCOperation(payload)
	if err != nil {
		return LinkEvent{}, err
	}
	switch operation {
	case OperationProxyAnswer:
		answer, err := ParseProxyAnswer(payload)
		if err != nil {
			return LinkEvent{}, err
		}
		return LinkEvent{
			Kind:         LinkEventProxyAnswer,
			ConnectionID: answer.ConnectionID,
			AnswerFlags:  answer.Flags,
			Packet:       answer.Packet,
		}, nil
	case OperationSimpleAck:
		ack, err := ParseSimpleAck(payload)
		if err != nil {
			return LinkEvent{}, err
		}
		return LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: ack.ConnectionID, ConfirmKey: ack.ConfirmKey}, nil
	case OperationCloseExternal:
		closeEvent, err := ParseCloseExternal(payload)
		if err != nil {
			return LinkEvent{}, err
		}
		return LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: closeEvent.ConnectionID}, nil
	case OperationPing:
		ping, err := ParsePing(payload)
		if err != nil {
			return LinkEvent{}, err
		}
		return LinkEvent{Kind: LinkEventPing, KeepaliveID: ping.ID}, nil
	case OperationPong:
		pong, err := ParsePong(payload)
		if err != nil {
			return LinkEvent{}, err
		}
		return LinkEvent{Kind: LinkEventPong, KeepaliveID: pong.ID}, nil
	default:
		return LinkEvent{}, fmt.Errorf("%w: inbound operation %08x", ErrUnexpectedLinkRPC, operation)
	}
}
