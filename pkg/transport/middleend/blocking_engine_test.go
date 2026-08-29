package middleend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func TestBlockingClientLinkEngineConformance(t *testing.T) {
	runClientLinkConformance(t, newBlockingEngineForTest)
}

func newBlockingEngineForTest(
	conn net.Conn,
	bootstrap *ClientBootstrap,
	limits LinkLimits,
) (ClientLink, error) {
	return NewBlockingClientLinkEngine(conn, bootstrap, limits)
}

func TestBlockingClientLinkEngineFormattingRedactsState(t *testing.T) {
	conn := &redactionConn{}
	link, err := NewBlockingClientLinkEngine(conn, newTestBootstrap(t), LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	secretMarker := strings.Repeat("ab", 16)
	link.submissions = []*blockingSubmission{{value: LinkSubmission{Payload: bytes.Repeat([]byte{0xab}, 16)}}}
	type enclosing struct {
		Link *BlockingClientLinkEngine
	}
	for name, value := range map[string]any{
		"pointer":   link,
		"enclosing": enclosing{Link: link},
	} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			if !strings.Contains(output, "redacted") || strings.Contains(strings.ToLower(output), secretMarker) {
				t.Fatalf("%s format %s disclosed state: %s", name, format, output)
			}
		}
	}
	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBlockingClientLinkEngineRejectsInvalidConstructorInputs(t *testing.T) {
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: 1,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      1,
	}
	if _, err := NewBlockingClientLinkEngine(nil, newTestBootstrap(t), limits); err == nil {
		t.Fatal("nil connection was accepted")
	}
	if _, err := NewBlockingClientLinkEngine(&redactionConn{}, nil, limits); err == nil {
		t.Fatal("nil bootstrap was accepted")
	}
	limits.MaxPendingEvents = 0
	if _, err := NewBlockingClientLinkEngine(&redactionConn{}, newTestBootstrap(t), limits); !errors.Is(err, ErrInvalidLinkLimits) {
		t.Fatalf("invalid limits error = %v", err)
	}

	maximumInt := int(^uint(0) >> 1)
	for _, test := range []struct {
		name   string
		mutate func(*LinkLimits)
	}{
		{name: "submission cap plus one", mutate: func(l *LinkLimits) { l.MaxPendingSubmissions = MaxLinkQueueItems + 1 }},
		{name: "event cap plus one", mutate: func(l *LinkLimits) { l.MaxPendingEvents = MaxLinkQueueItems + 1 }},
		{name: "maximum int", mutate: func(l *LinkLimits) { l.MaxPendingEvents = maximumInt }},
		{name: "maximum int minus one", mutate: func(l *LinkLimits) { l.MaxPendingSubmissions = maximumInt - 1 }},
		{name: "submission byte overflow", mutate: func(l *LinkLimits) { l.MaxPendingSubmissionBytes = maximumInt }},
		{name: "event byte overflow", mutate: func(l *LinkLimits) { l.MaxPendingEventBytes = maximumInt - 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := LinkLimits{
				MaxPendingSubmissions:     1,
				MaxPendingSubmissionBytes: 1,
				MaxPendingEvents:          1,
				MaxPendingEventBytes:      1,
			}
			test.mutate(&candidate)
			if _, err := NewBlockingClientLinkEngine(&redactionConn{}, newTestBootstrap(t), candidate); !errors.Is(err, ErrInvalidLinkLimits) {
				t.Fatalf("constructor error = %v, want %v", err, ErrInvalidLinkLimits)
			}
		})
	}

	atCap := LinkLimits{
		MaxPendingSubmissions:     MaxLinkQueueItems,
		MaxPendingSubmissionBytes: MaxLinkQueueBytes,
		MaxPendingEvents:          MaxLinkQueueItems,
		MaxPendingEventBytes:      MaxLinkQueueBytes,
	}
	link, err := NewBlockingClientLinkEngine(&redactionConn{}, newTestBootstrap(t), atCap)
	if err != nil {
		t.Fatalf("at-cap constructor: %v", err)
	}
	if err := link.Close(); err != nil {
		t.Fatalf("close at-cap link: %v", err)
	}
}

func TestBlockingClientLinkEngineEagerMetadataBudget(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("documented eager metadata derivation is for 64-bit architectures")
	}
	perEvent := unsafe.Sizeof(LinkEvent{}) +
		unsafe.Sizeof((*blockingWriteJob)(nil)) +
		unsafe.Sizeof(blockingWriteResult{})
	if perEvent != 88 {
		t.Fatalf("blocking eager metadata = %d bytes/item, documentation assumes 88", perEvent)
	}
	total := unsafe.Sizeof(LinkEvent{})*MaxLinkQueueItems +
		unsafe.Sizeof((*blockingWriteJob)(nil))*(MaxLinkQueueItems+1) +
		unsafe.Sizeof(blockingWriteResult{})*(MaxLinkQueueItems+1)
	if total != 360480 {
		t.Fatalf("blocking eager channel element cap = %d, want 360480", total)
	}
}

func TestBlockingClientLinkEngineWriteNWithErrorIsTerminal(t *testing.T) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	want := errors.New("injected partial write")
	conn := &partialErrorNetConn{Conn: clientConn, err: want}
	link, err := NewBlockingClientLinkEngine(conn, newTestBootstrap(t), LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := link.Start(newHarnessContext(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	conn.enabled.Store(true)
	if err := link.TrySubmit(LinkSubmission{SubmissionID: 1, Payload: (Ping{ID: 7}).MarshalBinary()}); err != nil {
		t.Fatalf("TrySubmit: %v", err)
	}
	waitLinkDone(t, link)
	if !errors.Is(link.Err(), want) {
		t.Fatalf("terminal error = %v, want %v", link.Err(), want)
	}
	if count := conn.partialCount.Load(); count != 1 {
		t.Fatalf("partial write attempts = %d, want 1", count)
	}
	if snapshot := link.Snapshot(); snapshot.State != LinkStateClosed ||
		snapshot.PendingSubmissions != 0 || snapshot.PendingSubmissionBytes != 0 ||
		snapshot.SubmissionHighWater != 1 || snapshot.SubmissionBytesHighWater != KeepalivePayloadSize {
		t.Fatalf("terminal snapshot = %+v", snapshot)
	}
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertFakePeerRaceCompletion(t, peer)
}

func TestBlockingClientLinkEngineStartCancellationIsShared(t *testing.T) {
	conn := newBlockingReadConn()
	link, err := NewBlockingClientLinkEngine(conn, newTestBootstrap(t), LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	first := make(chan error, 1)
	go func() { first <- link.Start(ctx) }()
	receiveSignal(t, conn.readStarted, "blocking engine bootstrap read")
	cancel()
	firstResult := receiveError(t, first, "canceled blocking engine Start")
	if !errors.Is(firstResult, context.Canceled) {
		t.Fatalf("Start result = %v, want cancellation", firstResult)
	}
	waitLinkDone(t, link)
	if !sameError(firstResult, link.Start(t.Context())) || !sameError(firstResult, link.Err()) {
		t.Fatalf("shared results = Start %v, repeated %v, Err %v", firstResult, link.Start(t.Context()), link.Err())
	}
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestBlockingClientLinkEngineCloseInterruptsBlockedWrite(t *testing.T) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{mode: fakePeerHoldAfterReady})
	workload := deterministicLinkWorkload(t)
	item := workload.items[len(workload.items)-1]
	link, err := NewBlockingClientLinkEngine(clientConn, newTestBootstrap(t), LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: item.submission.ByteSize(),
		MaxPendingEvents:          2,
		MaxPendingEventBytes:      MaxMEFrameSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := link.Start(newHarnessContext(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := link.TrySubmit(item.submission); err != nil {
		t.Fatalf("TrySubmit: %v", err)
	}
	peer.readOneAndHold(t)

	const callers = 16
	results := make(chan error, callers)
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Go(func() { results <- link.Close() })
	}
	if err := waitGroupBounded(&waitGroup, 5*time.Second, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}); err != nil {
		t.Fatalf("concurrent Close: %v", err)
	}
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("Close result: %v", err)
		}
	}
	receiveSignal(t, link.readerDone, "blocking engine reader termination")
	receiveSignal(t, link.writerDone, "blocking engine writer termination")
	if link.Err() != nil {
		t.Fatalf("explicit Close lost terminal race: %v", link.Err())
	}
	if snapshot := link.Snapshot(); snapshot.State != LinkStateClosed ||
		snapshot.PendingSubmissions != 0 || snapshot.PendingSubmissionBytes != 0 {
		t.Fatalf("terminal snapshot = %+v", snapshot)
	}
	peer.stopHolding()
	assertFakePeerRaceCompletion(t, peer)
}

func TestBlockingClientLinkEngineCloseRetiresReadyBootstrapAndPreservesEvents(t *testing.T) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	item := deterministicLinkWorkload(t).items[0]
	answerBytes := (LinkEvent{Kind: LinkEventProxyAnswer, Packet: item.wantPacket}).ByteSize()
	bootstrap := newTestBootstrap(t)
	link, err := NewBlockingClientLinkEngine(clientConn, bootstrap, LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: item.submission.ByteSize(),
		MaxPendingEvents:          2,
		MaxPendingEventBytes:      answerBytes + SimpleAckPayloadSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := link.Start(newHarnessContext(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	owned := captureReadyBootstrapState(t, bootstrap)
	if err := link.TrySubmit(item.submission); err != nil {
		t.Fatalf("TrySubmit: %v", err)
	}
	waitForLinkSnapshot(t, link, func(snapshot LinkSnapshot) bool {
		return snapshot.PendingSubmissions == 0 && snapshot.PendingEvents == 2
	})
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertRetiredBootstrapState(t, bootstrap, owned)

	events := make([]LinkEvent, 0, 2)
	for event := range link.Events() {
		events = append(events, event)
	}
	if len(events) != 2 || events[0].Kind != LinkEventProxyAnswer ||
		!bytes.Equal(events[0].Packet, item.wantPacket) || events[1].Kind != LinkEventSimpleAck {
		t.Fatalf("preserved events = %+v", events)
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func TestBlockingClientLinkEngineCleanEOFRetiresReadyBootstrap(t *testing.T) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{mode: fakePeerCloseAfterReady})
	bootstrap := newTestBootstrap(t)
	link, err := NewBlockingClientLinkEngine(clientConn, bootstrap, LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := link.Start(newHarnessContext(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	owned := captureReadyBootstrapState(t, bootstrap)
	if err := link.TrySubmit(LinkSubmission{SubmissionID: 1, Payload: (Ping{ID: 19}).MarshalBinary()}); err != nil {
		t.Fatalf("TrySubmit: %v", err)
	}
	waitLinkDone(t, link)
	if !errors.Is(link.Err(), io.EOF) {
		t.Fatalf("terminal error = %v, want EOF", link.Err())
	}
	assertRetiredBootstrapState(t, bootstrap, owned)
	events := make([]LinkEvent, 0, 1)
	for event := range link.Events() {
		events = append(events, event)
	}
	if len(events) != 1 || events[0].Kind != LinkEventPong || events[0].KeepaliveID != 19 {
		t.Fatalf("preserved EOF events = %+v", events)
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

type readyBootstrapState struct {
	encoder   *FrameEncoder
	decoder   *FrameDecoder
	encrypter *CBCEncrypter
	decrypter *CBCDecrypter
}

func captureReadyBootstrapState(t testing.TB, bootstrap *ClientBootstrap) readyBootstrapState {
	t.Helper()
	if !bootstrap.Ready() || bootstrap.encoder == nil || bootstrap.decoder == nil ||
		bootstrap.encrypter == nil || bootstrap.decrypter == nil {
		t.Fatalf("bootstrap was not fully ready: stage=%d", bootstrap.stage)
	}
	return readyBootstrapState{
		encoder: bootstrap.encoder, decoder: bootstrap.decoder,
		encrypter: bootstrap.encrypter, decrypter: bootstrap.decrypter,
	}
}

func assertRetiredBootstrapState(t testing.TB, bootstrap *ClientBootstrap, owned readyBootstrapState) {
	t.Helper()
	if bootstrap.stage != clientBootstrapRetired || bootstrap.Ready() || bootstrap.err != nil {
		t.Fatalf("retired bootstrap stage=%d ready=%t error=%v", bootstrap.stage, bootstrap.Ready(), bootstrap.err)
	}
	if bootstrap.config.Secret != nil || bootstrap.config.NonceSource != nil ||
		bootstrap.config.ServerAddr.IsValid() || bootstrap.config.ClientAddr.IsValid() ||
		bootstrap.config.LocalProcessID != (ProcessID{}) || bootstrap.config.ClientTimestamp != 0 ||
		bootstrap.selector != 0 || bootstrap.clientNonce != ([16]byte{}) || bootstrap.nonceBuffer != nil ||
		bootstrap.encoder != nil || bootstrap.decoder != nil || bootstrap.encrypter != nil || bootstrap.decrypter != nil ||
		bootstrap.localHandshake != (HandshakePacket{}) || bootstrap.remoteProcessID != (ProcessID{}) {
		t.Fatal("retired bootstrap retained connection-owned state")
	}
	if *owned.encoder != (FrameEncoder{}) ||
		owned.decoder.buffer != nil || owned.decoder.nextSequence != 0 || owned.decoder.maxFrameSize != 0 ||
		owned.decoder.mode != 0 || owned.decoder.peerHandshake != (HandshakePacket{}) ||
		owned.decoder.checksumTransitionOpen || owned.decoder.checksumTransitionDone ||
		owned.decoder.exhausted || owned.decoder.err != nil ||
		owned.encrypter.mode != nil || owned.decrypter.mode != nil || owned.decrypter.pending != nil {
		t.Fatal("retired bootstrap left data in detached protocol owners")
	}
	if _, err := bootstrap.Encode((Ping{ID: 1}).MarshalBinary()); !errors.Is(err, ErrBootstrapState) {
		t.Fatalf("Encode after retirement error = %v", err)
	}
}

type redactionConn struct {
	closeOnce sync.Once
}

type partialErrorNetConn struct {
	net.Conn
	enabled      atomic.Bool
	partialCount atomic.Int32
	err          error
}

func (c *partialErrorNetConn) Write(data []byte) (int, error) {
	if !c.enabled.Load() || !c.partialCount.CompareAndSwap(0, 1) {
		return c.Conn.Write(data)
	}
	written, err := c.Conn.Write(data[:min(5, len(data))])
	if err != nil {
		return written, err
	}
	return written, c.err
}

func (*redactionConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (*redactionConn) Write(data []byte) (int, error)   { return len(data), nil }
func (*redactionConn) LocalAddr() net.Addr              { return dummyNetAddr("local") }
func (*redactionConn) RemoteAddr() net.Addr             { return dummyNetAddr("remote") }
func (*redactionConn) SetDeadline(time.Time) error      { return nil }
func (*redactionConn) SetReadDeadline(time.Time) error  { return nil }
func (*redactionConn) SetWriteDeadline(time.Time) error { return nil }
func (c *redactionConn) Close() error {
	c.closeOnce.Do(func() {})
	return nil
}
