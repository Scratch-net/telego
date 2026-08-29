package middleend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/panjf2000/gnet/v2"
)

func TestGnetClientLinkConformance(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	factory := func(conn net.Conn, bootstrap *ClientBootstrap, limits LinkLimits) (ClientLink, error) {
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			return nil, errors.New("gnet conformance requires a concrete TCP connection")
		}
		return gnetRuntime.NewClientLink(tcpConn, bootstrap, limits)
	}
	runClientLinkConformance(t, factory)
}

func TestGnetStartReadyPublicationDetachesSimultaneouslyCanceledContext(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	for iteration := range 100 {
		clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
		clientLink, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), newTestBootstrap(t), limits)
		if err != nil {
			t.Fatalf("iteration %d NewClientLink: %v", iteration, err)
		}
		link := clientLink.(*GnetClientLink)
		ctx := newCancelWhenReadyContext(link.startDone)
		if err := link.Start(ctx); err != nil {
			t.Fatalf("iteration %d Start: %v", iteration, err)
		}
		if snapshot := link.Snapshot(); snapshot.State != LinkStateReady {
			t.Fatalf("iteration %d state = %d, want ready", iteration, snapshot.State)
		}
		if err := link.Err(); err != nil {
			t.Fatalf("iteration %d terminal error after ready/cancel barrier = %v", iteration, err)
		}
		if err := link.Close(); err != nil {
			t.Fatalf("iteration %d Close: %v", iteration, err)
		}
		if err := waitFakePeer(t, peer); err != nil {
			t.Fatalf("iteration %d fake peer: %v", iteration, err)
		}
	}
}

type cancelWhenReadyContext struct {
	ready    <-chan struct{}
	canceled chan struct{}
	once     sync.Once
}

func newCancelWhenReadyContext(ready <-chan struct{}) *cancelWhenReadyContext {
	return &cancelWhenReadyContext{ready: ready, canceled: make(chan struct{})}
}

func (*cancelWhenReadyContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (c *cancelWhenReadyContext) Done() <-chan struct{} {
	<-c.ready
	c.once.Do(func() { close(c.canceled) })
	return c.canceled
}

func (c *cancelWhenReadyContext) Err() error {
	select {
	case <-c.canceled:
		return context.Canceled
	default:
		return nil
	}
}

func (*cancelWhenReadyContext) Value(any) any {
	return nil
}

func TestGnetClientRuntimeConfigRequiresExplicitSupportedEventLoops(t *testing.T) {
	if err := (GnetClientRuntimeConfig{EventLoops: MaxGnetClientEventLoops}).Validate(); err != nil {
		t.Fatalf("maximum supported event loops were rejected: %v", err)
	}
	for _, eventLoops := range []int{-1, 0, MaxGnetClientEventLoops + 1} {
		if _, err := NewGnetClientRuntime(GnetClientRuntimeConfig{EventLoops: eventLoops}); !errors.Is(err, ErrInvalidGnetRuntimeConfig) {
			t.Fatalf("NewGnetClientRuntime with %d event loops error = %v", eventLoops, err)
		}
	}
}

func TestGnetClientOptionsPinAuditedBufferCaps(t *testing.T) {
	config := GnetClientRuntimeConfig{EventLoops: 3}
	var options gnet.Options
	for _, option := range gnetClientOptions(config) {
		option(&options)
	}
	if options.NumEventLoop != config.EventLoops || options.TCPNoDelay != gnet.TCPNoDelay {
		t.Fatalf("gnet client options = loops %d no-delay %d", options.NumEventLoop, options.TCPNoDelay)
	}
	if options.ReadBufferCap != gnetClientReadBufferCap || options.WriteBufferCap != gnetClientWriteBufferCap {
		t.Fatalf("gnet client buffer caps = read %d write %d, want %d and %d", options.ReadBufferCap, options.WriteBufferCap, gnetClientReadBufferCap, gnetClientWriteBufferCap)
	}
}

func TestMaximumGnetOutboundBytes(t *testing.T) {
	limits := LinkLimits{
		MaxPendingSubmissions:     3,
		MaxPendingSubmissionBytes: 4096,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      1,
	}
	want := limits.MaxPendingSubmissionBytes + limits.MaxPendingSubmissions*maxLinkSubmissionWireOverhead +
		max(gnetEncryptedPongSize, limits.MaxPendingEventBytes)
	if got, err := maximumGnetOutboundBytes(limits); err != nil || got != want {
		t.Fatalf("maximumGnetOutboundBytes = %d, %v; want %d", got, err, want)
	}

	limits.MaxPendingSubmissions = int(^uint(0) >> 1)
	if _, err := maximumGnetOutboundBytes(limits); !errors.Is(err, ErrInvalidLinkLimits) {
		t.Fatalf("overflow error = %v, want %v", err, ErrInvalidLinkLimits)
	}
}

func TestGnetSlowPeerKeepsOnlyOneEncodedBatchInUserSpace(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{mode: fakePeerHoldAfterReady})
	workload := deterministicLinkWorkload(t)
	item := workload.items[len(workload.items)-1]
	limits := LinkLimits{
		MaxPendingSubmissions:     3,
		MaxPendingSubmissionBytes: 3 * item.submission.ByteSize(),
		MaxPendingEvents:          8,
		MaxPendingEventBytes: 3 * ((LinkEvent{Kind: LinkEventProxyAnswer, Packet: item.wantPacket}).ByteSize() +
			(LinkEvent{Kind: LinkEventSimpleAck}).ByteSize()),
	}
	clientLink, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), newTestBootstrap(t), limits)
	if err != nil {
		t.Fatalf("NewClientLink: %v", err)
	}
	link := clientLink.(*GnetClientLink)
	if err := link.Start(newHarnessContext(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for index := range 3 {
		submission := item.submission
		submission.SubmissionID += uint64(index)
		submission.Payload = slices.Clone(item.submission.Payload)
		if err := link.TrySubmit(submission); err != nil {
			t.Fatalf("TrySubmit %d: %v", index, err)
		}
	}

	deadline := time.Now().Add(time.Second)
	for {
		link.mu.Lock()
		queued := len(link.submissions)
		link.mu.Unlock()
		if queued == 2 {
			break
		}
		if queued < 2 {
			t.Fatalf("queued submissions = %d before the peer read, want 2", queued)
		}
		if time.Now().After(deadline) {
			t.Fatalf("first encoded batch was not submitted; queued submissions = %d", queued)
		}
		time.Sleep(time.Millisecond)
	}
	stable := time.NewTimer(50 * time.Millisecond)
	defer stable.Stop()
	for {
		select {
		case <-stable.C:
			goto releasePeer
		default:
		}
		link.mu.Lock()
		queued := len(link.submissions)
		link.mu.Unlock()
		if queued != 2 {
			t.Fatalf("queued submissions changed to %d while the first batch was buffered", queued)
		}
		time.Sleep(time.Millisecond)
	}

releasePeer:
	peer.stopHolding()
	for range 6 {
		receiveLinkEvent(t, link)
	}
	waitForLinkSnapshot(t, link, func(snapshot LinkSnapshot) bool {
		return snapshot.PendingSubmissions == 0 && snapshot.PendingSubmissionBytes == 0 &&
			snapshot.PendingEvents == 0 && snapshot.PendingEventBytes == 0
	})
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func TestGnetClientRuntimeRejectsSharedLimitCeilingViolations(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	valid := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: 1,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      1,
	}
	tests := []struct {
		name   string
		mutate func(*LinkLimits)
	}{
		{name: "submission items", mutate: func(limits *LinkLimits) { limits.MaxPendingSubmissions = MaxLinkQueueItems + 1 }},
		{name: "event items", mutate: func(limits *LinkLimits) { limits.MaxPendingEvents = MaxLinkQueueItems + 1 }},
		{name: "submission bytes", mutate: func(limits *LinkLimits) { limits.MaxPendingSubmissionBytes = MaxLinkQueueBytes + 1 }},
		{name: "event bytes", mutate: func(limits *LinkLimits) { limits.MaxPendingEventBytes = MaxLinkQueueBytes + 1 }},
		{name: "extreme values", mutate: func(limits *LinkLimits) {
			limits.MaxPendingSubmissions = int(^uint(0) >> 1)
			limits.MaxPendingSubmissionBytes = int(^uint(0) >> 1)
			limits.MaxPendingEvents = int(^uint(0) >> 1)
			limits.MaxPendingEventBytes = int(^uint(0) >> 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := valid
			test.mutate(&limits)
			clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
			if _, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), newTestBootstrap(t), limits); !errors.Is(err, ErrInvalidLinkLimits) {
				t.Fatalf("NewClientLink error = %v, want %v", err, ErrInvalidLinkLimits)
			}
			_ = clientConn.Close()
			if err := waitFakePeer(t, peer); err != nil && !errors.Is(err, io.EOF) {
				t.Fatalf("fake peer: %v", err)
			}
		})
	}
}

func TestGnetClientRuntimeConstructorTransfersTCPOnlyOnSuccess(t *testing.T) {
	valid := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	t.Run("nil runtime", func(t *testing.T) {
		clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
		tcpConn := clientConn.(*net.TCPConn)
		var gnetRuntime *GnetClientRuntime
		if _, err := gnetRuntime.NewClientLink(tcpConn, newTestBootstrap(t), valid); !errors.Is(err, ErrInvalidGnetLink) {
			t.Fatalf("NewClientLink error = %v", err)
		}
		assertTCPConnOpen(t, tcpConn)
		_ = tcpConn.Close()
		assertPeerSawConstructorClose(t, peer)
	})

	t.Run("nil bootstrap", func(t *testing.T) {
		gnetRuntime := newTestGnetRuntime(t)
		clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
		tcpConn := clientConn.(*net.TCPConn)
		if _, err := gnetRuntime.NewClientLink(tcpConn, nil, valid); !errors.Is(err, ErrInvalidGnetLink) {
			t.Fatalf("NewClientLink error = %v", err)
		}
		assertTCPConnOpen(t, tcpConn)
		_ = tcpConn.Close()
		assertPeerSawConstructorClose(t, peer)
	})

	t.Run("invalid limits", func(t *testing.T) {
		gnetRuntime := newTestGnetRuntime(t)
		clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
		tcpConn := clientConn.(*net.TCPConn)
		if _, err := gnetRuntime.NewClientLink(tcpConn, newTestBootstrap(t), LinkLimits{}); !errors.Is(err, ErrInvalidLinkLimits) {
			t.Fatalf("NewClientLink error = %v", err)
		}
		assertTCPConnOpen(t, tcpConn)
		_ = tcpConn.Close()
		assertPeerSawConstructorClose(t, peer)
	})

	t.Run("stopped runtime", func(t *testing.T) {
		gnetRuntime := newTestGnetRuntime(t)
		stopTestGnetRuntime(t, gnetRuntime)
		clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
		tcpConn := clientConn.(*net.TCPConn)
		if _, err := gnetRuntime.NewClientLink(tcpConn, newTestBootstrap(t), valid); !errors.Is(err, ErrGnetRuntimeStopped) {
			t.Fatalf("NewClientLink error = %v", err)
		}
		assertTCPConnOpen(t, tcpConn)
		_ = tcpConn.Close()
		assertPeerSawConstructorClose(t, peer)
	})

	t.Run("successful enrollment", func(t *testing.T) {
		gnetRuntime := newTestGnetRuntime(t)
		clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
		tcpConn := clientConn.(*net.TCPConn)
		clientLink, err := gnetRuntime.NewClientLink(tcpConn, newTestBootstrap(t), valid)
		if err != nil {
			t.Fatalf("NewClientLink: %v", err)
		}
		if err := clientLink.Start(newHarnessContext(t)); err != nil {
			t.Fatalf("Start: %v", err)
		}
		if err := tcpConn.SetDeadline(time.Now().Add(time.Second)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("original TCPConn SetDeadline after enrollment = %v, want %v", err, net.ErrClosed)
		}
		if err := clientLink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := waitFakePeer(t, peer); err != nil {
			t.Fatalf("fake peer: %v", err)
		}
	})
}

func TestGnetOnOpenNonceFailureDoesNotDeadlockEnrollment(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	baselineFDs := 0
	if runtime.GOOS == "linux" {
		baselineFDs = countOpenFileDescriptors(t)
	}
	baselineGoroutines := runtime.NumGoroutine()
	clientConn, peerDone := dialPassiveTCP(t)
	original := errors.New("injected nonce source failure")
	config := testBootstrapConfig()
	config.NonceSource = iotest.ErrReader(original)
	bootstrap, err := NewClientBootstrap(config)
	if err != nil {
		t.Fatalf("NewClientBootstrap: %v", err)
	}
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	clientLink, err := gnetRuntime.NewClientLink(clientConn, bootstrap, limits)
	if err != nil {
		t.Fatalf("NewClientLink: %v", err)
	}
	link := clientLink.(*GnetClientLink)
	startResult := make(chan error, 1)
	go func() { startResult <- link.Start(newHarnessContext(t)) }()
	select {
	case err := <-startResult:
		if !errors.Is(err, original) {
			t.Fatalf("Start error = %v, want original nonce error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start deadlocked during synchronous OnOpen failure")
	}
	waitLinkDone(t, link)
	if !errors.Is(link.Err(), original) {
		t.Fatalf("terminal error = %v, want original nonce error", link.Err())
	}
	if bootstrap.stage != clientBootstrapFailed || bootstrap.config.NonceSource != nil ||
		bootstrap.encoder != nil || bootstrap.decoder != nil || bootstrap.encrypter != nil ||
		bootstrap.decrypter != nil || len(bootstrap.config.Secret) != 0 {
		t.Fatal("nonce failure retained bootstrap state")
	}
	gnetRuntime.mu.Lock()
	_, registered := gnetRuntime.links[link]
	gnetRuntime.mu.Unlock()
	if registered {
		t.Fatal("nonce failure left link registered")
	}
	waitPassiveTCPPeer(t, peerDone)
	waitForGoroutineCount(t, baselineGoroutines+2)
	if runtime.GOOS == "linux" {
		waitForOpenFileDescriptorCount(t, baselineFDs)
	}
	stopTestGnetRuntime(t, gnetRuntime)
}

func TestGnetClientRuntimeConcurrentEnrollAndStop(t *testing.T) {
	for _, test := range []struct {
		name       string
		nonceError bool
	}{
		{name: "successful OnOpen"},
		{name: "failing OnOpen", nonceError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			for iteration := range 20 {
				gnetRuntime, err := NewGnetClientRuntime(GnetClientRuntimeConfig{EventLoops: 1})
				if err != nil {
					t.Fatalf("iteration %d NewGnetClientRuntime: %v", iteration, err)
				}
				baselineGoroutines := runtime.NumGoroutine()
				baselineFDs := 0
				if runtime.GOOS == "linux" {
					baselineFDs = countOpenFileDescriptors(t)
				}
				clientConn, peerDone := dialPassiveTCP(t)
				gate := newGatedNonceReader(test.nonceError)
				config := testBootstrapConfig()
				config.NonceSource = gate
				bootstrap, err := NewClientBootstrap(config)
				if err != nil {
					t.Fatalf("iteration %d NewClientBootstrap: %v", iteration, err)
				}
				limits := LinkLimits{
					MaxPendingSubmissions:     1,
					MaxPendingSubmissionBytes: KeepalivePayloadSize,
					MaxPendingEvents:          1,
					MaxPendingEventBytes:      KeepalivePayloadSize,
				}
				clientLink, err := gnetRuntime.NewClientLink(clientConn, bootstrap, limits)
				if err != nil {
					t.Fatalf("iteration %d NewClientLink: %v", iteration, err)
				}
				link := clientLink.(*GnetClientLink)
				startResult := make(chan error, 1)
				go func() { startResult <- link.Start(newHarnessContext(t)) }()
				receiveSignal(t, gate.entered, "gnet enrollment OnOpen")
				stopResult := make(chan error, 1)
				go func() {
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					stopResult <- gnetRuntime.Stop(ctx)
				}()
				waitForGnetRuntimeStopping(t, gnetRuntime)
				gate.release()
				var startErr error
				select {
				case startErr = <-startResult:
				case <-time.After(5 * time.Second):
					t.Fatalf("iteration %d Start did not return", iteration)
				}
				select {
				case err := <-stopResult:
					if err != nil {
						t.Fatalf("iteration %d Stop: %v", iteration, err)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("iteration %d Stop did not return", iteration)
				}
				waitLinkDone(t, link)
				terminalErr := link.Err()
				switch {
				case test.nonceError && errors.Is(startErr, gate.err):
					if !errors.Is(terminalErr, gate.err) {
						t.Fatalf("iteration %d bootstrap won with Start error %v but terminal error = %v", iteration, startErr, terminalErr)
					}
				case errors.Is(startErr, ErrLinkClosed):
					if terminalErr != nil {
						t.Fatalf("iteration %d Stop won with Start error %v but terminal error = %v", iteration, startErr, terminalErr)
					}
				default:
					t.Fatalf("iteration %d incoherent Start/terminal errors = %v / %v", iteration, startErr, terminalErr)
				}
				gnetRuntime.mu.Lock()
				remaining := len(gnetRuntime.links)
				gnetRuntime.mu.Unlock()
				if remaining != 0 {
					t.Fatalf("iteration %d registered links = %d, want zero", iteration, remaining)
				}
				waitPassiveTCPPeer(t, peerDone)
				waitForGoroutineCount(t, baselineGoroutines+2)
				if runtime.GOOS == "linux" {
					waitForOpenFileDescriptorCount(t, baselineFDs)
				}
			}
		})
	}
}

func assertTCPConnOpen(t testing.TB, conn *net.TCPConn) {
	t.Helper()
	if err := conn.SetNoDelay(true); err != nil {
		t.Fatalf("caller TCPConn was closed on constructor error: %v", err)
	}
}

func assertPeerSawConstructorClose(t testing.TB, peer *fakeMiddleEndPeer) {
	t.Helper()
	if err := waitFakePeer(t, peer); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("fake peer after caller close: %v", err)
	}
}

func waitForGnetRuntimeStopping(t testing.TB, gnetRuntime *GnetClientRuntime) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		gnetRuntime.mu.Lock()
		stopping := gnetRuntime.stopping
		gnetRuntime.mu.Unlock()
		if stopping {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("gnet runtime did not start stopping")
		}
	}
}

func TestGnetTypesRedactNestedState(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	clientLink, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), newTestBootstrap(t), limits)
	if err != nil {
		t.Fatalf("NewClientLink: %v", err)
	}
	link := clientLink.(*GnetClientLink)
	for name, value := range map[string]any{"runtime": gnetRuntime, "link": link} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, value); output != fmt.Sprintf("middleend.%s{redacted}", map[string]string{"runtime": "GnetClientRuntime", "link": "GnetClientLink"}[name]) {
				t.Fatalf("%s with %s = %q", name, format, output)
			}
		}
	}
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := waitFakePeer(t, peer); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("fake peer: %v", err)
	}
}

func TestGnetClientLinkLifecycleStatePrecedesPayloadValidation(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	clientLink, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), newTestBootstrap(t), limits)
	if err != nil {
		t.Fatalf("NewClientLink: %v", err)
	}
	invalid := LinkSubmission{}
	if err := clientLink.TrySubmit(invalid); !errors.Is(err, ErrLinkNotReady) {
		t.Fatalf("pre-start TrySubmit error = %v", err)
	}
	if err := clientLink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := clientLink.TrySubmit(invalid); !errors.Is(err, ErrLinkClosed) {
		t.Fatalf("post-close TrySubmit error = %v", err)
	}
	if err := waitFakePeer(t, peer); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("fake peer: %v", err)
	}
}

func TestGnetClientLinkRetiresBootstrapAfterStreamClose(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	bootstrap := newTestBootstrap(t)
	clientLink, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), bootstrap, limits)
	if err != nil {
		t.Fatalf("NewClientLink: %v", err)
	}
	if err := clientLink.Start(newHarnessContext(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := clientLink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if bootstrap.Ready() || bootstrap.encoder != nil || bootstrap.decoder != nil ||
		bootstrap.encrypter != nil || bootstrap.decrypter != nil || len(bootstrap.config.Secret) != 0 {
		t.Fatal("terminal gnet link retained ready bootstrap cryptographic state")
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func TestGnetOwnerFrameCleanupPreservesOnlyTransferredPackets(t *testing.T) {
	packet := []byte{1, 2, 3, 4}
	payload, err := (ProxyAnswer{
		Flags:        ProxyAnswerFlagFlush,
		ConnectionID: 41,
		Packet:       packet,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	payloadBacking := payload
	link := &GnetClientLink{
		state: LinkStateReady,
		limits: LinkLimits{
			MaxPendingSubmissions:     1,
			MaxPendingSubmissionBytes: 1,
			MaxPendingEvents:          1,
			MaxPendingEventBytes:      MaxClientPacketSize,
		},
		events: make(chan LinkEvent, 1),
	}
	frames := []Frame{{Payload: payload}}
	if err := link.processOwnerFrames(nil, frames); err != nil {
		t.Fatalf("processOwnerFrames: %v", err)
	}
	if frames[0].Sequence != 0 || frames[0].Payload != nil || !allZero(payloadBacking) {
		t.Fatal("consumed frame payload was not cleared")
	}
	rejectedPacket := []byte{9, 8, 7, 6}
	if err := link.enqueueOwnerEvent(LinkEvent{
		Kind:         LinkEventProxyAnswer,
		ConnectionID: 42,
		Packet:       rejectedPacket,
	}); !errors.Is(err, ErrLinkEventBackpressure) {
		t.Fatalf("rejected event error = %v, want %v", err, ErrLinkEventBackpressure)
	}
	if !allZero(rejectedPacket) {
		t.Fatal("rejected cloned event packet was not cleared")
	}
	event := <-link.events
	if !slices.Equal(event.Packet, packet) {
		t.Fatalf("clearing a rejected packet altered transferred packet %v", event.Packet)
	}
}

func TestGnetPeerPingFloodFailsAtControlCaps(t *testing.T) {
	tests := []struct {
		name      string
		itemLimit int
		byteLimit int
		want      error
		wantItems int
		wantBytes int
	}{
		{
			name:      "items",
			itemLimit: 2,
			byteLimit: MaxLinkQueueBytes,
			want:      ErrGnetControlItemBackpressure,
			wantItems: 2,
			wantBytes: 2 * gnetEncryptedPongSize,
		},
		{
			name:      "bytes",
			itemLimit: MaxLinkQueueItems + 1,
			byteLimit: gnetEncryptedPongSize,
			want:      ErrGnetControlByteBackpressure,
			wantItems: 1,
			wantBytes: gnetEncryptedPongSize,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gnetRuntime := newTestGnetRuntime(t)
			clientConn, peer := dialGnetPingFloodPeer(t, 32*MaxLinkQueueItems)
			if err := clientConn.SetWriteBuffer(1024); err != nil {
				t.Fatalf("set client write buffer: %v", err)
			}
			limits := LinkLimits{
				MaxPendingSubmissions:     1,
				MaxPendingSubmissionBytes: KeepalivePayloadSize,
				MaxPendingEvents:          MaxLinkQueueItems,
				MaxPendingEventBytes:      MaxLinkQueueItems * KeepalivePayloadSize,
			}
			clientLink, err := gnetRuntime.NewClientLink(clientConn, newTestBootstrap(t), limits)
			if err != nil {
				t.Fatalf("NewClientLink: %v", err)
			}
			link := clientLink.(*GnetClientLink)
			link.maxControlItems = test.itemLimit
			link.maxControlBytes = test.byteLimit
			if err := link.Start(newHarnessContext(t)); err != nil {
				t.Fatalf("Start: %v", err)
			}

			eventsDrained := make(chan struct{})
			go func() {
				for range link.Events() {
				}
				close(eventsDrained)
			}()
			peer.startFlood()
			waitLinkDone(t, link)
			if !errors.Is(link.Err(), test.want) {
				t.Fatalf("terminal error = %v, want %v", link.Err(), test.want)
			}
			link.mu.Lock()
			itemHighWater := link.ownerControlItemHighWater
			byteHighWater := link.ownerControlByteHighWater
			currentItems := link.ownerControlItems
			currentBytes := link.ownerControlBytes
			segments := len(link.ownerWireSegments)
			link.mu.Unlock()
			if itemHighWater != test.wantItems || byteHighWater != test.wantBytes {
				t.Fatalf("control high-water = (%d items, %d bytes), want (%d, %d)",
					itemHighWater, byteHighWater, test.wantItems, test.wantBytes)
			}
			if currentItems != 0 || currentBytes != 0 || segments != 0 {
				t.Fatalf("terminal control state = (%d items, %d bytes, %d segments), want zero",
					currentItems, currentBytes, segments)
			}
			receiveSignal(t, eventsDrained, "ping flood event drain")
			peer.stop(t)
		})
	}
}

func TestGnetOnCloseFinalizesWithoutLiveOwnerLoop(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	bootstrap := newTestBootstrap(t)
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	clientLink, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), bootstrap, limits)
	if err != nil {
		t.Fatalf("NewClientLink: %v", err)
	}
	link := clientLink.(*GnetClientLink)
	_ = clientConn.Close()
	injected := errors.New("injected dead event loop")
	link.onClose(nil, injected)
	waitLinkDone(t, link)
	if !errors.Is(link.Err(), injected) {
		t.Fatalf("terminal error = %v, want %v", link.Err(), injected)
	}
	if bootstrap.stage != clientBootstrapFailed || bootstrap.encoder != nil || bootstrap.decrypter != nil ||
		bootstrap.encrypter != nil || len(bootstrap.config.Secret) != 0 {
		t.Fatal("dead-loop OnClose retained bootstrap state")
	}
	gnetRuntime.mu.Lock()
	_, registered := gnetRuntime.links[link]
	gnetRuntime.mu.Unlock()
	if registered {
		t.Fatal("dead-loop OnClose left link registered")
	}
	stopTestGnetRuntime(t, gnetRuntime)
	assertPeerSawConstructorClose(t, peer)
}

func TestGnetClientRuntimeStopClosesAllLinks(t *testing.T) {
	gnetRuntime := newTestGnetRuntimeWithEventLoops(t, 2)
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}

	links := make([]ClientLink, 0, 2)
	peers := make([]*fakeMiddleEndPeer, 0, 2)
	for range 2 {
		clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
		tcpConn, ok := clientConn.(*net.TCPConn)
		if !ok {
			t.Fatalf("client connection type = %T, want *net.TCPConn", clientConn)
		}
		link, err := gnetRuntime.NewClientLink(tcpConn, newTestBootstrap(t), limits)
		if err != nil {
			t.Fatalf("NewClientLink: %v", err)
		}
		if err := link.Start(newHarnessContext(t)); err != nil {
			t.Fatalf("Start: %v", err)
		}
		links = append(links, link)
		peers = append(peers, peer)
	}

	stopContext, cancelStop := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelStop()
	if err := gnetRuntime.Stop(stopContext); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for index, link := range links {
		waitLinkDone(t, link)
		if err := link.Err(); err != nil {
			t.Fatalf("link %d terminal error = %v", index, err)
		}
	}
	for index, peer := range peers {
		if err := waitFakePeer(t, peer); err != nil {
			t.Fatalf("peer %d: %v", index, err)
		}
	}

	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	peer.stopHolding()
	_ = clientConn.Close()
	if _, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), newTestBootstrap(t), limits); !errors.Is(err, ErrGnetRuntimeStopped) {
		t.Fatalf("NewClientLink after Stop error = %v, want %v", err, ErrGnetRuntimeStopped)
	}
	if err := waitFakePeer(t, peer); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Fatalf("unused fake peer: %v", err)
	}
}

func TestGnetClientRuntimeConcurrentStopUsesOneResult(t *testing.T) {
	gnetRuntime, err := NewGnetClientRuntime(GnetClientRuntimeConfig{EventLoops: 1})
	if err != nil {
		t.Fatalf("NewGnetClientRuntime: %v", err)
	}

	const callers = 16
	results := make(chan error, callers)
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Go(func() {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			results <- gnetRuntime.Stop(ctx)
		})
	}
	waitGroup.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent Stop: %v", err)
		}
	}
}

func TestGnetClientRuntimeStopContextExpiresWithoutAbandoningShutdown(t *testing.T) {
	gnetRuntime, err := NewGnetClientRuntime(GnetClientRuntimeConfig{EventLoops: 1})
	if err != nil {
		t.Fatalf("NewGnetClientRuntime: %v", err)
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := gnetRuntime.Stop(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Stop error = %v", err)
	}
	ctx, cancelWait := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelWait()
	if err := gnetRuntime.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestGnetClientLinkPollingTerminates(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	tcpConn := clientConn.(*net.TCPConn)
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	clientLink, err := gnetRuntime.NewClientLink(tcpConn, newTestBootstrap(t), limits)
	if err != nil {
		t.Fatalf("NewClientLink: %v", err)
	}
	link := clientLink.(*GnetClientLink)
	if err := link.Start(newHarnessContext(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	const pingID = 0x3132333435363738
	if err := link.TrySubmit(LinkSubmission{SubmissionID: 1, Payload: (Ping{ID: pingID}).MarshalBinary()}); err != nil {
		t.Fatalf("TrySubmit: %v", err)
	}
	event := receiveLinkEvent(t, link)
	if event.Kind != LinkEventPong || event.KeepaliveID != pingID {
		t.Fatalf("event = %v", event)
	}
	waitForLinkSnapshot(t, link, func(snapshot LinkSnapshot) bool {
		return snapshot.PendingSubmissions == 0 && snapshot.PendingEvents == 0
	})
	link.mu.Lock()
	pollScheduled := link.pollScheduled
	pollDelay := link.pollDelay
	pollTimer := link.pollTimer
	drainScheduled := link.drainScheduled
	segments := len(link.ownerWireSegments)
	link.mu.Unlock()
	if pollScheduled || pollDelay != 0 || pollTimer != nil || drainScheduled || segments != 0 {
		t.Fatalf("idle scheduling state: poll=%t delay=%v timer=%v drain=%t segments=%d", pollScheduled, pollDelay, pollTimer, drainScheduled, segments)
	}
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func TestGnetClientRuntimeDoesNotLeakPerLinkSchedulers(t *testing.T) {
	warmup, err := NewGnetClientRuntime(GnetClientRuntimeConfig{EventLoops: 1})
	if err != nil {
		t.Fatalf("warm-up NewGnetClientRuntime: %v", err)
	}
	stopTestGnetRuntime(t, warmup)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	for range 4 {
		gnetRuntime, err := NewGnetClientRuntime(GnetClientRuntimeConfig{EventLoops: 1})
		if err != nil {
			t.Fatalf("NewGnetClientRuntime: %v", err)
		}
		stopTestGnetRuntime(t, gnetRuntime)
	}
	waitForGoroutineCount(t, baseline+2)
}

func TestGnetIndividualCloseRemovesRegistrationAndResources(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("file-descriptor proof uses /proc/self/fd")
	}
	gnetRuntime := newTestGnetRuntime(t)
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	runLink := func(t *testing.T) {
		clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
		clientLink, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), newTestBootstrap(t), limits)
		if err != nil {
			t.Fatalf("NewClientLink: %v", err)
		}
		link := clientLink.(*GnetClientLink)
		if err := link.Start(newHarnessContext(t)); err != nil {
			t.Fatalf("Start: %v", err)
		}
		if err := link.Close(); err != nil {
			t.Fatalf("first Close: %v", err)
		}
		if err := link.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		gnetRuntime.mu.Lock()
		_, registered := gnetRuntime.links[link]
		gnetRuntime.mu.Unlock()
		if registered {
			t.Fatal("Done closed before runtime registration removal")
		}
		if err := waitFakePeer(t, peer); err != nil {
			t.Fatalf("fake peer: %v", err)
		}
	}
	t.Run("warmup", runLink)
	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()
	baselineFDs := countOpenFileDescriptors(t)

	for index := range 32 {
		t.Run(fmt.Sprintf("link-%d", index), runLink)
	}
	waitForGoroutineCount(t, baselineGoroutines+2)
	waitForOpenFileDescriptorCount(t, baselineFDs)
}

func newTestGnetRuntime(t testing.TB) *GnetClientRuntime {
	t.Helper()
	return newTestGnetRuntimeWithEventLoops(t, 1)
}

func newTestGnetRuntimeWithEventLoops(t testing.TB, eventLoops int) *GnetClientRuntime {
	t.Helper()
	gnetRuntime, err := NewGnetClientRuntime(GnetClientRuntimeConfig{EventLoops: eventLoops})
	if err != nil {
		t.Fatalf("NewGnetClientRuntime: %v", err)
	}
	t.Cleanup(func() {
		stopTestGnetRuntime(t, gnetRuntime)
	})
	return gnetRuntime
}

func stopTestGnetRuntime(t testing.TB, gnetRuntime *GnetClientRuntime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := gnetRuntime.Stop(ctx); err != nil {
		t.Errorf("Stop gnet runtime: %v", err)
	}
}

func waitForGoroutineCount(t testing.TB, maximum int) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if count := runtime.NumGoroutine(); count <= maximum {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("goroutine count = %d, want at most %d", runtime.NumGoroutine(), maximum)
		}
	}
}

func countOpenFileDescriptors(t testing.TB) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read open file descriptors: %v", err)
	}
	return len(entries)
}

func waitForOpenFileDescriptorCount(t testing.TB, maximum int) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if count := countOpenFileDescriptors(t); count <= maximum {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("open file descriptor count = %d, want at most %d", countOpenFileDescriptors(t), maximum)
		}
	}
}

type gatedNonceReader struct {
	entered     chan struct{}
	releaseRead chan struct{}
	data        []byte
	err         error
	enterOnce   sync.Once
	releaseOnce sync.Once
}

func newGatedNonceReader(fail bool) *gatedNonceReader {
	reader := &gatedNonceReader{
		entered:     make(chan struct{}),
		releaseRead: make(chan struct{}),
		data:        []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
	}
	if fail {
		reader.err = errors.New("injected gated nonce failure")
	}
	return reader
}

func (r *gatedNonceReader) Read(buffer []byte) (int, error) {
	r.enterOnce.Do(func() { close(r.entered) })
	<-r.releaseRead
	if r.err != nil {
		return 0, r.err
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	read := copy(buffer, r.data)
	r.data = r.data[read:]
	return read, nil
}

func (r *gatedNonceReader) release() {
	r.releaseOnce.Do(func() { close(r.releaseRead) })
}

func dialPassiveTCP(t testing.TB) (*net.TCPConn, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for passive TCP peer: %v", err)
	}
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	clientRaw, err := (&net.Dialer{}).DialContext(t.Context(), "tcp4", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatalf("dial passive TCP peer: %v", err)
	}
	clientConn, ok := clientRaw.(*net.TCPConn)
	if !ok {
		_ = clientRaw.Close()
		_ = listener.Close()
		t.Fatalf("passive client connection type = %T, want *net.TCPConn", clientRaw)
	}
	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		_ = clientConn.Close()
		_ = listener.Close()
		t.Fatalf("accept passive TCP peer: %v", err)
	case <-time.After(5 * time.Second):
		_ = clientConn.Close()
		_ = listener.Close()
		t.Fatal("timed out accepting passive TCP peer")
	}
	_ = listener.Close()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	done := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		_, err := io.Copy(io.Discard, serverConn)
		done <- err
		close(done)
	}()
	return clientConn, done
}

func waitPassiveTCPPeer(t testing.TB, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("passive TCP peer: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for passive TCP peer")
	}
}

type gnetPingFloodPeer struct {
	conn       net.Conn
	flood      chan struct{}
	stopSignal chan struct{}
	done       chan error
	startOnce  sync.Once
	stopOnce   sync.Once
}

func dialGnetPingFloodPeer(t testing.TB, pingCount int) (*net.TCPConn, *gnetPingFloodPeer) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for gnet ping flood: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	dialer := net.Dialer{}
	clientRaw, err := dialer.DialContext(t.Context(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial gnet ping flood: %v", err)
	}
	clientConn, ok := clientRaw.(*net.TCPConn)
	if !ok {
		_ = clientRaw.Close()
		t.Fatalf("gnet ping flood client type = %T, want *net.TCPConn", clientRaw)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		_ = clientConn.Close()
		t.Fatalf("accept gnet ping flood: %v", err)
	case <-time.After(5 * time.Second):
		_ = clientConn.Close()
		t.Fatal("timed out accepting gnet ping flood")
	}
	serverTCP, ok := serverConn.(*net.TCPConn)
	if !ok {
		_ = serverConn.Close()
		t.Fatalf("gnet ping flood server type = %T, want *net.TCPConn", serverConn)
	}
	if err := serverTCP.SetReadBuffer(1024); err != nil {
		_ = serverConn.Close()
		t.Fatalf("set server read buffer: %v", err)
	}
	peer := &gnetPingFloodPeer{
		conn:       serverConn,
		flood:      make(chan struct{}),
		stopSignal: make(chan struct{}),
		done:       make(chan error, 1),
	}
	t.Cleanup(func() {
		peer.stopOnce.Do(func() { close(peer.stopSignal) })
		_ = peer.conn.Close()
	})
	go func() {
		peer.done <- peer.run(pingCount)
		close(peer.done)
	}()
	return clientConn, peer
}

func (p *gnetPingFloodPeer) startFlood() {
	p.startOnce.Do(func() { close(p.flood) })
}

func (p *gnetPingFloodPeer) stop(t testing.TB) {
	t.Helper()
	p.stopOnce.Do(func() { close(p.stopSignal) })
	_ = p.conn.Close()
	select {
	case err := <-p.done:
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
			var networkErr net.Error
			if !errors.As(err, &networkErr) || networkErr.Timeout() {
				t.Fatalf("gnet ping flood peer: %v", err)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out stopping gnet ping flood peer")
	}
}

func (p *gnetPingFloodPeer) run(pingCount int) error {
	defer p.conn.Close()
	if err := p.conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set gnet ping flood deadline: %w", err)
	}
	clientNonceWire := make([]byte, NoncePacketSize+FullFrameOverhead)
	if _, err := io.ReadFull(p.conn, clientNonceWire); err != nil {
		return fmt.Errorf("read gnet ping flood nonce: %w", err)
	}
	server, err := newRuntimeTestServer(clientNonceWire)
	if err != nil {
		return fmt.Errorf("create gnet ping flood state: %w", err)
	}
	if err := writeAll(p.conn, server.nonceWire); err != nil {
		return fmt.Errorf("write gnet ping flood nonce: %w", err)
	}
	clientHandshake := make([]byte, 48)
	if _, err := io.ReadFull(p.conn, clientHandshake); err != nil {
		return fmt.Errorf("read gnet ping flood handshake: %w", err)
	}
	if err := server.acceptClientHandshakeRuntime(clientHandshake); err != nil {
		return fmt.Errorf("accept gnet ping flood handshake: %w", err)
	}
	serverHandshake, err := server.encodeHandshakeRuntime(HandshakePacket{
		Flags:  HandshakeFlagCRC32C,
		Sender: ProcessID{IP: 0xc0000201, Port: 443, PID: 71, Uptime: 12345},
		Peer:   testLocalProcessID(),
	})
	if err != nil {
		return fmt.Errorf("encode gnet ping flood handshake: %w", err)
	}
	if err := writeAll(p.conn, serverHandshake); err != nil {
		return fmt.Errorf("write gnet ping flood handshake: %w", err)
	}
	select {
	case <-p.flood:
	case <-p.stopSignal:
		return nil
	}

	wire := make([]byte, 0, pingCount*gnetEncryptedPongSize)
	for index := range pingCount {
		pingWire, err := server.encodePayloadRuntime((Ping{ID: uint64(index + 1)}).MarshalBinary())
		if err != nil {
			return fmt.Errorf("encode gnet ping flood item %d: %w", index, err)
		}
		wire = append(wire, pingWire...)
	}
	if err := writeAll(p.conn, wire); err != nil {
		return fmt.Errorf("write gnet ping flood: %w", err)
	}
	select {
	case <-p.stopSignal:
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("gnet ping flood peer stop timed out")
	}
}
