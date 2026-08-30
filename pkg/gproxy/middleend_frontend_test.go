package gproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

type middleEndTestLink struct {
	mu          sync.Mutex
	state       middleend.LinkState
	err         error
	tryErr      error
	autoPong    bool
	events      chan middleend.LinkEvent
	ready       chan struct{}
	done        chan struct{}
	submitted   chan middleend.LinkSubmission
	submissions []middleend.LinkSubmission
	startCount  int
	tryCount    atomic.Int64
	closeOnce   sync.Once
}

func newMiddleEndTestLink() *middleEndTestLink {
	return &middleEndTestLink{
		state:     middleend.LinkStateCreated,
		events:    make(chan middleend.LinkEvent, 64),
		ready:     make(chan struct{}, 1),
		done:      make(chan struct{}),
		submitted: make(chan middleend.LinkSubmission, 64),
	}
}

func (l *middleEndTestLink) Start(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.startCount++
	if l.state == middleend.LinkStateClosed {
		return middleend.ErrLinkClosed
	}
	l.state = middleend.LinkStateReady
	return nil
}

func (l *middleEndTestLink) TrySubmit(submission middleend.LinkSubmission) error {
	l.tryCount.Add(1)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != middleend.LinkStateReady {
		return middleend.ErrLinkClosed
	}
	if l.tryErr != nil {
		return l.tryErr
	}
	l.submissions = append(l.submissions, submission)
	l.submitted <- submission
	if l.autoPong {
		if ping, err := middleend.ParsePing(submission.Payload); err == nil {
			l.events <- middleend.LinkEvent{Kind: middleend.LinkEventPong, KeepaliveID: ping.ID}
		}
	}
	return nil
}

func (l *middleEndTestLink) SubmissionReady() <-chan struct{}   { return l.ready }
func (l *middleEndTestLink) Events() <-chan middleend.LinkEvent { return l.events }

func (l *middleEndTestLink) Snapshot() middleend.LinkSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	return middleend.LinkSnapshot{State: l.state}
}

func (l *middleEndTestLink) Done() <-chan struct{} { return l.done }

func (l *middleEndTestLink) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

func (l *middleEndTestLink) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.state = middleend.LinkStateClosed
		for index := range l.submissions {
			clear(l.submissions[index].Payload)
			l.submissions[index] = middleend.LinkSubmission{}
		}
		l.submissions = nil
		l.mu.Unlock()
		close(l.events)
		close(l.done)
	})
	return nil
}

func (l *middleEndTestLink) setTryError(err error) {
	l.mu.Lock()
	wasBackpressured := errors.Is(l.tryErr, middleend.ErrLinkBackpressure)
	l.tryErr = err
	l.mu.Unlock()
	if wasBackpressured && err == nil {
		select {
		case l.ready <- struct{}{}:
		default:
		}
	}
}

func (l *middleEndTestLink) emit(event middleend.LinkEvent) {
	l.events <- event
}

func (l *middleEndTestLink) snapshotSubmissions() []middleend.LinkSubmission {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]middleend.LinkSubmission(nil), l.submissions...)
}

type middleEndOwnerConn struct {
	*testMockGnetConn
	owner      atomic.Bool
	ownerFault atomic.Bool
	wakes      atomic.Int64
	flushes    atomic.Int64
	writes     atomic.Int64
	behaviorMu sync.Mutex
	wakeErr    error
	writeErr   error
	shortWrite int
}

func newMiddleEndOwnerConn() *middleEndOwnerConn {
	return &middleEndOwnerConn{testMockGnetConn: newTestMockGnetConn(), shortWrite: -1}
}

func (c *middleEndOwnerConn) Write(data []byte) (int, error) {
	if !c.owner.Load() {
		c.ownerFault.Store(true)
	}
	c.writes.Add(1)
	c.behaviorMu.Lock()
	writeErr := c.writeErr
	shortWrite := c.shortWrite
	c.behaviorMu.Unlock()
	if writeErr != nil {
		return 0, writeErr
	}
	if shortWrite >= 0 {
		return min(shortWrite, len(data)), nil
	}
	return c.testMockGnetConn.Write(data)
}

func (c *middleEndOwnerConn) Flush() error {
	if !c.owner.Load() {
		c.ownerFault.Store(true)
	}
	c.flushes.Add(1)
	return nil
}

func (c *middleEndOwnerConn) OutboundBuffered() int {
	if !c.owner.Load() {
		c.ownerFault.Store(true)
	}
	return c.testMockGnetConn.OutboundBuffered()
}

func (c *middleEndOwnerConn) Wake(callback gnet.AsyncCallback) error {
	c.wakes.Add(1)
	c.behaviorMu.Lock()
	wakeErr := c.wakeErr
	c.behaviorMu.Unlock()
	if wakeErr != nil {
		return wakeErr
	}
	if callback != nil {
		return callback(c, nil)
	}
	return nil
}

func (c *middleEndOwnerConn) setWakeError(err error) {
	c.behaviorMu.Lock()
	c.wakeErr = err
	c.behaviorMu.Unlock()
}

func (c *middleEndOwnerConn) setWriteError(err error) {
	c.behaviorMu.Lock()
	c.writeErr = err
	c.behaviorMu.Unlock()
}

func (c *middleEndOwnerConn) setShortWrite(size int) {
	c.behaviorMu.Lock()
	c.shortWrite = size
	c.behaviorMu.Unlock()
}

func runMiddleEndOwner(c *middleEndOwnerConn, operation func() gnet.Action) gnet.Action {
	c.owner.Store(true)
	defer c.owner.Store(false)
	return operation()
}

func middleEndTestLimits() middleend.FixedBindingLimits {
	return middleend.FixedBindingLimits{
		MaxResidentBindings:               32,
		MaxResidentBindingsPerSlot:        16,
		MaxPendingRequestItemsPerBinding:  1,
		MaxPendingRequestBytesPerBinding:  1 << 20,
		MaxPendingRequestItemsPerSlot:     16,
		MaxPendingRequestBytesPerSlot:     4 << 20,
		MaxPendingRequestItems:            32,
		MaxPendingRequestBytes:            8 << 20,
		MaxPendingControlItemsPerSlot:     16,
		MaxPendingControlBytesPerSlot:     1 << 20,
		MaxPendingControlItems:            32,
		MaxPendingControlBytes:            2 << 20,
		MaxPendingResponseItemsPerBinding: 8,
		MaxPendingResponseBytesPerBinding: 1 << 20,
		MaxPendingResponseItemsPerSlot:    16,
		MaxPendingResponseBytesPerSlot:    4 << 20,
		MaxPendingResponseItems:           32,
		MaxPendingResponseBytes:           8 << 20,
	}
}

func newMiddleEndTestManager(
	t *testing.T,
	dcID middleend.DCID,
	link *middleEndTestLink,
) *middleend.FixedBindingManager {
	t.Helper()
	return newMiddleEndTestManagerWithLimits(t, dcID, link, middleEndTestLimits())
}

func newMiddleEndTestManagerWithLimits(
	t *testing.T,
	dcID middleend.DCID,
	link *middleEndTestLink,
	limits middleend.FixedBindingLimits,
) *middleend.FixedBindingManager {
	t.Helper()
	manager := newUnstartedMiddleEndTestManager(t, dcID, link, limits)
	if err := manager.Start(t.Context()); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager
}

func newUnstartedMiddleEndTestManager(
	t *testing.T,
	dcID middleend.DCID,
	link *middleEndTestLink,
	limits middleend.FixedBindingLimits,
) *middleend.FixedBindingManager {
	t.Helper()
	manager, err := middleend.NewFixedBindingManager(
		[]middleend.FixedBindingSlot{{DCID: dcID, Link: link}},
		limits,
	)
	if err != nil {
		t.Fatalf("NewFixedBindingManager: %v", err)
	}
	return manager
}

func middleEndTestNATResolver(t *testing.T) *middleend.NATResolver {
	t.Helper()
	natResolver, err := middleend.NewNATResolver(middleend.NATResolverConfig{
		PublicIP: netip.MustParseAddr("8.8.8.8"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return natResolver
}

func middleEndTestFrontendConfig(t *testing.T, manager *middleend.FixedBindingManager) MiddleEndFrontendConfig {
	t.Helper()
	return MiddleEndFrontendConfig{
		Source:                     manager,
		NATResolver:                middleEndTestNATResolver(t),
		PrecommitFailure:           MiddleEndPrecommitClose,
		MaxPendingClientBytes:      2 << 20,
		MaxPendingClientBytesTotal: 8 << 20,
		MaxPendingOutputBytesTotal: 8 << 20,
		OutputRetryInitial:         time.Millisecond,
		OutputRetryMax:             10 * time.Millisecond,
		OutputStallTimeout:         time.Second,
	}
}

func newMiddleEndTestHandler(
	t *testing.T,
	dcID middleend.DCID,
	connectionType obfuscated2.ConnectionType,
	frontendConfig func(*MiddleEndFrontendConfig),
) (*ProxyHandler, *middleEndTestLink, *middleEndOwnerConn, *ConnContext, []byte, cipher.Stream) {
	t.Helper()
	secret := []byte("0123456789abcdef")
	link := newMiddleEndTestLink()
	manager := newMiddleEndTestManager(t, dcID, link)
	config := middleEndTestFrontendConfig(t, manager)
	if frontendConfig != nil {
		frontendConfig(&config)
	}
	handler, err := NewProxyHandlerWithMiddleEnd(&Config{
		Secrets:           []Secret{{Name: "test", Key: secret, Host: "example.com"}},
		TimeSkewTolerance: time.Minute,
	}, &testLogger{}, config)
	if err != nil {
		t.Fatalf("NewProxyHandlerWithMiddleEnd: %v", err)
	}
	handler.OnBoot(gnet.Engine{})
	t.Cleanup(func() { handler.OnShutdown(gnet.Engine{}) })

	frame := buildDeterministicO2ClientFrame(t, secret, int(dcID), connectionType)
	_, _, serverEncryptor, _, err := obfuscated2.ParseClientFrameWithType(secret, frame)
	if err != nil {
		t.Fatalf("ParseClientFrameWithType: %v", err)
	}
	conn := newMiddleEndOwnerConn()
	conn.localAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8888}
	conn.remoteIP = &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
	ctx := NewConnContext()
	conn.SetContext(ctx)
	return handler, link, conn, ctx, frame, serverEncryptor
}

func validMiddleEndPacket() []byte {
	packet := make([]byte, middleend.EncryptedMessageHeaderSize)
	binary.LittleEndian.PutUint64(packet[:8], 1)
	return packet
}

func encodeMiddleEndClientPacket(
	t *testing.T,
	connectionType obfuscated2.ConnectionType,
	packet []byte,
	clientEncryptor cipher.Stream,
) []byte {
	t.Helper()
	encoder, err := middleend.NewClientPacketEncoder(connectionType, middleend.MaxClientPacketSize)
	if err != nil {
		t.Fatalf("NewClientPacketEncoder: %v", err)
	}
	wire, err := encoder.Encode(packet)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	encrypted := make([]byte, len(wire))
	clientEncryptor.XORKeyStream(encrypted, wire)
	clear(wire)
	return encrypted
}

func encodeMiddleEndClientPacketFixture(
	t *testing.T,
	connectionType obfuscated2.ConnectionType,
	packet []byte,
	quickAck bool,
	padding []byte,
	clientEncryptor cipher.Stream,
) []byte {
	t.Helper()
	var wire []byte
	switch connectionType {
	case obfuscated2.ConnectionTypeAbridged:
		words := len(packet) / 4
		if words <= 0 || words > 0x7e {
			t.Fatalf("unsupported abridged fixture size %d", len(packet))
		}
		header := byte(words)
		if quickAck {
			header |= 0x80
		}
		wire = append([]byte{header}, packet...)
	case obfuscated2.ConnectionTypeIntermediate, obfuscated2.ConnectionTypePaddedIntermediate:
		if connectionType == obfuscated2.ConnectionTypeIntermediate {
			padding = nil
		}
		declared := uint32(len(packet) + len(padding))
		if quickAck {
			declared |= uint32(middleend.ProxyRequestFlagQuickAck)
		}
		wire = binary.LittleEndian.AppendUint32(nil, declared)
		wire = append(wire, packet...)
		wire = append(wire, padding...)
	default:
		t.Fatalf("unsupported fixture framing %08x", uint32(connectionType))
	}
	encrypted := make([]byte, len(wire))
	clientEncryptor.XORKeyStream(encrypted, wire)
	clear(wire)
	return encrypted
}

func middleEndProxyV2Header(famProto byte) []byte {
	header := make([]byte, 28)
	copy(header[:12], proxyProtoV2Sig)
	header[12] = 0x21
	header[13] = famProto
	binary.BigEndian.PutUint16(header[14:16], 12)
	copy(header[16:20], net.ParseIP("198.51.100.20").To4())
	copy(header[20:24], net.ParseIP("203.0.113.10").To4())
	binary.BigEndian.PutUint16(header[24:26], 45678)
	binary.BigEndian.PutUint16(header[26:28], 443)
	return header
}

func waitMiddleEndSubmission(t *testing.T, link *middleEndTestLink) middleend.LinkSubmission {
	t.Helper()
	select {
	case submission := <-link.submitted:
		return submission
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Middle-End submission")
		return middleend.LinkSubmission{}
	}
}

func waitMiddleEndToken(t *testing.T, client *middleEndClient) *middleend.ClientReadyToken {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if token := client.route.currentToken(); token != nil {
			return token
		}
		select {
		case <-deadline.C:
			t.Fatal("timed out waiting for Middle-End ready token")
			return nil
		case <-ticker.C:
		}
	}
}

func consumeMiddleEndRequestResult(
	t *testing.T,
	handler *ProxyHandler,
	conn *middleEndOwnerConn,
	ctx *ConnContext,
) {
	t.Helper()
	waitMiddleEndToken(t, ctx.middleEnd)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("consume request result action = %v", action)
	}
	if ctx.middleEnd.awaitingResult {
		t.Fatal("request result did not release frontend input")
	}
}

func establishMiddleEndDD(
	t *testing.T,
	frontendConfig func(*MiddleEndFrontendConfig),
) (*ProxyHandler, *middleEndTestLink, *middleEndOwnerConn, *ConnContext, cipher.Stream) {
	t.Helper()
	handler, link, conn, ctx, frame, responseDecryptor := newMiddleEndTestHandler(
		t,
		2,
		obfuscated2.ConnectionTypeIntermediate,
		frontendConfig,
	)
	_, _, _, requestEncryptor, err := obfuscated2.ParseClientFrameWithType(handler.config.Secrets[0].Key, frame)
	if err != nil {
		t.Fatal(err)
	}
	requestWire := encodeMiddleEndClientPacket(
		t,
		obfuscated2.ConnectionTypeIntermediate,
		validMiddleEndPacket(),
		requestEncryptor,
	)
	conn.SetReadData(append(bytes.Clone(frame), requestWire...))
	if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
		t.Fatalf("commit action = %v", action)
	}
	runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) })
	waitMiddleEndSubmission(t, link)
	consumeMiddleEndRequestResult(t, handler, conn, ctx)
	return handler, link, conn, ctx, responseDecryptor
}

func commitMiddleEndDDClient(
	t *testing.T,
	handler *ProxyHandler,
) (*middleEndOwnerConn, *ConnContext, cipher.Stream) {
	t.Helper()
	frame := buildDeterministicO2ClientFrame(
		t,
		handler.config.Secrets[0].Key,
		2,
		obfuscated2.ConnectionTypeIntermediate,
	)
	_, connectionType, encryptor, decryptor, err := obfuscated2.ParseClientFrameWithType(handler.config.Secrets[0].Key, frame)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, requestEncryptor, err := obfuscated2.ParseClientFrameWithType(handler.config.Secrets[0].Key, frame)
	if err != nil {
		t.Fatal(err)
	}
	conn := newMiddleEndOwnerConn()
	conn.localAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8888}
	conn.remoteIP = &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
	ctx := NewConnContext()
	ctx.mu.Lock()
	ctx.dcID = 2
	ctx.o2ConnectionType = connectionType
	ctx.encryptor = encryptor
	ctx.decryptor = decryptor
	ctx.mu.Unlock()
	ctx.SetProtocolMode(ModeDD)
	conn.SetContext(ctx)
	committed, commitErr := handler.middleEnd.commit(conn, ctx, false, false, 0)
	if !committed || commitErr != nil {
		t.Fatalf("commit = %v, %v", committed, commitErr)
	}
	return conn, ctx, requestEncryptor
}

func closeMiddleEndTestClient(handler *ProxyHandler, conn *middleEndOwnerConn, ctx *ConnContext) {
	if ctx.State() == StateClosed {
		return
	}
	atomic.AddInt64(&handler.activeConns, 1)
	runMiddleEndOwner(conn, func() gnet.Action { return handler.OnClose(conn, nil) })
}

func TestMiddleEndFrontendStatsTrackActiveAndLifetimeBindings(t *testing.T) {
	handler, _, _, _, _, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
	conn, ctx, _ := commitMiddleEndDDClient(t, handler)

	stats := handler.MiddleEndFrontendStats()
	if stats.MiddleEndBindingsActive != 1 || stats.MiddleEndBindingsTotal != 1 ||
		stats.DirectFallbacksActive != 0 || stats.DirectFallbacksTotal != 0 {
		t.Fatalf("committed route stats = %+v", stats)
	}

	closeMiddleEndTestClient(handler, conn, ctx)
	stats = handler.MiddleEndFrontendStats()
	if stats.MiddleEndBindingsActive != 0 || stats.MiddleEndBindingsTotal != 1 {
		t.Fatalf("closed route stats = %+v", stats)
	}
}

func driveMiddleEndCommit(
	t *testing.T,
	handler *ProxyHandler,
	conn *middleEndOwnerConn,
	ctx *ConnContext,
) gnet.Action {
	t.Helper()
	action := runMiddleEndOwner(conn, func() gnet.Action { return handler.handleDetectProtocol(conn, ctx) })
	for range 8 {
		if action != gnet.None || ctx.State() == StateMiddleEnd || ctx.State() == StateDialingDC {
			return action
		}
		action = runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) })
	}
	t.Fatalf("handshake did not commit a route: state=%v action=%v", ctx.State(), action)
	return gnet.Close
}

func TestMiddleEndFrontendConfigValidationAndRedaction(t *testing.T) {
	link := newMiddleEndTestLink()
	manager := newMiddleEndTestManager(t, 2, link)
	valid := middleEndTestFrontendConfig(t, manager)
	var typedNilSource *middleend.FixedBindingManager
	tests := []MiddleEndFrontendConfig{
		{},
		func() MiddleEndFrontendConfig { c := valid; c.Source = nil; return c }(),
		func() MiddleEndFrontendConfig { c := valid; c.Source = typedNilSource; return c }(),
		func() MiddleEndFrontendConfig { c := valid; c.PrecommitFailure = 0; return c }(),
		func() MiddleEndFrontendConfig { c := valid; c.MaxPendingClientBytes = 0; return c }(),
		func() MiddleEndFrontendConfig { c := valid; c.OutputRetryInitial = 0; return c }(),
		func() MiddleEndFrontendConfig { c := valid; c.OutputRetryMax = c.OutputRetryInitial / 2; return c }(),
		func() MiddleEndFrontendConfig { c := valid; c.OutputStallTimeout = 0; return c }(),
	}
	for index, config := range tests {
		if _, err := NewProxyHandlerWithMiddleEnd(&Config{}, &testLogger{}, config); !errors.Is(err, ErrInvalidMiddleEndFrontend) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
	tooSmall := valid
	if _, err := NewProxyHandlerWithMiddleEnd(&Config{MaxWriteBuffer: middleEndMaxEncodedResponse - 1}, &testLogger{}, tooSmall); !errors.Is(err, ErrInvalidMiddleEndFrontend) {
		t.Fatalf("small MaxWriteBuffer error = %v", err)
	}
	marker := middleend.ProxyTag{0xde, 0xad, 0xbe, 0xef}
	valid.ProxyTag = &marker
	formatted := fmt.Sprintf("%v %+v %#v", valid, valid, valid)
	if stringsContainsAny(formatted, "222 173 190 239", "deadbeef") {
		t.Fatalf("frontend config leaked tag: %s", formatted)
	}
}

func TestRunWithMiddleEndRejectsInvalidFrontendBeforeRuntimeStart(t *testing.T) {
	shutdown, handler, errCh, err := RunWithMiddleEnd(
		&Config{},
		&testLogger{},
		MiddleEndFrontendConfig{},
	)
	if !errors.Is(err, ErrInvalidMiddleEndFrontend) {
		t.Fatalf("RunWithMiddleEnd error = %v", err)
	}
	if shutdown != nil || handler != nil || errCh != nil {
		t.Fatalf("invalid start returned runtime values: shutdown=%v handler=%v errCh=%v", shutdown != nil, handler != nil, errCh != nil)
	}
}

func stringsContainsAny(value string, markers ...string) bool {
	for _, marker := range markers {
		if bytes.Contains([]byte(value), []byte(marker)) {
			return true
		}
	}
	return false
}

func TestMiddleEndAddrPortAllowsOnlyProxyWildcard(t *testing.T) {
	wildcard := &net.TCPAddr{IP: net.IPv4zero, Port: 443}
	if _, err := middleEndAddrPort("remote", wildcard, false, false); !errors.Is(err, middleend.ErrInvalidProxyAddress) {
		t.Fatalf("remote wildcard error = %v", err)
	}
	got, err := middleEndAddrPort("proxy", wildcard, true, false)
	if err != nil || got != netip.MustParseAddrPort("0.0.0.0:443") {
		t.Fatalf("proxy wildcard = %s, %v", got, err)
	}
	unknownPort := &net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 0}
	if _, err := middleEndAddrPort("remote", unknownPort, false, false); !errors.Is(err, middleend.ErrInvalidProxyAddress) {
		t.Fatalf("unauthenticated zero remote port error = %v", err)
	}
	got, err = middleEndAddrPort("remote", unknownPort, false, true)
	if err != nil || got != netip.MustParseAddrPort("198.51.100.7:0") {
		t.Fatalf("authenticated zero remote port = %s, %v", got, err)
	}
}

func TestMiddleEndAuthenticatedWEBTupleAllowsUnknownClientPort(t *testing.T) {
	handler, link, conn, ctx, frame, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
	conn.localAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 8888}
	ctx.internalProxyAuthenticated = true
	ctx.setTrustedProxyTuple(
		&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 0},
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
	)
	_, _, _, clientEncryptor, err := obfuscated2.ParseClientFrameWithType(handler.config.Secrets[0].Key, frame)
	if err != nil {
		t.Fatal(err)
	}
	packet := validMiddleEndPacket()
	encrypted := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, packet, clientEncryptor)
	conn.SetReadData(append(bytes.Clone(frame), encrypted...))
	if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
		t.Fatalf("commit action = %v", action)
	}
	runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) })
	request, err := middleend.ParseProxyRequest(waitMiddleEndSubmission(t, link).Payload)
	if err != nil {
		t.Fatal(err)
	}
	if request.RemoteAddr != netip.MustParseAddrPort("198.51.100.7:0") ||
		request.ProxyAddr != netip.MustParseAddrPort("8.8.8.8:8888") {
		t.Fatalf("WEB tuple = %s -> %s", request.RemoteAddr, request.ProxyAddr)
	}
	closeMiddleEndTestClient(handler, conn, ctx)
}

func TestMiddleEndDDCommitPreservesInputAndRoutesExactSignedDC(t *testing.T) {
	for _, dcID := range []middleend.DCID{-2, 0, 2} {
		t.Run(fmt.Sprintf("dc_%d", dcID), func(t *testing.T) {
			tag := middleend.ProxyTag{1, 2, 3, byte(dcID)}
			handler, link, conn, ctx, frame, _ := newMiddleEndTestHandler(
				t,
				dcID,
				obfuscated2.ConnectionTypeIntermediate,
				func(config *MiddleEndFrontendConfig) { config.ProxyTag = &tag },
			)
			// gnet returns the listener address, not getsockname(2), for accepted
			// sockets. A wildcard listener must retain its port and use NAT state.
			conn.localAddr = &net.TCPAddr{IP: net.IPv4zero, Port: 8888}
			originalTag := tag
			tag[0] = 99
			_, _, _, clientEncryptor, err := obfuscated2.ParseClientFrameWithType(
				handler.config.Secrets[0].Key,
				frame,
			)
			if err != nil {
				t.Fatal(err)
			}
			packet := validMiddleEndPacket()
			encrypted := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, packet, clientEncryptor)
			conn.SetReadData(append(bytes.Clone(frame), encrypted...))

			action := driveMiddleEndCommit(t, handler, conn, ctx)
			if action != gnet.None || ctx.State() != StateMiddleEnd {
				t.Fatalf("commit action/state = %v/%v", action, ctx.State())
			}
			if got, _ := conn.Peek(-1); !bytes.Equal(got, encrypted) {
				t.Fatalf("DD input changed at commit: got %x want %x", got, encrypted)
			}

			runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) })
			submission := waitMiddleEndSubmission(t, link)
			request, err := middleend.ParseProxyRequest(submission.Payload)
			if err != nil {
				t.Fatalf("ParseProxyRequest: %v", err)
			}
			if ctx.middleEnd.binding.DCID() != dcID || submission.ConnectionID != ctx.middleEnd.binding.ConnectionID() {
				t.Fatalf("route = DC %d connection %d", ctx.middleEnd.binding.DCID(), submission.ConnectionID)
			}
			if request.RemoteAddr != netip.MustParseAddrPort("192.168.1.1:12345") ||
				request.ProxyAddr != netip.MustParseAddrPort("8.8.8.8:8888") {
				t.Fatalf("socket tuple = %s -> %s", request.RemoteAddr, request.ProxyAddr)
			}
			if request.Tag == nil || *request.Tag != originalTag {
				t.Fatalf("copied proxy tag = %v, want %v", request.Tag, originalTag)
			}
			if !bytes.Equal(request.Packet, packet) {
				t.Fatalf("request packet = %x want %x", request.Packet, packet)
			}
			closeMiddleEndTestClient(handler, conn, ctx)
		})
	}
}

func TestMiddleEndAllClientFramingsPreserveQuickAckAndStripPadding(t *testing.T) {
	for _, connectionType := range []obfuscated2.ConnectionType{
		obfuscated2.ConnectionTypeAbridged,
		obfuscated2.ConnectionTypeIntermediate,
		obfuscated2.ConnectionTypePaddedIntermediate,
	} {
		t.Run(fmt.Sprintf("%08x", uint32(connectionType)), func(t *testing.T) {
			handler, link, conn, ctx, frame, _ := newMiddleEndTestHandler(t, 2, connectionType, nil)
			_, _, _, requestEncryptor, err := obfuscated2.ParseClientFrameWithType(handler.config.Secrets[0].Key, frame)
			if err != nil {
				t.Fatal(err)
			}
			packet := validMiddleEndPacket()
			encrypted := encodeMiddleEndClientPacketFixture(
				t,
				connectionType,
				packet,
				true,
				[]byte{0xaa, 0xbb, 0xcc},
				requestEncryptor,
			)
			conn.SetReadData(append(bytes.Clone(frame), encrypted...))
			if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
				t.Fatalf("commit action = %v", action)
			}
			if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
				t.Fatalf("request action = %v", action)
			}
			request, err := middleend.ParseProxyRequest(waitMiddleEndSubmission(t, link).Payload)
			if err != nil {
				t.Fatal(err)
			}
			if request.Flags&middleend.ProxyRequestFlagQuickAck == 0 {
				t.Fatalf("request flags %08x omitted QuickAck", request.Flags)
			}
			if !bytes.Equal(request.Packet, packet) {
				t.Fatalf("forwarded packet retained transport padding: got %x want %x", request.Packet, packet)
			}
			closeMiddleEndTestClient(handler, conn, ctx)
		})
	}
}

func TestMiddleEndAuthenticatedProxyV2RequiresStream(t *testing.T) {
	t.Run("DGRAM rejected before Bind", func(t *testing.T) {
		handler, link, conn, ctx, frame, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
		ctx.internalProxyAuthenticated = true
		ctx.SetState(StateReadProxyProto)
		conn.SetReadData(append(middleEndProxyV2Header(0x12), frame...))
		if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
			t.Fatalf("authenticated DGRAM action = %v, want Close", action)
		}
		if ctx.middleEnd != nil || len(link.snapshotSubmissions()) != 0 {
			t.Fatal("authenticated DGRAM reached Bind or submission")
		}
		closeMiddleEndTestClient(handler, conn, ctx)
	})

	t.Run("STREAM accepted", func(t *testing.T) {
		handler, _, conn, ctx, frame, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
		ctx.internalProxyAuthenticated = true
		ctx.SetState(StateReadProxyProto)
		conn.SetReadData(append(middleEndProxyV2Header(0x11), frame...))
		if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
			t.Fatalf("authenticated STREAM action = %v", action)
		}
		if ctx.State() != StateMiddleEnd || ctx.middleEnd.remoteAddr != netip.MustParseAddrPort("198.51.100.20:45678") {
			t.Fatalf("authenticated STREAM state/tuple = %v/%s", ctx.State(), ctx.middleEnd.remoteAddr)
		}
		closeMiddleEndTestClient(handler, conn, ctx)
	})
}

func TestMiddleEndPublicProxyTupleIgnoredAuthenticatedTupleRequired(t *testing.T) {
	handler, link, conn, ctx, frame, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
	ctx.SetRealClientAddr(&net.TCPAddr{IP: net.ParseIP("203.0.113.99"), Port: 65000})
	_, _, _, clientEncryptor, err := obfuscated2.ParseClientFrameWithType(handler.config.Secrets[0].Key, frame)
	if err != nil {
		t.Fatal(err)
	}
	packet := validMiddleEndPacket()
	encrypted := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, packet, clientEncryptor)
	conn.SetReadData(append(bytes.Clone(frame), encrypted...))
	if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
		t.Fatalf("commit action = %v", action)
	}
	runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) })
	request, err := middleend.ParseProxyRequest(waitMiddleEndSubmission(t, link).Payload)
	if err != nil {
		t.Fatal(err)
	}
	if request.RemoteAddr.String() != "192.168.1.1:12345" {
		t.Fatalf("unauthenticated PROXY tuple was trusted: %s", request.RemoteAddr)
	}
	closeMiddleEndTestClient(handler, conn, ctx)

	handler2, link2, conn2, ctx2, frame2, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
	ctx2.internalProxyAuthenticated = true
	ctx2.setTrustedProxyTuple(
		&net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 45678},
		&net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 443},
	)
	_, _, _, clientEncryptor2, err := obfuscated2.ParseClientFrameWithType(handler2.config.Secrets[0].Key, frame2)
	if err != nil {
		t.Fatal(err)
	}
	encrypted2 := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, packet, clientEncryptor2)
	conn2.SetReadData(append(bytes.Clone(frame2), encrypted2...))
	driveMiddleEndCommit(t, handler2, conn2, ctx2)
	runMiddleEndOwner(conn2, func() gnet.Action { return handler2.OnTraffic(conn2) })
	request2, err := middleend.ParseProxyRequest(waitMiddleEndSubmission(t, link2).Payload)
	if err != nil {
		t.Fatal(err)
	}
	if request2.RemoteAddr.String() != "198.51.100.20:45678" || request2.ProxyAddr.String() != "8.8.8.8:443" {
		t.Fatalf("authenticated tuple = %s -> %s", request2.RemoteAddr, request2.ProxyAddr)
	}
	closeMiddleEndTestClient(handler2, conn2, ctx2)
}

func TestMiddleEndEECommitRetainsEncryptedPendingUntilOwnerTraffic(t *testing.T) {
	handler, link, conn, ctx, frame, _ := newMiddleEndTestHandler(t, 3, obfuscated2.ConnectionTypeIntermediate, nil)
	secret := handler.config.Secrets[0].Key
	_, _, _, clientEncryptor, err := obfuscated2.ParseClientFrameWithType(secret, frame)
	if err != nil {
		t.Fatal(err)
	}
	packet := validMiddleEndPacket()
	encrypted := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, packet, clientEncryptor)
	clientHello := buildTLSRecord(
		faketls.RecordTypeHandshake,
		buildValidClientHello(secret, "example.com", bytes.Repeat([]byte{7}, 32)),
	)
	o2Payload := append(bytes.Clone(frame), encrypted...)
	input := append(clientHello, buildTLSRecord(faketls.RecordTypeApplicationData, o2Payload)...)
	conn.SetReadData(input)

	if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
		t.Fatalf("EE commit action/state = %v/%v", action, ctx.State())
	}
	if ctx.State() != StateMiddleEnd || !bytes.Equal(ctx.middleEnd.pendingCipher, encrypted) {
		t.Fatalf("EE pending ciphertext changed at commit: state=%v pending=%x", ctx.State(), ctx.middleEnd.pendingCipher)
	}
	runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) })
	request, err := middleend.ParseProxyRequest(waitMiddleEndSubmission(t, link).Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request.Packet, packet) || len(ctx.middleEnd.pendingCipher) != 0 {
		t.Fatalf("EE request/pending = %x/%d", request.Packet, len(ctx.middleEnd.pendingCipher))
	}
	closeMiddleEndTestClient(handler, conn, ctx)
}

func TestMiddleEndBindFailurePreservesFallbackCiphertextAndCipherPosition(t *testing.T) {
	handler, _, conn, ctx, _, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, func(config *MiddleEndFrontendConfig) {
		config.PrecommitFailure = MiddleEndPrecommitDirectFallback
	})
	secret := handler.config.Secrets[0].Key
	frame := buildDeterministicO2ClientFrame(t, secret, 3, obfuscated2.ConnectionTypeIntermediate)
	_, connectionType, encryptor, decryptor, err := obfuscated2.ParseClientFrameWithType(secret, frame)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, peerEncryptor, err := obfuscated2.ParseClientFrameWithType(secret, frame)
	if err != nil {
		t.Fatal(err)
	}
	packet := validMiddleEndPacket()
	encoder, err := middleend.NewClientPacketEncoder(connectionType, middleend.MaxClientPacketSize)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encoder.Encode(packet)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(wire))
	peerEncryptor.XORKeyStream(ciphertext, wire)
	wantCiphertext := bytes.Clone(ciphertext)

	ctx.mu.Lock()
	ctx.dcID = 3
	ctx.o2ConnectionType = connectionType
	ctx.encryptor = encryptor
	ctx.decryptor = decryptor
	ctx.pendingData = ciphertext
	ctx.mu.Unlock()
	ctx.SetProtocolMode(ModeEE)

	committed, commitErr := handler.middleEnd.commit(conn, ctx, false, false, handler.IdleTimeout())
	if committed || !errors.Is(commitErr, middleend.ErrFixedBindingUnknownDC) {
		t.Fatalf("commit = %v, %v", committed, commitErr)
	}
	if !bytes.Equal(ctx.pendingData, wantCiphertext) {
		t.Fatalf("Bind failure changed fallback ciphertext: got %x want %x", ctx.pendingData, wantCiphertext)
	}
	decrypted := make([]byte, len(ctx.pendingData))
	ctx.decryptor.XORKeyStream(decrypted, ctx.pendingData)
	if !bytes.Equal(decrypted, wire) {
		t.Fatalf("Bind failure advanced fallback decryptor: got %x want %x", decrypted, wire)
	}
	clear(decrypted)
	closeMiddleEndTestClient(handler, conn, ctx)
}

func TestMiddleEndAnswerFlagsIgnoredAndOrderlyCloseDrainsOutput(t *testing.T) {
	handler, link, conn, ctx, frame, responseDecryptor := newMiddleEndTestHandler(
		t,
		2,
		obfuscated2.ConnectionTypeIntermediate,
		nil,
	)
	_, _, _, requestEncryptor, err := obfuscated2.ParseClientFrameWithType(handler.config.Secrets[0].Key, frame)
	if err != nil {
		t.Fatal(err)
	}
	requestPacket := validMiddleEndPacket()
	requestWire := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, requestPacket, requestEncryptor)
	conn.SetReadData(append(bytes.Clone(frame), requestWire...))
	if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
		t.Fatalf("commit action = %v", action)
	}
	runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) })
	waitMiddleEndSubmission(t, link)
	consumeMiddleEndRequestResult(t, handler, conn, ctx)

	answer := append(validMiddleEndPacket(), 0xaa, 0xbb, 0xcc, 0xdd)
	link.emit(middleend.LinkEvent{
		Kind:         middleend.LinkEventProxyAnswer,
		ConnectionID: ctx.middleEnd.binding.ConnectionID(),
		AnswerFlags:  middleend.ProxyAnswerFlagFlush | middleend.ProxyAnswerFlagSmallError,
		Packet:       bytes.Clone(answer),
	})
	waitMiddleEndToken(t, ctx.middleEnd)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("answer action = %v", action)
	}
	written := conn.GetWrittenData()
	plaintext := make([]byte, len(written))
	responseDecryptor.XORKeyStream(plaintext, written)
	decoder, err := middleend.NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, middleend.MaxClientPacketSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed(plaintext); err != nil {
		t.Fatal(err)
	}
	decoded, ok, err := decoder.Next()
	if err != nil || !ok || !bytes.Equal(decoded.Payload, answer) {
		t.Fatalf("decoded answer = %x, %v, %v; want %x", decoded.Payload, ok, err, answer)
	}
	clear(decoded.Payload)
	if conn.flushes.Load() != 0 {
		t.Fatalf("ProxyAnswer flags caused %d Flush calls", conn.flushes.Load())
	}

	conn.SetOutboundBuffered(1)
	link.emit(middleend.LinkEvent{
		Kind:         middleend.LinkEventCloseExternal,
		ConnectionID: ctx.middleEnd.binding.ConnectionID(),
	})
	waitMiddleEndToken(t, ctx.middleEnd)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("CloseExternal with buffered output action = %v, want None", action)
	}
	if !ctx.middleEnd.closeAfterDrain {
		t.Fatal("CloseExternal did not enter close-after-drain state")
	}
	conn.SetReadData(make([]byte, ctx.middleEnd.frontend.maxPendingClient+1))
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
		t.Fatalf("close-drain input overflow action = %v, want Close", action)
	}
	conn.SetReadData(nil)
	conn.mu.Lock()
	conn.outboundBuffered = 0
	conn.writeBuf = nil
	conn.mu.Unlock()
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
		t.Fatalf("drained CloseExternal action = %v, want Close", action)
	}
	if conn.ownerFault.Load() {
		t.Fatal("Middle-End accessed owner-only gnet APIs off the owner loop")
	}
	closeMiddleEndTestClient(handler, conn, ctx)
}

func TestMiddleEndOutputStallTimeoutDoesNotPopEvent(t *testing.T) {
	handler, link, conn, ctx, _ := establishMiddleEndDD(t, func(config *MiddleEndFrontendConfig) {
		config.OutputRetryInitial = time.Millisecond
		config.OutputRetryMax = 2 * time.Millisecond
		config.OutputStallTimeout = 10 * time.Millisecond
	})
	conn.SetOutboundBuffered(handler.maxWriteBuffer)
	packet := append(validMiddleEndPacket(), 1, 2, 3, 4)
	link.emit(middleend.LinkEvent{
		Kind:         middleend.LinkEventProxyAnswer,
		ConnectionID: ctx.middleEnd.binding.ConnectionID(),
		Packet:       bytes.Clone(packet),
	})
	token := waitMiddleEndToken(t, ctx.middleEnd)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("parked output action = %v", action)
	}
	if ctx.middleEnd.route.currentToken() != token || conn.writes.Load() != 0 {
		t.Fatal("blocked output popped its event or replaced its ready token")
	}
	ctx.middleEnd.retryMu.Lock()
	timer := ctx.middleEnd.retryTimer
	ctx.middleEnd.retryMu.Unlock()
	if timer == nil {
		t.Fatal("blocked output did not arm its coalesced retry timer")
	}
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("repeated parked output action = %v", action)
	}
	ctx.middleEnd.retryMu.Lock()
	sameTimer := ctx.middleEnd.retryTimer == timer
	ctx.middleEnd.retryMu.Unlock()
	if !sameTimer || ctx.middleEnd.route.currentToken() != token {
		t.Fatal("repeated blocked output replaced its timer or token")
	}
	time.Sleep(25 * time.Millisecond)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
		t.Fatalf("stalled output action = %v, want Close", action)
	}
	if conn.writes.Load() != 0 {
		t.Fatal("stalled output was written without headroom")
	}
	closeMiddleEndTestClient(handler, conn, ctx)
}

func TestMiddleEndOutputHeadroomBoundariesAndSingleEncryption(t *testing.T) {
	handler, link, conn, ctx, responseDecryptor := establishMiddleEndDD(t, nil)
	threshold := handler.maxWriteBuffer - middleEndMaxEncodedResponse
	for _, test := range []struct {
		name string
		used int
		want bool
	}{
		{name: "below", used: threshold - 1, want: true},
		{name: "equal", used: threshold, want: true},
		{name: "above", used: threshold + 1, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn.SetOutboundBuffered(test.used)
			got := false
			runMiddleEndOwner(conn, func() gnet.Action {
				got = ctx.middleEnd.outputHeadroom(conn, handler.maxWriteBuffer)
				return gnet.None
			})
			if got != test.want {
				t.Fatalf("outputHeadroom(%d) = %v, want %v", test.used, got, test.want)
			}
		})
	}

	answer := append(validMiddleEndPacket(), 9, 10, 11, 12)
	conn.SetOutboundBuffered(threshold + 1)
	link.emit(middleend.LinkEvent{
		Kind:         middleend.LinkEventProxyAnswer,
		ConnectionID: ctx.middleEnd.binding.ConnectionID(),
		Packet:       bytes.Clone(answer),
	})
	token := waitMiddleEndToken(t, ctx.middleEnd)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("above-boundary action = %v", action)
	}
	if ctx.middleEnd.route.currentToken() != token || conn.writes.Load() != 0 {
		t.Fatal("above-boundary attempt popped or encrypted the answer")
	}
	conn.SetOutboundBuffered(threshold)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("equal-boundary action = %v", action)
	}
	written := conn.GetWrittenData()
	plaintext := make([]byte, len(written))
	responseDecryptor.XORKeyStream(plaintext, written)
	decoder, err := middleend.NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, middleend.MaxClientPacketSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed(plaintext); err != nil {
		t.Fatal(err)
	}
	decoded, ok, err := decoder.Next()
	if err != nil || !ok || !bytes.Equal(decoded.Payload, answer) {
		t.Fatalf("single-encryption answer = %x, %v, %v; want %x", decoded.Payload, ok, err, answer)
	}
	clear(decoded.Payload)
	closeMiddleEndTestClient(handler, conn, ctx)
}

func TestMiddleEndWriteFailureFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*middleEndOwnerConn)
	}{
		{name: "error", setup: func(conn *middleEndOwnerConn) { conn.setWriteError(errors.New("injected write failure")) }},
		{name: "short", setup: func(conn *middleEndOwnerConn) { conn.setShortWrite(1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, link, conn, ctx, _ := establishMiddleEndDD(t, nil)
			test.setup(conn)
			link.emit(middleend.LinkEvent{
				Kind:         middleend.LinkEventProxyAnswer,
				ConnectionID: ctx.middleEnd.binding.ConnectionID(),
				Packet:       validMiddleEndPacket(),
			})
			waitMiddleEndToken(t, ctx.middleEnd)
			if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
				t.Fatalf("write failure action = %v, want Close", action)
			}
			if conn.writes.Load() != 1 || conn.ownerFault.Load() {
				t.Fatalf("write attempts/owner fault = %d/%v", conn.writes.Load(), conn.ownerFault.Load())
			}
			closeMiddleEndTestClient(handler, conn, ctx)
		})
	}
}

func TestMiddleEndNoFallbackAfterSuccessfulBind(t *testing.T) {
	handler, _, conn, ctx, frame, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, func(config *MiddleEndFrontendConfig) {
		config.PrecommitFailure = MiddleEndPrecommitDirectFallback
	})
	var directDials atomic.Int64
	handler.directDCDial = func(int, obfuscated2.ConnectionType) (*directDCConn, error) {
		directDials.Add(1)
		return nil, errors.New("unexpected direct fallback")
	}
	conn.setWakeError(errors.New("injected committed wake failure"))
	conn.SetReadData(bytes.Clone(frame))
	if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.Close {
		t.Fatalf("post-Bind wake failure action = %v, want Close", action)
	}
	if ctx.State() != StateMiddleEnd || ctx.middleEnd == nil {
		t.Fatalf("successful Bind was not committed: state=%v", ctx.State())
	}
	if directDials.Load() != 0 {
		t.Fatalf("post-Bind failure attempted %d direct fallbacks", directDials.Load())
	}
	closeMiddleEndTestClient(handler, conn, ctx)
}

func TestMiddleEndEERecordWorkIsBoundedAndInvalidRecordsFail(t *testing.T) {
	t.Run("bounded minimal records", func(t *testing.T) {
		handler, link, conn, ctx, frame, _ := newMiddleEndTestHandler(t, 3, obfuscated2.ConnectionTypeIntermediate, nil)
		secret := handler.config.Secrets[0].Key
		_, _, _, requestEncryptor, err := obfuscated2.ParseClientFrameWithType(secret, frame)
		if err != nil {
			t.Fatal(err)
		}
		clientHello := buildTLSRecord(
			faketls.RecordTypeHandshake,
			buildValidClientHello(secret, "example.com", bytes.Repeat([]byte{8}, 32)),
		)
		conn.SetReadData(append(clientHello, buildTLSRecord(faketls.RecordTypeApplicationData, frame)...))
		if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
			t.Fatalf("EE commit action = %v", action)
		}
		packet := make([]byte, 4*(middleEndTLSRecordWorkLimit+1))
		binary.LittleEndian.PutUint64(packet[:8], 1)
		wire := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, packet, requestEncryptor)
		records := make([]byte, 0, len(wire)*(faketls.RecordHeaderSize+1))
		for _, value := range wire {
			records = append(records, buildTLSRecord(faketls.RecordTypeApplicationData, []byte{value})...)
		}
		conn.SetReadData(records)
		wakesBefore := conn.wakes.Load()
		if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
			t.Fatalf("budgeted record action = %v", action)
		}
		if conn.wakes.Load() <= wakesBefore {
			t.Fatal("record work budget did not coalesce continuation through Wake")
		}
		select {
		case submission := <-link.submitted:
			t.Fatalf("request escaped one-turn record budget: %v", submission)
		default:
		}
		for range 8 {
			if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
				t.Fatalf("budget continuation action = %v", action)
			}
			if ctx.middleEnd.awaitingResult {
				waitMiddleEndSubmission(t, link)
				closeMiddleEndTestClient(handler, conn, ctx)
				return
			}
		}
		t.Fatal("budgeted record continuation did not produce request")
	})

	for _, test := range []struct {
		name   string
		record []byte
	}{
		{name: "zero application data", record: buildTLSRecord(faketls.RecordTypeApplicationData, nil)},
		{name: "post-handshake control", record: buildTLSRecord(faketls.RecordTypeHandshake, []byte{1})},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, _, conn, ctx, frame, _ := newMiddleEndTestHandler(t, 3, obfuscated2.ConnectionTypeIntermediate, nil)
			secret := handler.config.Secrets[0].Key
			clientHello := buildTLSRecord(
				faketls.RecordTypeHandshake,
				buildValidClientHello(secret, "example.com", bytes.Repeat([]byte{9}, 32)),
			)
			conn.SetReadData(append(clientHello, buildTLSRecord(faketls.RecordTypeApplicationData, frame)...))
			if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
				t.Fatalf("EE commit action = %v", action)
			}
			conn.SetReadData(test.record)
			if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
				t.Fatalf("invalid record action = %v, want Close", action)
			}
			closeMiddleEndTestClient(handler, conn, ctx)
		})
	}
}

func TestMiddleEndSimpleAckIsUnframed(t *testing.T) {
	handler, link, conn, ctx, responseDecryptor := establishMiddleEndDD(t, nil)
	const confirmKey = uint32(0x10203040)
	link.emit(middleend.LinkEvent{
		Kind:         middleend.LinkEventSimpleAck,
		ConnectionID: ctx.middleEnd.binding.ConnectionID(),
		ConfirmKey:   confirmKey,
	})
	waitMiddleEndToken(t, ctx.middleEnd)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("SimpleAck action = %v", action)
	}
	written := conn.GetWrittenData()
	if len(written) != 4 {
		t.Fatalf("SimpleAck wire length = %d, want 4", len(written))
	}
	plaintext := make([]byte, len(written))
	responseDecryptor.XORKeyStream(plaintext, written)
	want, err := middleend.EncodeSimpleAckForClient(obfuscated2.ConnectionTypeIntermediate, confirmKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, want) {
		t.Fatalf("SimpleAck plaintext = %x, want %x", plaintext, want)
	}
	if conn.flushes.Load() != 0 || conn.ownerFault.Load() {
		t.Fatalf("SimpleAck owner/flush = %v/%d", conn.ownerFault.Load(), conn.flushes.Load())
	}
	closeMiddleEndTestClient(handler, conn, ctx)
}

func TestMiddleEndEEResponseUsesOwnerCodec(t *testing.T) {
	handler, link, conn, ctx, frame, responseDecryptor := newMiddleEndTestHandler(t, 3, obfuscated2.ConnectionTypeIntermediate, nil)
	handler.config.EnableDRS = true
	handler.config.EnableSplitTLS = true
	secret := handler.config.Secrets[0].Key
	_, _, _, requestEncryptor, err := obfuscated2.ParseClientFrameWithType(secret, frame)
	if err != nil {
		t.Fatal(err)
	}
	request := validMiddleEndPacket()
	encryptedRequest := encodeMiddleEndClientPacket(t, obfuscated2.ConnectionTypeIntermediate, request, requestEncryptor)
	clientHello := buildTLSRecord(
		faketls.RecordTypeHandshake,
		buildValidClientHello(secret, "example.com", bytes.Repeat([]byte{10}, 32)),
	)
	o2Payload := append(bytes.Clone(frame), encryptedRequest...)
	conn.SetReadData(append(clientHello, buildTLSRecord(faketls.RecordTypeApplicationData, o2Payload)...))
	if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
		t.Fatalf("EE commit action = %v", action)
	}
	runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) })
	waitMiddleEndSubmission(t, link)
	consumeMiddleEndRequestResult(t, handler, conn, ctx)

	answer := append(validMiddleEndPacket(), 5, 6, 7, 8)
	link.emit(middleend.LinkEvent{
		Kind:         middleend.LinkEventProxyAnswer,
		ConnectionID: ctx.middleEnd.binding.ConnectionID(),
		AnswerFlags:  middleend.ProxyAnswerFlagFlush | middleend.ProxyAnswerFlagSmallError,
		Packet:       bytes.Clone(answer),
	})
	writesBefore := conn.writes.Load()
	bytesBefore := len(conn.GetWrittenData())
	waitMiddleEndToken(t, ctx.middleEnd)
	if conn.writes.Load() != writesBefore || len(conn.GetWrittenData()) != bytesBefore {
		t.Fatal("manager pump wrote EE response off owner loop")
	}
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("EE answer action = %v", action)
	}
	written := conn.GetWrittenData()[bytesBefore:]
	var encryptedPayload []byte
	recordCount := 0
	for offset := 0; offset < len(written); {
		if len(written)-offset < faketls.RecordHeaderSize {
			t.Fatalf("truncated EE record at %d", offset)
		}
		if written[offset] != faketls.RecordTypeApplicationData {
			t.Fatalf("EE record type = %d", written[offset])
		}
		size := int(binary.BigEndian.Uint16(written[offset+3 : offset+5]))
		offset += faketls.RecordHeaderSize
		if size <= 0 || size > len(written)-offset {
			t.Fatalf("EE record size = %d remaining %d", size, len(written)-offset)
		}
		encryptedPayload = append(encryptedPayload, written[offset:offset+size]...)
		offset += size
		recordCount++
	}
	if recordCount < 2 {
		t.Fatalf("DRS+Split response record count = %d, want at least 2", recordCount)
	}
	plaintext := make([]byte, len(encryptedPayload))
	responseDecryptor.XORKeyStream(plaintext, encryptedPayload)
	decoder, err := middleend.NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, middleend.MaxClientPacketSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Feed(plaintext); err != nil {
		t.Fatal(err)
	}
	decoded, ok, err := decoder.Next()
	if err != nil || !ok || !bytes.Equal(decoded.Payload, answer) {
		t.Fatalf("EE decoded answer = %x, %v, %v; want %x", decoded.Payload, ok, err, answer)
	}
	clear(decoded.Payload)
	if conn.flushes.Load() != 0 || conn.ownerFault.Load() {
		t.Fatalf("EE owner/flush = %v/%d", conn.ownerFault.Load(), conn.flushes.Load())
	}
	closeMiddleEndTestClient(handler, conn, ctx)
}

func TestMiddleEndPrecommitActionAndZeroPort(t *testing.T) {
	t.Run("close", func(t *testing.T) {
		handler, _, conn, ctx, frame, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
		conn.remoteIP = &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 0}
		conn.SetReadData(bytes.Clone(frame))
		if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.Close {
			t.Fatalf("zero-port close action = %v", action)
		}
		if ctx.State() == StateMiddleEnd || ctx.middleEnd != nil {
			t.Fatal("zero-port precommit failure committed Middle-End state")
		}
		closeMiddleEndTestClient(handler, conn, ctx)
	})

	t.Run("direct fallback has no precommit failure count", func(t *testing.T) {
		handler, _, conn, ctx, _, _ := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, func(config *MiddleEndFrontendConfig) {
			config.PrecommitFailure = MiddleEndPrecommitDirectFallback
		})
		frame := buildDeterministicO2ClientFrame(t, handler.config.Secrets[0].Key, 3, obfuscated2.ConnectionTypeIntermediate)
		entered := make(chan struct{})
		release := make(chan struct{})
		handler.directDCDial = func(int, obfuscated2.ConnectionType) (*directDCConn, error) {
			close(entered)
			<-release
			return nil, errors.New("injected direct dial stop")
		}
		conn.SetReadData(frame)
		if action := driveMiddleEndCommit(t, handler, conn, ctx); action != gnet.None {
			t.Fatalf("direct fallback action = %v", action)
		}
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("direct fallback did not start")
		}
		if ctx.State() != StateDialingDC || handler.handshakeFailures[handshakeFailureBackendDial].Load() != 0 {
			t.Fatalf("precommit fallback state/count = %v/%d", ctx.State(), handler.handshakeFailures[handshakeFailureBackendDial].Load())
		}
		stats := handler.MiddleEndFrontendStats()
		if stats.MiddleEndBindingsActive != 0 || stats.MiddleEndBindingsTotal != 0 ||
			stats.DirectFallbacksActive != 1 || stats.DirectFallbacksTotal != 1 {
			t.Fatalf("active direct fallback stats = %+v", stats)
		}
		close(release)
		closeMiddleEndTestClient(handler, conn, ctx)
		stats = handler.MiddleEndFrontendStats()
		if stats.DirectFallbacksActive != 0 || stats.DirectFallbacksTotal != 1 {
			t.Fatalf("closed direct fallback stats = %+v", stats)
		}
	})
}

func TestMiddleEndReservationWithoutRetainedRequestFailsClosed(t *testing.T) {
	link := newMiddleEndTestLink()
	limits := middleEndTestLimits()
	limits.MaxPendingRequestItemsPerSlot = 1
	manager := newMiddleEndTestManagerWithLimits(t, 2, link, limits)
	handler, err := NewProxyHandlerWithMiddleEnd(
		&Config{Secrets: []Secret{{Name: "test", Key: []byte("0123456789abcdef")}}},
		&testLogger{},
		middleEndTestFrontendConfig(t, manager),
	)
	if err != nil {
		t.Fatal(err)
	}
	handler.OnBoot(gnet.Engine{})
	t.Cleanup(func() { handler.OnShutdown(gnet.Engine{}) })

	newClient := func() (*middleEndOwnerConn, *ConnContext, cipher.Stream) {
		frame := buildDeterministicO2ClientFrame(
			t,
			handler.config.Secrets[0].Key,
			2,
			obfuscated2.ConnectionTypeIntermediate,
		)
		_, connectionType, encryptor, decryptor, parseErr := obfuscated2.ParseClientFrameWithType(handler.config.Secrets[0].Key, frame)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		_, _, _, requestEncryptor, parseErr := obfuscated2.ParseClientFrameWithType(handler.config.Secrets[0].Key, frame)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		conn := newMiddleEndOwnerConn()
		conn.localAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8888}
		conn.remoteIP = &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
		ctx := NewConnContext()
		ctx.mu.Lock()
		ctx.dcID = 2
		ctx.o2ConnectionType = connectionType
		ctx.encryptor = encryptor
		ctx.decryptor = decryptor
		ctx.mu.Unlock()
		ctx.SetProtocolMode(ModeDD)
		conn.SetContext(ctx)
		committed, commitErr := handler.middleEnd.commit(conn, ctx, false, false, 0)
		if !committed || commitErr != nil {
			t.Fatalf("commit = %v, %v", committed, commitErr)
		}
		return conn, ctx, requestEncryptor
	}

	firstConn, firstCtx, firstEncryptor := newClient()
	secondConn, secondCtx, secondEncryptor := newClient()
	link.setTryError(middleend.ErrLinkBackpressure)
	firstConn.SetReadData(encodeMiddleEndClientPacket(
		t,
		obfuscated2.ConnectionTypeIntermediate,
		validMiddleEndPacket(),
		firstEncryptor,
	))
	if action := runMiddleEndOwner(firstConn, func() gnet.Action { return handler.OnTraffic(firstConn) }); action != gnet.None {
		t.Fatalf("first request action = %v", action)
	}
	deadline := time.Now().Add(3 * time.Second)
	for link.tryCount.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if link.tryCount.Load() == 0 {
		t.Fatal("first request never reached backpressured link")
	}
	paused := encodeMiddleEndClientPacket(
		t,
		obfuscated2.ConnectionTypeIntermediate,
		validMiddleEndPacket(),
		firstEncryptor,
	)
	firstConn.SetReadData(paused)
	if action := runMiddleEndOwner(firstConn, func() gnet.Action { return handler.OnTraffic(firstConn) }); action != gnet.None {
		t.Fatalf("paused second request action = %v", action)
	}
	if got, _ := firstConn.Peek(-1); !bytes.Equal(got, paused) {
		t.Fatalf("second request changed before first acceptance: got %x want %x", got, paused)
	}
	firstConn.SetReadData(make([]byte, handler.middleEnd.maxPendingClient+1))
	if action := runMiddleEndOwner(firstConn, func() gnet.Action { return handler.OnTraffic(firstConn) }); action != gnet.Close {
		t.Fatalf("accepted/BP input overflow action = %v, want Close", action)
	}
	firstConn.SetReadData(nil)

	secondConn.SetReadData(encodeMiddleEndClientPacket(
		t,
		obfuscated2.ConnectionTypeIntermediate,
		validMiddleEndPacket(),
		secondEncryptor,
	))
	if action := runMiddleEndOwner(secondConn, func() gnet.Action { return handler.OnTraffic(secondConn) }); action != gnet.None {
		t.Fatalf("waiting request action = %v", action)
	}
	if secondCtx.middleEnd.waiting == nil {
		t.Fatal("second request did not register a capacity waiter")
	}
	secondConn.SetReadData(make([]byte, handler.middleEnd.maxPendingClient+1))
	if action := runMiddleEndOwner(secondConn, func() gnet.Action { return handler.OnTraffic(secondConn) }); action != gnet.Close {
		t.Fatalf("waiting input overflow action = %v, want Close", action)
	}
	secondConn.SetReadData(nil)
	secondCtx.middleEnd.clearWaitingRequest()
	link.setTryError(nil)
	waitMiddleEndToken(t, secondCtx.middleEnd)
	if action := runMiddleEndOwner(secondConn, func() gnet.Action { return handler.OnTraffic(secondConn) }); action != gnet.Close {
		t.Fatalf("reservation without retained request action = %v, want Close", action)
	}
	closeMiddleEndTestClient(handler, firstConn, firstCtx)
	closeMiddleEndTestClient(handler, secondConn, secondCtx)
}

func TestMiddleEndWaitingReservationAcceptsThenProcessesNextPacket(t *testing.T) {
	link := newMiddleEndTestLink()
	limits := middleEndTestLimits()
	limits.MaxPendingRequestItemsPerSlot = 1
	manager := newMiddleEndTestManagerWithLimits(t, 2, link, limits)
	handler, err := NewProxyHandlerWithMiddleEnd(
		&Config{Secrets: []Secret{{Name: "test", Key: []byte("0123456789abcdef")}}},
		&testLogger{},
		middleEndTestFrontendConfig(t, manager),
	)
	if err != nil {
		t.Fatal(err)
	}
	handler.OnBoot(gnet.Engine{})
	t.Cleanup(func() { handler.OnShutdown(gnet.Engine{}) })
	firstConn, firstCtx, firstEncryptor := commitMiddleEndDDClient(t, handler)
	secondConn, secondCtx, secondEncryptor := commitMiddleEndDDClient(t, handler)
	link.setTryError(middleend.ErrLinkBackpressure)

	firstConn.SetReadData(encodeMiddleEndClientPacket(
		t,
		obfuscated2.ConnectionTypeIntermediate,
		validMiddleEndPacket(),
		firstEncryptor,
	))
	runMiddleEndOwner(firstConn, func() gnet.Action { return handler.OnTraffic(firstConn) })
	deadline := time.Now().Add(3 * time.Second)
	for link.tryCount.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if link.tryCount.Load() == 0 {
		t.Fatal("first request never reached backpressured link")
	}

	secondConn.SetReadData(encodeMiddleEndClientPacket(
		t,
		obfuscated2.ConnectionTypeIntermediate,
		validMiddleEndPacket(),
		secondEncryptor,
	))
	if action := runMiddleEndOwner(secondConn, func() gnet.Action { return handler.OnTraffic(secondConn) }); action != gnet.None {
		t.Fatalf("waiting request action = %v", action)
	}
	if secondCtx.middleEnd.waiting == nil || !secondCtx.middleEnd.awaitingResult {
		t.Fatal("second request did not enter retained Waiting state")
	}
	link.setTryError(nil)
	waitMiddleEndToken(t, secondCtx.middleEnd)
	if action := runMiddleEndOwner(secondConn, func() gnet.Action { return handler.OnTraffic(secondConn) }); action != gnet.None {
		t.Fatalf("reservation materialization action = %v", action)
	}
	if secondCtx.middleEnd.waiting != nil || !secondCtx.middleEnd.awaitingResult {
		t.Fatal("reservation did not transfer retained request into manager ownership")
	}

	var accepted middleend.LinkSubmission
	for range 2 {
		submission := waitMiddleEndSubmission(t, link)
		if submission.ConnectionID == secondCtx.middleEnd.binding.ConnectionID() {
			accepted = submission
		}
	}
	if accepted.SubmissionID == 0 {
		t.Fatal("materialized waiting request was not accepted")
	}
	consumeMiddleEndRequestResult(t, handler, secondConn, secondCtx)

	secondConn.SetReadData(encodeMiddleEndClientPacket(
		t,
		obfuscated2.ConnectionTypeIntermediate,
		validMiddleEndPacket(),
		secondEncryptor,
	))
	if action := runMiddleEndOwner(secondConn, func() gnet.Action { return handler.OnTraffic(secondConn) }); action != gnet.None {
		t.Fatalf("next request action = %v", action)
	}
	next := waitMiddleEndSubmission(t, link)
	if next.ConnectionID != accepted.ConnectionID || next.SubmissionID == accepted.SubmissionID {
		t.Fatalf("next accepted request identity = connection %d submission %d; prior %d/%d", next.ConnectionID, next.SubmissionID, accepted.ConnectionID, accepted.SubmissionID)
	}
	closeMiddleEndTestClient(handler, firstConn, firstCtx)
	closeMiddleEndTestClient(handler, secondConn, secondCtx)
}

func TestMiddleEndCleanupUnregistersBeforeBindingClose(t *testing.T) {
	handler, link, conn, ctx, _ := establishMiddleEndDD(t, nil)
	connectionID := ctx.middleEnd.binding.ConnectionID()
	closeMiddleEndTestClient(handler, conn, ctx)
	handler.middleEnd.mu.Lock()
	_, registered := handler.middleEnd.routes[connectionID]
	handler.middleEnd.mu.Unlock()
	if registered {
		t.Fatal("closed client remained registered with readiness dispatcher")
	}
	closeSubmission := waitMiddleEndSubmission(t, link)
	operation, err := middleend.ParseRPCOperation(closeSubmission.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if operation != middleend.OperationCloseConnection || closeSubmission.ConnectionID != connectionID {
		t.Fatalf("cleanup submission = operation %08x connection %d", operation, closeSubmission.ConnectionID)
	}
	if conn.ownerFault.Load() {
		t.Fatal("cleanup caused an off-owner gnet call")
	}
}

func TestMiddleEndWakeErrorsCloseInsteadOfStranding(t *testing.T) {
	t.Run("output retry timer", func(t *testing.T) {
		handler, link, conn, ctx, _ := establishMiddleEndDD(t, func(config *MiddleEndFrontendConfig) {
			config.OutputRetryInitial = time.Millisecond
			config.OutputRetryMax = time.Millisecond
			config.OutputStallTimeout = time.Second
		})
		conn.SetOutboundBuffered(handler.maxWriteBuffer)
		link.emit(middleend.LinkEvent{
			Kind:         middleend.LinkEventProxyAnswer,
			ConnectionID: ctx.middleEnd.binding.ConnectionID(),
			Packet:       validMiddleEndPacket(),
		})
		waitMiddleEndToken(t, ctx.middleEnd)
		if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
			t.Fatalf("park action = %v", action)
		}
		conn.setWakeError(errors.New("injected retry Wake failure"))
		deadline := time.Now().Add(3 * time.Second)
		for !conn.IsClosed() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !conn.IsClosed() {
			t.Fatal("retry Wake failure stranded the live route")
		}
		closeMiddleEndTestClient(handler, conn, ctx)
	})

	t.Run("manager Done wakeAll", func(t *testing.T) {
		handler, _, conn, ctx, _ := establishMiddleEndDD(t, nil)
		conn.setWakeError(errors.New("injected manager-Done Wake failure"))
		manager := handler.middleEnd.source.(*middleend.FixedBindingManager)
		if err := manager.Close(); err != nil {
			t.Fatalf("manager.Close: %v", err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for !conn.IsClosed() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !conn.IsClosed() {
			t.Fatal("manager-Done Wake failure stranded the live route")
		}
		closeMiddleEndTestClient(handler, conn, ctx)
	})
}

func TestMiddleEndSupervisorWakesClientWhenRetiringGenerationIsForcedClosed(t *testing.T) {
	const dcID middleend.DCID = 2
	newManager := func() *middleend.FixedBindingManager {
		link := newMiddleEndTestLink()
		link.autoPong = true
		return newUnstartedMiddleEndTestManager(t, dcID, link, middleEndTestLimits())
	}
	oldActive := newManager()
	newActive := newManager()
	newFactory := func(managers ...*middleend.FixedBindingManager) middleend.FixedBindingGenerationFactory {
		var mu sync.Mutex
		next := 0
		return func(context.Context) (*middleend.FixedBindingManager, error) {
			mu.Lock()
			defer mu.Unlock()
			if next == len(managers) {
				return nil, errors.New("test generation factory exhausted")
			}
			manager := managers[next]
			next++
			return manager, nil
		}
	}

	supervisor, err := middleend.NewFixedBindingGenerationSupervisor(middleend.GenerationSupervisorConfig{
		PreparationTimeout:   time.Second,
		ProbeInterval:        10 * time.Second,
		ProbeFailureTimeout:  30 * time.Second,
		DrainTimeout:         time.Hour,
		RepairBackoffInitial: time.Millisecond,
		RepairBackoffMaximum: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewFixedBindingGenerationSupervisor: %v", err)
	}
	t.Cleanup(func() { _ = supervisor.Close() })
	if err := supervisor.Start(t.Context(), newFactory(oldActive)); err != nil {
		t.Fatalf("supervisor.Start: %v", err)
	}

	secret := []byte("0123456789abcdef")
	handler, err := NewProxyHandlerWithMiddleEnd(&Config{
		Secrets:           []Secret{{Name: "test", Key: secret, Host: "example.com"}},
		TimeSkewTolerance: time.Minute,
	}, &testLogger{}, MiddleEndFrontendConfig{
		Source:                     supervisor,
		NATResolver:                middleEndTestNATResolver(t),
		PrecommitFailure:           MiddleEndPrecommitClose,
		MaxPendingClientBytes:      2 << 20,
		MaxPendingClientBytesTotal: 8 << 20,
		MaxPendingOutputBytesTotal: 8 << 20,
		OutputRetryInitial:         time.Millisecond,
		OutputRetryMax:             10 * time.Millisecond,
		OutputStallTimeout:         time.Second,
	})
	if err != nil {
		t.Fatalf("NewProxyHandlerWithMiddleEnd: %v", err)
	}
	handler.OnBoot(gnet.Engine{})
	t.Cleanup(func() { handler.OnShutdown(gnet.Engine{}) })

	conn, ctx, _ := commitMiddleEndDDClient(t, handler)
	t.Cleanup(func() { closeMiddleEndTestClient(handler, conn, ctx) })
	if err := supervisor.Rotate(t.Context(), newFactory(newActive)); err != nil {
		t.Fatalf("supervisor.Rotate: %v", err)
	}
	wakesBeforeFailure := conn.wakes.Load()

	if err := newActive.Close(); err != nil {
		t.Fatalf("close replacement active: %v", err)
	}
	select {
	case <-oldActive.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("displaced retiring manager did not close")
	}
	deadline := time.Now().Add(3 * time.Second)
	for conn.wakes.Load() == wakesBeforeFailure && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if conn.wakes.Load() == wakesBeforeFailure {
		t.Fatal("forced retiring-generation close did not wake its bound gnet client")
	}
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.Close {
		t.Fatalf("forced retiring-generation close action = %v, want close", action)
	}
}

func TestMiddleEndParkedTokenRetiresOnClientClose(t *testing.T) {
	handler, link, conn, ctx, _ := establishMiddleEndDD(t, func(config *MiddleEndFrontendConfig) {
		config.OutputRetryInitial = 20 * time.Millisecond
		config.OutputRetryMax = 20 * time.Millisecond
		config.OutputStallTimeout = time.Second
	})
	client := ctx.middleEnd
	connectionID := client.binding.ConnectionID()
	conn.SetOutboundBuffered(handler.maxWriteBuffer)
	link.emit(middleend.LinkEvent{
		Kind:         middleend.LinkEventProxyAnswer,
		ConnectionID: connectionID,
		Packet:       validMiddleEndPacket(),
	})
	token := waitMiddleEndToken(t, client)
	if action := runMiddleEndOwner(conn, func() gnet.Action { return handler.OnTraffic(conn) }); action != gnet.None {
		t.Fatalf("park action = %v", action)
	}
	if client.route.currentToken() != token {
		t.Fatal("expected one parked token before close")
	}
	closeMiddleEndTestClient(handler, conn, ctx)
	handler.middleEnd.mu.Lock()
	_, registered := handler.middleEnd.routes[connectionID]
	handler.middleEnd.mu.Unlock()
	client.retryMu.Lock()
	timer := client.retryTimer
	client.retryMu.Unlock()
	if registered || client.route.currentToken() != nil || timer != nil {
		t.Fatalf("closed parked route retained registry/token/timer = %v/%v/%v", registered, client.route.currentToken() != nil, timer != nil)
	}
	wakes := conn.wakes.Load()
	time.Sleep(40 * time.Millisecond)
	if conn.wakes.Load() != wakes {
		t.Fatal("retired output timer woke a closed route")
	}
}

func TestMiddleEndActualShutdownOrderLeavesManagerExternal(t *testing.T) {
	link := newMiddleEndTestLink()
	limits := middleEndTestLimits()
	limits.MaxResidentBindings = 1
	limits.MaxResidentBindingsPerSlot = 1
	manager := newMiddleEndTestManagerWithLimits(t, 2, link, limits)
	handler, err := NewProxyHandlerWithMiddleEnd(
		&Config{Secrets: []Secret{{Name: "test", Key: []byte("0123456789abcdef")}}},
		&testLogger{},
		middleEndTestFrontendConfig(t, manager),
	)
	if err != nil {
		t.Fatal(err)
	}
	handler.OnBoot(gnet.Engine{})
	conn, ctx, _ := commitMiddleEndDDClient(t, handler)
	connectionID := ctx.middleEnd.binding.ConnectionID()

	// gnet v2.10 invokes OnShutdown before the connection OnClose callbacks.
	handler.OnShutdown(gnet.Engine{})
	handler.middleEnd.mu.Lock()
	_, stillRegistered := handler.middleEnd.routes[connectionID]
	handler.middleEnd.mu.Unlock()
	if !stillRegistered {
		t.Fatal("OnShutdown prematurely removed a live route before OnClose")
	}
	select {
	case <-manager.Done():
		t.Fatal("frontend shutdown closed its externally owned manager")
	default:
	}

	closeMiddleEndTestClient(handler, conn, ctx)
	closeSubmission := waitMiddleEndSubmission(t, link)
	operation, err := middleend.ParseRPCOperation(closeSubmission.Payload)
	if err != nil || operation != middleend.OperationCloseConnection {
		t.Fatalf("post-OnShutdown close control = %08x, %v", operation, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var rebound *middleend.ClientBinding
	for time.Now().Before(deadline) {
		rebound, err = manager.Bind(2)
		if err == nil {
			break
		}
		if !errors.Is(err, middleend.ErrFixedBindingLimit) {
			t.Fatalf("rebind after OnClose: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	if rebound == nil {
		t.Fatal("OnClose did not release the sole resident binding")
	}
	reboundDone := rebound.BeginClose()
	waitMiddleEndSubmission(t, link)
	select {
	case <-reboundDone:
	case <-time.After(3 * time.Second):
		t.Fatal("rebound close did not complete")
	}
	if closeErr, set := rebound.CloseResult(); !set || closeErr != nil {
		t.Fatalf("rebound CloseResult = %v, %v", closeErr, set)
	}
}
