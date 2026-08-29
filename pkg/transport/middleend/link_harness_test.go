package middleend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clientLinkFactory func(net.Conn, *ClientBootstrap, LinkLimits) (ClientLink, error)

type fakePeerMode uint8

const (
	fakePeerNormal fakePeerMode = iota
	fakePeerHoldAfterReady
	fakePeerCloseAfterReady
	fakePeerMalformedAfterRequest
	fakePeerHeldMalformedAfterRequest
)

var errFakePeerPlannedClose = errors.New("fake Middle-End peer planned close")
var errFakePeerRecordLimit = errors.New("fake Middle-End peer record limit reached")
var errFakePeerWaitTimeout = errors.New("fake Middle-End peer did not stop")
var errHarnessWaitTimeout = errors.New("harness wait timed out")
var errHarnessWaitStuck = errors.New("harness goroutine remained blocked after release")

type fakePeerConfig struct {
	mode            fakePeerMode
	fragmentPattern []int
	peerPingID      uint64
	maxRecords      int
	holdBootstrap   bool
	discardRecords  bool
	recordCounter   *atomic.Uint64
}

type fakePeerRecord struct {
	operation    uint32
	connectionID int64
	keepaliveID  uint64
}

// fakeMiddleEndPeer is a deterministic, test-only peer shared by every link
// engine. It exercises the real bootstrap and continuous CBC/frame state over
// a TCP connection. It never contacts Telegram or a public network.
type fakeMiddleEndPeer struct {
	conn                 net.Conn
	config               fakePeerConfig
	ready                chan struct{}
	readOne              chan struct{}
	readAck              chan error
	release              chan struct{}
	done                 chan error
	stopped              chan struct{}
	bootstrapStarted     chan struct{}
	bootstrapRelease     chan struct{}
	bootstrapCount       atomic.Int32
	recordCount          atomic.Uint64
	malformedReady       chan struct{}
	malformedRelease     chan struct{}
	allowHeldRead        func()
	releaseHeldRead      func()
	releaseBootstrapOnce func()
	releaseMalformedOnce func()

	mu      sync.Mutex
	records []fakePeerRecord
}

func newFakeMiddleEndPeer(conn net.Conn, config fakePeerConfig) *fakeMiddleEndPeer {
	if len(config.fragmentPattern) == 0 {
		config.fragmentPattern = []int{1, 7, 2, 19, 4096, 64 << 10}
	}
	if config.maxRecords == 0 {
		config.maxRecords = len(benchmarkPacketSizes())*4 + 8
	}
	peer := &fakeMiddleEndPeer{
		conn:             conn,
		config:           config,
		ready:            make(chan struct{}),
		readOne:          make(chan struct{}),
		readAck:          make(chan error, 1),
		release:          make(chan struct{}),
		done:             make(chan error, 1),
		stopped:          make(chan struct{}),
		bootstrapStarted: make(chan struct{}),
		bootstrapRelease: make(chan struct{}),
		malformedReady:   make(chan struct{}),
		malformedRelease: make(chan struct{}),
	}
	peer.allowHeldRead = sync.OnceFunc(func() { close(peer.readOne) })
	peer.releaseHeldRead = sync.OnceFunc(func() { close(peer.release) })
	peer.releaseBootstrapOnce = sync.OnceFunc(func() { close(peer.bootstrapRelease) })
	peer.releaseMalformedOnce = sync.OnceFunc(func() { close(peer.malformedRelease) })
	return peer
}

func (p *fakeMiddleEndPeer) start() {
	go func() {
		p.done <- p.run()
		close(p.done)
		close(p.stopped)
	}()
}

func (p *fakeMiddleEndPeer) run() error {
	defer p.conn.Close()
	clientNonceWire := make([]byte, NoncePacketSize+FullFrameOverhead)
	if _, err := io.ReadFull(p.conn, clientNonceWire[:1]); err != nil {
		return fmt.Errorf("fake peer read client nonce: %w", err)
	}
	p.bootstrapCount.Add(1)
	close(p.bootstrapStarted)
	if p.config.holdBootstrap {
		if err := waitFakePeerSignal(p.bootstrapRelease, "bootstrap release"); err != nil {
			return err
		}
	}
	if _, err := io.ReadFull(p.conn, clientNonceWire[1:]); err != nil {
		return fmt.Errorf("fake peer read client nonce: %w", err)
	}
	server, err := newRuntimeTestServer(clientNonceWire)
	if err != nil {
		return fmt.Errorf("fake peer create state: %w", err)
	}
	if err := writeFragments(p.conn, server.nonceWire, p.config.fragmentPattern); err != nil {
		return fmt.Errorf("fake peer write nonce: %w", err)
	}

	clientHandshake := make([]byte, 48)
	if _, err := io.ReadFull(p.conn, clientHandshake); err != nil {
		return fmt.Errorf("fake peer read handshake: %w", err)
	}
	if err := server.acceptClientHandshakeRuntime(clientHandshake); err != nil {
		return fmt.Errorf("fake peer accept handshake: %w", err)
	}
	serverHandshake, err := server.encodeHandshakeRuntime(HandshakePacket{
		Flags:  HandshakeFlagCRC32C,
		Sender: ProcessID{IP: 0xc0000201, Port: 443, PID: 71, Uptime: 12345},
		Peer:   testLocalProcessID(),
	})
	if err != nil {
		return fmt.Errorf("fake peer encode handshake: %w", err)
	}
	initial := serverHandshake
	if p.config.peerPingID != 0 {
		ping, err := server.encodePayloadRuntime((Ping{ID: p.config.peerPingID}).MarshalBinary())
		if err != nil {
			return fmt.Errorf("fake peer encode ping: %w", err)
		}
		initial = append(initial, ping...)
	}
	if err := writeFragments(p.conn, initial, p.config.fragmentPattern); err != nil {
		return fmt.Errorf("fake peer write coalesced handshake: %w", err)
	}
	close(p.ready)

	if p.config.mode == fakePeerHoldAfterReady {
		if err := waitFakePeerSignal(p.readOne, "held read permission"); err != nil {
			return err
		}
		var first [1]byte
		read, err := p.conn.Read(first[:])
		if err == nil && read != len(first) {
			err = io.ErrNoProgress
		}
		p.readAck <- err
		close(p.readAck)
		if err != nil {
			return fmt.Errorf("fake peer read held byte: %w", err)
		}
		if err := waitFakePeerSignal(p.release, "held read release"); err != nil {
			return err
		}
		if err := p.process(server, first[:]); err != nil {
			return err
		}
	}

	readBuffer := make([]byte, 32<<10)
	for {
		read, readErr := p.conn.Read(readBuffer)
		if read > 0 {
			if err := p.process(server, readBuffer[:read]); err != nil {
				if errors.Is(err, errFakePeerPlannedClose) {
					return nil
				}
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, net.ErrClosed) || errors.Is(readErr, io.EOF) {
				return nil
			}
			return fmt.Errorf("fake peer read: %w", readErr)
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
}

func (p *fakeMiddleEndPeer) process(server *runtimeTestServer, ciphertext []byte) error {
	_, plaintext := server.decrypter.Feed(ciphertext)
	for len(plaintext) != 0 {
		consumed, err := server.decoder.Feed(plaintext)
		if err != nil {
			return fmt.Errorf("fake peer frame Feed: %w", err)
		}
		plaintext = plaintext[consumed:]
		progress := false
		for {
			frame, ok, err := server.decoder.Next()
			if err != nil {
				return fmt.Errorf("fake peer frame Next: %w", err)
			}
			if !ok {
				break
			}
			progress = true
			if err := p.handleFrame(server, frame); err != nil {
				return err
			}
			if p.config.mode == fakePeerCloseAfterReady {
				return errFakePeerPlannedClose
			}
		}
		if consumed == 0 && !progress {
			return io.ErrNoProgress
		}
	}
	return nil
}

func (p *fakeMiddleEndPeer) handleFrame(server *runtimeTestServer, frame Frame) error {
	operation, err := ParseRPCOperation(frame.Payload)
	if err != nil {
		return fmt.Errorf("fake peer parse operation: %w", err)
	}
	switch operation {
	case OperationProxyRequest:
		request, err := ParseProxyRequest(frame.Payload)
		if err != nil {
			return err
		}
		if err := p.record(fakePeerRecord{operation: operation, connectionID: request.ConnectionID}); err != nil {
			return err
		}
		if p.config.mode == fakePeerMalformedAfterRequest || p.config.mode == fakePeerHeldMalformedAfterRequest {
			if p.config.mode == fakePeerHeldMalformedAfterRequest {
				close(p.malformedReady)
				if err := waitFakePeerSignal(p.malformedRelease, "malformed response release"); err != nil {
					return err
				}
			}
			wire, err := server.encodePayloadRuntime((CloseConnection{ConnectionID: request.ConnectionID}).MarshalBinary())
			if err != nil {
				return err
			}
			if err := writeFragments(p.conn, wire, p.config.fragmentPattern); err != nil {
				return err
			}
			return nil
		}
		answer, err := (ProxyAnswer{
			Flags:        ProxyAnswerFlagFlush,
			ConnectionID: request.ConnectionID,
			Packet:       request.Packet,
		}).MarshalBinary()
		if err != nil {
			return err
		}
		answerWire, err := server.encodePayloadRuntime(answer)
		if err != nil {
			return err
		}
		ackWire, err := server.encodePayloadRuntime((SimpleAck{
			ConnectionID: request.ConnectionID,
			ConfirmKey:   uint32(request.ConnectionID),
		}).MarshalBinary())
		if err != nil {
			return err
		}
		return writeFragments(p.conn, append(answerWire, ackWire...), p.config.fragmentPattern)
	case OperationCloseConnection:
		closeRequest, err := ParseCloseConnection(frame.Payload)
		if err != nil {
			return err
		}
		if err := p.record(fakePeerRecord{operation: operation, connectionID: closeRequest.ConnectionID}); err != nil {
			return err
		}
		if p.config.mode == fakePeerCloseAfterReady {
			return nil
		}
		wire, err := server.encodePayloadRuntime((CloseExternal{ConnectionID: closeRequest.ConnectionID}).MarshalBinary())
		if err != nil {
			return err
		}
		return writeFragments(p.conn, wire, p.config.fragmentPattern)
	case OperationPing:
		ping, err := ParsePing(frame.Payload)
		if err != nil {
			return err
		}
		if err := p.record(fakePeerRecord{operation: operation, keepaliveID: ping.ID}); err != nil {
			return err
		}
		wire, err := server.encodePayloadRuntime((Pong{ID: ping.ID}).MarshalBinary())
		if err != nil {
			return err
		}
		return writeFragments(p.conn, wire, p.config.fragmentPattern)
	case OperationPong:
		pong, err := ParsePong(frame.Payload)
		if err != nil {
			return err
		}
		if err := p.record(fakePeerRecord{operation: operation, keepaliveID: pong.ID}); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("fake peer received operation %08x: %w", operation, ErrUnexpectedLinkRPC)
	}
}

func waitFakePeerSignal(signal <-chan struct{}, operation string) error {
	select {
	case <-signal:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("fake peer timed out waiting for %s", operation)
	}
}

func (p *fakeMiddleEndPeer) record(record fakePeerRecord) error {
	p.recordCount.Add(1)
	if p.config.recordCounter != nil {
		p.config.recordCounter.Add(1)
	}
	if p.config.discardRecords {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.records) >= p.config.maxRecords {
		return fmt.Errorf("%w: maximum %d", errFakePeerRecordLimit, p.config.maxRecords)
	}
	p.records = append(p.records, record)
	return nil
}

func (p *fakeMiddleEndPeer) snapshotRecords() []fakePeerRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.records)
}

func (p *fakeMiddleEndPeer) stopHolding() {
	p.releaseBootstrapOnce()
	p.allowHeldRead()
	p.releaseHeldRead()
	p.releaseMalformedOnce()
}

func (p *fakeMiddleEndPeer) waitBootstrapStarted(t testing.TB) {
	t.Helper()
	select {
	case <-p.bootstrapStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("fake peer did not observe bootstrap start")
	}
}

func (p *fakeMiddleEndPeer) releaseBootstrap() {
	p.releaseBootstrapOnce()
}

func (p *fakeMiddleEndPeer) waitMalformedReady(t testing.TB) {
	t.Helper()
	select {
	case <-p.malformedReady:
	case <-time.After(5 * time.Second):
		t.Fatal("fake peer did not prepare the malformed response")
	}
}

func (p *fakeMiddleEndPeer) releaseMalformed() {
	p.releaseMalformedOnce()
}

func (p *fakeMiddleEndPeer) readOneAndHold(t testing.TB) {
	t.Helper()
	p.allowHeldRead()
	select {
	case err := <-p.readAck:
		if err != nil {
			t.Fatalf("fake peer held read: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake peer did not acknowledge its held read")
	}
}

type linkWorkItem struct {
	sessionIndex int
	submission   LinkSubmission
	wantPacket   []byte
}

type linkWorkload struct {
	name  string
	items []linkWorkItem
}

// deterministicLinkWorkload returns the same interleaved four-session payload
// matrix for both engines. All addresses are documentation-only ranges.
func deterministicLinkWorkload(t testing.TB) linkWorkload {
	t.Helper()
	workload, err := buildDeterministicLinkWorkload()
	if err != nil {
		t.Fatalf("build deterministic Middle-End workload: %v", err)
	}
	return workload
}

func buildDeterministicLinkWorkload() (linkWorkload, error) {
	sizes := benchmarkPacketSizes()
	items := make([]linkWorkItem, 0, len(sizes)*4)
	var submissionID uint64 = 1
	for sizeIndex, size := range sizes {
		for sessionIndex := range 4 {
			connectionID := int64(1000 + sessionIndex)
			packet := deterministicEncryptedPacket(size, sessionIndex, sizeIndex)
			var tag ProxyTag
			for index := range tag {
				tag[index] = byte(sessionIndex*len(tag) + index)
			}
			payload, err := (ProxyRequest{
				Flags: ProxyRequestFlagHasAdTag |
					ProxyRequestFlagMagic |
					ProxyRequestFlagExternalMode2 |
					ProxyRequestFlagIntermediate,
				ConnectionID: connectionID,
				RemoteAddr:   netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:%d", sessionIndex+1, 20000+sessionIndex)),
				ProxyAddr:    netip.MustParseAddrPort("[2001:db8::2]:443"),
				Tag:          &tag,
				Packet:       packet,
			}).MarshalBinary()
			if err != nil {
				return linkWorkload{}, err
			}
			items = append(items, linkWorkItem{
				sessionIndex: sessionIndex,
				submission: LinkSubmission{
					SubmissionID: submissionID,
					ConnectionID: connectionID,
					Payload:      payload,
				},
				wantPacket: bytes.Clone(packet),
			})
			submissionID++
		}
	}
	return linkWorkload{name: "four-sessions-payload-matrix", items: items}, nil
}

func deterministicEncryptedPacket(size int, sessionIndex int, sizeIndex int) []byte {
	packet := make([]byte, size)
	copy(packet, []byte{8, 7, 6, 5, 4, 3, 2, 1})
	for index := 8; index < len(packet); index++ {
		packet[index] = byte(index + sessionIndex*17 + sizeIndex*31)
	}
	return packet
}

func submissionsBySession(workload linkWorkload) [][]LinkSubmission {
	sessions := make([][]LinkSubmission, 4)
	for _, item := range workload.items {
		sessions[item.sessionIndex] = append(sessions[item.sessionIndex], item.submission)
	}
	return sessions
}

// runClientLinkConformance applies the same correctness cases to each engine.
// Engine tests call this function with only their constructor adapter.
func runClientLinkConformance(t *testing.T, factory clientLinkFactory) {
	t.Helper()
	t.Run("fragmentation coalescing parallel sessions and RPCs", func(t *testing.T) {
		runClientLinkWorkload(t, factory)
	})
	t.Run("submission backpressure", func(t *testing.T) {
		runSubmissionBackpressure(t, factory)
	})
	t.Run("submission capacity notification", func(t *testing.T) {
		runSubmissionCapacityNotification(t, factory)
	})
	t.Run("permanent oversized submission", func(t *testing.T) {
		runOversizedSubmission(t, factory)
	})
	t.Run("submission notification lifecycle", func(t *testing.T) {
		runSubmissionNotificationLifecycle(t, factory)
	})
	t.Run("event backpressure fails closed", func(t *testing.T) {
		runEventBackpressure(t, factory)
	})
	t.Run("peer close fails closed", func(t *testing.T) {
		runPeerFailure(t, factory, fakePeerCloseAfterReady, io.EOF)
	})
	t.Run("malformed response fails closed", func(t *testing.T) {
		runPeerFailure(t, factory, fakePeerMalformedAfterRequest, ErrUnexpectedLinkRPC)
	})
	t.Run("close races protocol failure", func(t *testing.T) {
		runCloseProtocolFailureRace(t, factory)
	})
	t.Run("fresh link after failure", func(t *testing.T) {
		runFreshLinkAfterFailure(t, factory)
	})
	t.Run("idempotent concurrent lifecycle", func(t *testing.T) {
		runConcurrentLifecycle(t, factory)
	})
	t.Run("concurrent initial start", func(t *testing.T) {
		runConcurrentInitialStart(t, factory)
	})
	t.Run("initial start races close", func(t *testing.T) {
		runInitialStartCloseRace(t, factory)
	})
	t.Run("start context is not retained", func(t *testing.T) {
		runStartContextLifetime(t, factory)
	})
	t.Run("close before start", func(t *testing.T) {
		runCloseBeforeStart(t, factory)
	})
}

func runClientLinkWorkload(t *testing.T, factory clientLinkFactory) {
	workload := deterministicLinkWorkload(t)
	limits := limitsForWorkload(workload)
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{peerPingID: 0x0102030405060708})
	link := makeAndStartLink(t, factory, clientConn, limits)

	errorsFound := make(chan error, len(workload.items))
	var waitGroup sync.WaitGroup
	for _, submissions := range submissionsBySession(workload) {
		waitGroup.Go(func() {
			for _, submission := range submissions {
				if err := link.TrySubmit(submission); err != nil {
					errorsFound <- fmt.Errorf("submit %d: %w", submission.SubmissionID, err)
					return
				}
			}
		})
	}
	if err := waitGroupBounded(&waitGroup, 5*time.Second, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}); err != nil {
		t.Fatalf("parallel TrySubmit calls: %v", err)
	}
	close(errorsFound)

submissionErrors:
	for {
		select {
		case err, ok := <-errorsFound:
			if !ok {
				break submissionErrors
			}
			t.Fatal(err)
		default:
			t.Fatal("closed submission error channel was not readable")
		}
	}

	const explicitPingID = 0x1112131415161718
	if err := link.TrySubmit(LinkSubmission{
		SubmissionID: uint64(len(workload.items) + 1),
		Payload:      (Ping{ID: explicitPingID}).MarshalBinary(),
	}); err != nil {
		t.Fatalf("submit ping: %v", err)
	}
	closeSubmission := LinkSubmission{
		SubmissionID: uint64(len(workload.items) + 2),
		ConnectionID: 1000,
		Payload:      (CloseConnection{ConnectionID: 1000}).MarshalBinary(),
	}
	if err := link.TrySubmit(closeSubmission); err != nil {
		t.Fatalf("submit close connection: %v", err)
	}

	expectedAnswers := make(map[workloadAnswerKey][]byte, len(workload.items))
	expectedAcks := make(map[int64]int, 4)
	for _, item := range workload.items {
		key := workloadAnswerKey{connectionID: item.submission.ConnectionID, packetSize: len(item.wantPacket)}
		expectedAnswers[key] = item.wantPacket
		expectedAcks[item.submission.ConnectionID]++
	}
	peerPingSeen := false
	pongSeen := false
	closeSeen := false
	for len(expectedAnswers) != 0 || totalExpectedAcks(expectedAcks) != 0 || !peerPingSeen || !pongSeen || !closeSeen {
		event := receiveLinkEvent(t, link)
		switch event.Kind {
		case LinkEventProxyAnswer:
			key := workloadAnswerKey{connectionID: event.ConnectionID, packetSize: len(event.Packet)}
			want, ok := expectedAnswers[key]
			if !ok || event.AnswerFlags != ProxyAnswerFlagFlush || !bytes.Equal(event.Packet, want) {
				t.Fatalf("unexpected proxy answer for connection %d with %d bytes", event.ConnectionID, len(event.Packet))
			}
			delete(expectedAnswers, key)
		case LinkEventSimpleAck:
			if expectedAcks[event.ConnectionID] == 0 || event.ConfirmKey != uint32(event.ConnectionID) {
				t.Fatalf("unexpected acknowledgement for connection %d", event.ConnectionID)
			}
			expectedAcks[event.ConnectionID]--
		case LinkEventCloseExternal:
			if event.ConnectionID != closeSubmission.ConnectionID || closeSeen {
				t.Fatalf("unexpected external close for connection %d", event.ConnectionID)
			}
			closeSeen = true
		case LinkEventPing:
			if event.KeepaliveID != 0x0102030405060708 || peerPingSeen {
				t.Fatalf("unexpected peer ping %x", event.KeepaliveID)
			}
			peerPingSeen = true
		case LinkEventPong:
			if event.KeepaliveID != explicitPingID || pongSeen {
				t.Fatalf("unexpected pong %x", event.KeepaliveID)
			}
			pongSeen = true
		default:
			t.Fatalf("unexpected link event %+v", event)
		}
	}

	beforeClose := link.Snapshot()
	closeResult := callErrorForTest(t, link.Close, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}, "workload Close")
	if closeResult != nil {
		t.Fatalf("Close: %v", closeResult)
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeClose, startResult: nil, initialCloseResult: closeResult, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("orderly close retained %d unexpected events", len(events))
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
	if !peerRecordedPong(peer.snapshotRecords(), 0x0102030405060708) {
		t.Fatal("fake peer did not receive the automatic pong")
	}
	if !peerRecordedConnectionOperation(peer.snapshotRecords(), OperationCloseConnection, closeSubmission.ConnectionID) {
		t.Fatal("fake peer did not receive the connection close")
	}
}

type workloadAnswerKey struct {
	connectionID int64
	packetSize   int
}

func totalExpectedAcks(expected map[int64]int) int {
	total := 0
	for _, count := range expected {
		total += count
	}
	return total
}

func peerRecordedPong(records []fakePeerRecord, id uint64) bool {
	for _, record := range records {
		if record.operation == OperationPong && record.keepaliveID == id {
			return true
		}
	}
	return false
}

func peerRecordedConnectionOperation(records []fakePeerRecord, operation uint32, connectionID int64) bool {
	for _, record := range records {
		if record.operation == operation && record.connectionID == connectionID {
			return true
		}
	}
	return false
}

func runSubmissionBackpressure(t *testing.T, factory clientLinkFactory) {
	t.Run("item limit", func(t *testing.T) {
		runSubmissionLimit(t, factory, true)
	})
	t.Run("byte limit", func(t *testing.T) {
		runSubmissionLimit(t, factory, false)
	})
}

func runSubmissionCapacityNotification(t *testing.T, factory clientLinkFactory) {
	t.Run("item release", func(t *testing.T) {
		runSubmissionCapacityRelease(t, factory, true)
	})
	t.Run("byte release", func(t *testing.T) {
		runSubmissionCapacityRelease(t, factory, false)
	})
}

func runSubmissionCapacityRelease(t *testing.T, factory clientLinkFactory, itemOnly bool) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{mode: fakePeerHoldAfterReady})
	workload := deterministicLinkWorkload(t)
	item := workload.items[len(workload.items)-1]
	answerBytes := (LinkEvent{Kind: LinkEventProxyAnswer, Packet: item.wantPacket}).ByteSize()
	ackBytes := (LinkEvent{Kind: LinkEventSimpleAck}).ByteSize()
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: 2 * item.submission.ByteSize(),
		MaxPendingEvents:          4,
		MaxPendingEventBytes:      2 * (answerBytes + ackBytes),
	}
	if !itemOnly {
		limits.MaxPendingSubmissions = 2
		limits.MaxPendingSubmissionBytes = item.submission.ByteSize()
	}
	link := makeAndStartLink(t, factory, clientConn, limits)
	ready := link.SubmissionReady()
	if ready == nil {
		t.Fatal("SubmissionReady returned nil")
	}

	accepted := item.submission
	accepted.Payload = bytes.Clone(item.submission.Payload)
	waiting := item.submission
	waiting.SubmissionID++
	waiting.ConnectionID++
	waitingRequest, err := ParseProxyRequest(waiting.Payload)
	if err != nil {
		t.Fatalf("parse waiting request: %v", err)
	}
	waitingRequest.ConnectionID = waiting.ConnectionID
	waiting.Payload, err = waitingRequest.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal waiting request: %v", err)
	}
	waitingBefore := bytes.Clone(waiting.Payload)
	if err := link.TrySubmit(accepted); err != nil {
		t.Fatalf("accept first submission: %v", err)
	}
	if err := link.TrySubmit(waiting); !errors.Is(err, ErrLinkBackpressure) {
		t.Fatalf("waiting submission error = %v, want backpressure", err)
	}
	if !bytes.Equal(waiting.Payload, waitingBefore) {
		t.Fatal("backpressured submission payload changed")
	}

	peer.readOneAndHold(t)
	waitForLinkSnapshot(t, link, func(snapshot LinkSnapshot) bool {
		return snapshot.PendingSubmissions == 1 && snapshot.PendingSubmissionBytes == accepted.ByteSize()
	})
	select {
	case <-ready:
		t.Fatal("capacity signal arrived before a pending charge was released")
	default:
	}

	peer.stopHolding()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("capacity signal did not arrive after a pending charge was released")
	}
	if err := link.TrySubmit(waiting); err != nil {
		t.Fatalf("retry waiting submission after capacity signal: %v", err)
	}

	wantConnections := map[int64]int{
		accepted.ConnectionID: 2,
		waiting.ConnectionID:  2,
	}
	for range 4 {
		event := receiveLinkEvent(t, link)
		if event.Kind != LinkEventProxyAnswer && event.Kind != LinkEventSimpleAck {
			t.Fatalf("unexpected event after retry: %v", event)
		}
		wantConnections[event.ConnectionID]--
	}
	for connectionID, remaining := range wantConnections {
		if remaining != 0 {
			t.Fatalf("connection %d event count remaining = %d", connectionID, remaining)
		}
	}
	waitForLinkSnapshot(t, link, func(snapshot LinkSnapshot) bool {
		return snapshot.PendingSubmissions == 0 && snapshot.PendingSubmissionBytes == 0 &&
			snapshot.PendingEvents == 0 && snapshot.PendingEventBytes == 0
	})

	beforeClose := link.Snapshot()
	closeResult := callErrorForTest(t, link.Close, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}, "capacity-notification Close")
	if closeResult != nil {
		t.Fatalf("Close: %v", closeResult)
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeClose, startResult: nil, initialCloseResult: closeResult, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("capacity notification close retained %d unexpected events", len(events))
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func runOversizedSubmission(t *testing.T, factory clientLinkFactory) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	workload := deterministicLinkWorkload(t)
	item := workload.items[len(workload.items)-1]
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: item.submission.ByteSize() - 1,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      (LinkEvent{Kind: LinkEventProxyAnswer, Packet: item.wantPacket}).ByteSize(),
	}
	link := makeAndStartLink(t, factory, clientConn, limits)
	ready := link.SubmissionReady()
	submission := item.submission
	submission.Payload = bytes.Clone(item.submission.Payload)
	before := bytes.Clone(submission.Payload)
	err := link.TrySubmit(submission)
	if !errors.Is(err, ErrLinkSubmissionTooLarge) || errors.Is(err, ErrLinkBackpressure) {
		t.Fatalf("oversized submission error = %v, want only ErrLinkSubmissionTooLarge", err)
	}
	if !bytes.Equal(submission.Payload, before) {
		t.Fatal("oversized rejected payload changed")
	}
	if snapshot := link.Snapshot(); snapshot.PendingSubmissions != 0 || snapshot.PendingSubmissionBytes != 0 {
		t.Fatalf("oversized rejection changed accounting: %+v", snapshot)
	}
	select {
	case <-ready:
		t.Fatal("oversized rejection emitted a capacity signal")
	default:
	}

	beforeClose := link.Snapshot()
	closeResult := callErrorForTest(t, link.Close, func() {
		_ = clientConn.Close()
	}, "oversized-submission Close")
	if closeResult != nil {
		t.Fatalf("Close: %v", closeResult)
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeClose, startResult: nil, initialCloseResult: closeResult, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("oversized submission close retained %d unexpected events", len(events))
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func runSubmissionNotificationLifecycle(t *testing.T, factory clientLinkFactory) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	limits := limitsForWorkload(deterministicLinkWorkload(t))
	link := makeAndStartLink(t, factory, clientConn, limits)
	want := link.SubmissionReady()
	if want == nil {
		t.Fatal("SubmissionReady returned nil")
	}

	channels := make([]<-chan struct{}, 64)
	var waitGroup sync.WaitGroup
	for index := range channels {
		waitGroup.Go(func() {
			channels[index] = link.SubmissionReady()
		})
	}
	waitGroup.Wait()
	for index, channel := range channels {
		if channel != want {
			t.Fatalf("SubmissionReady channel %d changed identity", index)
		}
	}

	beforeClose := link.Snapshot()
	closeResult := callErrorForTest(t, link.Close, func() {
		_ = clientConn.Close()
	}, "submission-notification-lifecycle Close")
	if closeResult != nil {
		t.Fatalf("Close: %v", closeResult)
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeClose, startResult: nil, initialCloseResult: closeResult, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("notification lifecycle close retained %d unexpected events", len(events))
	}
	if got := link.SubmissionReady(); got != want {
		t.Fatal("SubmissionReady channel changed identity after terminal publication")
	}
	select {
	case _, open := <-want:
		if !open {
			t.Fatal("SubmissionReady channel was closed at terminal publication")
		}
		t.Fatal("SubmissionReady emitted an unexpected terminal signal")
	default:
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func runSubmissionLimit(t *testing.T, factory clientLinkFactory, itemOnly bool) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{mode: fakePeerHoldAfterReady})
	workload := deterministicLinkWorkload(t)
	item := workload.items[len(workload.items)-1]
	answerBytes := (LinkEvent{Kind: LinkEventProxyAnswer, Packet: item.wantPacket}).ByteSize()
	ackBytes := (LinkEvent{Kind: LinkEventSimpleAck}).ByteSize()
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: 2 * item.submission.ByteSize(),
		MaxPendingEvents:          2,
		MaxPendingEventBytes:      answerBytes + ackBytes,
	}
	if !itemOnly {
		limits.MaxPendingSubmissions = 2
		limits.MaxPendingSubmissionBytes = 2*item.submission.ByteSize() - 1
	}
	link := makeAndStartLink(t, factory, clientConn, limits)

	accepted := item.submission
	accepted.Payload = bytes.Clone(item.submission.Payload)
	acceptedPacket := bytes.Clone(item.wantPacket)
	acceptedSize := accepted.ByteSize()
	acceptedConnectionID := accepted.ConnectionID
	if err := link.TrySubmit(accepted); err != nil {
		t.Fatalf("accept first submission: %v", err)
	}
	rejected := item.submission
	rejected.SubmissionID++
	rejected.Payload = bytes.Clone(item.submission.Payload)
	rejectedBefore := bytes.Clone(rejected.Payload)
	if err := link.TrySubmit(rejected); !errors.Is(err, ErrLinkBackpressure) {
		t.Fatalf("second submission error = %v, want backpressure", err)
	}
	if !bytes.Equal(rejected.Payload, rejectedBefore) {
		t.Fatal("rejected submission payload changed")
	}
	rejected.Payload[len(rejected.Payload)-1] ^= 0xff

	peer.readOneAndHold(t)
	snapshot := link.Snapshot()
	if snapshot.PendingSubmissions != 1 || snapshot.PendingSubmissionBytes != acceptedSize ||
		snapshot.SubmissionHighWater != 1 || snapshot.SubmissionBytesHighWater != acceptedSize {
		t.Fatalf("held submission accounting = %+v", snapshot)
	}
	if records := peer.snapshotRecords(); len(records) != 0 {
		t.Fatalf("peer parsed %d records before release", len(records))
	}

	peer.stopHolding()
	answerEvent := receiveLinkEvent(t, link)
	ackEvent := receiveLinkEvent(t, link)
	if answerEvent.Kind != LinkEventProxyAnswer || answerEvent.ConnectionID != acceptedConnectionID ||
		answerEvent.AnswerFlags != ProxyAnswerFlagFlush || !bytes.Equal(answerEvent.Packet, acceptedPacket) {
		t.Fatalf("answer event = %v", answerEvent)
	}
	if ackEvent.Kind != LinkEventSimpleAck || ackEvent.ConnectionID != acceptedConnectionID ||
		ackEvent.ConfirmKey != uint32(acceptedConnectionID) {
		t.Fatalf("ack event = %v", ackEvent)
	}
	waitForLinkSnapshot(t, link, func(snapshot LinkSnapshot) bool {
		return snapshot.PendingSubmissions == 0 && snapshot.PendingSubmissionBytes == 0 &&
			snapshot.PendingEvents == 0 && snapshot.PendingEventBytes == 0
	})
	after := link.Snapshot()
	if after.SubmissionHighWater != snapshot.SubmissionHighWater ||
		after.SubmissionBytesHighWater != snapshot.SubmissionBytesHighWater {
		t.Fatalf("submission high-water values changed: before=%+v after=%+v", snapshot, after)
	}
	records := peer.snapshotRecords()
	if len(records) != 1 || records[0].operation != OperationProxyRequest || records[0].connectionID != acceptedConnectionID {
		t.Fatalf("peer records = %+v", records)
	}

	beforeClose := link.Snapshot()
	closeResult := callErrorForTest(t, link.Close, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}, "submission-limit Close")
	if closeResult != nil {
		t.Fatalf("Close: %v", closeResult)
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeClose, startResult: nil, initialCloseResult: closeResult, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("submission limit close retained %d unexpected events", len(events))
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func runEventBackpressure(t *testing.T, factory clientLinkFactory) {
	t.Run("item limit", func(t *testing.T) {
		runEventLimit(t, factory, true)
	})
	t.Run("byte limit", func(t *testing.T) {
		runEventLimit(t, factory, false)
	})
}

func runEventLimit(t *testing.T, factory clientLinkFactory, itemOnly bool) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	item := deterministicLinkWorkload(t).items[0]
	answerBytes := (LinkEvent{Kind: LinkEventProxyAnswer, Packet: item.wantPacket}).ByteSize()
	ackBytes := (LinkEvent{Kind: LinkEventSimpleAck}).ByteSize()
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: item.submission.ByteSize(),
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      answerBytes + ackBytes,
	}
	if !itemOnly {
		limits.MaxPendingEvents = 2
		limits.MaxPendingEventBytes = answerBytes + ackBytes - 1
	}
	link := makeAndStartLink(t, factory, clientConn, limits)
	if err := link.Start(newHarnessContext(t)); err != nil {
		t.Fatalf("repeated Start: %v", err)
	}
	beforeFailure := link.Snapshot()
	if err := link.TrySubmit(item.submission); err != nil {
		t.Fatalf("TrySubmit: %v", err)
	}
	events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeFailure, errorCategory: ErrLinkEventBackpressure, startResult: nil,
	})
	snapshot := link.Snapshot()
	if snapshot.SubmissionHighWater != 1 || snapshot.SubmissionBytesHighWater != item.submission.ByteSize() ||
		snapshot.EventHighWater != 1 || snapshot.EventBytesHighWater != answerBytes {
		t.Fatalf("terminal high-water values = %+v", snapshot)
	}

	if len(events) != 1 {
		t.Fatalf("retained event count = %d, want 1", len(events))
	}
	event := events[0]
	if event.Kind != LinkEventProxyAnswer || event.ConnectionID != item.submission.ConnectionID ||
		event.AnswerFlags != ProxyAnswerFlagFlush || !bytes.Equal(event.Packet, item.wantPacket) {
		t.Fatalf("retained event = %v", event)
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func runPeerFailure(t *testing.T, factory clientLinkFactory, mode fakePeerMode, want error) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{mode: mode})
	item := deterministicLinkWorkload(t).items[0]
	const pingID uint64 = 1
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: item.submission.ByteSize(),
		MaxPendingEvents:          2,
		MaxPendingEventBytes:      MaxMEFrameSize,
	}
	link := makeAndStartLink(t, factory, clientConn, limits)
	beforeFailure := link.Snapshot()
	if mode == fakePeerMalformedAfterRequest {
		if err := link.TrySubmit(item.submission); err != nil {
			t.Fatalf("TrySubmit: %v", err)
		}
	} else if mode == fakePeerCloseAfterReady {
		if err := link.TrySubmit(LinkSubmission{SubmissionID: 1, Payload: (Ping{ID: pingID}).MarshalBinary()}); err != nil {
			t.Fatalf("TrySubmit ping: %v", err)
		}
	}
	events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeFailure, errorCategory: want, startResult: nil,
	})
	if mode == fakePeerCloseAfterReady {
		if len(events) != 1 {
			t.Fatalf("peer close retained %d events, want the accepted pong", len(events))
		}
		pong := events[0]
		if pong.Kind != LinkEventPong || pong.ConnectionID != 0 || pong.KeepaliveID != pingID {
			t.Fatalf("peer close event = %v, want pong with connection ID 0 and keepalive ID %d", pong, pingID)
		}
	} else if len(events) != 0 {
		t.Fatalf("malformed response retained %d unexpected events", len(events))
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func runCloseProtocolFailureRace(t *testing.T, factory clientLinkFactory) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{mode: fakePeerHeldMalformedAfterRequest})
	item := deterministicLinkWorkload(t).items[0]
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: item.submission.ByteSize(),
		MaxPendingEvents:          2,
		MaxPendingEventBytes:      MaxMEFrameSize,
	}
	link := makeAndStartLink(t, factory, clientConn, limits)
	beforeRace := link.Snapshot()
	if err := link.TrySubmit(item.submission); err != nil {
		t.Fatalf("TrySubmit: %v", err)
	}
	peer.waitMalformedReady(t)

	raceStart := make(chan struct{})
	closeResultChannel := make(chan error, 1)
	releaseDone := make(chan struct{}, 1)
	go func() {
		select {
		case <-raceStart:
			closeResultChannel <- link.Close()
		case <-time.After(5 * time.Second):
			closeResultChannel <- errors.New("timed out waiting for Close/protocol race gate")
		}
	}()
	go func() {
		select {
		case <-raceStart:
			peer.releaseMalformed()
			releaseDone <- struct{}{}
		case <-time.After(5 * time.Second):
		}
	}()
	close(raceStart)
	closeResult := receiveError(t, closeResultChannel, "racing Close")
	receiveSignal(t, releaseDone, "malformed response release")
	waitLinkDone(t, link)
	terminal := link.Err()
	wantCategory := error(nil)
	if terminal != nil {
		if !errors.Is(terminal, ErrUnexpectedLinkRPC) {
			t.Fatalf("race terminal error = %v, want nil or %v", terminal, ErrUnexpectedLinkRPC)
		}
		wantCategory = ErrUnexpectedLinkRPC
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeRace, errorCategory: wantCategory, startResult: nil,
		initialCloseResult: closeResult, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("close/protocol race retained %d unexpected events", len(events))
	}
	assertFakePeerRaceCompletion(t, peer)
}

func runFreshLinkAfterFailure(t *testing.T, factory clientLinkFactory) {
	runPeerFailure(t, factory, fakePeerMalformedAfterRequest, ErrUnexpectedLinkRPC)

	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	item := deterministicLinkWorkload(t).items[0]
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: item.submission.ByteSize(),
		MaxPendingEvents:          2,
		MaxPendingEventBytes:      MaxMEFrameSize + SimpleAckPayloadSize,
	}
	link := makeAndStartLink(t, factory, clientConn, limits)
	if err := link.TrySubmit(item.submission); err != nil {
		t.Fatalf("fresh link TrySubmit: %v", err)
	}
	answer := receiveLinkEvent(t, link)
	if answer.Kind != LinkEventProxyAnswer || answer.ConnectionID != item.submission.ConnectionID ||
		answer.AnswerFlags != ProxyAnswerFlagFlush || !bytes.Equal(answer.Packet, item.wantPacket) {
		t.Fatalf("fresh link answer = %v", answer)
	}
	ack := receiveLinkEvent(t, link)
	if ack.Kind != LinkEventSimpleAck || ack.ConnectionID != item.submission.ConnectionID ||
		ack.ConfirmKey != uint32(item.submission.ConnectionID) {
		t.Fatalf("fresh link acknowledgement = %v", ack)
	}
	beforeClose := link.Snapshot()
	closeResult := callErrorForTest(t, link.Close, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}, "fresh-link Close")
	if closeResult != nil {
		t.Fatalf("close fresh link: %v", closeResult)
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeClose, startResult: nil, initialCloseResult: closeResult, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("fresh link close retained %d unexpected events", len(events))
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fresh fake peer: %v", err)
	}
}

func runConcurrentLifecycle(t *testing.T, factory clientLinkFactory) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	link := makeAndStartLink(t, factory, clientConn, limits)
	beforeClose := link.Snapshot()
	const callers = 16
	startResults := make(chan error, callers)
	closeResults := make(chan error, callers)
	startContext := newHarnessContext(t)
	var waitGroup sync.WaitGroup
	for range callers {
		waitGroup.Go(func() {
			startResults <- link.Start(startContext)
			_ = link.Err()
			_ = link.Snapshot()
			closeResults <- link.Close()
		})
	}
	if err := waitGroupBounded(&waitGroup, 5*time.Second, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}); err != nil {
		t.Fatalf("concurrent lifecycle calls: %v", err)
	}
	close(startResults)
	close(closeResults)
	for range callers {
		err := receiveError(t, startResults, "concurrent Start result")
		if err != nil {
			t.Fatalf("repeated Start result = %v", err)
		}
	}
	var firstClose error
	for index := range callers {
		err := receiveError(t, closeResults, "concurrent Close result")
		if index == 0 {
			firstClose = err
			continue
		}
		if !sameError(firstClose, err) {
			t.Fatalf("concurrent Close results differ: %v and %v", firstClose, err)
		}
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeClose, startResult: nil, initialCloseResult: firstClose, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("concurrent close retained %d unexpected events", len(events))
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func runConcurrentInitialStart(t *testing.T, factory clientLinkFactory) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{holdBootstrap: true})
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	link := makeUnstartedLink(t, factory, clientConn, limits)
	const callers = 16
	startGate := make(chan struct{})
	startContext := newHarnessContext(t)
	ready := make(chan struct{}, callers)
	results := make(chan error, callers)
	for range callers {
		go func() {
			ready <- struct{}{}
			select {
			case <-startGate:
				results <- link.Start(startContext)
			case <-time.After(5 * time.Second):
				results <- errors.New("timed out waiting for initial Start gate")
			}
		}()
	}
	for range callers {
		receiveSignal(t, ready, "initial Start caller")
	}
	close(startGate)
	peer.waitBootstrapStarted(t)
	if count := peer.bootstrapCount.Load(); count != 1 {
		t.Fatalf("bootstrap count while held = %d, want 1", count)
	}
	peer.releaseBootstrap()
	for range callers {
		if err := receiveError(t, results, "initial Start result"); err != nil {
			t.Fatalf("initial Start result = %v", err)
		}
	}
	if count := peer.bootstrapCount.Load(); count != 1 {
		t.Fatalf("bootstrap count = %d, want 1", count)
	}
	if snapshot := link.Snapshot(); snapshot.State != LinkStateReady {
		t.Fatalf("state after concurrent Start = %d", snapshot.State)
	}

	const pingID = 0x2122232425262728
	if err := link.TrySubmit(LinkSubmission{SubmissionID: 1, Payload: (Ping{ID: pingID}).MarshalBinary()}); err != nil {
		t.Fatalf("TrySubmit after concurrent Start: %v", err)
	}
	event := receiveLinkEvent(t, link)
	if event.Kind != LinkEventPong || event.KeepaliveID != pingID {
		t.Fatalf("event after concurrent Start = %v", event)
	}
	beforeClose := link.Snapshot()
	closeResult := callErrorForTest(t, link.Close, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}, "concurrent-Start Close")
	if closeResult != nil {
		t.Fatalf("Close: %v", closeResult)
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeClose, startResult: nil, initialCloseResult: closeResult, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("concurrent Start close retained %d unexpected events", len(events))
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func runInitialStartCloseRace(t *testing.T, factory clientLinkFactory) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{holdBootstrap: true})
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	link := makeUnstartedLink(t, factory, clientConn, limits)
	beforeRace := link.Snapshot()
	startResultChannel := make(chan error, 1)
	startContext := newHarnessContext(t)
	go func() {
		startResultChannel <- link.Start(startContext)
	}()
	peer.waitBootstrapStarted(t)

	raceGate := make(chan struct{})
	closeResultChannel := make(chan error, 1)
	releaseDone := make(chan struct{}, 1)
	go func() {
		select {
		case <-raceGate:
			closeResultChannel <- link.Close()
		case <-time.After(5 * time.Second):
			closeResultChannel <- errors.New("timed out waiting for Start/Close race gate")
		}
	}()
	go func() {
		select {
		case <-raceGate:
			peer.releaseBootstrap()
			releaseDone <- struct{}{}
		case <-time.After(5 * time.Second):
		}
	}()
	close(raceGate)
	closeResult := receiveError(t, closeResultChannel, "initial racing Close")
	receiveSignal(t, releaseDone, "bootstrap release")
	startResult := receiveError(t, startResultChannel, "initial racing Start")
	if startResult != nil && !errors.Is(startResult, ErrLinkClosed) {
		t.Fatalf("racing Start result = %v, want nil or %v", startResult, ErrLinkClosed)
	}
	if count := peer.bootstrapCount.Load(); count != 1 {
		t.Fatalf("racing bootstrap count = %d, want 1", count)
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeRace, startResult: startResult,
		initialCloseResult: closeResult, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("Start/Close race retained %d unexpected events", len(events))
	}
	assertFakePeerRaceCompletion(t, peer)
}

func runStartContextLifetime(t *testing.T, factory clientLinkFactory) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	item := deterministicLinkWorkload(t).items[0]
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: item.submission.ByteSize(),
		MaxPendingEvents:          2,
		MaxPendingEventBytes:      MaxMEFrameSize,
	}
	link := makeUnstartedLink(t, factory, clientConn, limits)
	startContext, cancel := context.WithCancel(newHarnessContext(t))
	if err := link.Start(startContext); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	cancel()
	receiveSignal(t, startContext.Done(), "Start context cancellation")

	if err := link.TrySubmit(item.submission); err != nil {
		t.Fatalf("TrySubmit after Start context cancellation: %v", err)
	}
	answer := receiveLinkEvent(t, link)
	ack := receiveLinkEvent(t, link)
	if answer.Kind != LinkEventProxyAnswer || answer.AnswerFlags != ProxyAnswerFlagFlush ||
		!bytes.Equal(answer.Packet, item.wantPacket) {
		t.Fatalf("answer after Start context cancellation = %v", answer)
	}
	if ack.Kind != LinkEventSimpleAck || ack.ConfirmKey != uint32(item.submission.ConnectionID) {
		t.Fatalf("acknowledgement after Start context cancellation = %v", ack)
	}
	beforeClose := link.Snapshot()
	closeResult := callErrorForTest(t, link.Close, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}, "context-lifetime Close")
	if closeResult != nil {
		t.Fatalf("Close: %v", closeResult)
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeClose, startResult: nil, initialCloseResult: closeResult, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("context lifetime close retained %d unexpected events", len(events))
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}

func runCloseBeforeStart(t *testing.T, factory clientLinkFactory) {
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	limits := LinkLimits{
		MaxPendingSubmissions:     1,
		MaxPendingSubmissionBytes: KeepalivePayloadSize,
		MaxPendingEvents:          1,
		MaxPendingEventBytes:      KeepalivePayloadSize,
	}
	link := makeUnstartedLink(t, factory, clientConn, limits)
	rejected := LinkSubmission{SubmissionID: 1, Payload: (Ping{ID: 1}).MarshalBinary()}
	rejectedBefore := bytes.Clone(rejected.Payload)
	if err := link.TrySubmit(rejected); !errors.Is(err, ErrLinkNotReady) {
		t.Fatalf("pre-start TrySubmit error = %v", err)
	}
	if !bytes.Equal(rejected.Payload, rejectedBefore) {
		t.Fatal("pre-start rejected payload changed")
	}
	beforeClose := link.Snapshot()
	firstClose := callErrorForTest(t, link.Close, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}, "pre-start Close")
	firstStart := link.Start(newHarnessContext(t))
	if !errors.Is(firstStart, ErrLinkClosed) {
		t.Fatalf("Start after pre-start Close error = %v", firstStart)
	}
	if events := assertLinkTerminal(t, link, terminalExpectation{
		before: beforeClose, startResult: firstStart,
		initialCloseResult: firstClose, hasInitialClose: true,
	}); len(events) != 0 {
		t.Fatalf("pre-start close retained %d unexpected events", len(events))
	}
	if err := waitFakePeer(t, peer); !errors.Is(err, io.EOF) {
		t.Fatalf("fake peer error = %v, want EOF", err)
	}
}

func makeAndStartLink(t *testing.T, factory clientLinkFactory, conn net.Conn, limits LinkLimits) ClientLink {
	t.Helper()
	link := makeUnstartedLink(t, factory, conn, limits)
	ctx := newHarnessContext(t)
	if err := link.Start(ctx); err != nil {
		t.Fatalf("start client link: %v", err)
	}
	if snapshot := link.Snapshot(); snapshot.State != LinkStateReady {
		t.Fatalf("state after Start = %d", snapshot.State)
	}
	return link
}

func newHarnessContext(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func makeUnstartedLink(t *testing.T, factory clientLinkFactory, conn net.Conn, limits LinkLimits) ClientLink {
	t.Helper()
	if err := limits.Validate(); err != nil {
		t.Fatalf("invalid harness limits: %v", err)
	}
	link, err := factory(conn, newTestBootstrap(t), limits)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("create client link: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_, waitError := callErrorBounded(link.Close, time.Second, func() { _ = conn.Close() })
		if waitError != nil {
			t.Errorf("cleanup client link Close: %v", waitError)
			return
		}
		select {
		case <-link.Done():
		case <-time.After(time.Second):
			t.Error("cleanup client link Done timed out")
		}
	})
	return link
}

func receiveLinkEvent(t *testing.T, link ClientLink) LinkEvent {
	t.Helper()
	select {
	case event, ok := <-link.Events():
		if !ok {
			t.Fatalf("event stream closed: %v", link.Err())
		}
		return event
	case <-time.After(5 * time.Second):
		done := false
		select {
		case <-link.Done():
			done = true
		default:
		}
		t.Fatalf("timed out waiting for a link event: done=%t err=%v snapshot=%+v", done, link.Err(), link.Snapshot())
		return LinkEvent{}
	}
}

func receiveError(t testing.TB, results <-chan error, operation string) error {
	t.Helper()
	select {
	case err := <-results:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
		return nil
	}
}

func receiveSignal(t testing.TB, signals <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signals:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func waitGroupBounded(waitGroup *sync.WaitGroup, timeout time.Duration, release func()) error {
	done := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(done)
	}()
	return waitForCompletionWithRelease(done, timeout, release)
}

func callErrorBounded(operation func() error, timeout time.Duration, release func()) (error, error) {
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		result <- operation()
	}()
	waitError := waitForCompletionWithRelease(finished, timeout, release)
	if errors.Is(waitError, errHarnessWaitStuck) {
		return nil, waitError
	}
	select {
	case operationError := <-result:
		return operationError, waitError
	default:
		return nil, errors.New("bounded operation finished without a result")
	}
}

func waitForCompletionWithRelease(done <-chan struct{}, timeout time.Duration, release func()) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
	}
	if release != nil {
		release()
	}
	secondTimer := time.NewTimer(timeout)
	defer secondTimer.Stop()
	select {
	case <-done:
		return errHarnessWaitTimeout
	case <-secondTimer.C:
		return errHarnessWaitStuck
	}
}

func callErrorForTest(t testing.TB, operation func() error, release func(), operationName string) error {
	t.Helper()
	operationError, waitError := callErrorBounded(operation, 5*time.Second, release)
	if waitError != nil {
		t.Fatalf("%s: %v", operationName, waitError)
	}
	return operationError
}

func registerBoundedCloseCleanup(t testing.TB, conn net.Conn, closeOperation func() error, operationName string) {
	t.Helper()
	t.Cleanup(func() {
		_ = conn.Close()
		_, waitError := callErrorBounded(closeOperation, time.Second, func() { _ = conn.Close() })
		if waitError != nil {
			t.Errorf("cleanup %s: %v", operationName, waitError)
		}
	})
}

func TestBoundedHarnessWaitsReleaseBlockedGoroutines(t *testing.T) {
	t.Run("error operation", func(t *testing.T) {
		gate := make(chan struct{})
		release := sync.OnceFunc(func() { close(gate) })
		terminated := make(chan struct{})
		wantOperationError := errors.New("released operation")
		operationError, waitError := callErrorBounded(func() error {
			defer close(terminated)
			select {
			case <-gate:
				return wantOperationError
			case <-time.After(time.Second):
				return errors.New("blocking stub was not released")
			}
		}, 5*time.Millisecond, release)
		if !errors.Is(waitError, errHarnessWaitTimeout) || !errors.Is(operationError, wantOperationError) {
			t.Fatalf("bounded error call = %v, %v", operationError, waitError)
		}
		receiveSignal(t, terminated, "bounded error-call goroutine termination")
	})

	t.Run("wait group", func(t *testing.T) {
		gate := make(chan struct{})
		release := sync.OnceFunc(func() { close(gate) })
		var waitGroup sync.WaitGroup
		waitGroup.Go(func() {
			select {
			case <-gate:
			case <-time.After(time.Second):
			}
		})
		if err := waitGroupBounded(&waitGroup, 5*time.Millisecond, release); !errors.Is(err, errHarnessWaitTimeout) {
			t.Fatalf("bounded WaitGroup result = %v", err)
		}
	})
}

func waitLinkDone(t *testing.T, link ClientLink) {
	t.Helper()
	select {
	case <-link.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for link shutdown")
	}
}

type terminalExpectation struct {
	before             LinkSnapshot
	errorCategory      error
	startResult        error
	initialCloseResult error
	hasInitialClose    bool
}

func assertLinkTerminal(t *testing.T, link ClientLink, expectation terminalExpectation) []LinkEvent {
	t.Helper()
	events := drainClosedEventsAfterDone(t, link)
	terminal := link.Err()
	if expectation.errorCategory == nil {
		if terminal != nil {
			t.Fatalf("terminal error = %v, want nil", terminal)
		}
	} else if !errors.Is(terminal, expectation.errorCategory) {
		t.Fatalf("terminal error = %v, want category %v", terminal, expectation.errorCategory)
	}
	if !sameError(terminal, link.Err()) {
		t.Fatalf("terminal error identity changed from %v to %v", terminal, link.Err())
	}

	snapshot := link.Snapshot()
	if snapshot.State != LinkStateClosed || snapshot.PendingSubmissions != 0 ||
		snapshot.PendingSubmissionBytes != 0 || snapshot.PendingEvents != 0 ||
		snapshot.PendingEventBytes != 0 {
		t.Fatalf("terminal snapshot = %+v", snapshot)
	}
	assertHighWaterMonotonic(t, expectation.before, snapshot)

	rejected := LinkSubmission{SubmissionID: 0xffffffffffffffff, Payload: (Ping{ID: 1}).MarshalBinary()}
	rejectedBefore := bytes.Clone(rejected.Payload)
	if err := link.TrySubmit(rejected); !errors.Is(err, ErrLinkClosed) {
		t.Fatalf("post-terminal TrySubmit error = %v, want %v", err, ErrLinkClosed)
	}
	if !bytes.Equal(rejected.Payload, rejectedBefore) {
		t.Fatal("post-terminal rejected payload changed")
	}
	rejected.Payload[len(rejected.Payload)-1] ^= 0xff

	if result := link.Start(newHarnessContext(t)); !sameError(result, expectation.startResult) {
		t.Fatalf("repeated Start result = %v, want %v", result, expectation.startResult)
	}
	firstClose := callErrorForTest(t, link.Close, nil, "post-terminal Close")
	secondClose := callErrorForTest(t, link.Close, nil, "repeated post-terminal Close")
	if !sameError(firstClose, secondClose) {
		t.Fatalf("Close results differ: %v and %v", firstClose, secondClose)
	}
	if expectation.hasInitialClose && !sameError(firstClose, expectation.initialCloseResult) {
		t.Fatalf("Close result changed from %v to %v", expectation.initialCloseResult, firstClose)
	}
	if !sameError(terminal, link.Err()) {
		t.Fatalf("terminal error changed after lifecycle calls from %v to %v", terminal, link.Err())
	}
	after := link.Snapshot()
	if after.State != LinkStateClosed || after.PendingSubmissions != 0 ||
		after.PendingSubmissionBytes != 0 || after.PendingEvents != 0 || after.PendingEventBytes != 0 {
		t.Fatalf("post-terminal snapshot = %+v", after)
	}
	if after.SubmissionHighWater != snapshot.SubmissionHighWater ||
		after.SubmissionBytesHighWater != snapshot.SubmissionBytesHighWater ||
		after.EventHighWater != snapshot.EventHighWater ||
		after.EventBytesHighWater != snapshot.EventBytesHighWater {
		t.Fatalf("terminal high-water values changed: before=%+v after=%+v", snapshot, after)
	}
	return events
}

func drainClosedEventsAfterDone(t *testing.T, link ClientLink) []LinkEvent {
	t.Helper()
	select {
	case <-link.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for link shutdown")
	}

	const maximumDrain = 1024
	events := make([]LinkEvent, 0)
	for range maximumDrain {
		select {
		case event, ok := <-link.Events():
			if !ok {
				return events
			}
			events = append(events, event)
		default:
			t.Fatal("Events was not closed before Done")
		}
	}
	t.Fatalf("Events did not close after %d buffered events", maximumDrain)
	return nil
}

func assertHighWaterMonotonic(t *testing.T, before, after LinkSnapshot) {
	t.Helper()
	if after.SubmissionHighWater < before.SubmissionHighWater ||
		after.SubmissionBytesHighWater < before.SubmissionBytesHighWater ||
		after.EventHighWater < before.EventHighWater ||
		after.EventBytesHighWater < before.EventBytesHighWater {
		t.Fatalf("high-water values decreased: before=%+v after=%+v", before, after)
	}
}

func waitForLinkSnapshot(t *testing.T, link ClientLink, accept func(LinkSnapshot) bool) LinkSnapshot {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		snapshot := link.Snapshot()
		if accept(snapshot) {
			return snapshot
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("timed out waiting for link snapshot; last snapshot: %+v", snapshot)
			return LinkSnapshot{}
		}
	}
}

func sameError(first error, second error) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return reflect.TypeOf(first) == reflect.TypeOf(second) && first.Error() == second.Error() &&
		errors.Is(first, second) && errors.Is(second, first)
}

func limitsForWorkload(workload linkWorkload) LinkLimits {
	limits := LinkLimits{
		MaxPendingSubmissions: len(workload.items) + 2,
		MaxPendingEvents:      len(workload.items)*2 + 3,
	}
	for _, item := range workload.items {
		limits.MaxPendingSubmissionBytes += item.submission.ByteSize()
		limits.MaxPendingEventBytes += (LinkEvent{Kind: LinkEventProxyAnswer, Packet: item.wantPacket}).ByteSize()
		limits.MaxPendingEventBytes += (LinkEvent{Kind: LinkEventSimpleAck}).ByteSize()
	}
	limits.MaxPendingSubmissionBytes += (LinkSubmission{Payload: (Ping{}).MarshalBinary()}).ByteSize()
	limits.MaxPendingSubmissionBytes += (LinkSubmission{Payload: (CloseConnection{}).MarshalBinary()}).ByteSize()
	limits.MaxPendingEventBytes += (LinkEvent{Kind: LinkEventPing}).ByteSize()
	limits.MaxPendingEventBytes += (LinkEvent{Kind: LinkEventPong}).ByteSize()
	limits.MaxPendingEventBytes += (LinkEvent{Kind: LinkEventCloseExternal}).ByteSize()
	return limits
}

type engineCorrectness struct {
	Bootstrap                      bool
	FragmentationCoalescing        bool
	ParallelSessions               bool
	RequestAnswerAck               bool
	PingPong                       bool
	CloseRouting                   bool
	SubmissionItemBackpressure     bool
	SubmissionByteBackpressure     bool
	SubmissionChargeRetention      bool
	EventItemBackpressureFailClose bool
	EventByteBackpressureFailClose bool
	RejectedOwnership              bool
	TerminalSemantics              bool
	PeerCloseFailClose             bool
	MalformedFailClose             bool
	CloseProtocolFailureRace       bool
	FreshLinkAfterFailure          bool
	ConcurrentLifecycle            bool
	ConcurrentInitialStart         bool
	InitialStartCloseRace          bool
	StartContextLifetime           bool
	CloseBeforeStart               bool
	OrderlyShutdown                bool
	ProtocolBytes                  bool
}

func (c engineCorrectness) passed() bool {
	return c.Bootstrap && c.FragmentationCoalescing && c.ParallelSessions &&
		c.RequestAnswerAck && c.PingPong && c.CloseRouting &&
		c.SubmissionItemBackpressure && c.SubmissionByteBackpressure &&
		c.SubmissionChargeRetention && c.EventItemBackpressureFailClose &&
		c.EventByteBackpressureFailClose && c.RejectedOwnership &&
		c.TerminalSemantics && c.PeerCloseFailClose && c.MalformedFailClose &&
		c.CloseProtocolFailureRace && c.FreshLinkAfterFailure && c.ConcurrentLifecycle &&
		c.ConcurrentInitialStart && c.InitialStartCloseRace && c.StartContextLifetime &&
		c.CloseBeforeStart && c.OrderlyShutdown && c.ProtocolBytes
}

type metricInterval struct {
	Estimate float64
	Low      float64
	High     float64
}

type decisionMetric string

const (
	metricSustainableRate          decisionMetric = "sustainable_requests_per_second"
	metricP50Latency               decisionMetric = "p50_latency"
	metricP95Latency               decisionMetric = "p95_latency"
	metricP99Latency               decisionMetric = "p99_latency"
	metricAllocsPerRequest         decisionMetric = "allocations_per_request"
	metricAllocatedBytesPerRequest decisionMetric = "allocated_bytes_per_request"
	metricAbsoluteGoroutineDelta   decisionMetric = "absolute_goroutine_delta"
	metricHeapBytesHighWater       decisionMetric = "heap_bytes_high_water"
	metricSubmissionHighWater      decisionMetric = "submission_items_high_water"
	metricSubmissionBytesHighWater decisionMetric = "submission_bytes_high_water"
	metricEventHighWater           decisionMetric = "event_items_high_water"
	metricEventBytesHighWater      decisionMetric = "event_bytes_high_water"
)

var eligibleDecisionMetrics = [...]decisionMetric{
	metricSustainableRate,
	metricP50Latency,
	metricP95Latency,
	metricP99Latency,
	metricAllocsPerRequest,
	metricAllocatedBytesPerRequest,
	metricAbsoluteGoroutineDelta,
	metricHeapBytesHighWater,
	metricSubmissionHighWater,
	metricSubmissionBytesHighWater,
	metricEventHighWater,
	metricEventBytesHighWater,
}

var resourceDecisionMetrics = [...]decisionMetric{
	metricAllocsPerRequest,
	metricAllocatedBytesPerRequest,
	metricAbsoluteGoroutineDelta,
	metricHeapBytesHighWater,
	metricSubmissionHighWater,
	metricSubmissionBytesHighWater,
	metricEventHighWater,
	metricEventBytesHighWater,
}

type engineBenchmarkControls struct {
	Purpose                   string
	Commit                    string
	SourceFingerprint         string
	GoVersion                 string
	Machine                   string
	CPUPolicy                 string
	Workload                  engineBenchmarkWorkloadEvidence
	EventLoops                int
	GOMAXPROCS                int
	MultiLinkCount            int
	Limits                    LinkLimits
	Warmup                    time.Duration
	WarmupCycles              int
	MeasurementDuration       time.Duration
	RequestsPerCycle          int
	ResourceCycles            int
	MaxInFlightPerConnection  int
	SlowReadChunk             int
	SlowReadDelay             time.Duration
	HeapSampleInterval        time.Duration
	ObservationTimeout        time.Duration
	RequestedSocketBuffer     int
	EffectiveWorkerSendBuffer int
	EffectiveWorkerReadBuffer int
	EffectivePeerSendBuffer   int
	EffectivePeerReadBuffer   int
	EffectiveWorkerNoDelay    bool
	EffectivePeerNoDelay      bool
	PeerGOMAXPROCS            int
	WorkerCPUSet              string
	PeerCPUSet                string
	ResourceAttribution       string
	ExpectedBytesRead         uint64
	ExpectedBytesWritten      uint64
}

const (
	engineBenchmarkPurposeSmoke    = "smoke"
	engineBenchmarkPurposeDecision = "decision"
)

type engineBenchmarkWorkloadEvidence struct {
	Name                     string
	SessionCount             int
	PacketSizes              [4]int
	ConnectionIDs            [4]int64
	RequestsPerCycle         int
	MaxInFlightPerConnection int
	WholeCycles              bool
	QueueHighWaterScope      string
}

type engineDecisionPolicy struct {
	TrialCount         int
	ConfidenceLevel    float64
	IntervalMethod     string
	MinimumImprovement map[decisionMetric]float64
	MaximumRegression  map[decisionMetric]float64
}

type engineTrialMetrics struct {
	// Duration, completed counts, and raw bytes describe the isolated
	// duration-based throughput phase. Latencies and resource fields describe
	// the separate fixed-cycle resource phase. BytesRead and BytesWritten are
	// normalized per complete workload cycle.
	Duration                    time.Duration
	CompletedCycles             int
	CompletedRequests           int
	SustainableRequestsPerSec   float64
	P50                         time.Duration
	P95                         time.Duration
	P99                         time.Duration
	LatencySamples              []time.Duration
	ResourceDuration            time.Duration
	ResourceCycles              int
	ResourceRequests            int
	ResourceRawBytesRead        uint64
	ResourceRawBytesWritten     uint64
	ResourceMallocs             uint64
	ResourceTotalAllocBytes     uint64
	AllocsPerRequest            float64
	AllocatedBytesPerRequest    float64
	BytesRead                   uint64
	BytesWritten                uint64
	RawBytesRead                uint64
	RawBytesWritten             uint64
	AbsoluteGoroutineDelta      int
	GoroutineBaseline           int
	GoroutinePeak               int
	HeapBytesHighWater          uint64
	HeapBytesWorkerBaseline     uint64
	HeapBytesAllocationBaseline uint64
	HeapBytesPeak               uint64
	SubmissionHighWater         int
	SubmissionBytesHighWater    int
	EventHighWater              int
	EventBytesHighWater         int
}

type pairedEngineTrial struct {
	PairIndex   int
	FirstEngine string
	Blocking    engineTrialMetrics
	Gnet        engineTrialMetrics
}

// engineMeasurement is deliberately test-only. PairedTrials retains every
// observation. EffectIntervals contains derived paired relative-improvement
// confidence intervals. Validation recomputes every interval from PairedTrials.
// The policy has no defaults.
type engineMeasurement struct {
	Controls            engineBenchmarkControls
	Policy              engineDecisionPolicy
	PairedTrials        []pairedEngineTrial
	EffectIntervals     map[decisionMetric]metricInterval
	BlockingCorrectness engineCorrectness
	GnetCorrectness     engineCorrectness
}

const (
	minimumPairedTrials         = 10
	conservativePairedT95Method = "paired-t-95-conservative-df9-v1"
	studentT975DF9              = 2.2621571628540993
)

func validateEngineMeasurementSchema(measurement engineMeasurement) error {
	controls := measurement.Controls
	if controls.Purpose != engineBenchmarkPurposeSmoke && controls.Purpose != engineBenchmarkPurposeDecision {
		return errors.New("engine benchmark purpose must be smoke or decision")
	}
	if controls.Commit == "" || controls.SourceFingerprint == "" || controls.GoVersion == "" || controls.Machine == "" ||
		controls.CPUPolicy == "" || controls.Workload.Name == "" || controls.EventLoops <= 0 ||
		controls.GOMAXPROCS <= 0 || controls.MultiLinkCount <= 1 || controls.Warmup <= 0 || controls.WarmupCycles <= 0 ||
		controls.MeasurementDuration <= 0 || controls.RequestsPerCycle <= 0 || controls.ResourceCycles <= 0 ||
		controls.MaxInFlightPerConnection != 1 || controls.SlowReadChunk < 0 || controls.SlowReadDelay < 0 ||
		(controls.SlowReadChunk == 0) != (controls.SlowReadDelay == 0) ||
		controls.HeapSampleInterval <= 0 || controls.ObservationTimeout <= 0 || controls.RequestedSocketBuffer <= 0 ||
		controls.EffectiveWorkerSendBuffer <= 0 || controls.EffectiveWorkerReadBuffer <= 0 ||
		controls.EffectivePeerSendBuffer <= 0 || controls.EffectivePeerReadBuffer <= 0 || controls.PeerGOMAXPROCS <= 0 ||
		controls.WorkerCPUSet == "" || controls.PeerCPUSet == "" || controls.ResourceAttribution == "" ||
		controls.ExpectedBytesRead == 0 ||
		controls.ExpectedBytesWritten == 0 {
		return errors.New("incomplete engine benchmark controls")
	}
	if !controls.EffectiveWorkerNoDelay || !controls.EffectivePeerNoDelay {
		return errors.New("engine benchmark TCP_NODELAY controls are not enforced")
	}
	workload := controls.Workload
	if workload.SessionCount <= 0 || workload.RequestsPerCycle != controls.RequestsPerCycle ||
		workload.MaxInFlightPerConnection != controls.MaxInFlightPerConnection || !workload.WholeCycles ||
		workload.QueueHighWaterScope == "" {
		return errors.New("incomplete structured engine benchmark workload")
	}
	if err := controls.Limits.Validate(); err != nil {
		return err
	}
	policy := measurement.Policy
	if policy.TrialCount < minimumPairedTrials || policy.TrialCount != len(measurement.PairedTrials) ||
		policy.ConfidenceLevel != 0.95 || policy.IntervalMethod != conservativePairedT95Method {
		return errors.New("incomplete engine decision policy")
	}
	if len(policy.MaximumRegression) != len(eligibleDecisionMetrics) ||
		len(policy.MinimumImprovement) != len(resourceDecisionMetrics)+1 {
		return errors.New("engine decision policy has unknown, missing, or duplicate metric keys")
	}
	for _, metric := range eligibleDecisionMetrics {
		maximumRegression, ok := policy.MaximumRegression[metric]
		if !ok {
			return fmt.Errorf("missing maximum regression for %s", metric)
		}
		if !validRegressionThreshold(maximumRegression) {
			return fmt.Errorf("invalid maximum regression for %s", metric)
		}
	}
	for _, metric := range append([]decisionMetric{metricSustainableRate}, resourceDecisionMetrics[:]...) {
		minimumImprovement, ok := policy.MinimumImprovement[metric]
		if !ok {
			return fmt.Errorf("missing minimum improvement for %s", metric)
		}
		if !validImprovementThreshold(minimumImprovement) {
			return fmt.Errorf("invalid minimum improvement for %s", metric)
		}
	}

	firstEngine := ""
	for index, trial := range measurement.PairedTrials {
		if trial.PairIndex != index+1 || trial.FirstEngine != "blocking" && trial.FirstEngine != "gnet" {
			return fmt.Errorf("invalid paired trial %d", index+1)
		}
		if err := validateTrialMetrics(trial.Blocking, controls); err != nil {
			return fmt.Errorf("blocking trial %d: %w", index+1, err)
		}
		if err := validateTrialMetrics(trial.Gnet, controls); err != nil {
			return fmt.Errorf("gnet trial %d: %w", index+1, err)
		}
		if index == 0 {
			firstEngine = trial.FirstEngine
			continue
		}
		want := firstEngine
		if index%2 == 1 {
			if firstEngine == "blocking" {
				want = "gnet"
			} else {
				want = "blocking"
			}
		}
		if trial.FirstEngine != want {
			return fmt.Errorf("paired trial %d does not alternate engine order", index+1)
		}
	}

	computed, err := computeEffectIntervals(measurement.PairedTrials, policy.IntervalMethod)
	if err != nil {
		return err
	}
	if len(measurement.EffectIntervals) != len(eligibleDecisionMetrics) {
		return errors.New("effect intervals have unknown or missing metric keys")
	}
	for _, metric := range eligibleDecisionMetrics {
		stored, ok := measurement.EffectIntervals[metric]
		if !ok {
			return fmt.Errorf("missing effect interval for %s", metric)
		}
		if stored != computed[metric] {
			return fmt.Errorf("effect interval for %s does not match paired trials", metric)
		}
	}
	return nil
}

func validRegressionThreshold(value float64) bool {
	return value >= 0 && value <= 1 && isFinite(value)
}

func validImprovementThreshold(value float64) bool {
	return value > 0 && value <= 1 && isFinite(value)
}

func isFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

func validateTrialMetrics(metrics engineTrialMetrics, controls engineBenchmarkControls) error {
	if metrics.Duration < controls.MeasurementDuration || metrics.CompletedCycles <= 0 ||
		metrics.CompletedCycles > int(^uint(0)>>1)/controls.RequestsPerCycle ||
		metrics.CompletedRequests != metrics.CompletedCycles*controls.RequestsPerCycle ||
		metrics.ResourceDuration <= 0 || metrics.ResourceCycles != controls.ResourceCycles ||
		metrics.ResourceCycles > int(^uint(0)>>1)/controls.RequestsPerCycle ||
		metrics.ResourceRequests != metrics.ResourceCycles*controls.RequestsPerCycle ||
		len(metrics.LatencySamples) != metrics.ResourceRequests ||
		metrics.P50 < 0 || metrics.P95 < metrics.P50 || metrics.P99 < metrics.P95 ||
		!isFinite(metrics.SustainableRequestsPerSec) || metrics.SustainableRequestsPerSec < 0 ||
		!isFinite(metrics.AllocsPerRequest) || metrics.AllocsPerRequest < 0 ||
		!isFinite(metrics.AllocatedBytesPerRequest) || metrics.AllocatedBytesPerRequest < 0 ||
		metrics.AbsoluteGoroutineDelta < 0 || metrics.GoroutineBaseline < 0 ||
		metrics.GoroutinePeak < metrics.GoroutineBaseline ||
		metrics.HeapBytesPeak < metrics.HeapBytesWorkerBaseline ||
		metrics.HeapBytesPeak < metrics.HeapBytesAllocationBaseline ||
		metrics.SubmissionHighWater < 0 ||
		metrics.SubmissionBytesHighWater < 0 || metrics.EventHighWater < 0 ||
		metrics.EventBytesHighWater < 0 {
		return errors.New("trial metrics must be finite, nonnegative, and ordered")
	}
	for _, latency := range metrics.LatencySamples {
		if latency < 0 {
			return errors.New("trial latency samples must be nonnegative")
		}
	}
	wantP50, wantP95, wantP99 := nearestRankLatencyQuantiles(metrics.LatencySamples)
	if metrics.P50 != wantP50 || metrics.P95 != wantP95 || metrics.P99 != wantP99 {
		return errors.New("trial latency quantiles do not match raw nearest-rank samples")
	}
	wantRate := float64(metrics.CompletedRequests) / metrics.Duration.Seconds()
	if metrics.SustainableRequestsPerSec != wantRate {
		return errors.New("trial sustainable request rate does not match completed requests and duration")
	}
	wantAllocs := float64(metrics.ResourceMallocs) / float64(metrics.ResourceRequests)
	wantAllocatedBytes := float64(metrics.ResourceTotalAllocBytes) / float64(metrics.ResourceRequests)
	if metrics.AllocsPerRequest != wantAllocs || metrics.AllocatedBytesPerRequest != wantAllocatedBytes {
		return errors.New("trial allocation metrics do not match raw resource counters")
	}
	wantGoroutineDelta := metrics.GoroutinePeak - metrics.GoroutineBaseline
	if metrics.AbsoluteGoroutineDelta != wantGoroutineDelta {
		return errors.New("trial goroutine delta does not match raw resource counters")
	}
	if metrics.HeapBytesHighWater != metrics.HeapBytesPeak-metrics.HeapBytesWorkerBaseline {
		return errors.New("trial heap high-water delta does not match raw resource counters")
	}
	if metrics.BytesRead != controls.ExpectedBytesRead || metrics.BytesWritten != controls.ExpectedBytesWritten {
		return errors.New("trial per-cycle protocol byte counts do not match controls")
	}
	cycles := uint64(metrics.CompletedCycles)
	if controls.ExpectedBytesRead > ^uint64(0)/cycles || controls.ExpectedBytesWritten > ^uint64(0)/cycles {
		return errors.New("trial expected protocol byte total overflows")
	}
	if metrics.RawBytesRead != controls.ExpectedBytesRead*cycles ||
		metrics.RawBytesWritten != controls.ExpectedBytesWritten*cycles {
		return errors.New("trial throughput protocol byte totals do not match completed cycles")
	}
	resourceCycles := uint64(metrics.ResourceCycles)
	if controls.ExpectedBytesRead > ^uint64(0)/resourceCycles || controls.ExpectedBytesWritten > ^uint64(0)/resourceCycles {
		return errors.New("trial expected resource protocol byte total overflows")
	}
	if metrics.ResourceRawBytesRead != controls.ExpectedBytesRead*resourceCycles ||
		metrics.ResourceRawBytesWritten != controls.ExpectedBytesWritten*resourceCycles {
		return errors.New("trial resource protocol byte totals do not match fixed cycles")
	}
	return nil
}

// nearestRankLatencyQuantiles freezes the benchmark quantile rule. It sorts a
// copy of the raw samples and selects ceil(p*n), with ranks starting at one.
func nearestRankLatencyQuantiles(samples []time.Duration) (time.Duration, time.Duration, time.Duration) {
	ordered := slices.Clone(samples)
	slices.Sort(ordered)
	nearestRank := func(numerator int) time.Duration {
		rank := (numerator*len(ordered) + 99) / 100
		return ordered[rank-1]
	}
	return nearestRank(50), nearestRank(95), nearestRank(99)
}

func pairedRelativeEffect(blocking, gnet float64, higherIsBetter bool) (float64, error) {
	if blocking < 0 || gnet < 0 || math.IsNaN(blocking) || math.IsNaN(gnet) ||
		math.IsInf(blocking, 0) || math.IsInf(gnet, 0) {
		return 0, errors.New("paired observations must be finite and nonnegative")
	}
	denominator := max(math.Abs(blocking), math.Abs(gnet))
	if denominator == 0 {
		return 0, nil
	}
	if higherIsBetter {
		return (gnet - blocking) / denominator, nil
	}
	return (blocking - gnet) / denominator, nil
}

func computeEffectIntervals(trials []pairedEngineTrial, method string) (map[decisionMetric]metricInterval, error) {
	if method != conservativePairedT95Method || len(trials) < minimumPairedTrials {
		return nil, errors.New("unsupported or incomplete effect interval input")
	}
	intervals := make(map[decisionMetric]metricInterval, len(eligibleDecisionMetrics))
	for _, metric := range eligibleDecisionMetrics {
		effects := make([]float64, 0, len(trials))
		for _, trial := range trials {
			blocking, higherIsBetter := trialMetricValue(trial.Blocking, metric)
			gnet, _ := trialMetricValue(trial.Gnet, metric)
			effect, err := pairedRelativeEffect(blocking, gnet, higherIsBetter)
			if err != nil {
				return nil, fmt.Errorf("%s effect: %w", metric, err)
			}
			effects = append(effects, effect)
		}
		intervals[metric] = conservativePairedT95Interval(effects)
	}
	return intervals, nil
}

func trialMetricValue(metrics engineTrialMetrics, metric decisionMetric) (float64, bool) {
	switch metric {
	case metricSustainableRate:
		return metrics.SustainableRequestsPerSec, true
	case metricP50Latency:
		return float64(metrics.P50), false
	case metricP95Latency:
		return float64(metrics.P95), false
	case metricP99Latency:
		return float64(metrics.P99), false
	case metricAllocsPerRequest:
		return metrics.AllocsPerRequest, false
	case metricAllocatedBytesPerRequest:
		return metrics.AllocatedBytesPerRequest, false
	case metricAbsoluteGoroutineDelta:
		return float64(metrics.AbsoluteGoroutineDelta), false
	case metricHeapBytesHighWater:
		return float64(metrics.HeapBytesHighWater), false
	case metricSubmissionHighWater:
		return float64(metrics.SubmissionHighWater), false
	case metricSubmissionBytesHighWater:
		return float64(metrics.SubmissionBytesHighWater), false
	case metricEventHighWater:
		return float64(metrics.EventHighWater), false
	case metricEventBytesHighWater:
		return float64(metrics.EventBytesHighWater), false
	default:
		panic(fmt.Sprintf("unknown decision metric %q", metric))
	}
}

// conservativePairedT95Interval uses the two-sided t(0.975, 9) critical
// value for every supported sample size. This is conservative for n > 10.
// Source: NIST/SEMATECH e-Handbook of Statistical Methods, table of critical
// values for the Student t distribution, row 9 and column 0.975.
func conservativePairedT95Interval(effects []float64) metricInterval {
	mean := 0.0
	for _, effect := range effects {
		mean += effect
	}
	mean /= float64(len(effects))
	squaredDeviation := 0.0
	for _, effect := range effects {
		difference := effect - mean
		squaredDeviation += difference * difference
	}
	standardError := math.Sqrt(squaredDeviation / float64(len(effects)-1) / float64(len(effects)))
	margin := studentT975DF9 * standardError
	return metricInterval{
		Estimate: mean,
		Low:      max(-1, mean-margin),
		High:     min(1, mean+margin),
	}
}

type engineSelection string

const (
	engineSelectionNone     engineSelection = "none"
	engineSelectionBlocking engineSelection = "blocking"
	engineSelectionGnet     engineSelection = "gnet"
)

func selectLinkEngine(measurement engineMeasurement) (engineSelection, error) {
	blockingCorrect := measurement.BlockingCorrectness.passed()
	gnetCorrect := measurement.GnetCorrectness.passed()
	switch {
	case !blockingCorrect && !gnetCorrect:
		return engineSelectionNone, nil
	case blockingCorrect && !gnetCorrect:
		return engineSelectionBlocking, nil
	case !blockingCorrect && gnetCorrect:
		return engineSelectionGnet, nil
	}
	if err := validateEngineMeasurementSchema(measurement); err != nil {
		return engineSelectionNone, err
	}

	for _, metric := range eligibleDecisionMetrics {
		if measurement.EffectIntervals[metric].Low < -measurement.Policy.MaximumRegression[metric] {
			return engineSelectionBlocking, nil
		}
	}
	rateLowerBound := measurement.EffectIntervals[metricSustainableRate].Low
	if rateLowerBound > 0 && rateLowerBound >= measurement.Policy.MinimumImprovement[metricSustainableRate] {
		return engineSelectionGnet, nil
	}
	for _, metric := range resourceDecisionMetrics {
		lowerBound := measurement.EffectIntervals[metric].Low
		if lowerBound > 0 && lowerBound >= measurement.Policy.MinimumImprovement[metric] {
			return engineSelectionGnet, nil
		}
	}
	return engineSelectionBlocking, nil
}

func captureRuntimeBaseline() (int, uint64) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return runtime.NumGoroutine(), memory.HeapAlloc
}

func TestEngineMeasurementSchemaCoverage(t *testing.T) {
	measurement := completeEngineMeasurementSchema()
	if err := validateEngineMeasurementSchema(measurement); err != nil {
		t.Fatalf("valid schema: %v", err)
	}
	tooFewTrials := measurement
	tooFewTrials.PairedTrials = slices.Clone(measurement.PairedTrials[:minimumPairedTrials-1])
	tooFewTrials.Policy.TrialCount = len(tooFewTrials.PairedTrials)
	if err := validateEngineMeasurementSchema(tooFewTrials); err == nil {
		t.Fatalf("%d paired trials were accepted", len(tooFewTrials.PairedTrials))
	}
	if _, err := computeEffectIntervals(tooFewTrials.PairedTrials, conservativePairedT95Method); err == nil {
		t.Fatal("effect computation accepted fewer than 10 paired trials")
	}

	for _, metric := range eligibleDecisionMetrics {
		t.Run(string(metric), func(t *testing.T) {
			missingEffect := measurement
			missingEffect.EffectIntervals = maps.Clone(measurement.EffectIntervals)
			delete(missingEffect.EffectIntervals, metric)
			if err := validateEngineMeasurementSchema(missingEffect); err == nil {
				t.Fatal("missing effect interval was accepted")
			}

			missingRegression := measurement
			missingRegression.Policy.MaximumRegression = maps.Clone(measurement.Policy.MaximumRegression)
			delete(missingRegression.Policy.MaximumRegression, metric)
			if err := validateEngineMeasurementSchema(missingRegression); err == nil {
				t.Fatal("missing regression policy was accepted")
			}
		})
	}
	for _, metric := range append([]decisionMetric{metricSustainableRate}, resourceDecisionMetrics[:]...) {
		t.Run("improvement/"+string(metric), func(t *testing.T) {
			missing := measurement
			missing.Policy.MinimumImprovement = maps.Clone(measurement.Policy.MinimumImprovement)
			delete(missing.Policy.MinimumImprovement, metric)
			if err := validateEngineMeasurementSchema(missing); err == nil {
				t.Fatal("missing improvement policy was accepted")
			}
		})
	}

	invalidInterval := measurement
	invalidInterval.EffectIntervals = maps.Clone(measurement.EffectIntervals)
	invalidInterval.EffectIntervals[metricP99Latency] = metricInterval{Estimate: 0.01, Low: 0, High: 0.01}
	if err := validateEngineMeasurementSchema(invalidInterval); err == nil {
		t.Fatal("effect interval that did not match raw trials was accepted")
	}
	unknownRegression := measurement
	unknownRegression.Policy.MaximumRegression = maps.Clone(measurement.Policy.MaximumRegression)
	unknownRegression.Policy.MaximumRegression[decisionMetric("unknown")] = 0.1
	if err := validateEngineMeasurementSchema(unknownRegression); err == nil {
		t.Fatal("unknown maximum-regression metric was accepted")
	}
	unknownImprovement := measurement
	unknownImprovement.Policy.MinimumImprovement = maps.Clone(measurement.Policy.MinimumImprovement)
	unknownImprovement.Policy.MinimumImprovement[decisionMetric("unknown")] = 0.1
	if err := validateEngineMeasurementSchema(unknownImprovement); err == nil {
		t.Fatal("unknown minimum-improvement metric was accepted")
	}
	unknownEffect := measurement
	unknownEffect.EffectIntervals = maps.Clone(measurement.EffectIntervals)
	unknownEffect.EffectIntervals[decisionMetric("unknown")] = metricInterval{}
	if err := validateEngineMeasurementSchema(unknownEffect); err == nil {
		t.Fatal("unknown effect metric was accepted")
	}
	staleInterval := measurement
	staleInterval.PairedTrials = slices.Clone(measurement.PairedTrials)
	staleInterval.PairedTrials[0].Blocking.ResourceMallocs = 1
	staleInterval.PairedTrials[0].Blocking.AllocsPerRequest = 1
	if err := validateEngineMeasurementSchema(staleInterval); err == nil {
		t.Fatal("raw trial change with a stale effect interval was accepted")
	}

	invalidMinimum := measurement
	invalidMinimum.Policy.MinimumImprovement = maps.Clone(measurement.Policy.MinimumImprovement)
	invalidMinimum.Policy.MinimumImprovement[metricSustainableRate] = 0
	if err := validateEngineMeasurementSchema(invalidMinimum); err == nil {
		t.Fatal("zero minimum improvement was accepted")
	}

	invalidMaximum := measurement
	invalidMaximum.Policy.MaximumRegression = maps.Clone(measurement.Policy.MaximumRegression)
	invalidMaximum.Policy.MaximumRegression[metricP99Latency] = -0.01
	if err := validateEngineMeasurementSchema(invalidMaximum); err == nil {
		t.Fatal("negative maximum regression was accepted")
	}

	invalidRaw := measurement
	invalidRaw.PairedTrials = slices.Clone(measurement.PairedTrials)
	invalidRaw.PairedTrials[0].Gnet.AllocsPerRequest = math.NaN()
	if err := validateEngineMeasurementSchema(invalidRaw); err == nil {
		t.Fatal("non-finite raw metric was accepted")
	}
	invalidRaw = measurement
	invalidRaw.PairedTrials = slices.Clone(measurement.PairedTrials)
	invalidRaw.PairedTrials[0].Gnet.AbsoluteGoroutineDelta = -1
	if err := validateEngineMeasurementSchema(invalidRaw); err == nil {
		t.Fatal("negative absolute goroutine difference was accepted")
	}

	invalidBytes := measurement
	invalidBytes.PairedTrials = slices.Clone(measurement.PairedTrials)
	invalidBytes.PairedTrials[0].Gnet.BytesWritten++
	if err := validateEngineMeasurementSchema(invalidBytes); err == nil {
		t.Fatal("incorrect protocol byte count was accepted")
	}

	invalidThroughputTotal := measurement
	invalidThroughputTotal.PairedTrials = slices.Clone(measurement.PairedTrials)
	invalidThroughputTotal.PairedTrials[0].Gnet.RawBytesWritten++
	if err := validateEngineMeasurementSchema(invalidThroughputTotal); err == nil {
		t.Fatal("incorrect raw throughput byte total was accepted")
	}
	invalidResourceTotal := measurement
	invalidResourceTotal.PairedTrials = slices.Clone(measurement.PairedTrials)
	invalidResourceTotal.PairedTrials[0].Gnet.ResourceRawBytesRead++
	if err := validateEngineMeasurementSchema(invalidResourceTotal); err == nil {
		t.Fatal("incorrect raw resource byte total was accepted")
	}
	invalidRate := measurement
	invalidRate.PairedTrials = slices.Clone(measurement.PairedTrials)
	invalidRate.PairedTrials[0].Gnet.SustainableRequestsPerSec++
	if err := validateEngineMeasurementSchema(invalidRate); err == nil {
		t.Fatal("unrecomputed sustainable rate was accepted")
	}
	invalidAllocationRaw := measurement
	invalidAllocationRaw.PairedTrials = slices.Clone(measurement.PairedTrials)
	invalidAllocationRaw.PairedTrials[0].Gnet.ResourceMallocs++
	if err := validateEngineMeasurementSchema(invalidAllocationRaw); err == nil {
		t.Fatal("unrecomputed allocation metric was accepted")
	}
	invalidHeapRaw := measurement
	invalidHeapRaw.PairedTrials = slices.Clone(measurement.PairedTrials)
	invalidHeapRaw.PairedTrials[0].Gnet.HeapBytesPeak++
	if err := validateEngineMeasurementSchema(invalidHeapRaw); err == nil {
		t.Fatal("unrecomputed heap metric was accepted")
	}
	invalidGoroutineRaw := measurement
	invalidGoroutineRaw.PairedTrials = slices.Clone(measurement.PairedTrials)
	invalidGoroutineRaw.PairedTrials[0].Gnet.GoroutinePeak++
	if err := validateEngineMeasurementSchema(invalidGoroutineRaw); err == nil {
		t.Fatal("unrecomputed goroutine metric was accepted")
	}
	invalidLatency := measurement
	invalidLatency.PairedTrials = slices.Clone(measurement.PairedTrials)
	invalidLatency.PairedTrials[0].Gnet.LatencySamples = slices.Clone(measurement.PairedTrials[0].Gnet.LatencySamples)
	invalidLatency.PairedTrials[0].Gnet.LatencySamples[0]++
	if err := validateEngineMeasurementSchema(invalidLatency); err == nil {
		t.Fatal("unrecomputed latency quantile was accepted")
	}
	shortDuration := measurement
	shortDuration.PairedTrials = slices.Clone(measurement.PairedTrials)
	shortDuration.PairedTrials[0].Gnet.Duration = measurement.Controls.MeasurementDuration - time.Nanosecond
	if err := validateEngineMeasurementSchema(shortDuration); err == nil {
		t.Fatal("short throughput duration was accepted")
	}

	for name, mutate := range map[string]func(*engineBenchmarkControls){
		"event loops": func(controls *engineBenchmarkControls) { controls.EventLoops = 0 },
		"GOMAXPROCS":  func(controls *engineBenchmarkControls) { controls.GOMAXPROCS = -1 },
		"in-flight":   func(controls *engineBenchmarkControls) { controls.MaxInFlightPerConnection = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := measurement
			mutate(&invalid.Controls)
			if err := validateEngineMeasurementSchema(invalid); err == nil {
				t.Fatal("non-positive benchmark control was accepted")
			}
		})
	}
	normalScenario := measurement
	normalScenario.Controls.SlowReadChunk = 0
	normalScenario.Controls.SlowReadDelay = 0
	if err := validateEngineMeasurementSchema(normalScenario); err != nil {
		t.Fatalf("zero/zero normal slow-read controls were rejected: %v", err)
	}
	for _, mixed := range []engineBenchmarkControls{
		func() engineBenchmarkControls {
			controls := measurement.Controls
			controls.SlowReadChunk = 0
			return controls
		}(),
		func() engineBenchmarkControls {
			controls := measurement.Controls
			controls.SlowReadDelay = 0
			return controls
		}(),
	} {
		invalid := measurement
		invalid.Controls = mixed
		if err := validateEngineMeasurementSchema(invalid); err == nil {
			t.Fatal("mixed zero/positive slow-read controls were accepted")
		}
	}
}

func TestPairedRelativeEffect(t *testing.T) {
	tests := []struct {
		name           string
		blocking       float64
		gnet           float64
		higherIsBetter bool
		want           float64
	}{
		{name: "higher is better", blocking: 100, gnet: 125, higherIsBetter: true, want: 0.2},
		{name: "lower is better", blocking: 100, gnet: 80, want: 0.2},
		{name: "regression", blocking: 100, gnet: 125, want: -0.2},
		{name: "both zero", higherIsBetter: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := pairedRelativeEffect(test.blocking, test.gnet, test.higherIsBetter)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("effect = %g, want %g", got, test.want)
			}
		})
	}
	if _, err := pairedRelativeEffect(-1, 1, true); err == nil {
		t.Fatal("negative observation was accepted")
	}
	effects := make([]float64, minimumPairedTrials)
	effects[len(effects)-1] = 1
	interval := conservativePairedT95Interval(effects)
	if math.Abs(interval.Estimate-0.1) > 1e-15 ||
		math.Abs(interval.Low-(-0.12621571628540993)) > 1e-15 ||
		math.Abs(interval.High-0.3262157162854099) > 1e-15 {
		t.Fatalf("conservative paired-t interval = %+v", interval)
	}

	measurement := completeEngineMeasurementSchema()
	for index := range measurement.PairedTrials {
		measurement.PairedTrials[index].Blocking.GoroutinePeak = 10
		measurement.PairedTrials[index].Gnet.GoroutinePeak = 5
		measurement.PairedTrials[index].Blocking.AbsoluteGoroutineDelta = 10
		measurement.PairedTrials[index].Gnet.AbsoluteGoroutineDelta = 5
	}
	recomputeEffectIntervals(t, &measurement)
	if interval := measurement.EffectIntervals[metricAbsoluteGoroutineDelta]; interval != (metricInterval{
		Estimate: 0.5, Low: 0.5, High: 0.5,
	}) {
		t.Fatalf("absolute goroutine effect interval = %+v", interval)
	}
}

func TestSelectLinkEngine(t *testing.T) {
	t.Run("correctness gate needs no performance schema", func(t *testing.T) {
		measurement := engineMeasurement{BlockingCorrectness: completeEngineCorrectness()}
		selection, err := selectLinkEngine(measurement)
		if err != nil || selection != engineSelectionBlocking {
			t.Fatalf("blocking-only selection = %q, %v", selection, err)
		}

		measurement = engineMeasurement{GnetCorrectness: completeEngineCorrectness()}
		selection, err = selectLinkEngine(measurement)
		if err != nil || selection != engineSelectionGnet {
			t.Fatalf("gnet-only selection = %q, %v", selection, err)
		}

		selection, err = selectLinkEngine(engineMeasurement{})
		if err != nil || selection != engineSelectionNone {
			t.Fatalf("no-correct-engine selection = %q, %v", selection, err)
		}

		blocking := completeEngineCorrectness()
		blocking.ProtocolBytes = false
		measurement = engineMeasurement{
			BlockingCorrectness: blocking,
			GnetCorrectness:     completeEngineCorrectness(),
		}
		selection, err = selectLinkEngine(measurement)
		if err != nil || selection != engineSelectionGnet {
			t.Fatalf("protocol-byte correctness selection = %q, %v", selection, err)
		}
	})

	t.Run("all-zero tie is blocking", func(t *testing.T) {
		measurement := completeEngineMeasurementSchema()
		selection, err := selectLinkEngine(measurement)
		if err != nil {
			t.Fatal(err)
		}
		if selection != engineSelectionBlocking {
			t.Fatalf("selection = %q, want %q", selection, engineSelectionBlocking)
		}
	})

	t.Run("resource win", func(t *testing.T) {
		measurement := completeEngineMeasurementSchema()
		for index := range measurement.PairedTrials {
			measurement.PairedTrials[index].Blocking.ResourceMallocs = 100
			measurement.PairedTrials[index].Gnet.ResourceMallocs = 75
			measurement.PairedTrials[index].Blocking.AllocsPerRequest = 100
			measurement.PairedTrials[index].Gnet.AllocsPerRequest = 75
		}
		recomputeEffectIntervals(t, &measurement)
		selection, err := selectLinkEngine(measurement)
		if err != nil {
			t.Fatal(err)
		}
		if selection != engineSelectionGnet {
			t.Fatalf("selection = %q, want %q", selection, engineSelectionGnet)
		}
	})

	t.Run("tail regression blocks resource win", func(t *testing.T) {
		measurement := completeEngineMeasurementSchema()
		for metric := range measurement.Policy.MaximumRegression {
			measurement.Policy.MaximumRegression[metric] = 0.1
		}
		for index := range measurement.PairedTrials {
			measurement.PairedTrials[index].Blocking.ResourceMallocs = 100
			measurement.PairedTrials[index].Gnet.ResourceMallocs = 75
			measurement.PairedTrials[index].Blocking.AllocsPerRequest = 100
			measurement.PairedTrials[index].Gnet.AllocsPerRequest = 75
			measurement.PairedTrials[index].Blocking.LatencySamples[0] = 100 * time.Nanosecond
			measurement.PairedTrials[index].Blocking.P50 = 100 * time.Nanosecond
			measurement.PairedTrials[index].Blocking.P95 = 100 * time.Nanosecond
			measurement.PairedTrials[index].Blocking.P99 = 100 * time.Nanosecond
			measurement.PairedTrials[index].Gnet.LatencySamples[0] = 125 * time.Nanosecond
			measurement.PairedTrials[index].Gnet.P50 = 125 * time.Nanosecond
			measurement.PairedTrials[index].Gnet.P95 = 125 * time.Nanosecond
			measurement.PairedTrials[index].Gnet.P99 = 125 * time.Nanosecond
		}
		recomputeEffectIntervals(t, &measurement)
		selection, err := selectLinkEngine(measurement)
		if err != nil {
			t.Fatal(err)
		}
		if selection != engineSelectionBlocking {
			t.Fatalf("selection = %q, want %q", selection, engineSelectionBlocking)
		}
	})

	t.Run("both-correct protocol byte mismatch rejects measurement", func(t *testing.T) {
		measurement := completeEngineMeasurementSchema()
		measurement.PairedTrials[0].Gnet.BytesWritten++
		if _, err := selectLinkEngine(measurement); err == nil {
			t.Fatal("protocol byte mismatch was accepted")
		}
	})
}

func recomputeEffectIntervals(t testing.TB, measurement *engineMeasurement) {
	t.Helper()
	intervals, err := computeEffectIntervals(measurement.PairedTrials, measurement.Policy.IntervalMethod)
	if err != nil {
		t.Fatalf("compute effect intervals: %v", err)
	}
	measurement.EffectIntervals = intervals
}

func completeEngineMeasurementSchema() engineMeasurement {
	maximumRegression := make(map[decisionMetric]float64, len(eligibleDecisionMetrics))
	for _, metric := range eligibleDecisionMetrics {
		maximumRegression[metric] = 0
	}
	minimumImprovement := make(map[decisionMetric]float64, len(resourceDecisionMetrics)+1)
	minimumImprovement[metricSustainableRate] = 0.1
	for _, metric := range resourceDecisionMetrics {
		minimumImprovement[metric] = 0.1
	}
	trials := make([]pairedEngineTrial, minimumPairedTrials)
	for index := range trials {
		firstEngine := "blocking"
		if index%2 == 1 {
			firstEngine = "gnet"
		}
		trials[index] = pairedEngineTrial{
			PairIndex: index + 1, FirstEngine: firstEngine,
			Blocking: engineTrialMetrics{
				Duration: time.Second, CompletedCycles: 1, CompletedRequests: 1,
				SustainableRequestsPerSec: 1, LatencySamples: []time.Duration{0},
				ResourceDuration: time.Second, ResourceCycles: 1, ResourceRequests: 1,
				BytesRead: 1, BytesWritten: 1, RawBytesRead: 1, RawBytesWritten: 1,
				ResourceRawBytesRead: 1, ResourceRawBytesWritten: 1,
			},
			Gnet: engineTrialMetrics{
				Duration: time.Second, CompletedCycles: 1, CompletedRequests: 1,
				SustainableRequestsPerSec: 1, LatencySamples: []time.Duration{0},
				ResourceDuration: time.Second, ResourceCycles: 1, ResourceRequests: 1,
				BytesRead: 1, BytesWritten: 1, RawBytesRead: 1, RawBytesWritten: 1,
				ResourceRawBytesRead: 1, ResourceRawBytesWritten: 1,
			},
		}
	}
	measurement := engineMeasurement{
		Controls: engineBenchmarkControls{
			Purpose: engineBenchmarkPurposeDecision, Commit: "synthetic-commit", SourceFingerprint: "synthetic-fingerprint",
			GoVersion: "go1.27", Machine: "synthetic-machine", CPUPolicy: "synthetic-policy",
			Workload: engineBenchmarkWorkloadEvidence{
				Name: "synthetic-workload", SessionCount: 1, PacketSizes: [4]int{1, 1, 1, 1},
				ConnectionIDs: [4]int64{1, 1, 1, 1}, RequestsPerCycle: 1,
				MaxInFlightPerConnection: 1, WholeCycles: true, QueueHighWaterScope: "per-link-max",
			},
			EventLoops: 1, GOMAXPROCS: 1,
			MultiLinkCount: 2,
			Limits: LinkLimits{
				MaxPendingSubmissions: 1, MaxPendingSubmissionBytes: 1,
				MaxPendingEvents: 1, MaxPendingEventBytes: 1,
			},
			Warmup: time.Second, WarmupCycles: 1, MeasurementDuration: time.Second,
			RequestsPerCycle: 1, ResourceCycles: 1, MaxInFlightPerConnection: 1,
			SlowReadChunk: 1, SlowReadDelay: time.Nanosecond, HeapSampleInterval: time.Nanosecond,
			ObservationTimeout:    time.Minute,
			RequestedSocketBuffer: 1, EffectiveWorkerSendBuffer: 1, EffectiveWorkerReadBuffer: 1,
			EffectivePeerSendBuffer: 1, EffectivePeerReadBuffer: 1,
			EffectiveWorkerNoDelay: true, EffectivePeerNoDelay: true, PeerGOMAXPROCS: 1,
			WorkerCPUSet: "0", PeerCPUSet: "1", ResourceAttribution: "synthetic",
			ExpectedBytesRead: 1, ExpectedBytesWritten: 1,
		},
		Policy: engineDecisionPolicy{
			TrialCount: minimumPairedTrials, ConfidenceLevel: 0.95,
			IntervalMethod:     conservativePairedT95Method,
			MinimumImprovement: minimumImprovement, MaximumRegression: maximumRegression,
		},
		PairedTrials:        trials,
		BlockingCorrectness: completeEngineCorrectness(),
		GnetCorrectness:     completeEngineCorrectness(),
	}
	intervals, err := computeEffectIntervals(measurement.PairedTrials, measurement.Policy.IntervalMethod)
	if err != nil {
		panic(err)
	}
	measurement.EffectIntervals = intervals
	return measurement
}

func completeEngineCorrectness() engineCorrectness {
	return engineCorrectness{
		Bootstrap: true, FragmentationCoalescing: true, ParallelSessions: true,
		RequestAnswerAck: true, PingPong: true, CloseRouting: true,
		SubmissionItemBackpressure: true, SubmissionByteBackpressure: true,
		SubmissionChargeRetention: true, EventItemBackpressureFailClose: true,
		EventByteBackpressureFailClose: true, RejectedOwnership: true,
		TerminalSemantics: true, PeerCloseFailClose: true, MalformedFailClose: true,
		CloseProtocolFailureRace: true, FreshLinkAfterFailure: true, ConcurrentLifecycle: true,
		ConcurrentInitialStart: true, InitialStartCloseRace: true, StartContextLifetime: true,
		CloseBeforeStart: true,
		OrderlyShutdown:  true, ProtocolBytes: true,
	}
}

func waitFakePeer(t testing.TB, peer *fakeMiddleEndPeer) error {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	var result error
	select {
	case err := <-peer.done:
		result = err
	case <-timer.C:
		return errFakePeerWaitTimeout
	}
	select {
	case <-peer.stopped:
		return result
	case <-timer.C:
		return errFakePeerWaitTimeout
	}
}

func assertFakePeerRaceCompletion(t testing.TB, peer *fakeMiddleEndPeer) {
	t.Helper()
	err := waitFakePeer(t, peer)
	if err == nil {
		return
	}
	if errors.Is(err, errFakePeerWaitTimeout) {
		t.Fatalf("fake peer race did not terminate: %v", err)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return
	}
	var networkError net.Error
	if errors.As(err, &networkError) && !networkError.Timeout() {
		return
	}
	t.Fatalf("fake peer race error = %v, want an orderly or connection-close result", err)
}

func acceptFakeMiddleEnd(listener *net.TCPListener, timeout time.Duration) (net.Conn, error) {
	if err := listener.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set accept deadline: %w", err)
	}
	connection, err := listener.Accept()
	if err != nil {
		return nil, err
	}
	return connection, nil
}

func dialFakeMiddleEnd(t testing.TB, config fakePeerConfig) (net.Conn, *fakeMiddleEndPeer) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for fake Middle-End: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		t.Fatalf("fake Middle-End listener type = %T, want *net.TCPListener", listener)
	}
	accepted := make(chan net.Conn, 1)
	acceptError := make(chan error, 1)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		connection, err := acceptFakeMiddleEnd(tcpListener, 5*time.Second)
		if err != nil {
			acceptError <- err
			return
		}
		accepted <- connection
	}()
	dialContext, cancelDial := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelDial()
	client, err := (&net.Dialer{}).DialContext(dialContext, "tcp4", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		receiveSignal(t, acceptDone, "fake Middle-End accept goroutine after dial failure")
		t.Fatalf("dial fake Middle-End: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	var server net.Conn
	select {
	case server = <-accepted:
		receiveSignal(t, acceptDone, "fake Middle-End accept goroutine")
	case err := <-acceptError:
		_ = client.Close()
		_ = listener.Close()
		receiveSignal(t, acceptDone, "fake Middle-End accept goroutine after accept failure")
		t.Fatalf("accept fake Middle-End: %v", err)
	case <-time.After(5 * time.Second):
		_ = client.Close()
		_ = listener.Close()
		receiveSignal(t, acceptDone, "fake Middle-End accept goroutine after timeout")
		t.Fatal("timed out waiting for fake Middle-End accept")
	}
	t.Cleanup(func() { _ = server.Close() })
	if config.mode == fakePeerHoldAfterReady {
		clientTCP, clientOK := client.(*net.TCPConn)
		serverTCP, serverOK := server.(*net.TCPConn)
		if !clientOK || !serverOK {
			t.Fatal("fake Middle-End hold mode requires TCP connections")
		}
		// Keep both buffers well below the 1 MiB held submission while avoiding
		// kernel-specific tiny-window progress that can dominate the release
		// deadline independently of either link engine.
		const heldSocketBuffer = 64 << 10
		if err := clientTCP.SetWriteBuffer(heldSocketBuffer); err != nil {
			t.Fatalf("set fake client write buffer: %v", err)
		}
		if err := serverTCP.SetReadBuffer(heldSocketBuffer); err != nil {
			t.Fatalf("set fake peer read buffer: %v", err)
		}
	}
	if err := listener.Close(); err != nil {
		_ = client.Close()
		_ = server.Close()
		t.Fatalf("close fake Middle-End listener: %v", err)
	}
	peer := newFakeMiddleEndPeer(server, config)
	peer.start()
	t.Cleanup(func() {
		peer.stopHolding()
		_ = peer.conn.Close()
		select {
		case <-peer.stopped:
		case <-time.After(time.Second):
			t.Errorf("cleanup fake Middle-End peer did not stop")
		}
	})
	return client, peer
}

func TestDeterministicLinkWorkload(t *testing.T) {
	workload := deterministicLinkWorkload(t)
	if workload.name == "" || len(workload.items) != len(benchmarkPacketSizes())*4 {
		t.Fatalf("workload = %q with %d items", workload.name, len(workload.items))
	}
	sessions := submissionsBySession(workload)
	for sessionIndex, submissions := range sessions {
		if len(submissions) != len(benchmarkPacketSizes()) {
			t.Fatalf("session %d has %d submissions", sessionIndex, len(submissions))
		}
		for sizeIndex, submission := range submissions {
			if err := submission.Validate(); err != nil {
				t.Fatalf("session %d size %d: %v", sessionIndex, sizeIndex, err)
			}
			request, err := ParseProxyRequest(submission.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if len(request.Packet) != benchmarkPacketSizes()[sizeIndex] {
				t.Fatalf("session %d packet %d size = %d", sessionIndex, sizeIndex, len(request.Packet))
			}
		}
	}
}

func TestFakeMiddleEndPeerFragmentationCoalescingAndPayloadMatrix(t *testing.T) {
	ctx := newHarnessContext(t)
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{peerPingID: 0x0102030405060708})
	link, err := BootstrapBlocking(ctx, clientConn, newTestBootstrap(t))
	if err != nil {
		t.Fatalf("BootstrapBlocking: %v", err)
	}
	registerBoundedCloseCleanup(t, clientConn, link.Close, "blocking link Close")

	peerPingFrame, err := link.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("ReadFrame peer ping: %v", err)
	}
	peerPing, err := ParsePing(peerPingFrame.Payload)
	if err != nil {
		t.Fatalf("ParsePing: %v", err)
	}
	if err := link.WritePayload(ctx, (Pong{ID: peerPing.ID}).MarshalBinary()); err != nil {
		t.Fatalf("write peer pong: %v", err)
	}

	workload := deterministicLinkWorkload(t)
	for _, item := range workload.items {
		if err := link.WritePayload(ctx, item.submission.Payload); err != nil {
			t.Fatalf("write submission %d: %v", item.submission.SubmissionID, err)
		}
		answerFrame, err := link.ReadFrame(ctx)
		if err != nil {
			t.Fatalf("read answer %d: %v", item.submission.SubmissionID, err)
		}
		answer, err := ParseProxyAnswer(answerFrame.Payload)
		if err != nil {
			t.Fatalf("parse answer %d: %v", item.submission.SubmissionID, err)
		}
		if answer.ConnectionID != item.submission.ConnectionID || answer.Flags != ProxyAnswerFlagFlush ||
			!bytes.Equal(answer.Packet, item.wantPacket) {
			t.Fatalf("answer %d does not match", item.submission.SubmissionID)
		}
		ackFrame, err := link.ReadFrame(ctx)
		if err != nil {
			t.Fatalf("read ack %d: %v", item.submission.SubmissionID, err)
		}
		ack, err := ParseSimpleAck(ackFrame.Payload)
		if err != nil {
			t.Fatalf("parse ack %d: %v", item.submission.SubmissionID, err)
		}
		if ack.ConnectionID != item.submission.ConnectionID || ack.ConfirmKey != uint32(item.submission.ConnectionID) {
			t.Fatalf("ack %d = %+v", item.submission.SubmissionID, ack)
		}
	}

	if err := link.Ping(ctx, 0x1112131415161718); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := link.WritePayload(ctx, (CloseConnection{ConnectionID: 1000}).MarshalBinary()); err != nil {
		t.Fatalf("write connection close: %v", err)
	}
	closeFrame, err := link.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("read external close: %v", err)
	}
	closeEvent, err := ParseCloseExternal(closeFrame.Payload)
	if err != nil || closeEvent.ConnectionID != 1000 {
		t.Fatalf("external close = %+v, %v", closeEvent, err)
	}
	if err := callErrorForTest(t, link.Close, func() {
		peer.stopHolding()
		_ = clientConn.Close()
	}, "blocking link Close"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}

	records := peer.snapshotRecords()
	if len(records) != len(workload.items)+3 {
		t.Fatalf("peer recorded %d operations, want %d", len(records), len(workload.items)+3)
	}
	if records[0].operation != OperationPong || records[len(records)-2].operation != OperationPing ||
		records[len(records)-1].operation != OperationCloseConnection {
		t.Fatalf("boundary peer operations = %08x/%08x/%08x", records[0].operation, records[len(records)-2].operation, records[len(records)-1].operation)
	}
}

func TestFakeMiddleEndPeerFailureModes(t *testing.T) {
	for _, test := range []struct {
		name string
		mode fakePeerMode
	}{
		{name: "peer close", mode: fakePeerCloseAfterReady},
		{name: "malformed response", mode: fakePeerMalformedAfterRequest},
		{name: "queue saturation hold", mode: fakePeerHoldAfterReady},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := newHarnessContext(t)
			clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{mode: test.mode})
			link, err := BootstrapBlocking(ctx, clientConn, newTestBootstrap(t))
			if err != nil {
				t.Fatalf("BootstrapBlocking: %v", err)
			}
			registerBoundedCloseCleanup(t, clientConn, link.Close, "blocking link Close")
			select {
			case <-peer.ready:
			case <-time.After(time.Second):
				t.Fatal("fake peer did not become ready")
			}
			switch test.mode {
			case fakePeerCloseAfterReady:
				if err := link.WritePayload(ctx, (CloseConnection{ConnectionID: 1}).MarshalBinary()); err != nil {
					t.Fatalf("WritePayload: %v", err)
				}
				if _, err := link.ReadFrame(ctx); err == nil {
					t.Fatal("peer close was not observed")
				}
			case fakePeerMalformedAfterRequest:
				item := deterministicLinkWorkload(t).items[0]
				if err := link.WritePayload(ctx, item.submission.Payload); err != nil {
					t.Fatalf("WritePayload: %v", err)
				}
				frame, err := link.ReadFrame(ctx)
				if err != nil {
					t.Fatalf("ReadFrame: %v", err)
				}
				if _, err := parseLinkEvent(frame.Payload); !errors.Is(err, ErrUnexpectedLinkRPC) {
					t.Fatalf("parseLinkEvent error = %v", err)
				}
			case fakePeerHoldAfterReady:
				item := deterministicLinkWorkload(t).items[0]
				writeDone := make(chan error, 1)
				go func() {
					writeDone <- link.WritePayload(ctx, item.submission.Payload)
				}()
				peer.readOneAndHold(t)
				peer.stopHolding()
				if err := receiveError(t, writeDone, "held blocking write"); err != nil {
					t.Fatalf("WritePayload: %v", err)
				}
				if _, err := link.ReadFrame(ctx); err != nil {
					t.Fatalf("ReadFrame answer: %v", err)
				}
				if _, err := link.ReadFrame(ctx); err != nil {
					t.Fatalf("ReadFrame acknowledgement: %v", err)
				}
			}
			_ = callErrorForTest(t, link.Close, func() {
				peer.stopHolding()
				_ = clientConn.Close()
			}, "blocking link Close")
			if err := waitFakePeer(t, peer); err != nil {
				t.Fatalf("fake peer: %v", err)
			}
		})
	}
}

func TestFakeMiddleEndPeerRecordLimitFailsClosed(t *testing.T) {
	ctx := newHarnessContext(t)
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{maxRecords: 1})
	link, err := BootstrapBlocking(ctx, clientConn, newTestBootstrap(t))
	if err != nil {
		t.Fatalf("BootstrapBlocking: %v", err)
	}
	registerBoundedCloseCleanup(t, clientConn, link.Close, "blocking link Close")
	if err := link.Ping(ctx, 1); err != nil {
		t.Fatalf("first Ping: %v", err)
	}
	if err := link.Ping(ctx, 2); err == nil {
		t.Fatal("second Ping did not observe the peer close")
	}
	if err := waitFakePeer(t, peer); !errors.Is(err, errFakePeerRecordLimit) {
		t.Fatalf("fake peer error = %v", err)
	}
}
