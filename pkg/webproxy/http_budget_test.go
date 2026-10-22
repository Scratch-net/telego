package webproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

// Ordinary bodies have one DATA frame, not the 4096 frame upper bound.
// Holding the first body prevents any batch from committing before all four
// bodies have been admitted, so this isolates false item pressure from I/O.
func TestHTTPOrdinaryFourBatchWindowExactAccounting(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, nil, dialer.DialContext)
	address := unusedTCPAddress(t)
	server, err := NewHTTPServer(HTTPServerConfig{Bind: address, Hostname: "proxy.example.com", Manager: manager, NumEventLoop: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := server.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	app := &httpTestApplication{server: server, manager: manager, profiles: profiles, address: address}
	created := createTestSession(t, manager, profiles[0])
	open := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1})
	opening := conveyorHTTPUp(t, app, created.Token, 1, len(open), open)
	conveyorHTTPAck(t, opening, http.StatusNoContent, 1)
	peer := dialer.Peer(t)
	defer peer.Close()
	bodies := make([][]byte, httpUpWindow)
	var want []byte
	for i := range bodies {
		payload := bytes.Repeat([]byte{byte('a' + i)}, 32*1024)
		bodies[i] = testFrameBatch(t, Frame{Type: FrameData, StreamID: 1, Payload: payload})
		want = append(want, payload...)
	}
	connections := make([]net.Conn, httpUpWindow)
	connections[0] = conveyorHTTPUp(t, app, created.Token, 2, len(bodies[0]), bodies[0][:1])
	for i := 1; i < httpUpWindow-1; i++ {
		connections[i] = conveyorHTTPUp(t, app, created.Token, uint64(i+2), len(bodies[i]), bodies[i])
		conveyorWaitKnown(t, created.Session, uint64(i+2))
	}
	connections[3] = conveyorHTTPUp(t, app, created.Token, 5, len(bodies[3]), bodies[3][:1])
	deadline := time.Now().Add(time.Second)
	admitted := false
	for time.Now().Before(deadline) {
		created.Session.mu.Lock()
		lane := created.Session.httpUpLanes[0]
		admitted = lane != nil && lane.pending[5] != nil && lane.pending[5].readers != 0
		created.Session.mu.Unlock()
		if admitted {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !admitted {
		created.Session.mu.Lock()
		bytesLimit, itemsLimit := created.Session.uplinkPendingLimits()
		created.Session.mu.Unlock()
		t.Fatalf("ordinary W4 fourth single-DATA body rejected: capacity=%+v uplink-bytes=%d uplink-items=%d; four pessimistic reservations=%d items", manager.Capacity(), bytesLimit, itemsLimit, httpUpWindow*(MaxBatchFrames+1))
	}
	if _, err := connections[3].Write(bodies[3][1:]); err != nil {
		t.Fatal(err)
	}
	if _, err := connections[0].Write(bodies[0][1:]); err != nil {
		t.Fatal(err)
	}
	for i, conn := range connections {
		conveyorHTTPAck(t, conn, http.StatusNoContent, uint64(i+2))
	}
	retry := conveyorHTTPUp(t, app, created.Token, 3, len(bodies[1]), bodies[1])
	conveyorHTTPAck(t, retry, http.StatusNoContent, 3)
	got := make([]byte, len(want))
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("backend data is not ordered byte-identical payload")
	}
	if err := peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("replayed body reached backend twice")
	}
}

func TestHTTPApplicationRefillKeepsGlobalCreditAndWakes(t *testing.T) {
	for _, amount := range []struct {
		name        string
		cost, items int
	}{{"bytes", queueItemCost, 0}, {"items", 0, 1}, {"both", queueItemCost, 1}} {
		t.Run(amount.name, func(t *testing.T) {
			profiles := testProfiles(t)
			manager := testManager(t, profiles, nil, nil)
			session := createTestSession(t, manager, profiles[0]).Session
			body := testFrameBatch(t, Frame{Type: FramePong})
			reader := reserveHTTPTest(t, session, 0, 1, body)
			session.mu.Lock()
			beforeFree := session.httpApplication
			if !reader.borrowApplicationLocked(amount.cost, amount.items) ||
				!reader.transferApplicationLocked(amount.cost, amount.items) {
				t.Fatal("cannot transfer bounded application credit")
			}
			wake := session.budgetNotify
			before := manager.Capacity()
			// The backend source has been disposed. Refill its application
			// credit before any other session can consume a global release.
			session.releaseUplinkPendingLocked(amount.cost, amount.items)
			if session.httpApplication.cost != beforeFree.cost || session.httpApplication.items != beforeFree.items {
				t.Fatalf("application credit not restored: %+v", session.httpApplication)
			}
			session.mu.Unlock()
			select {
			case <-wake:
			default:
				t.Fatal("refill did not wake a waiting head")
			}
			if after := manager.Capacity(); after.PendingBytes != before.PendingBytes || after.PendingItems != before.PendingItems {
				t.Fatalf("refill exposed global progress credit: before=%+v after=%+v", before, after)
			}
			reader.Release()
			if capacity := manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
				t.Fatalf("idle application pool leaked: %+v", capacity)
			}
		})
	}
}

func TestHTTPApplicationDoesNotRecycleProtectedCapacity(t *testing.T) {
	for _, class := range []pendingClass{pendingControl, pendingDownlink, pendingHandoff, pendingBackendInput} {
		t.Run(string(rune('0'+class)), func(t *testing.T) {
			profiles := testProfiles(t)
			manager := testManager(t, profiles, nil, nil)
			session := createTestSession(t, manager, profiles[0]).Session
			reader := reserveHTTPTest(t, session, 0, 1, testFrameBatch(t, Frame{Type: FramePong}))
			session.mu.Lock()
			if !reader.borrowApplicationLocked(queueItemCost, 1) || !reader.transferApplicationLocked(queueItemCost, 1) {
				t.Fatal("cannot transfer bounded application credit")
			}
			before := session.httpApplication
			if !session.reservePendingLocked(queueItemCost, 1, class) {
				t.Fatal("cannot acquire protected test allocation")
			}
			session.releasePendingLocked(queueItemCost, 1)
			if session.httpApplication.cost != before.cost || session.httpApplication.items != before.items {
				t.Fatal("protected release became ordinary application credit")
			}
			session.releaseUplinkPendingLocked(queueItemCost, 1)
			session.mu.Unlock()
			reader.Release()
		})
	}
}

func TestHTTPApplicationCanceledHeadLeavesQueueBeforeBodyRelease(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	body := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1}, Frame{Type: FrameData, StreamID: 1, Payload: []byte("x")})
	reader := reserveHTTPTest(t, session, 0, 1, body)
	session.mu.Lock()
	poolCost, poolItems := session.httpApplication.cost, session.httpApplication.items
	if !reader.borrowApplicationLocked(poolCost, poolItems) || !reader.transferApplicationLocked(poolCost, poolItems) {
		t.Fatal("cannot occupy application pool")
	}
	session.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { _, err := reader.Process(ctx, body); result <- err }()
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return len(session.httpApplication.waiters) == 1
	})
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("head cancellation: %v", err)
	}
	session.mu.Lock()
	if len(session.httpApplication.waiters) != 0 || reader.cost == 0 {
		t.Fatal("canceled head retained queue position or released live body")
	}
	session.releaseUplinkPendingLocked(poolCost, poolItems)
	session.mu.Unlock()
	reader.Release()
}

func TestHTTPApplicationLanesShareCreditFairlyAtGlobalLimit(t *testing.T) {
	profiles := testProfiles(t)
	dialer := newPipeDialer()
	manager := testManager(t, profiles, func(config *ManagerConfig) {
		config.Carrier = CarrierHTTPSLanes
		config.Limits.MaxSessions = 3
		config.Limits.MaxPendingGlobal = config.Limits.MaxPendingPerSession
		config.Limits.MaxPendingItemsGlobal = config.Limits.MaxPendingItemsPerSession
	}, dialer.DialContext)
	session := createTestSession(t, manager, profiles[0]).Session
	// Finish opening the control backend before either DATA lane starts.
	// OPEN+CLOSE together can otherwise enqueue an already-canceled pipe
	// peer, making later dialer.Peer calls depend on select scheduling.
	if _, err := session.ProcessUpLane(43, 1, testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 43})); err != nil {
		t.Fatal(err)
	}
	controlPeer := dialer.Peer(t)
	defer controlPeer.Close()
	readers := make([]*httpUpReservation, 2)
	bodies := make([][]byte, 2)
	for index := range readers {
		lane := uint32(41 + index)
		bodies[index] = testFrameBatch(t, Frame{Type: FrameOpen, StreamID: lane},
			Frame{Type: FrameData, StreamID: lane, Payload: []byte{byte(lane)}})
		readers[index] = reserveHTTPTest(t, session, lane, 1, bodies[index])
	}
	controlBody := testFrameBatch(t, Frame{Type: FrameClose, StreamID: 43})
	control := reserveHTTPTest(t, session, 43, 2, controlBody)
	session.mu.Lock()
	poolCost, poolItems := session.httpApplication.cost, session.httpApplication.items
	if !readers[0].borrowApplicationLocked(poolCost, poolItems) || !readers[0].transferApplicationLocked(poolCost, poolItems) {
		t.Fatal("cannot occupy shared credit")
	}
	session.mu.Unlock()
	fillHTTPProgressBudget(t, manager, profiles[0])
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	results := make(chan int, 2)
	for index, reader := range readers {
		go func() {
			if _, err := reader.Process(ctx, bodies[index]); err != nil {
				t.Errorf("lane %d: %v", index, err)
			}
			results <- index
		}()
		eventually(t, time.Second, func() bool {
			session.mu.Lock()
			defer session.mu.Unlock()
			return len(session.httpApplication.waiters) == index+1
		})
	}
	// A zero-DATA head must apply while both DATA heads are waiting. Keep
	// its body owned so its later disposal cannot provide test credit early.
	if ack, err := control.Process(ctx, controlBody); err != nil || ack != 2 {
		t.Fatalf("control head waited for DATA credit: %d, %v", ack, err)
	}
	const firstCost = queueItemCost + 1
	session.mu.Lock()
	before := manager.Capacity()
	session.releaseUplinkPendingLocked(firstCost, 1)
	session.mu.Unlock()
	if after := manager.Capacity(); after.PendingBytes != before.PendingBytes || after.PendingItems != before.PendingItems {
		t.Fatal("first head's credit escaped to a global competitor")
	}
	if index := <-results; index != 0 {
		t.Fatalf("later lane bypassed the first ready head: %d", index)
	}
	firstPeer := dialer.Peer(t)
	defer firstPeer.Close()
	select {
	case <-results:
		t.Fatal("second lane applied without application credit")
	case <-time.After(10 * time.Millisecond):
	}
	session.mu.Lock()
	session.releaseUplinkPendingLocked(poolCost-firstCost, poolItems-1)
	session.mu.Unlock()
	if index := <-results; index != 1 {
		t.Fatalf("second ready head did not advance: %d", index)
	}
	secondPeer := dialer.Peer(t)
	defer secondPeer.Close()
	for index, peer := range []net.Conn{firstPeer, secondPeer} {
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		var got [1]byte
		if _, err := io.ReadFull(peer, got[:]); err != nil || got[0] != byte(41+index) {
			t.Fatalf("lane delivery=%x err=%v", got, err)
		}
	}
	for _, reader := range readers {
		reader.Release()
	}
	control.Release()
}

func TestHTTPApplicationLateDataNeedsNoCredit(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	session.mu.Lock()
	session.usedStreams.Add(1)
	session.mu.Unlock()
	body := testFrameBatch(t, Frame{Type: FrameData, StreamID: 1, Payload: []byte("late")})
	reader := reserveHTTPTest(t, session, 0, 1, body)
	session.mu.Lock()
	cost, items := session.httpApplication.cost, session.httpApplication.items
	if !reader.borrowApplicationLocked(cost, items) || !reader.transferApplicationLocked(cost, items) {
		t.Fatal("cannot occupy application pool")
	}
	session.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if ack, err := reader.Process(ctx, body); err != nil || ack != 1 {
		t.Fatalf("valid late DATA waited for unused application credit: %d, %v", ack, err)
	}
	session.mu.Lock()
	session.releaseUplinkPendingLocked(cost, items)
	session.mu.Unlock()
	reader.Release()
}

func TestHTTPApplicationBoundMatchesBackendTransitions(t *testing.T) {
	profiles := testProfiles(t)
	manager := testManager(t, profiles, nil, nil)
	session := createTestSession(t, manager, profiles[0]).Session
	body := testFrameBatch(t,
		Frame{Type: FrameData, StreamID: 2, Payload: []byte("late")},
		Frame{Type: FrameOpen, StreamID: 3},
		Frame{Type: FrameData, StreamID: 3, Payload: []byte("open")},
		Frame{Type: FrameClose, StreamID: 3},
		Frame{Type: FrameData, StreamID: 3, Payload: []byte("late")},
		Frame{Type: FrameData, StreamID: 1, Payload: []byte("live")})
	frames, err := parseUplinkBatch(body, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	session.streams[1] = &streamState{}
	cost, items := session.httpApplicationBoundLocked(body)
	wantCost, wantItems, ok := session.backendWriteReservationLocked(frames)
	delete(session.streams, 1)
	session.mu.Unlock()
	if !ok || cost != wantCost || items != wantItems || items != 2 {
		t.Fatalf("live DATA accounting=%d/%d backend=%d/%d", cost, items, wantCost, wantItems)
	}
}

func TestHTTPRetiredLaneValidationDoesNotAllocateFrameWorkspace(t *testing.T) {
	body := bytes.Repeat(testFrameBatch(t, Frame{Type: FrameClose, StreamID: 41}), MaxBatchFrames)
	if _, _, valid := (webSocketInbound{body: body}).applicationBound(); !valid {
		t.Fatal("invalid bounded test body")
	}
	if allocations := testing.AllocsPerRun(20, func() {
		if !validRetiredHTTPUp(body, 41) {
			panic("valid retired body rejected")
		}
	}); allocations != 0 {
		t.Fatalf("retired reader allocated frame workspace: %g", allocations)
	}
}

func TestHTTPApplicationPartialSourceCloseRetainsLiveOwners(t *testing.T) {
	opened := make(chan *ownerProbeBackend, 1)
	app := newHTTPTestApplicationWithConfig(t, time.Second, func(config *ManagerConfig) {
		config.Limits.MaxStreamsPerSession = 2
		config.Limits.MaxSessions = 2
		config.Limits.MaxPendingPerSession = 256 * 1024
		config.Limits.MaxPendingGlobal = 1024 * 1024
		config.Limits.MaxBodyBytes = 4096
		config.Limits.CarrierBatchBytes = 4096
		config.BackendFactory = ownerProbeFactory(opened, 1, true)
	}, nil)
	_, session, _ := createOwnerTestSession(t, app)
	body := testFrameBatch(t, Frame{Type: FrameOpen, StreamID: 1},
		Frame{Type: FrameData, StreamID: 1, Payload: bytes.Repeat([]byte("x"), 3000)})
	reader := reserveHTTPTest(t, session, 0, 1, body)
	if _, err := reader.Process(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	backend := <-opened
	eventually(t, time.Second, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return session.streams[1].writeOffset == 1
	})
	session.mu.Lock()
	if state := session.streams[1]; state.pendingWriteCost != 3000+queueItemCost || state.pendingWriteItems != 1 {
		t.Fatal("partial TryWrite released its retained source allocation")
	}
	session.mu.Unlock()
	session.Close()
	eventually(t, time.Second, backend.requested.Load)
	want := int64(reader.cost + 1 + queueItemCost)
	if capacity := app.manager.Capacity(); capacity.PendingBytes != want || capacity.PendingItems != int64(reader.items+1) {
		t.Fatalf("Close lost live HTTP body or core-copy owner: want=%d capacity=%+v", want, capacity)
	}
	reader.Release()
	if capacity := app.manager.Capacity(); capacity.PendingBytes != 1+queueItemCost || capacity.PendingItems != 1 {
		t.Fatalf("HTTP cleanup released the core-owned copy: %+v", capacity)
	}
	finished := make(chan struct{})
	if err := backend.options.Owner.Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		backend.finish()
		close(finished)
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	<-finished
	if capacity := app.manager.Capacity(); capacity.PendingBytes != 0 || capacity.PendingItems != 0 {
		t.Fatalf("last owner retained HTTP application credit: %+v", capacity)
	}
}
