package middleend

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func responseSinkTestLink() *GnetClientLink {
	return &GnetClientLink{
		state:  LinkStateCreated,
		limits: LinkLimits{MaxPendingEvents: 4, MaxPendingEventBytes: 128},
		events: make(chan LinkEvent, 4),
	}
}

func TestGnetResponseSinkInstallAndChannelBoundary(t *testing.T) {
	link := responseSinkTestLink()
	var delivered []LinkEventKind
	sink := func(event LinkEvent) error {
		// Snapshot takes link.mu. This also proves callback lock ordering.
		_ = link.Snapshot()
		delivered = append(delivered, event.Kind)
		event.Release()
		return nil
	}
	if err := link.installResponseSink(nil); !errors.Is(err, errLinkResponseSink) {
		t.Fatalf("nil sink: %v", err)
	}
	if err := link.enqueueOwnerEvent(LinkEvent{Kind: LinkEventSimpleAck}); err != nil {
		t.Fatal(err)
	}
	if err := link.installResponseSink(sink); !errors.Is(err, errLinkResponseSink) {
		t.Fatalf("installed over a pending channel event: %v", err)
	}
	event := <-link.events
	event.Release()
	if err := link.installResponseSink(sink); err != nil {
		t.Fatal(err)
	}
	if err := link.installResponseSink(sink); !errors.Is(err, errLinkResponseSink) {
		t.Fatalf("installed a second sink: %v", err)
	}
	for _, kind := range []LinkEventKind{LinkEventProxyAnswer, LinkEventSimpleAck, LinkEventCloseExternal, LinkEventPing, LinkEventPong} {
		if err := link.enqueueOwnerEvent(LinkEvent{Kind: kind}); err != nil {
			t.Fatal(err)
		}
	}
	if len(delivered) != 3 || len(link.events) != 2 {
		t.Fatalf("sink kinds %v, channel events %d", delivered, len(link.events))
	}
	for _, kind := range []LinkEventKind{LinkEventPing, LinkEventPong} {
		if event := <-link.events; event.Kind != kind {
			t.Fatalf("channel event %v, want %v", event.Kind, kind)
		}
	}
	for _, state := range []LinkState{LinkStateBootstrapping, LinkStateClosing, LinkStateClosed} {
		other := responseSinkTestLink()
		other.state = state
		if err := other.installResponseSink(sink); !errors.Is(err, errLinkResponseSink) {
			t.Fatalf("installed in state %v: %v", state, err)
		}
	}
}

func TestGnetResponseSinkInstallRacesChannelDelivery(t *testing.T) {
	for range 100 {
		link := responseSinkTestLink()
		delivered := make(chan struct{}, 1)
		start := make(chan struct{})
		var group sync.WaitGroup
		var installErr, deliveryErr error
		group.Go(func() {
			<-start
			installErr = link.installResponseSink(func(event LinkEvent) error {
				event.Release()
				delivered <- struct{}{}
				return nil
			})
		})
		group.Go(func() {
			<-start
			deliveryErr = link.enqueueOwnerEvent(LinkEvent{Kind: LinkEventSimpleAck})
		})
		close(start)
		group.Wait()
		if deliveryErr != nil {
			t.Fatal(deliveryErr)
		}
		if installErr == nil {
			if len(link.events) != 0 || len(delivered) != 1 {
				t.Fatal("successful installation left a response in the old channel")
			}
		} else if !errors.Is(installErr, errLinkResponseSink) || len(link.events) != 1 || len(delivered) != 0 {
			t.Fatalf("failed installation lost channel ownership: %v", installErr)
		}
	}
}

func TestGnetResponseSinkBorrowedPacketsAndRejection(t *testing.T) {
	for _, sinkMode := range []bool{false, true} {
		link := responseSinkTestLink()
		packet := []byte{1, 2, 3, 4}
		want := bytes.Clone(packet)
		var retained []byte
		failure := errors.New("sink rejected protocol event")
		if sinkMode {
			if err := link.installResponseSink(func(event LinkEvent) error {
				retained = bytes.Clone(event.Packet)
				event.Release()
				return failure
			}); err != nil {
				t.Fatal(err)
			}
		}
		err := link.deliverOwnerEvent(LinkEvent{Kind: LinkEventProxyAnswer, Packet: packet}, true)
		if sinkMode {
			if !errors.Is(err, failure) || len(link.events) != 0 {
				t.Fatalf("sink rejection = %v, channel %d", err, len(link.events))
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			event := <-link.events
			retained = bytes.Clone(event.Packet)
			event.Release()
		}
		if !allZero(packet) || !bytes.Equal(retained, want) {
			t.Fatal("borrowed packet was retained or cleared before transfer")
		}
	}
}

func responseSinkWireManager(t *testing.T, budget *ResponseBudget, config fakePeerConfig) (*FixedBindingManager, *GnetClientLink) {
	t.Helper()
	runtime := newTestGnetRuntime(t)
	conn, peer := dialFakeMiddleEnd(t, config)
	linkInterface, err := runtime.NewClientLink(conn.(*net.TCPConn), newTestBootstrap(t), LinkLimits{
		MaxPendingSubmissions: 32, MaxPendingSubmissionBytes: 2 << 20,
		MaxPendingEvents: 8, MaxPendingEventBytes: 2 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	link := linkInterface.(*GnetClientLink)
	limits := fixedBindingTestLimits()
	limits.MaxPendingResponseItemsPerBinding = 64
	limits.MaxPendingResponseItemsPerSlot = 128
	limits.MaxPendingResponseItems = 256
	limits.MaxPendingResponseBytesPerBinding = 8 << 20
	limits.MaxPendingResponseBytesPerSlot = 16 << 20
	limits.MaxPendingResponseBytes = 32 << 20
	manager, err := NewFixedBindingManagerWithResponseBudget([]FixedBindingSlot{{DCID: 2, Link: link}}, limits, budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
		if err := waitFakePeer(t, peer); err != nil {
			t.Error(err)
		}
	})
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	return manager, link
}

func responseSinkSubmitPacket(t *testing.T, link ClientLink, binding *ClientBinding, size int, marker byte) {
	t.Helper()
	request := fixedBindingProxyRequest()
	request.ConnectionID = binding.ConnectionID()
	request.Packet = bytes.Repeat([]byte{marker}, size)
	request.Packet[0] = 1
	payload, err := request.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	id, err := allocateFixedBindingSubmissionID()
	if err != nil {
		t.Fatal(err)
	}
	waitFixedBindingCondition(t, func() bool {
		err = link.TrySubmit(LinkSubmission{SubmissionID: id, ConnectionID: binding.ConnectionID(), Payload: payload})
		return !errors.Is(err, ErrLinkBackpressure)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGnetResponseSinkEncryptedBurstExceedsLinkQueue(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 16 << 20})
	manager, link := responseSinkWireManager(t, budget, fakePeerConfig{})
	binding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	const packets = 8
	const packetSize = 512 << 10
	for index := range packets {
		responseSinkSubmitPacket(t, link, binding, packetSize, byte(index+1))
	}
	waitFixedBindingCondition(t, func() bool { return manager.Snapshot().ResponseItems == 2*packets || link.Err() != nil })
	if snapshot := manager.Snapshot(); snapshot.ResponseBytes <= link.limits.MaxPendingEventBytes || snapshot.SlotFailures != 0 {
		t.Fatalf("burst did not remain isolated in manager: %+v", snapshot)
	}
	if snapshot := link.Snapshot(); snapshot.EventHighWater != 0 || snapshot.PendingEvents != 0 || snapshot.State != LinkStateReady {
		t.Fatalf("responses used physical event queue: %+v", snapshot)
	}
	for index := range packets {
		answer := nextFixedBindingEvent(t, binding)
		if answer.Kind != LinkEventProxyAnswer || len(answer.Packet) != packetSize || answer.Packet[0] != 1 ||
			!bytes.Equal(answer.Packet[1:], bytes.Repeat([]byte{byte(index + 1)}, packetSize-1)) {
			t.Fatalf("response %d changed bytes or order", index)
		}
		answer.Release()
		ack := nextFixedBindingEvent(t, binding)
		if ack.Kind != LinkEventSimpleAck || ack.ConfirmKey != uint32(binding.ConnectionID()) {
			t.Fatalf("response %d acknowledgement: %v", index, ack)
		}
		ack.Release()
	}
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != ResponseParticipantBytes || snapshot.HighWaterBytes > snapshot.LimitBytes {
		t.Fatalf("burst ownership: %+v", snapshot)
	}
}

func TestGnetResponseSinkSharedPressurePreservesLink(t *testing.T) {
	runResponseSinkSharedPressure(t, false)
}

func TestGnetResponseSinkSharedPressurePreservesHealthyBinding(t *testing.T) {
	runResponseSinkSharedPressure(t, true)
}

func runResponseSinkSharedPressure(t *testing.T, existingHealthy bool) {
	t.Helper()
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 2 << 20})
	manager, link := responseSinkWireManager(t, budget, fakePeerConfig{maxRecords: 128})
	slow, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	var fast *ClientBinding
	if existingHealthy {
		fast, err = manager.Bind(2)
		if err != nil {
			t.Fatal(err)
		}
	}
	for range 8 {
		responseSinkSubmitPacket(t, link, slow, 512<<10, 7)
	}
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return slow.state.terminal
	})
	// Existing healthy bindings survive another binding's shared pressure.
	if fast == nil {
		fast, err = manager.Bind(2)
		if err != nil {
			t.Fatal(err)
		}
	}
	responseSinkSubmitPacket(t, link, fast, 64, 9)
	answer := nextFixedBindingEvent(t, fast)
	if answer.Kind != LinkEventProxyAnswer || len(answer.Packet) != 64 || answer.Packet[1] != 9 {
		t.Fatalf("healthy response: %v", answer)
	}
	answer.Release()
	ack := nextFixedBindingEvent(t, fast)
	ack.Release()
	if snapshot := manager.Snapshot(); snapshot.SlotFailures != 0 || snapshot.ResponseBackpressureEvents == 0 {
		t.Fatalf("pressure failed physical slot or was not exercised: %+v", snapshot)
	}
	if snapshot := link.Snapshot(); snapshot.State != LinkStateReady || link.Err() != nil {
		t.Fatalf("pressure closed shared link: %+v, %v", snapshot, link.Err())
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.HighWaterBytes > snapshot.LimitBytes {
		t.Fatalf("pressure ownership: %+v", snapshot)
	}
}

type responseSinkFakeLink struct {
	*fixedBindingFakeLink
	installErr error
	prepareErr error
	sink       func(LinkEvent) error
	installs   int
	prepares   int
}

func newResponseSinkFakeLink() *responseSinkFakeLink {
	return &responseSinkFakeLink{fixedBindingFakeLink: newFixedBindingFakeLink()}
}

func (l *responseSinkFakeLink) prepareResponseSink() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prepares++
	if l.startCalls != 0 {
		return errLinkResponseSink
	}
	return l.prepareErr
}

func (l *responseSinkFakeLink) installResponseSink(sink func(LinkEvent) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.installs++
	if l.installErr != nil {
		return l.installErr
	}
	l.sink = sink
	return nil
}

func TestResponseSinkInitialFailureClosesOwnedLinks(t *testing.T) {
	link := newResponseSinkFakeLink()
	link.installErr = errLinkResponseSink
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 2, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); !errors.Is(err, errLinkResponseSink) {
		t.Fatalf("start sink failure: %v", err)
	}
	starts, _, closes, _, _ := link.stats()
	if starts != 0 || closes != 1 || !channelClosed(manager.Done()) {
		t.Fatalf("initial rejection started or retained link: starts %d closes %d", starts, closes)
	}
}

func TestResponseSinkOldIncarnationCannotRouteAfterRepair(t *testing.T) {
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 2, Link: newFixedBindingFakeLink()})
	binding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	slot := binding.state.slot
	oldEvents := make(chan LinkEvent)
	packet := []byte{1, 2, 3, 4}
	if err := manager.state.routeEventIncarnation(slot, oldEvents, LinkEvent{
		Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet,
	}); err != nil {
		t.Fatal(err)
	}
	if !allZero(packet) || manager.Snapshot().ResponseItems != 0 {
		t.Fatal("old physical incarnation routed into replacement")
	}
}

func TestResponseSinkReplacementInstallation(t *testing.T) {
	for _, repair := range []bool{false, true} {
		for _, rejected := range []bool{false, true} {
			synctest.Test(t, func(t *testing.T) {
				old := newFixedBindingFakeLink()
				candidate := newResponseSinkFakeLink()
				if rejected {
					candidate.installErr = errLinkResponseSink
				}
				manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(candidate))
				if repair {
					manager.state.failSlot(manager.state.slots[2], errors.New("planned slot failure"), FixedBindingSlotFailureLinkTerminal)
					go func() { _ = manager.state.repairFailedSlots(t.Context()) }()
				} else {
					dueSlotRefreshes(manager)
					manager.state.refreshUnusedSlots(t.Context(), time.Now())
				}
				synctest.Wait()
				candidate.mu.Lock()
				installedBeforeProbe := candidate.installs
				preparedBeforeProbe := candidate.prepares
				candidate.mu.Unlock()
				if installedBeforeProbe != 0 || preparedBeforeProbe != 1 {
					t.Fatal("candidate did not guard responses before its channel probe")
				}
				ping := candidatePing(t, candidate.fixedBindingFakeLink)
				candidate.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
				synctest.Wait()
				candidate.mu.Lock()
				installs := candidate.installs
				sink := candidate.sink
				candidate.mu.Unlock()
				if installs != 1 {
					t.Fatalf("candidate installed %d times", installs)
				}
				if rejected {
					if !channelClosed(candidate.Done()) || manager.state.slots[2].link != old {
						t.Fatal("sink rejection published or retained candidate")
					}
					return
				}
				if sink == nil || manager.state.slots[2].link != candidate {
					t.Fatal("replacement published without sink")
				}
				binding, err := manager.Bind(2)
				if err != nil {
					t.Fatal(err)
				}
				if err := sink(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID(), ConfirmKey: 42}); err != nil {
					t.Fatal(err)
				}
				event := nextFixedBindingEvent(t, binding)
				if event.ConfirmKey != 42 {
					t.Fatal("published sink captured the previous incarnation")
				}
				event.Release()
			})
		}
	}
}

func TestResponseSinkCandidateCancellationBeforePublication(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		old := newFixedBindingFakeLink()
		candidate := newResponseSinkFakeLink()
		manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, func(_ context.Context, dcID DCID) (FixedBindingSlot, error) {
			return FixedBindingSlot{DCID: dcID, Link: candidate, SourceIP: netip.MustParseAddr("8.8.8.8")}, nil
		})
		dueSlotRefreshes(manager)
		ctx, cancel := context.WithCancel(t.Context())
		manager.state.refreshUnusedSlots(ctx, time.Now())
		synctest.Wait()
		_ = candidatePing(t, candidate.fixedBindingFakeLink)
		cancel()
		synctest.Wait()
		if !channelClosed(candidate.Done()) || candidate.installs != 0 || manager.state.slots[2].link != old {
			t.Fatal("canceled candidate installed or published its sink")
		}
	})
}

func TestGnetResponseSinkRoutingErrorClosesWithoutOwnerJoin(t *testing.T) {
	runtime := newTestGnetRuntime(t)
	var slots []FixedBindingSlot
	var peers []*fakeMiddleEndPeer
	for _, dcID := range []DCID{2, 3} {
		conn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
		link, err := runtime.NewClientLink(conn.(*net.TCPConn), newTestBootstrap(t), LinkLimits{
			MaxPendingSubmissions: 4, MaxPendingSubmissionBytes: 1 << 20,
			MaxPendingEvents: 4, MaxPendingEventBytes: 1 << 20,
		})
		if err != nil {
			t.Fatal(err)
		}
		slots = append(slots, FixedBindingSlot{DCID: dcID, Link: link})
		peers = append(peers, peer)
	}
	manager, err := NewFixedBindingManager(slots, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = manager.Close()
		for _, peer := range peers {
			_ = waitFakePeer(t, peer)
		}
	})
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	binding, err := manager.Bind(3)
	if err != nil {
		t.Fatal(err)
	}
	// The peer echoes a valid event on the wrong physical slot. This reaches
	// manager routing, rather than failing in the RPC parser.
	responseSinkSubmitPacket(t, slots[0].Link, binding, 64, 9)
	select {
	case <-slots[0].Link.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("routing failure waited for its own gnet owner to close")
	}
	if !errors.Is(slots[0].Link.Err(), ErrFixedBindingProtocol) {
		t.Fatalf("routing failure cause: %v", slots[0].Link.Err())
	}
	responseSinkSubmitPacket(t, slots[1].Link, binding, 64, 7)
	answer := nextFixedBindingEvent(t, binding)
	if answer.Kind != LinkEventProxyAnswer || answer.Packet[1] != 7 {
		t.Fatal("failed routing damaged another physical slot")
	}
	answer.Release()
	ack := nextFixedBindingEvent(t, binding)
	ack.Release()
}

func TestGnetResponseSinkCloseWaitsForDelivery(t *testing.T) {
	runtime := newTestGnetRuntime(t)
	conn, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	clientLink, err := runtime.NewClientLink(conn.(*net.TCPConn), newTestBootstrap(t), LinkLimits{
		MaxPendingSubmissions: 4, MaxPendingSubmissionBytes: 1 << 20,
		MaxPendingEvents: 4, MaxPendingEventBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	link := clientLink.(*GnetClientLink)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	t.Cleanup(func() {
		releaseOnce()
		_ = link.Close()
		_ = waitFakePeer(t, peer)
	})
	var first sync.Once
	if err := link.installResponseSink(func(event LinkEvent) error {
		first.Do(func() {
			close(entered)
			<-release
		})
		event.Release()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := link.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	request := fixedBindingProxyRequest()
	request.ConnectionID = 41
	payload, err := request.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := link.TrySubmit(LinkSubmission{SubmissionID: 1, ConnectionID: request.ConnectionID, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sink never entered")
	}
	closed := make(chan struct{})
	go func() {
		_ = link.Close()
		close(closed)
	}()
	waitFixedBindingCondition(t, func() bool { return link.Snapshot().State == LinkStateClosing })
	if channelClosed(closed) || channelClosed(link.Done()) {
		t.Fatal("terminal publication outran active owner delivery")
	}
	releaseOnce()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not finish after delivery released")
	}
	if link.responseSink != nil {
		t.Fatal("closed link retained the manager callback")
	}
}
