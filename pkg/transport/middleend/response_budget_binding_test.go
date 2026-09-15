package middleend

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func responsePacketEnvelopeCharge(packetBytes int) int {
	bound, _ := ClientResponseOutputBound(LinkEventProxyAnswer, packetBytes)
	return ResponseAllocationCharge(bound + ResponseOutputMetadataBytes)
}

func responseAckEnvelopeCharge() int {
	return ResponseAllocationCharge(14 + ResponseOutputMetadataBytes)
}

func responseBudgetBindingForTest(t *testing.T, budget *ResponseBudget) (*FixedBindingManager, *ClientBinding) {
	t.Helper()
	manager, err := NewFixedBindingManagerWithResponseBudget(
		[]FixedBindingSlot{{DCID: 2, Link: newFixedBindingFakeLink()}}, fixedBindingTestLimits(), budget,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	binding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	return manager, binding
}

func TestResponseBudgetDequeueTransfersAllocation(t *testing.T) {
	for _, tokenMode := range []bool{false, true} {
		name := "blocking"
		if tokenMode {
			name = "token"
		}
		t.Run(name, func(t *testing.T) {
			budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
			manager, binding := responseBudgetBindingForTest(t, budget)
			packet := make([]byte, 128, 2048)
			packet[0] = 42
			if err := manager.state.routeEvent(binding.state.slot, LinkEvent{
				Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet,
			}); err != nil {
				t.Fatal(err)
			}
			wantPayload := responsePacketEnvelopeCharge(128)
			if snapshot := budget.Snapshot(); snapshot.StageBytes[ResponseMemoryQueuePayload] != wantPayload || snapshot.StageBytes[ResponseMemoryQueueMetadata] != ResponseAllocationCharge(responseQueueChunkBytes) {
				t.Fatalf("queue retained oversized input or missed metadata: %+v", snapshot)
			}
			var event LinkEvent
			if tokenMode {
				token := manager.TryNextReady()
				if token == nil {
					t.Fatal("missing readiness token")
				}
				var ok bool
				var err error
				event, ok, err = token.TryNextEvent()
				if !ok || err != nil {
					t.Fatalf("event = %v, %v", ok, err)
				}
				if err := token.Ack(); err != nil {
					t.Fatal(err)
				}
			} else {
				var err error
				event, err = binding.NextEvent(t.Context())
				if err != nil {
					t.Fatal(err)
				}
			}
			if event.Packet[0] != 42 || cap(event.Packet) != 128 || event.ResponseAllocation == nil {
				t.Fatalf("dequeue lost packet ownership: %v", event)
			}
			if snapshot := budget.Snapshot(); snapshot.UsedBytes != wantPayload+ResponseParticipantBytes || snapshot.StageBytes[ResponseMemoryQueueMetadata] != 0 {
				t.Fatalf("dequeue released retained packet or retained empty ring: %+v", snapshot)
			}
			if snapshot := manager.Snapshot(); snapshot.ResponseBytes != 0 || snapshot.ResponseItems != 0 {
				t.Fatalf("queue counters did not release on dequeue: %+v", snapshot)
			}
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
			if budget.Snapshot().UsedBytes != wantPayload+ResponseParticipantBytes {
				t.Fatal("shutdown released externally owned event")
			}
			event.Release()
			event.Release()
			if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.Allocations != 0 {
				t.Fatalf("event cleanup leaked ownership: %+v", snapshot)
			}
		})
	}
}

func TestResponseBudgetChunkGrowthReservesBeforeAllocation(t *testing.T) {
	chunkCharge := ResponseAllocationCharge(responseQueueChunkBytes)
	for _, enough := range []bool{false, true} {
		name := "reject_without_chunk_credit"
		limit := ResponseParticipantBytes + 2*chunkCharge + (responseQueueChunkItems+1)*responseAckEnvelopeCharge() - 1
		if enough {
			name = "reserve_before_allocation"
			limit++
		}
		t.Run(name, func(t *testing.T) {
			budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: limit})
			manager, binding := responseBudgetBindingForTest(t, budget)
			event := LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID()}
			manager.state.mu.Lock()
			var err error
			for range responseQueueChunkItems {
				if err = manager.state.enqueueEventLocked(binding.state, event); err != nil {
					break
				}
			}
			first := binding.state.responseQueueHead
			var growthErr error
			if err == nil {
				growthErr = manager.state.enqueueEventLocked(binding.state, event)
			}
			unchanged := first == binding.state.responseQueueHead && first.head == 0 && first.tail == responseQueueChunkItems
			manager.state.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if !unchanged {
				t.Fatal("chunk growth copied or changed existing entries")
			}
			if enough {
				if growthErr != nil || budget.Snapshot().UsedBytes != limit || budget.Snapshot().HighWaterBytes != limit {
					t.Fatalf("growth = %v, %+v", growthErr, budget.Snapshot())
				}
			} else if !errors.Is(growthErr, ErrFixedBindingResponseBackpressure) || budget.Snapshot().UsedBytes != ResponseParticipantBytes+chunkCharge+responseQueueChunkItems*responseAckEnvelopeCharge() {
				t.Fatalf("growth rejection = %v, %+v", growthErr, budget.Snapshot())
			}
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
			if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.Allocations != 0 {
				t.Fatalf("shutdown retained chunks: %+v", snapshot)
			}
		})
	}
}

func TestResponseBudgetAdoptsRetainedPacketCapacity(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 8192, ProcessingReserveBytes: 4096})
	manager, binding := responseBudgetBindingForTest(t, budget)
	packet := make([]byte, 128, 1024)
	allocation := reserveResponseForTest(t, budget, cap(packet), ResponseMemoryProcessing, ResponseMemoryDecode)
	if err := manager.state.routeEvent(binding.state.slot, LinkEvent{
		Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet, ResponseAllocation: allocation,
	}); err != nil {
		t.Fatal(err)
	}
	event, err := binding.NextEvent(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if event.ResponseAllocation != allocation || cap(event.Packet) != 1024 || budget.Snapshot().UsedBytes != ResponseAllocationCharge(1024)+ResponseParticipantBytes {
		t.Fatal("owned packet transfer lost original allocation capacity")
	}
	event.Release()
}

func TestResponseBudgetCancellationAndSlotFailure(t *testing.T) {
	for _, failSlot := range []bool{false, true} {
		name := "binding_close"
		if failSlot {
			name = "slot_failure"
		}
		t.Run(name, func(t *testing.T) {
			budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
			manager, binding := responseBudgetBindingForTest(t, budget)
			if err := manager.state.routeEvent(binding.state.slot, LinkEvent{
				Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: make([]byte, 128),
			}); err != nil {
				t.Fatal(err)
			}
			if failSlot {
				manager.state.failSlot(binding.state.slot, errors.New("test slot failure"), FixedBindingSlotFailureLinkTerminal)
				// Slot failure preserves already accepted responses before its
				// terminal result. Their ownership must remain charged until drain.
				if budget.Snapshot().UsedBytes == 0 {
					t.Fatal("slot failure released retained response")
				}
				event, err := binding.NextEvent(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				event.Release()
			} else {
				<-binding.BeginClose()
			}
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
			if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.Allocations != 0 {
				t.Fatalf("terminal path retained queue: %+v", snapshot)
			}
		})
	}
}

func TestResponseBudgetAdoptionGrowthRejection(t *testing.T) {
	chunkCharge := ResponseAllocationCharge(responseQueueChunkBytes)
	payloadCharge := responsePacketEnvelopeCharge(128)
	queuedCharge := ResponseParticipantBytes + chunkCharge + responseQueueChunkItems*responseAckEnvelopeCharge()
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: queuedCharge + payloadCharge + chunkCharge - 1})
	manager, binding := responseBudgetBindingForTest(t, budget)
	for range responseQueueChunkItems {
		if err := manager.state.routeEvent(binding.state.slot, LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID()}); err != nil {
			t.Fatal(err)
		}
	}
	packet := make([]byte, 128)
	packet[0] = 42
	allocation := reserveResponseForTest(t, budget, cap(packet), ResponseMemoryOrdinary, ResponseMemoryDecode)
	event := LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet, ResponseAllocation: allocation}
	manager.state.mu.Lock()
	err := manager.state.enqueueEventLocked(binding.state, event)
	manager.state.mu.Unlock()
	if !errors.Is(err, ErrFixedBindingResponseBackpressure) || allocation.Bytes() != payloadCharge || packet[0] != 42 {
		t.Fatalf("growth rejection lost source ownership: %v, %+v", err, budget.Snapshot())
	}
	if budget.Snapshot().UsedBytes != queuedCharge+payloadCharge {
		t.Fatalf("growth rejection changed retained capacity: %+v", budget.Snapshot())
	}
	if snapshot := binding.state.responseParticipant.Snapshot(); snapshot.InflightBytes != payloadCharge || snapshot.StageBytes[ResponseMemoryQueuePayload] != responseQueueChunkItems*responseAckEnvelopeCharge() {
		t.Fatalf("unattached adopted payload counted as reclaimable queue: %+v", snapshot)
	}
	event.Release()
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if budget.Snapshot().UsedBytes != 0 {
		t.Fatal("rejected event or original queue charge leaked")
	}
}

func TestResponseBudgetForeignPacketCopy(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
	foreign := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
	manager, binding := responseBudgetBindingForTest(t, budget)
	packet := make([]byte, 128, 1024)
	packet[0] = 42
	allocation := reserveResponseForTest(t, foreign, cap(packet), ResponseMemoryOrdinary, ResponseMemoryDecode)
	if err := manager.state.routeEvent(binding.state.slot, LinkEvent{
		Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet, ResponseAllocation: allocation,
	}); err != nil {
		t.Fatal(err)
	}
	if foreign.Snapshot().UsedBytes != 0 || packet[0] != 0 {
		t.Fatal("copy kept source ownership")
	}
	event, err := binding.NextEvent(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if event.ResponseAllocation == allocation || event.ResponseAllocation.budget != budget || cap(event.Packet) != 128 || event.Packet[0] != 42 {
		t.Fatal("copy did not establish destination ownership")
	}
	event.Release()
	if budget.Snapshot().UsedBytes != ResponseParticipantBytes {
		t.Fatal("destination retained released packet charge")
	}
}

func TestResponseBudgetForeignAckGrowthRejection(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: ResponseParticipantBytes + ResponseAllocationCharge(responseQueueChunkBytes) + responseQueueChunkItems*responseAckEnvelopeCharge()})
	foreign := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
	manager, binding := responseBudgetBindingForTest(t, budget)
	for range responseQueueChunkItems {
		if err := manager.state.routeEvent(binding.state.slot, LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID()}); err != nil {
			t.Fatal(err)
		}
	}
	allocation := reserveResponseForTest(t, foreign, 0, ResponseMemoryOrdinary, ResponseMemoryDecode)
	event := LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID(), ResponseAllocation: allocation}
	manager.state.mu.Lock()
	err := manager.state.enqueueEventLocked(binding.state, event)
	manager.state.mu.Unlock()
	if !errors.Is(err, ErrFixedBindingResponseBackpressure) || allocation.Bytes() == 0 {
		t.Fatalf("failed enqueue released incoming ownership: %v", err)
	}
	event.Release()
	if foreign.Snapshot().UsedBytes != 0 {
		t.Fatal("foreign ACK cancellation leaked charge")
	}
}

func TestResponseBudgetSharedByFactoryGenerations(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
	factory := newGenerationFactoryForTest(t,
		generationFactoryTestSnapshot(map[DCID][]netip.AddrPort{2: {netip.MustParseAddrPort("192.0.2.1:8888")}}),
		&generationFactoryTestDialer{}, &generationFactoryTestLinkBuilder{},
		func(config *GnetGenerationFactoryConfig) { config.ResponseBudget = budget },
	)
	var managers [2]*FixedBindingManager
	for index := range managers {
		manager, err := factory.Build(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = manager.Close() })
		managers[index] = manager
		if manager.state.responseBudget != budget {
			t.Fatal("factory created an independent generation budget")
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		binding, err := manager.Bind(2)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.state.routeEvent(binding.state.slot, LinkEvent{
			Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: make([]byte, 128),
		}); err != nil {
			t.Fatal(err)
		}
	}
	charge := ResponseParticipantBytes + responsePacketEnvelopeCharge(128) + ResponseAllocationCharge(responseQueueChunkBytes)
	if budget.Snapshot().UsedBytes != 2*charge {
		t.Fatalf("overlapping generation usage: %+v", budget.Snapshot())
	}
	if err := managers[0].Close(); err != nil {
		t.Fatal(err)
	}
	if budget.Snapshot().UsedBytes != charge {
		t.Fatal("closing one generation released another generation's ownership")
	}
	if err := managers[1].Close(); err != nil {
		t.Fatal(err)
	}
	if budget.Snapshot().UsedBytes != 0 {
		t.Fatal("generation shutdown retained allocation charges")
	}
}

func TestResponseBudgetServiceOptIn(t *testing.T) {
	config := serviceTestConfig(t, artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		return RawArtifacts{}, errors.New("unused")
	}))
	config.ResponseBudget = &ResponseBudgetConfig{LimitBytes: 8192, ProcessingReserveBytes: 4096}
	service, err := NewService(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close(t.Context()) })
	config.ResponseBudget.LimitBytes = 16384
	if service.ResponseBudget() == nil || service.ResponseBudget().Snapshot().LimitBytes != 8192 {
		t.Fatal("service did not retain one immutable budget configuration")
	}
	config.ResponseBudget = &ResponseBudgetConfig{LimitBytes: 1, ProcessingReserveBytes: 1}
	if err := config.Validate(); !errors.Is(err, ErrInvalidResponseBudget) {
		t.Fatalf("invalid service reserve: %v", err)
	}
}

func TestResponseBudgetCrossManagerExhaustionAndRetry(t *testing.T) {
	charge := ResponseParticipantBytes + responsePacketEnvelopeCharge(128) + ResponseAllocationCharge(responseQueueChunkBytes)
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: charge + ResponseParticipantBytes})
	first, firstBinding := responseBudgetBindingForTest(t, budget)
	second, secondBinding := responseBudgetBindingForTest(t, budget)
	if err := first.state.routeEvent(firstBinding.state.slot, LinkEvent{
		Kind: LinkEventProxyAnswer, ConnectionID: firstBinding.ConnectionID(), Packet: make([]byte, 128),
	}); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 128)
	packet[0] = 42
	incoming := LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: secondBinding.ConnectionID(), Packet: packet}
	enqueueSecond := func() error {
		second.state.mu.Lock()
		defer second.state.mu.Unlock()
		return second.state.enqueueEventLocked(secondBinding.state, incoming)
	}
	if err := enqueueSecond(); !errors.Is(err, ErrFixedBindingResponseBackpressure) || budget.Snapshot().UsedBytes != charge+ResponseParticipantBytes {
		t.Fatalf("second manager bypassed shared exhaustion: %v, %+v", err, budget.Snapshot())
	}
	firstEvent, err := firstBinding.NextEvent(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := enqueueSecond(); !errors.Is(err, ErrFixedBindingResponseBackpressure) {
		t.Fatalf("dequeue returned still-owned payload capacity: %v", err)
	}
	firstEvent.Release()
	if err := enqueueSecond(); err != nil {
		t.Fatalf("released capacity was not reusable across managers: %v", err)
	}
	secondEvent, err := secondBinding.NextEvent(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if secondEvent.Packet[0] != 42 {
		t.Fatal("failed admission changed the incoming packet")
	}
	secondEvent.Release()
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.HighWaterBytes > snapshot.LimitBytes {
		t.Fatalf("cross-manager capacity breach: %+v", snapshot)
	}
}

func TestResponseBudgetRepairedSlotRetainsSharedOwnership(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
	failed := newFixedBindingFakeLink()
	replacement := newFixedBindingFakeLink()
	respondToFixedBindingPings(replacement)
	manager, err := newFixedBindingManagerWithResponseBudget(
		[]FixedBindingSlot{{DCID: 2, Link: failed}}, fixedBindingTestLimits(),
		func(_ context.Context, dcID DCID) (FixedBindingSlot, error) {
			return FixedBindingSlot{DCID: dcID, SourceIP: netip.MustParseAddr("8.8.8.8"), Link: replacement}, nil
		}, budget,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	oldBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.state.routeEvent(oldBinding.state.slot, LinkEvent{
		Kind: LinkEventProxyAnswer, ConnectionID: oldBinding.ConnectionID(), Packet: make([]byte, 128),
	}); err != nil {
		t.Fatal(err)
	}
	failed.peerClose(errors.New("replace response source"))
	waitFixedBindingCondition(t, func() bool { return manager.Snapshot().Slots[0].Failed })
	if err := manager.state.repairFailedSlots(t.Context()); err != nil {
		t.Fatal(err)
	}
	newBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	replacement.emit(LinkEvent{
		Kind: LinkEventProxyAnswer, ConnectionID: newBinding.ConnectionID(), Packet: make([]byte, 128),
	})
	waitFixedBindingCondition(t, func() bool { return manager.Snapshot().ResponseItems == 2 })
	charge := ResponseParticipantBytes + responsePacketEnvelopeCharge(128) + ResponseAllocationCharge(responseQueueChunkBytes)
	if budget.Snapshot().UsedBytes != 2*charge || manager.state.responseBudget != budget {
		t.Fatalf("repair lost old or new response ownership: %+v", budget.Snapshot())
	}
	for _, binding := range []*ClientBinding{oldBinding, newBinding} {
		event, err := binding.NextEvent(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if event.ResponseAllocation == nil || event.ResponseAllocation.budget != budget {
			t.Fatal("repaired response used a different pool")
		}
		event.Release()
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 || snapshot.Allocations != 0 {
		t.Fatalf("repair retained released events: %+v", snapshot)
	}
}
