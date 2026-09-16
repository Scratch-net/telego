package middleend

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestGnetCandidateRejectsResponsesBeforeCopy(t *testing.T) {
	for _, kind := range []LinkEventKind{LinkEventProxyAnswer, LinkEventSimpleAck, LinkEventCloseExternal} {
		link := responseSinkTestLink()
		if err := link.prepareResponseSink(); err != nil {
			t.Fatal(err)
		}
		var packet []byte
		if kind == LinkEventProxyAnswer {
			packet = []byte{1, 2, 3, 4}
		}
		err := link.deliverOwnerEvent(LinkEvent{Kind: kind, Packet: packet}, true)
		if !errors.Is(err, ErrFixedBindingProtocol) || !allZero(packet) {
			t.Fatalf("candidate response %v: error %v, retained packet %v", kind, err, packet)
		}
		if snapshot := link.Snapshot(); snapshot.PendingEvents != 0 || snapshot.EventBytesHighWater != 0 || len(link.events) != 0 {
			t.Fatalf("candidate queued response %v: %+v", kind, snapshot)
		}
		// Delivery rejected the response before its owner could close the link.
		// A simultaneous publication must not install a sink in this interval.
		link.state = LinkStateReady
		if err := link.installResponseSink(func(event LinkEvent) error { event.Release(); return nil }); !errors.Is(err, errLinkResponseSink) {
			t.Fatalf("published a rejected candidate: %v", err)
		}
	}
}

func TestGnetCandidateGuardPreservesKeepaliveAndPublishedSink(t *testing.T) {
	link := responseSinkTestLink()
	if err := link.prepareResponseSink(); err != nil {
		t.Fatal(err)
	}
	if err := link.prepareResponseSink(); !errors.Is(err, errLinkResponseSink) {
		t.Fatalf("prepared twice: %v", err)
	}
	for _, kind := range []LinkEventKind{LinkEventPing, LinkEventPong} {
		if err := link.enqueueOwnerEvent(LinkEvent{Kind: kind, KeepaliveID: 42}); err != nil {
			t.Fatal(err)
		}
		if event := <-link.events; event.Kind != kind || event.KeepaliveID != 42 {
			t.Fatalf("candidate lost keepalive: %+v", event)
		}
	}
	link.state = LinkStateReady
	delivered := 0
	if err := link.installResponseSink(func(event LinkEvent) error {
		_ = link.Snapshot() // Callback must run outside link.mu.
		delivered++
		event.Release()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []LinkEventKind{LinkEventProxyAnswer, LinkEventSimpleAck, LinkEventCloseExternal} {
		if err := link.enqueueOwnerEvent(LinkEvent{Kind: kind}); err != nil {
			t.Fatal(err)
		}
	}
	if delivered != 3 || len(link.events) != 0 {
		t.Fatalf("published delivery: sink %d, channel %d", delivered, len(link.events))
	}
}

func TestGnetCandidatePublicationRacesResponseRejection(t *testing.T) {
	for range 100 {
		link := responseSinkTestLink()
		if err := link.prepareResponseSink(); err != nil {
			t.Fatal(err)
		}
		link.state = LinkStateReady
		var group sync.WaitGroup
		var installErr, deliveryErr error
		delivered := 0
		start := make(chan struct{})
		group.Go(func() {
			<-start
			installErr = link.installResponseSink(func(event LinkEvent) error {
				delivered++
				event.Release()
				return nil
			})
		})
		group.Go(func() {
			<-start
			deliveryErr = link.deliverOwnerEvent(LinkEvent{Kind: LinkEventProxyAnswer, Packet: []byte{1, 2, 3, 4}}, true)
		})
		close(start)
		group.Wait()
		if installErr == nil {
			if deliveryErr != nil || delivered != 1 {
				t.Fatalf("published response lost: %v, delivered %d", deliveryErr, delivered)
			}
		} else if !errors.Is(installErr, errLinkResponseSink) || !errors.Is(deliveryErr, ErrFixedBindingProtocol) || delivered != 0 {
			t.Fatalf("rejected candidate published: install %v, delivery %v, delivered %d", installErr, deliveryErr, delivered)
		}
		if len(link.events) != 0 || link.Snapshot().EventBytesHighWater != 0 {
			t.Fatal("candidate response reached the channel during publication")
		}
	}
}

func TestResponseSinkCandidatePreparationFailure(t *testing.T) {
	for _, repair := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			old := newFixedBindingFakeLink()
			candidate := newResponseSinkFakeLink()
			candidate.prepareErr = errLinkResponseSink
			manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(candidate))
			if repair {
				manager.state.failSlot(manager.state.slots[2], errors.New("planned slot failure"), FixedBindingSlotFailureLinkTerminal)
				if err := manager.state.repairFailedSlots(t.Context()); !errors.Is(err, errLinkResponseSink) {
					t.Fatalf("repair preparation: %v", err)
				}
			} else {
				dueSlotRefreshes(manager)
				manager.state.refreshUnusedSlots(t.Context(), time.Now())
			}
			synctest.Wait()
			starts, _, closes, _, _ := candidate.stats()
			if starts != 0 || closes != 1 || candidate.prepares != 1 || candidate.installs != 0 || manager.state.slots[2].link != old {
				t.Fatal("failed preparation started or published a candidate, or lost cleanup ownership")
			}
		})
	}
}

func TestResponseSinkGuardedCandidateCancellation(t *testing.T) {
	for _, repair := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			old := newFixedBindingFakeLink()
			candidate := newResponseSinkFakeLink()
			manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: 2, Link: old}}, refreshCandidateFactory(candidate))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if repair {
				manager.state.failSlot(manager.state.slots[2], errors.New("planned slot failure"), FixedBindingSlotFailureLinkTerminal)
				go func() { _ = manager.state.repairFailedSlots(ctx) }()
			} else {
				dueSlotRefreshes(manager)
				manager.state.refreshUnusedSlots(ctx, time.Now())
			}
			synctest.Wait()
			_ = candidatePing(t, candidate.fixedBindingFakeLink)
			cancel()
			synctest.Wait()
			if candidate.prepares != 1 || candidate.installs != 0 || !channelClosed(candidate.Done()) || manager.state.slots[2].link != old {
				t.Fatal("canceled guarded candidate installed or published its sink")
			}
		})
	}
}
