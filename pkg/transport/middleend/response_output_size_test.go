package middleend

import (
	"bytes"
	"errors"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

func TestClientResponseOutputBoundAcrossDRSPhases(t *testing.T) {
	sizes := []int{4, 128, 504, 508, 1368, 1372, 10948, 10952, 16380, 16384, 16388, 131072, MaxClientPacketSize}
	for _, kind := range []LinkEventKind{LinkEventProxyAnswer, LinkEventSimpleAck} {
		for _, size := range sizes {
			bound, err := ClientResponseOutputBound(kind, size)
			if err != nil {
				t.Fatal(err)
			}
			wire := size + 7
			if kind == LinkEventSimpleAck {
				wire = 4
				if bound != 14 {
					t.Fatalf("ACK bound = %d, want 14", bound)
				}
			}
			for _, drsOn := range []bool{false, true} {
				for _, split := range []bool{false, true} {
					for phase := range faketls.DRSRampRecords + 2 {
						for _, byteRamp := range []bool{false, true} {
							drs := faketls.NewDRSState(drsOn, split, faketls.MaxRecordPayload)
							for range phase {
								drs.Advance(drs.NextChunk(faketls.MaxRecordPayload))
							}
							if byteRamp {
								drs.Advance(faketls.DRSRampBytes)
							}
							if got := drs.PlanSize(wire); got > bound || drs.PlanSize(wire) != got {
								t.Fatalf("size=%d kind=%d drs=%t split=%t phase=%d ramp=%t: size=%d bound=%d", size, kind, drsOn, split, phase, byteRamp, got, bound)
							}
						}
					}
				}
			}
		}
	}
}

func TestClientPacketEncodedSizeBoundDoesNotConsumePadding(t *testing.T) {
	for _, framing := range []obfuscated2.ConnectionType{
		obfuscated2.ConnectionTypeAbridged, obfuscated2.ConnectionTypeIntermediate, obfuscated2.ConnectionTypePaddedIntermediate,
	} {
		for _, size := range []int{4, 504, 508, MaxClientPacketSize} {
			random := bytes.NewReader(bytes.Repeat([]byte{3}, 32))
			encoder, err := newClientPacketEncoder(framing, MaxClientPacketSize, random)
			if err != nil {
				t.Fatal(err)
			}
			before := random.Len()
			bound, err := encoder.EncodedSizeBound(size)
			if err != nil || random.Len() != before {
				t.Fatalf("bound consumed padding: %d, %v", bound, err)
			}
			wire, err := encoder.Encode(make([]byte, size))
			if err != nil || cap(wire) > bound {
				t.Fatalf("framing=%x size=%d cap=%d bound=%d: %v", framing, size, cap(wire), bound, err)
			}
		}
	}
}

func TestResponseHeadCannotTakeAnotherEvent(t *testing.T) {
	budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 4096})
	manager, binding := responseBudgetBindingForTest(t, budget)
	for _, key := range []uint32{11, 22} {
		if err := manager.state.routeEvent(binding.state.slot, LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID(), ConfirmKey: key}); err != nil {
			t.Fatal(err)
		}
	}
	token := manager.TryNextReady()
	head, ok, err := token.TryPeekResponse()
	if err != nil || !ok || head.Kind != LinkEventSimpleAck || head.PacketBytes != 0 {
		t.Fatalf("head = %+v, %v, %v", head, ok, err)
	}
	first, ok, err := token.TryTakeResponse(head)
	if err != nil || !ok || first.ConfirmKey != 11 {
		t.Fatal("wrong first response")
	}
	first.Release()
	if event, ok, err := token.TryTakeResponse(head); err != nil || ok {
		event.Release()
		t.Fatalf("stale head took another event: %v, %v", ok, err)
	}
	head, ok, err = token.TryPeekResponse()
	if err != nil || !ok {
		t.Fatal("second response missing")
	}
	<-binding.BeginClose()
	if event, ok, err := token.TryTakeResponse(head); ok || err != nil && !errors.Is(err, ErrFixedBindingReadyToken) {
		event.Release()
		t.Fatalf("canceled head taken: %v, %v", ok, err)
	}
	if err := token.Ack(); err != nil && !errors.Is(err, ErrFixedBindingReadyToken) {
		t.Fatal(err)
	}
	if _, _, err := token.TryPeekResponse(); err == nil {
		t.Fatal("acknowledged token accepted")
	}
	if budget.Snapshot().UsedBytes != 0 {
		t.Fatal("canceled head retained ownership")
	}
}
