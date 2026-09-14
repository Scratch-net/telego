package middleend

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestResponsePressureCountersSurviveDroppedRecordsAndManagerRemoval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		link := newFixedBindingFakeLink()
		limits := fixedBindingTestLimits()
		limits.MaxPendingResponseItemsPerBinding = 1
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 2, Link: link}}, limits)
		if err != nil {
			t.Fatal(err)
		}
		supervisor := newGenerationTestSupervisor(t, generationTestConfig())
		manager.state.responsePressureObserver = supervisor.state.recordResponsePressure
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		for range generationDiagnosticCapacity {
			supervisor.state.diagnostics.append(GenerationDiagnosticRecord{})
		}
		binding, err := manager.BindReady(2)
		if err != nil {
			t.Fatal(err)
		}
		link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID()})
		synctest.Wait()
		token := manager.TryNextReady()
		if _, ok, err := token.TryNextEvent(); err != nil || !ok {
			t.Fatalf("dequeue = %t, %v", ok, err)
		}
		dequeued := time.Now()
		token.Ack()
		time.Sleep(time.Second)
		link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID()})
		synctest.Wait()
		token = manager.TryNextReady() // Keep the owner lease while a burst fills its queue.
		time.Sleep(time.Second)
		link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID()})
		synctest.Wait()
		p := binding.state.responsePressure.Pressure
		if !p.ReadyLeased || p.ReadyQueued || p.LastDequeueAt != dequeued || p.DequeuedItems != 1 ||
			p.DequeuedBytes != SimpleAckPayloadSize || p.QueueNonemptySince != dequeued.Add(time.Second) {
			t.Fatalf("lost queue/consumer timing: %+v", p)
		}
		binding.ReportResponsePressureOutput(ResponsePressureOutput{At: time.Now()})
		token.Ack()
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
		snapshot := supervisor.Snapshot()
		if snapshot.ResponsePressureEvictions[ResponsePressureBindingItems] != 1 ||
			snapshot.ResponsePressureDiscardedBytes[ResponsePressureBindingItems] != SimpleAckPayloadSize ||
			snapshot.DiagnosticRecordsDropped != 2 || snapshot.SlotFailures != 0 || snapshot.SlotFailureAffectedBindings != 0 {
			t.Fatalf("service counters were lost or double counted: %+v", snapshot)
		}
		supervisor.AcknowledgeDiagnostics(^uint64(0))
		if supervisor.Snapshot().ResponsePressureEvictions[ResponsePressureBindingItems] != 1 {
			t.Fatal("acknowledgement reset counters")
		}
	})
}
