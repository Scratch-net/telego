package middleend

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestSlotRefreshGnetHandshakePongAndStickyBinding(t *testing.T) {
	for _, bindDuringBootstrap := range []bool{false, true} {
		name := "publish after matching pong"
		if bindDuringBootstrap {
			name = "binding during bootstrap keeps incumbent"
		}
		t.Run(name, func(t *testing.T) {
			runtime := newTestGnetRuntime(t)
			limits := LinkLimits{
				MaxPendingSubmissions: 8, MaxPendingSubmissionBytes: 64 << 10,
				MaxPendingEvents: 8, MaxPendingEventBytes: 64 << 10,
			}
			factory := func(conn net.Conn, bootstrap *ClientBootstrap, limits LinkLimits) (ClientLink, error) {
				tcp, ok := conn.(*net.TCPConn)
				if !ok {
					return nil, errors.New("refresh integration requires a TCP connection")
				}
				return runtime.NewClientLink(tcp, bootstrap, limits)
			}
			oldConn, oldPeer := dialFakeMiddleEnd(t, fakePeerConfig{})
			old := makeUnstartedLink(t, factory, oldConn, limits)
			candidateConn, candidatePeer := dialFakeMiddleEnd(t, fakePeerConfig{
				holdBootstrap: true, mode: fakePeerHoldAfterReady,
			})
			candidate := makeUnstartedLink(t, factory, candidateConn, limits)
			manager := newSlotRefreshTestManager(t, []FixedBindingSlot{{DCID: -2, Link: old}}, refreshCandidateFactory(candidate))
			manager.state.mu.Lock()
			incumbent := manager.state.slots[-2]
			manager.state.mu.Unlock()

			assertIncumbent := func() {
				t.Helper()
				snapshot := manager.Snapshot()
				if !snapshot.Accepting || len(snapshot.DCs) != 1 || snapshot.DCs[0].ReadySlots != 1 ||
					snapshot.RefreshingSlots != 1 || snapshot.SlotFailures != 0 || snapshot.DCs[0].ZeroReadyTransitions != 0 {
					t.Fatalf("candidate preparation changed DC availability: %+v", snapshot)
				}
				manager.state.mu.Lock()
				current := manager.state.slots[-2]
				manager.state.mu.Unlock()
				if current != incumbent || channelClosed(old.Done()) {
					t.Fatal("candidate replaced the incumbent before its matching pong")
				}
			}
			dueSlotRefreshes(manager)
			manager.state.refreshUnusedSlots(t.Context(), time.Now())
			candidatePeer.waitBootstrapStarted(t)
			assertIncumbent()

			var binding *ClientBinding
			if bindDuringBootstrap {
				var err error
				binding, err = manager.Bind(-2)
				if err != nil {
					t.Fatal(err)
				}
				if binding.state.slot != incumbent {
					t.Fatal("new binding did not select the ready incumbent")
				}
			}
			candidatePeer.releaseBootstrapOnce()
			receiveSignal(t, candidatePeer.ready, "candidate bilateral handshake")
			candidatePeer.allowHeldRead()
			select {
			case err := <-candidatePeer.readAck:
				if err != nil {
					t.Fatalf("candidate encrypted probe read: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("candidate did not send an encrypted probe after bootstrap")
			}
			// The peer has only one encrypted byte. It cannot decode the ping
			// or send a matching pong until this gate opens.
			assertIncumbent()
			if records := candidatePeer.snapshotRecords(); len(records) != 0 {
				t.Fatalf("candidate processed an RPC before its read gate opened: %+v", records)
			}
			candidatePeer.releaseHeldRead()
			waitFixedBindingCondition(t, func() bool {
				snapshot := manager.Snapshot()
				return snapshot.RefreshingSlots == 0 && len(snapshot.DCs) == 1 &&
					snapshot.DCs[0].SlotRefreshSuccesses+snapshot.DCs[0].SlotRefreshCanceled == 1
			})
			if candidatePeer.bootstrapCount.Load() != 1 {
				t.Fatal("candidate did not complete exactly one real bootstrap")
			}
			records := candidatePeer.snapshotRecords()
			if len(records) != 1 || records[0].operation != OperationPing || records[0].keepaliveID == 0 {
				t.Fatalf("candidate wire operations = %+v, want one identified RPC ping", records)
			}
			snapshot := manager.Snapshot()
			if !snapshot.Accepting || snapshot.DCs[0].ReadySlots != 1 || snapshot.SlotFailures != 0 ||
				snapshot.DCs[0].ZeroReadyTransitions != 0 || snapshot.DCs[0].SlotRefreshFailures != 0 {
				t.Fatalf("refresh outcome changed DC availability: %+v", snapshot)
			}
			manager.state.mu.Lock()
			current := manager.state.slots[-2]
			manager.state.mu.Unlock()
			if bindDuringBootstrap {
				if current != incumbent || binding.state.slot != incumbent || channelClosed(old.Done()) || !channelClosed(candidate.Done()) ||
					snapshot.DCs[0].SlotRefreshCanceled != 1 {
					t.Fatal("candidate cleanup moved or closed the incumbent binding")
				}
				if err := waitFakePeer(t, candidatePeer); err != nil {
					t.Fatalf("discarded candidate peer did not close: %v", err)
				}
			} else {
				if current == incumbent || current.link != candidate || !channelClosed(old.Done()) || snapshot.DCs[0].SlotRefreshSuccesses != 1 {
					t.Fatal("validated candidate did not replace and close the incumbent")
				}
				if err := waitFakePeer(t, oldPeer); err != nil {
					t.Fatalf("retired incumbent peer did not close: %v", err)
				}
				var err error
				binding, err = manager.Bind(-2)
				if err != nil {
					t.Fatal(err)
				}
				if binding.state.slot != current {
					t.Fatal("new client did not bind to the published candidate")
				}
			}

			// A real proxy request and response prove the retained or replaced
			// physical link still serves its sticky client binding.
			request := fixedBindingProxyRequest()
			if _, err := binding.PrepareProxyRequest(request); err != nil {
				t.Fatal(err)
			}
			event := nextFixedBindingEvent(t, binding)
			if event.Kind != LinkEventProxyAnswer || !bytes.Equal(event.Packet, request.Packet) {
				t.Fatalf("post-refresh proxy response = %+v", event)
			}
			if err := binding.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
