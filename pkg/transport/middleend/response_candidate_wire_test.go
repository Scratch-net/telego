package middleend

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

func TestReplacementCandidateRejectsEncryptedResponseBurst(t *testing.T) {
	for _, replacement := range []string{"refresh", "repair"} {
		for _, phase := range []string{"startup", "probe"} {
			t.Run(replacement+"/"+phase, func(t *testing.T) {
				runtime := newTestGnetRuntime(t)
				limits := LinkLimits{
					MaxPendingSubmissions: 8, MaxPendingSubmissionBytes: 64 << 10,
					MaxPendingEvents: 8, MaxPendingEventBytes: 64 << 10,
				}
				factory := func(conn net.Conn, bootstrap *ClientBootstrap, limits LinkLimits) (ClientLink, error) {
					tcp, ok := conn.(*net.TCPConn)
					if !ok {
						return nil, errors.New("candidate wire test requires a TCP connection")
					}
					return runtime.NewClientLink(tcp, bootstrap, limits)
				}
				oldConn, _ := dialFakeMiddleEnd(t, fakePeerConfig{})
				old := makeUnstartedLink(t, factory, oldConn, limits)
				var burst [][]byte
				for index := range 3 {
					payload, err := (ProxyAnswer{
						ConnectionID: int64(index + 1), Packet: bytes.Repeat([]byte{byte(index + 1)}, 4096),
					}).MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
					burst = append(burst, payload)
				}
				peerConfig := fakePeerConfig{}
				if phase == "startup" {
					peerConfig.initialPayloads = burst
				} else {
					peerConfig.beforePongPayloads = burst
				}
				candidateConn, candidatePeer := dialFakeMiddleEnd(t, peerConfig)
				candidate := makeUnstartedLink(t, factory, candidateConn, limits)
				budget := responseBudgetForTest(t, ResponseBudgetConfig{LimitBytes: 2 << 20})
				manager, err := newFixedBindingManagerWithResponseBudget(
					[]FixedBindingSlot{{DCID: 2, Link: old}}, fixedBindingTestLimits(), refreshCandidateFactory(candidate), budget,
				)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := manager.Close(); err != nil {
						t.Error(err)
					}
					if snapshot := budget.Snapshot(); snapshot.UsedBytes != 0 {
						t.Errorf("candidate test retained response ownership: %+v", snapshot)
					}
				})
				if err := manager.Start(newHarnessContext(t)); err != nil {
					t.Fatal(err)
				}
				manager.state.mu.Lock()
				incumbent := manager.state.slots[2]
				manager.state.mu.Unlock()
				if replacement == "refresh" {
					dueSlotRefreshes(manager)
					manager.state.refreshUnusedSlots(newHarnessContext(t), time.Now())
					waitFixedBindingCondition(t, func() bool {
						snapshot := manager.Snapshot()
						return snapshot.RefreshingSlots == 0 && snapshot.DCs[0].SlotRefreshFailures == 1
					})
				} else {
					if err := old.Close(); err != nil {
						t.Fatal(err)
					}
					waitFixedBindingCondition(t, func() bool { return manager.Snapshot().Slots[0].Failed })
					if err := manager.state.repairFailedSlots(newHarnessContext(t)); err == nil {
						t.Fatal("repair published a candidate that sent unsolicited responses")
					}
				}
				receiveSignal(t, candidate.Done(), "rejected encrypted candidate closure")
				if err := candidate.Err(); !errors.Is(err, ErrFixedBindingProtocol) {
					t.Errorf("candidate terminal error = %v, want protocol rejection", err)
				}
				if snapshot := candidate.Snapshot(); snapshot.EventHighWater != 0 || snapshot.EventBytesHighWater != 0 ||
					snapshot.PendingEvents != 0 || snapshot.PendingEventBytes != 0 {
					t.Errorf("unpublished candidate retained response events: %+v", snapshot)
				}
				if candidatePeer.bootstrapCount.Load() != 1 {
					t.Fatal("candidate did not run exactly one real bootstrap")
				}
				if phase == "probe" {
					records := candidatePeer.snapshotRecords()
					if len(records) != 1 || records[0].operation != OperationPing || records[0].keepaliveID == 0 {
						t.Fatalf("candidate wire operations = %+v, want one identified probe", records)
					}
				}
				manager.state.mu.Lock()
				current := manager.state.slots[2]
				manager.state.mu.Unlock()
				if current != incumbent || current.link != old {
					t.Fatal("rejected candidate replaced the incumbent slot")
				}
				if replacement == "refresh" {
					if snapshot := manager.Snapshot(); channelClosed(old.Done()) || snapshot.SlotFailures != 0 || snapshot.DCs[0].ReadySlots != 1 {
						t.Fatalf("candidate rejection interrupted incumbent availability: %+v", snapshot)
					}
					binding, err := manager.Bind(2)
					if err != nil {
						t.Fatal(err)
					}
					request := fixedBindingProxyRequest()
					if _, err := binding.PrepareProxyRequest(request); err != nil {
						t.Fatal(err)
					}
					event := nextFixedBindingEvent(t, binding)
					matches := event.Kind == LinkEventProxyAnswer && bytes.Equal(event.Packet, request.Packet)
					event.Release()
					if !matches {
						t.Fatal("incumbent did not serve the post-rejection response")
					}
				}
			})
		}
	}
}
