package middleend

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"
)

// BenchmarkGnetLinkRequestThroughput submits workload requests through one
// real gnet link and a local fake ME peer that answers every request.
func BenchmarkGnetLinkRequestThroughput(b *testing.B) {
	workload, err := buildDeterministicLinkWorkload()
	if err != nil {
		b.Fatal(err)
	}
	for _, sizeIndex := range []int{0, 1, 2} {
		item := workload.items[sizeIndex*4]
		b.Run(fmt.Sprintf("%d", len(item.wantPacket)), func(b *testing.B) {
			gnetRuntime := newTestGnetRuntime(b)
			clientConn, peer := dialFakeMiddleEnd(b, fakePeerConfig{discardRecords: true})
			bootstrap, err := NewClientBootstrap(testBootstrapConfig())
			if err != nil {
				b.Fatal(err)
			}
			limits := LinkLimits{
				MaxPendingSubmissions:     64,
				MaxPendingSubmissionBytes: 64 * item.submission.ByteSize(),
				MaxPendingEvents:          256,
				MaxPendingEventBytes:      256 * (LinkEvent{Kind: LinkEventProxyAnswer, Packet: item.wantPacket}).ByteSize(),
			}
			clientLink, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), bootstrap, limits)
			if err != nil {
				b.Fatal(err)
			}
			if err := clientLink.Start(newHarnessContext(b)); err != nil {
				b.Fatal(err)
			}
			outstanding := 0
			receive := func() {
				select {
				case event := <-clientLink.Events():
					event.Release()
					outstanding--
				case <-time.After(5 * time.Second):
					b.Fatalf("timed out: %+v", clientLink.Snapshot())
				}
			}
			b.SetBytes(int64(len(item.wantPacket)))
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				submission := item.submission
				submission.SubmissionID = uint64(index + 1)
				submission.Payload = slices.Clone(item.submission.Payload)
				for {
					err := clientLink.TrySubmit(submission)
					if err == nil {
						break
					}
					if !errors.Is(err, ErrLinkBackpressure) {
						b.Fatal(err)
					}
					if outstanding > 0 {
						receive()
					} else {
						<-clientLink.SubmissionReady()
					}
				}
				// The peer answers each request with an answer and an ACK.
				outstanding += 2
				for outstanding > 64 {
					receive()
				}
			}
			for outstanding > 0 {
				receive()
			}
			b.StopTimer()
			_ = clientLink.Close()
			_ = waitFakePeer(b, peer)
		})
	}
}

// TestGnetBackloggedLinkDrainWakeups counts outbound poll timer wakeups while a
// peer stops reading and gnet holds an encoded batch in user space.
func TestGnetBackloggedLinkDrainWakeups(t *testing.T) {
	gnetRuntime := newTestGnetRuntime(t)
	clientConn, peer := dialFakeMiddleEnd(t, fakePeerConfig{mode: fakePeerHoldAfterReady})
	workload := deterministicLinkWorkload(t)
	item := workload.items[len(workload.items)-1]
	limits := LinkLimits{
		MaxPendingSubmissions:     3,
		MaxPendingSubmissionBytes: 3 * item.submission.ByteSize(),
		MaxPendingEvents:          8,
		MaxPendingEventBytes: 3 * ((LinkEvent{Kind: LinkEventProxyAnswer, Packet: item.wantPacket}).ByteSize() +
			(LinkEvent{Kind: LinkEventSimpleAck}).ByteSize()),
	}
	clientLink, err := gnetRuntime.NewClientLink(clientConn.(*net.TCPConn), newTestBootstrap(t), limits)
	if err != nil {
		t.Fatalf("NewClientLink: %v", err)
	}
	link := clientLink.(*GnetClientLink)
	if err := link.Start(newHarnessContext(t)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for index := range 3 {
		submission := item.submission
		submission.SubmissionID += uint64(index)
		submission.Payload = slices.Clone(item.submission.Payload)
		if err := link.TrySubmit(submission); err != nil {
			t.Fatalf("TrySubmit %d: %v", index, err)
		}
	}
	waitForLinkSnapshot(t, link, func(LinkSnapshot) bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return len(link.submissions) == 2
	})
	link.mu.Lock()
	before := link.pollFires
	link.mu.Unlock()
	const window = 500 * time.Millisecond
	time.Sleep(window)
	link.mu.Lock()
	fires := link.pollFires - before
	link.mu.Unlock()
	t.Logf("outbound poll wakeups while backlogged: %d in %v (%.0f/s)", fires, window, float64(fires)/window.Seconds())
	// A drain notification needs no periodic wakeup while the peer is silent.
	if fires > 10 {
		t.Errorf("backlogged link woke its owner loop %d times in %v", fires, window)
	}

	started := time.Now()
	peer.stopHolding()
	for range 6 {
		receiveLinkEvent(t, link)
	}
	t.Logf("drain after release: %v", time.Since(started))
	waitForLinkSnapshot(t, link, func(snapshot LinkSnapshot) bool {
		return snapshot.PendingSubmissions == 0 && snapshot.PendingSubmissionBytes == 0
	})
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatalf("fake peer: %v", err)
	}
}
