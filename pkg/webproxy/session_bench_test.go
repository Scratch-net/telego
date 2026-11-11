package webproxy

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func benchmarkSession(b *testing.B, mutate func(*ManagerConfig)) (*Manager, *Session) {
	b.Helper()
	profiles, err := DeriveProfiles("desktop", "proxy.example.com", bytes.Repeat([]byte{0x5a}, 16))
	if err != nil {
		b.Fatal(err)
	}
	config := DefaultManagerConfig(profiles[:], "127.0.0.1:443")
	if mutate != nil {
		mutate(&config)
	}
	manager, err := NewManager(config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = manager.Shutdown(ctx)
	})
	bootstrap, err := manager.IssueBootstrap(profiles[0].Capability(), "192.0.2.1")
	if err != nil {
		b.Fatal(err)
	}
	created, err := manager.Create(bootstrap, "192.0.2.1", testFrameBatchTB(b, Frame{Type: FrameHello, Payload: []byte{1}}))
	if err != nil {
		b.Fatal(err)
	}
	return manager, created.Session
}

func testFrameBatchTB(tb testing.TB, frames ...Frame) []byte {
	tb.Helper()
	var body []byte
	for _, frame := range frames {
		encoded, err := EncodeFrame(frame)
		if err != nil {
			tb.Fatal(err)
		}
		body = append(body, encoded...)
	}
	return body
}

// Every bridge request issues a bootstrap. Full bootstrap and closed-token
// tables are the worst case for expiry and eviction under Manager.mu.
func BenchmarkManagerIssueBootstrapFullTables(b *testing.B) {
	manager, _ := benchmarkSession(b, nil)
	manager.mu.Lock()
	for index := range manager.limits.MaxClosedTokens {
		var key sessionBearer
		key[0], key[1], key[8] = byte(index), byte(index>>8), 0xa5
		manager.rememberClosedTokenLocked(key, time.Now().Add(time.Hour))
	}
	manager.mu.Unlock()
	capability := manager.profiles[0].Capability()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := manager.IssueBootstrap(capability, "192.0.2.1"); err != nil {
			b.Fatal(err)
		}
	}
}

// Each session reserve and release also changes the global budget under
// Manager.mu. The local variant removes that global step for comparison.
func BenchmarkSessionPendingBudgetParallel(b *testing.B) {
	for _, global := range []bool{true, false} {
		name := "global"
		if !global {
			name = "session-only"
		}
		b.Run(name, func(b *testing.B) {
			manager, _ := benchmarkSession(b, nil)
			const sessions = 64
			pool := make(chan *Session, sessions)
			for range sessions {
				bootstrap, err := manager.IssueBootstrap(manager.profiles[0].Capability(), "192.0.2.1")
				if err != nil {
					b.Fatal(err)
				}
				created, err := manager.Create(bootstrap, "192.0.2.1", testFrameBatchTB(b, Frame{Type: FrameHello, Payload: []byte{1}}))
				if err != nil {
					b.Fatal(err)
				}
				if !global {
					created.Session.budget = nil
				}
				pool <- created.Session
			}
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				session := <-pool
				for pb.Next() {
					session.mu.Lock()
					if !session.reservePendingLocked(1024, 1, pendingDownlink) {
						session.mu.Unlock()
						b.Error("cannot reserve")
						return
					}
					session.releasePendingLocked(1024, 1)
					session.mu.Unlock()
				}
			})
		})
	}
}

// The HTTP and WebSocket carriers poll this way for each downlink batch.
func BenchmarkSessionCarrierPollLargeBatch(b *testing.B) {
	_, session := benchmarkSession(b, nil)
	payload := bytes.Repeat([]byte{0x41}, MaxFramePayload-FrameHeaderSize)
	cursor := uint64(0)
	b.SetBytes(int64(2 * MaxFramePayload))
	b.ReportAllocs()
	for b.Loop() {
		session.mu.Lock()
		if !session.queueFrameLocked(FrameData, 1, payload) || !session.queueFrameLocked(FrameData, 2, payload) {
			session.mu.Unlock()
			b.Fatal("cannot queue downlink")
		}
		session.mu.Unlock()
		body, next, lease, err := session.pollCarrierShared(b.Context(), cursor)
		if err != nil || len(body) == 0 {
			b.Fatal(err)
		}
		lease.Release()
		cursor = next
	}
}
