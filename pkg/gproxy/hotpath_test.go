package gproxy

import (
	"crypto/cipher"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Hot path and multithreading tests to catch gnet-related race conditions.
// These tests should be run with -race to detect data races.

// mockStreamCipher implements cipher.Stream for testing
type mockStreamCipher struct {
	calls atomic.Int64
}

func (m *mockStreamCipher) XORKeyStream(dst, src []byte) {
	m.calls.Add(1)
	copy(dst, src) // Identity transform
}

var _ cipher.Stream = (*mockStreamCipher)(nil)

// TestConnContext_ConcurrentStateTransitions tests concurrent state changes.
// This is a hot path - state can change during relay from any goroutine.
func TestConnContext_ConcurrentStateTransitions(t *testing.T) {
	ctx := NewConnContext()

	const numGoroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent writers
	for i := range numGoroutines / 2 {
		go func(id int) {
			defer wg.Done()
			states := []ConnState{
				StateReadTLSHeader,
				StateReadTLSPayload,
				StateReadO2Frame,
				StateDialingDC,
				StateRelaying,
			}
			for range iterations {
				state := states[(id+int(ctx.State()))%len(states)]
				ctx.SetState(state)
			}
		}(i)
	}

	// Concurrent readers
	for range numGoroutines / 2 {
		go func() {
			defer wg.Done()
			for range iterations {
				state := ctx.State()
				// Verify state is valid
				if state < StateReadProxyProto || state > StateClosed {
					t.Errorf("invalid state value: %d", state)
				}
				_ = state.String()
			}
		}()
	}

	wg.Wait()
}

// TestConnContext_ConcurrentRelayAccess tests concurrent relay field access.
// The relay field is set once during handshake but read during relay.
func TestConnContext_ConcurrentRelayAccess(t *testing.T) {
	ctx := NewConnContext()

	relay := &RelayContext{
		Encryptor: &mockStreamCipher{},
		Decryptor: &mockStreamCipher{},
	}

	const numReaders = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(numReaders + 1)

	// Writer sets relay once
	go func() {
		defer wg.Done()
		ctx.SetRelay(relay)
	}()

	// Concurrent readers
	for range numReaders {
		go func() {
			defer wg.Done()
			for range iterations {
				r := ctx.Relay()
				// After SetRelay, relay should not be nil
				if r != nil && r != relay {
					t.Error("relay changed unexpectedly")
				}
			}
		}()
	}

	wg.Wait()

	// Final check
	if ctx.Relay() != relay {
		t.Error("relay should be set")
	}
}

// TestConnContext_ConcurrentTrafficCounters tests concurrent traffic counting.
// Traffic counters are updated in the hot path during relay.
func TestConnContext_ConcurrentTrafficCounters(t *testing.T) {
	ctx := NewConnContext()

	var bytesIn, bytesOut atomic.Int64
	ctx.SetTrafficCounters(&bytesIn, &bytesOut)

	const numGoroutines = 100
	const bytesPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Concurrent writers to bytesIn
	for range numGoroutines {
		go func() {
			defer wg.Done()
			for range bytesPerGoroutine {
				ctx.TrafficIn().Add(1)
			}
		}()
	}

	// Concurrent writers to bytesOut
	for range numGoroutines {
		go func() {
			defer wg.Done()
			for range bytesPerGoroutine {
				ctx.TrafficOut().Add(1)
			}
		}()
	}

	wg.Wait()

	// Verify totals
	expectedIn := int64(numGoroutines * bytesPerGoroutine)
	expectedOut := int64(numGoroutines * bytesPerGoroutine)

	if bytesIn.Load() != expectedIn {
		t.Errorf("bytesIn = %d, want %d", bytesIn.Load(), expectedIn)
	}
	if bytesOut.Load() != expectedOut {
		t.Errorf("bytesOut = %d, want %d", bytesOut.Load(), expectedOut)
	}
}

// TestConnContext_ConcurrentCleanup tests that cleanup is safe with concurrent access.
func TestConnContext_ConcurrentCleanup(t *testing.T) {
	const iterations = 100

	for range iterations {
		ctx := NewConnContext()
		ctx.SetRelay(&RelayContext{
			Encryptor: &mockStreamCipher{},
			Decryptor: &mockStreamCipher{},
		})

		var bytesIn, bytesOut atomic.Int64
		ctx.SetTrafficCounters(&bytesIn, &bytesOut)

		var wg sync.WaitGroup
		wg.Add(3)

		// Reader goroutine
		go func() {
			defer wg.Done()
			for range 100 {
				_ = ctx.State()
				_ = ctx.Relay()
				_ = ctx.TrafficIn()
				_ = ctx.TrafficOut()
			}
		}()

		// Writer goroutine
		go func() {
			defer wg.Done()
			for i := range 100 {
				ctx.SetState(ConnState(i % 7))
			}
		}()

		// Cleanup goroutine
		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond)
			ctx.Cleanup()
		}()

		wg.Wait()
	}
}

// TestMockGnetConn_ConcurrentWrites tests concurrent writes to mock connection.
// This simulates the gnet pattern where multiple goroutines might write.
func TestMockGnetConn_ConcurrentWrites(t *testing.T) {
	conn := newTestMockGnetConn()

	const numWriters = 10
	const writesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numWriters)

	for i := range numWriters {
		go func(id int) {
			defer wg.Done()
			for j := range writesPerGoroutine {
				data := []byte{byte(id), byte(j)}
				conn.Write(data)
			}
		}(i)
	}

	wg.Wait()

	// Verify all writes were recorded
	written := conn.GetWrittenData()
	expectedBytes := numWriters * writesPerGoroutine * 2 // 2 bytes per write
	if len(written) != expectedBytes {
		t.Errorf("written bytes = %d, want %d", len(written), expectedBytes)
	}
}

// TestMockGnetConn_ConcurrentAsyncWrites tests concurrent async writes.
func TestMockGnetConn_ConcurrentAsyncWrites(t *testing.T) {
	conn := newTestMockGnetConn()

	const numWriters = 10
	const writesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numWriters)

	for i := range numWriters {
		go func(id int) {
			defer wg.Done()
			for j := range writesPerGoroutine {
				data := []byte{byte(id), byte(j)}
				conn.AsyncWrite(data, nil)
			}
		}(i)
	}

	wg.Wait()

	// Verify all async writes were recorded
	asyncWrites := conn.GetAsyncWrites()
	if len(asyncWrites) != numWriters*writesPerGoroutine {
		t.Errorf("async writes = %d, want %d", len(asyncWrites), numWriters*writesPerGoroutine)
	}
}

// TestRelayContext_ConcurrentCipherAccess tests concurrent cipher operations.
// During relay, both encryptor and decryptor are used concurrently.
func TestRelayContext_ConcurrentCipherAccess(t *testing.T) {
	encryptor := &mockStreamCipher{}
	decryptor := &mockStreamCipher{}

	relay := &RelayContext{
		Encryptor: encryptor,
		Decryptor: decryptor,
	}

	const numGoroutines = 100
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Concurrent encryption
	for range numGoroutines {
		go func() {
			defer wg.Done()
			src := make([]byte, 1024)
			dst := make([]byte, 1024)
			for range iterations {
				relay.Encryptor.XORKeyStream(dst, src)
			}
		}()
	}

	// Concurrent decryption
	for range numGoroutines {
		go func() {
			defer wg.Done()
			src := make([]byte, 1024)
			dst := make([]byte, 1024)
			for range iterations {
				relay.Decryptor.XORKeyStream(dst, src)
			}
		}()
	}

	wg.Wait()

	// Verify calls
	expectedCalls := int64(numGoroutines * iterations)
	if encryptor.calls.Load() != expectedCalls {
		t.Errorf("encryptor calls = %d, want %d", encryptor.calls.Load(), expectedCalls)
	}
	if decryptor.calls.Load() != expectedCalls {
		t.Errorf("decryptor calls = %d, want %d", decryptor.calls.Load(), expectedCalls)
	}
}

// TestReplayCache_ConcurrentAccess tests concurrent access to replay cache.
// The replay cache is checked on every handshake.
func TestReplayCache_ConcurrentAccess(t *testing.T) {
	cache := NewReplayCache(1000, 5*time.Minute)

	const numGoroutines = 100
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Concurrent inserts with unique values
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for j := range iterations {
				key := []byte{byte(id), byte(j)}
				cache.Seen(key)
			}
		}(i)
	}

	// Concurrent checks with same values
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for j := range iterations {
				key := []byte{byte(id), byte(j)}
				cache.Seen(key)
			}
		}(i)
	}

	wg.Wait()
}

// TestDesyncDetector_ConcurrentReport tests concurrent desync reporting.
func TestDesyncDetector_ConcurrentReport(t *testing.T) {
	detector := NewDesyncDetector()

	const numGoroutines = 100
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Create a mock logger that does nothing
	logger := &mockLogger{}

	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			ctx := NewConnContext()
			for range iterations {
				detector.Report(ctx, 100000, "c2dc", logger)
			}
		}(i)
	}

	wg.Wait()
}

// mockLogger implements Logger for testing
type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...any) {}
func (m *mockLogger) Info(msg string, fields ...any)  {}
func (m *mockLogger) Warn(msg string, fields ...any)  {}
func (m *mockLogger) Error(msg string, fields ...any) {}
func (m *mockLogger) DebugEnabled() bool              { return false }

var _ Logger = (*mockLogger)(nil)

// TestUserIPLimiter_ConcurrentMultipleUsers tests concurrent access with multiple users.
func TestUserIPLimiter_ConcurrentMultipleUsers(t *testing.T) {
	l := NewUserIPLimiter(10, 5*time.Minute)
	defer l.Close()

	const numUsers = 10
	const numIPsPerUser = 10
	const numGoroutines = 100
	const iterations = 100

	secrets := make([][]byte, numUsers)
	for i := range numUsers {
		secrets[i] = make([]byte, 16)
		for j := range 16 {
			secrets[i][j] = byte(i*16 + j)
		}
	}

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			secret := secrets[id%numUsers]
			for j := range iterations {
				ip := net.ParseIP("192.168.1." + itoa(j%numIPsPerUser))
				key, ok := l.TryAcquire(ip, secret, "user"+itoa(id%numUsers))
				if ok {
					l.Release(key)
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestConnContext_StateTransitionRace tests for race in state transitions.
// Specifically tests the pattern: check state -> act -> set state.
func TestConnContext_StateTransitionRace(t *testing.T) {
	const iterations = 1000

	for range iterations {
		ctx := NewConnContext()

		var wg sync.WaitGroup
		wg.Add(2)

		// Simulate handshake completing
		go func() {
			defer wg.Done()
			if ctx.State() == StateReadTLSHeader {
				ctx.SetState(StateReadTLSPayload)
			}
			if ctx.State() == StateReadTLSPayload {
				ctx.SetState(StateReadO2Frame)
			}
		}()

		// Simulate another state check
		go func() {
			defer wg.Done()
			state := ctx.State()
			// Verify state is valid
			if state < StateReadProxyProto || state > StateClosed {
				t.Errorf("invalid state: %d", state)
			}
		}()

		wg.Wait()
	}
}

// TestTrafficCounters_ConcurrentAddAndRead tests concurrent add and read.
// This simulates the hot path where traffic is counted while stats are read.
func TestTrafficCounters_ConcurrentAddAndRead(t *testing.T) {
	l := NewUserIPLimiter(10, 5*time.Minute)
	defer l.Close()

	secret := []byte("0123456789abcdef")
	ip := net.ParseIP("192.168.1.1")

	key, _ := l.TryAcquire(ip, secret, "test")
	defer l.Release(key)

	bytesIn, bytesOut := l.TrafficCounters(secret)

	const numWriters = 10
	const numReaders = 10
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(numWriters + numReaders)

	// Writers
	for range numWriters {
		go func() {
			defer wg.Done()
			for range iterations {
				bytesIn.Add(100)
				bytesOut.Add(200)
			}
		}()
	}

	// Readers (simulating stats collection)
	for range numReaders {
		go func() {
			defer wg.Done()
			for range iterations {
				_ = l.Stats()
			}
		}()
	}

	wg.Wait()

	// Verify totals
	expectedIn := int64(numWriters * iterations * 100)
	expectedOut := int64(numWriters * iterations * 200)

	stats := l.Stats()
	if len(stats) != 1 {
		t.Fatalf("expected 1 stat, got %d", len(stats))
	}
	if stats[0].BytesIn != expectedIn {
		t.Errorf("BytesIn = %d, want %d", stats[0].BytesIn, expectedIn)
	}
	if stats[0].BytesOut != expectedOut {
		t.Errorf("BytesOut = %d, want %d", stats[0].BytesOut, expectedOut)
	}
}

// itoa converts int to string (avoiding strconv import)
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b) - 1
	for i > 0 {
		b[n] = byte('0' + i%10)
		n--
		i /= 10
	}
	return string(b[n+1:])
}

// Benchmarks for hot paths

func BenchmarkConnContext_StateAccess(b *testing.B) {
	ctx := NewConnContext()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = ctx.State()
		}
	})
}

func BenchmarkConnContext_StateTransition(b *testing.B) {
	ctx := NewConnContext()
	b.ResetTimer()
	for b.Loop() {
		ctx.SetState(StateRelaying)
	}
}

func BenchmarkTrafficCounter_Add(b *testing.B) {
	var counter atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			counter.Add(1)
		}
	})
}

func BenchmarkRelayContext_CipherXOR(b *testing.B) {
	cipher := &mockStreamCipher{}
	src := make([]byte, 1024)
	dst := make([]byte, 1024)
	b.ResetTimer()
	for b.Loop() {
		cipher.XORKeyStream(dst, src)
	}
}
