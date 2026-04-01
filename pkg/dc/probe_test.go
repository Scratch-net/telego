package dc

import (
	"net"
	"slices"
	"testing"
	"time"
)

func TestProbeResult_Fields(t *testing.T) {
	result := ProbeResult{
		Addr:    Addr{Network: "tcp4", Address: "1.2.3.4:443"},
		RTT:     50 * time.Millisecond,
		Success: true,
		Error:   "",
	}

	if result.Addr.Address != "1.2.3.4:443" {
		t.Errorf("Addr.Address: got %s", result.Addr.Address)
	}
	if result.RTT != 50*time.Millisecond {
		t.Errorf("RTT: got %v", result.RTT)
	}
	if !result.Success {
		t.Error("Success should be true")
	}
}

func TestDCProbeResult_Fields(t *testing.T) {
	result := DCProbeResult{
		DCID: 2,
		Results: []ProbeResult{
			{Addr: Addr{Network: "tcp4", Address: "1.2.3.4:443"}, Success: true},
			{Addr: Addr{Network: "tcp4", Address: "5.6.7.8:443"}, Success: false},
		},
	}

	if result.DCID != 2 {
		t.Errorf("DCID: got %d", result.DCID)
	}
	if len(result.Results) != 2 {
		t.Errorf("Results count: got %d", len(result.Results))
	}
}

func TestSetProbeSocks5(t *testing.T) {
	// Empty address should clear
	err := SetProbeSocks5("")
	if err != nil {
		t.Errorf("SetProbeSocks5(\"\") failed: %v", err)
	}
	if probeSocks5 != "" {
		t.Error("probeSocks5 should be empty")
	}
	if probeDialer != nil {
		t.Error("probeDialer should be nil")
	}

	// Valid address format (doesn't need actual SOCKS5 server)
	err = SetProbeSocks5("127.0.0.1:1080")
	if err != nil {
		t.Errorf("SetProbeSocks5 with valid format failed: %v", err)
	}
	if probeSocks5 != "127.0.0.1:1080" {
		t.Errorf("probeSocks5: got %s", probeSocks5)
	}
	if probeDialer == nil {
		t.Error("probeDialer should be set")
	}

	// Reset
	SetProbeSocks5("")
}

func TestStoreSortedAddresses(t *testing.T) {
	// Create test results
	results := []DCProbeResult{
		{
			DCID: 1,
			Results: []ProbeResult{
				{Addr: Addr{Network: "tcp4", Address: "1.1.1.1:443"}, Success: true},
				{Addr: Addr{Network: "tcp4", Address: "1.1.1.2:443"}, Success: true},
			},
		},
		{
			DCID: 2,
			Results: []ProbeResult{
				{Addr: Addr{Network: "tcp4", Address: "2.2.2.1:443"}, Success: true},
			},
		},
	}

	// Store them
	storeSortedAddresses(results)

	// Check they're stored
	probedMu.RLock()
	defer probedMu.RUnlock()

	if probedDCs == nil {
		t.Fatal("probedDCs should not be nil")
	}

	dc1Addrs, ok := probedDCs[1]
	if !ok {
		t.Error("DC 1 should be stored")
	}
	if len(dc1Addrs) != 2 {
		t.Errorf("DC 1 should have 2 addresses, got %d", len(dc1Addrs))
	}

	dc2Addrs, ok := probedDCs[2]
	if !ok {
		t.Error("DC 2 should be stored")
	}
	if len(dc2Addrs) != 1 {
		t.Errorf("DC 2 should have 1 address, got %d", len(dc2Addrs))
	}
}

func TestProbeAddr_DirectConnection(t *testing.T) {
	// Start a mock server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read garbage handshake
			buf := make([]byte, 64)
			conn.SetReadDeadline(time.Now().Add(time.Second))
			conn.Read(buf)
			// Close (simulates DC rejection)
			conn.Close()
		}
	}()

	// Ensure direct mode (no SOCKS5)
	SetProbeSocks5("")

	addr := Addr{Network: "tcp4", Address: ln.Addr().String()}
	result := probeAddr(addr)

	if !result.Success {
		t.Errorf("probe should succeed: %s", result.Error)
	}
	if result.RTT <= 0 {
		t.Error("RTT should be positive")
	}
}

func TestProbeAddr_ConnectionRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow connection refused test in short mode")
	}

	// Ensure direct mode
	SetProbeSocks5("")

	// Try to connect to a port that's not listening
	addr := Addr{Network: "tcp4", Address: "127.0.0.1:1"} // Port 1 is privileged, unlikely to be open
	result := probeAddr(addr)

	if result.Success {
		t.Error("probe to closed port should fail")
	}
	if result.Error == "" {
		t.Error("should have error message")
	}
}

func TestProbeAddr_IPv6ViaSocks5Skipped(t *testing.T) {
	// Set up SOCKS5
	SetProbeSocks5("127.0.0.1:1080")
	defer SetProbeSocks5("")

	// IPv6 via SOCKS5 should be skipped
	addr := Addr{Network: "tcp6", Address: "[::1]:443"}
	result := probeAddr(addr)

	if result.Success {
		t.Error("IPv6 via SOCKS5 should be skipped")
	}
	if result.Error == "" {
		t.Error("should have skip message")
	}
}

func TestLogProbe_NilLogger(t *testing.T) {
	// Should not panic with nil logger (uses fmt.Printf)
	SetProbeLogger(nil)
	logProbe("test %d", 42)
}

func TestProbeDC(t *testing.T) {
	// Start multiple mock servers
	var listeners []net.Listener
	var addrs []Addr

	for i := range 3 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		listeners = append(listeners, ln)
		addrs = append(addrs, Addr{Network: "tcp4", Address: ln.Addr().String()})

		// Accept in background
		go func(listener net.Listener, delay time.Duration) {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				time.Sleep(delay) // Simulate different RTTs
				buf := make([]byte, 64)
				conn.SetReadDeadline(time.Now().Add(time.Second))
				conn.Read(buf)
				conn.Close()
			}
		}(ln, time.Duration(i*10)*time.Millisecond)
	}

	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	// Ensure direct mode
	SetProbeSocks5("")

	result := probeDC(99, addrs)

	if result.DCID != 99 {
		t.Errorf("DCID: got %d", result.DCID)
	}
	if len(result.Results) != 3 {
		t.Errorf("Results count: got %d", len(result.Results))
	}

	// Results should be sorted by RTT (successful first)
	var lastRTT time.Duration
	for i, r := range result.Results {
		if r.Success {
			if r.RTT < lastRTT {
				t.Errorf("results not sorted by RTT at index %d", i)
			}
			lastRTT = r.RTT
		}
	}
}

func TestGetProbedAddresses_AfterStore(t *testing.T) {
	// Store some test addresses
	results := []DCProbeResult{
		{
			DCID: 42,
			Results: []ProbeResult{
				{Addr: Addr{Network: "tcp4", Address: "42.42.42.42:443"}, Success: true},
			},
		},
	}
	storeSortedAddresses(results)

	// Verify we can retrieve them
	addrs, ok := GetProbedAddresses(42)
	if !ok {
		t.Error("DC 42 should be found after storing")
	}
	if len(addrs) != 1 {
		t.Errorf("expected 1 address, got %d", len(addrs))
	}
	if addrs[0].Address != "42.42.42.42:443" {
		t.Errorf("unexpected address: %s", addrs[0].Address)
	}
}

func TestPrintProbeResults_IPv4Only(t *testing.T) {
	// Capture logs
	var logs []string
	SetProbeLogger(func(format string, args ...any) {
		logs = append(logs, format)
	})
	defer SetProbeLogger(nil)

	results := []DCProbeResult{
		{
			DCID: 1,
			Results: []ProbeResult{
				{Addr: Addr{Network: "tcp4", Address: "1.1.1.1:443"}, RTT: 50 * time.Millisecond, Success: true},
				{Addr: Addr{Network: "tcp4", Address: "1.1.1.2:443"}, RTT: 0, Success: false, Error: "timeout"},
			},
		},
	}

	printProbeResults(results)

	if len(logs) < 3 {
		t.Errorf("expected at least 3 log lines, got %d", len(logs))
	}
}

func TestPrintProbeResults_IPv6Only(t *testing.T) {
	var logs []string
	SetProbeLogger(func(format string, args ...any) {
		logs = append(logs, format)
	})
	defer SetProbeLogger(nil)

	results := []DCProbeResult{
		{
			DCID: 2,
			Results: []ProbeResult{
				{Addr: Addr{Network: "tcp6", Address: "[2001:db8::1]:443"}, RTT: 30 * time.Millisecond, Success: true},
			},
		},
	}

	printProbeResults(results)

	if len(logs) < 3 {
		t.Errorf("expected at least 3 log lines, got %d", len(logs))
	}
}

func TestPrintProbeResults_BothIPv4AndIPv6(t *testing.T) {
	var logs []string
	SetProbeLogger(func(format string, args ...any) {
		logs = append(logs, format)
	})
	defer SetProbeLogger(nil)

	results := []DCProbeResult{
		{
			DCID: 3,
			Results: []ProbeResult{
				{Addr: Addr{Network: "tcp4", Address: "3.3.3.3:443"}, RTT: 40 * time.Millisecond, Success: true},
				{Addr: Addr{Network: "tcp6", Address: "[2001:db8::3]:443"}, RTT: 35 * time.Millisecond, Success: true},
			},
		},
	}

	printProbeResults(results)

	if len(logs) < 4 {
		t.Errorf("expected at least 4 log lines, got %d", len(logs))
	}
}

func TestPrintProbeResults_NoConnectivity(t *testing.T) {
	var logs []string
	SetProbeLogger(func(format string, args ...any) {
		logs = append(logs, format)
	})
	defer SetProbeLogger(nil)

	results := []DCProbeResult{
		{
			DCID: 4,
			Results: []ProbeResult{
				{Addr: Addr{Network: "tcp4", Address: "4.4.4.4:443"}, Success: false, Error: "timeout"},
				{Addr: Addr{Network: "tcp6", Address: "[2001:db8::4]:443"}, Success: false, Error: "timeout"},
			},
		},
	}

	printProbeResults(results)

	// Should log "No DC connectivity!"
	found := slices.Contains(logs, "  No DC connectivity!")
	if !found {
		t.Error("expected 'No DC connectivity!' message")
	}
}

func TestPrintProbeResults_ViaSocks5(t *testing.T) {
	// Set SOCKS5 to change the header
	probeSocks5 = "127.0.0.1:1080"
	defer func() { probeSocks5 = "" }()

	var logs []string
	SetProbeLogger(func(format string, args ...any) {
		logs = append(logs, format)
	})
	defer SetProbeLogger(nil)

	results := []DCProbeResult{
		{
			DCID: 5,
			Results: []ProbeResult{
				{Addr: Addr{Network: "tcp4", Address: "5.5.5.5:443"}, RTT: 100 * time.Millisecond, Success: true},
			},
		},
	}

	printProbeResults(results)

	// First log should mention SOCKS5
	if len(logs) == 0 {
		t.Fatal("expected logs")
	}
	found := slices.Contains(logs, "============== Telegram DC Connectivity (via SOCKS5) ============")
	if !found {
		t.Error("expected SOCKS5 header in output")
	}
}

func TestPrintProbeResults_FailedAddresses(t *testing.T) {
	var logs []string
	SetProbeLogger(func(format string, args ...any) {
		logs = append(logs, format)
	})
	defer SetProbeLogger(nil)

	results := []DCProbeResult{
		{
			DCID: 6,
			Results: []ProbeResult{
				{Addr: Addr{Network: "tcp4", Address: "6.6.6.6:443"}, RTT: 50 * time.Millisecond, Success: true},
				{Addr: Addr{Network: "tcp4", Address: "6.6.6.7:443"}, Success: false, Error: "connection refused"},
				{Addr: Addr{Network: "tcp6", Address: "[2001:db8::6]:443"}, RTT: 45 * time.Millisecond, Success: true},
				{Addr: Addr{Network: "tcp6", Address: "[2001:db8::7]:443"}, Success: false, Error: "timeout"},
			},
		},
	}

	printProbeResults(results)

	if len(logs) < 6 {
		t.Errorf("expected at least 6 log lines for mixed results, got %d", len(logs))
	}
}

// BenchmarkProbeAddr benchmarks address probing
func BenchmarkProbeAddr(b *testing.B) {
	// Start a fast mock server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 64)
			conn.Read(buf)
			conn.Close()
		}
	}()

	SetProbeSocks5("")
	addr := Addr{Network: "tcp4", Address: ln.Addr().String()}

	b.ResetTimer()
	for b.Loop() {
		probeAddr(addr)
	}
}
