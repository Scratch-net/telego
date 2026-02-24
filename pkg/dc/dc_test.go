package dc

import (
	"net"
	"testing"
)

// TestDCAddresses_Known tests that DC 1-5 return addresses.
func TestDCAddresses_Known(t *testing.T) {
	for dc := 1; dc <= 5; dc++ {
		addrs, known := DCAddresses(dc)
		if !known {
			t.Errorf("DC %d should be known", dc)
		}
		if len(addrs) == 0 {
			t.Errorf("DC %d should have addresses", dc)
		}
	}
}

// TestDCAddresses_Unknown tests that unknown DC returns DC 2 fallback.
func TestDCAddresses_Unknown(t *testing.T) {
	addrs, known := DCAddresses(99)
	if known {
		t.Error("DC 99 should not be known")
	}

	// Should return DC 2 fallback
	dc2Addrs, _ := DCAddresses(2)
	if len(addrs) != len(dc2Addrs) {
		t.Errorf("Fallback should return DC 2 addresses, got %d addresses", len(addrs))
	}
}

// TestDCAddresses_Negative tests that DC -2 maps to DC 2.
func TestDCAddresses_Negative(t *testing.T) {
	testCases := []struct {
		negativeDC int
		positiveDC int
	}{
		{-1, 1},
		{-2, 2},
		{-3, 3},
		{-4, 4},
		{-5, 5},
	}

	for _, tc := range testCases {
		t.Run("dc_mapping", func(t *testing.T) {
			negAddrs, negKnown := DCAddresses(tc.negativeDC)
			posAddrs, posKnown := DCAddresses(tc.positiveDC)

			if negKnown != posKnown {
				t.Errorf("DC %d and DC %d should have same known status", tc.negativeDC, tc.positiveDC)
			}

			if len(negAddrs) != len(posAddrs) {
				t.Errorf("DC %d and DC %d should have same number of addresses", tc.negativeDC, tc.positiveDC)
			}
		})
	}
}

// TestDCAddresses_CDN tests that DC 203 returns CDN address.
func TestDCAddresses_CDN(t *testing.T) {
	addrs, known := DCAddresses(203)
	if !known {
		t.Error("DC 203 (CDN) should be known")
	}

	if len(addrs) == 0 {
		t.Error("DC 203 should have addresses")
	}

	// Verify it's not the same as DC 2 (not a fallback)
	dc2Addrs, _ := DCAddresses(2)
	if addrs[0].Address == dc2Addrs[0].Address {
		t.Error("DC 203 should have different addresses than DC 2")
	}
}

// TestDCAddressesIPv4 tests filtering to IPv4 only.
func TestDCAddressesIPv4(t *testing.T) {
	addrs, _ := DCAddressesIPv4(2)

	if len(addrs) == 0 {
		t.Error("DC 2 should have IPv4 addresses")
	}

	for _, addr := range addrs {
		if addr.IsIPv6() {
			t.Errorf("IPv4 filter returned IPv6 address: %s", addr.Address)
		}
	}
}

// TestDCAddressesIPv6 tests filtering to IPv6 only.
func TestDCAddressesIPv6(t *testing.T) {
	addrs, _ := DCAddressesIPv6(2)

	// DC 2 has IPv6 addresses
	for _, addr := range addrs {
		if !addr.IsIPv6() {
			t.Errorf("IPv6 filter returned IPv4 address: %s", addr.Address)
		}
	}
}

// TestAddr_IsIPv6 tests IPv6 detection.
func TestAddr_IsIPv6(t *testing.T) {
	testCases := []struct {
		network  string
		expected bool
	}{
		{"tcp4", false},
		{"tcp6", true},
		{"tcp", false}, // Default to IPv4
	}

	for _, tc := range testCases {
		addr := Addr{Network: tc.network, Address: "127.0.0.1:443"}
		if addr.IsIPv6() != tc.expected {
			t.Errorf("IsIPv6() for %q: got %v, want %v", tc.network, addr.IsIPv6(), tc.expected)
		}
	}
}

// TestAddr_IP tests IP extraction from address string.
func TestAddr_IP(t *testing.T) {
	testCases := []struct {
		address    string
		expectedIP string
	}{
		{"149.154.175.50:443", "149.154.175.50"},
		{"[2001:b28:f23d:f001::a]:443", "2001:b28:f23d:f001::a"},
		{"127.0.0.1:8080", "127.0.0.1"},
	}

	for _, tc := range testCases {
		addr := Addr{Address: tc.address}
		ip := addr.IP()

		if ip == nil {
			t.Errorf("IP() returned nil for %q", tc.address)
			continue
		}

		if ip.String() != tc.expectedIP {
			t.Errorf("IP() for %q: got %s, want %s", tc.address, ip.String(), tc.expectedIP)
		}
	}
}

// TestAddr_IP_Invalid tests IP extraction with invalid address.
func TestAddr_IP_Invalid(t *testing.T) {
	addr := Addr{Address: "invalid"}
	ip := addr.IP()
	// SplitHostPort may fail, resulting in nil IP
	if ip != nil && ip.String() != "invalid" {
		// This is implementation-dependent
		t.Logf("IP() for invalid address: %v", ip)
	}
}

// TestDefaultDC tests the default DC constant.
func TestDefaultDC(t *testing.T) {
	if DefaultDC != 2 {
		t.Errorf("DefaultDC should be 2, got %d", DefaultDC)
	}
}

// TestIPPreference tests IP preference constants.
func TestIPPreference(t *testing.T) {
	if PreferIPv4 != 0 {
		t.Errorf("PreferIPv4 should be 0, got %d", PreferIPv4)
	}
	if PreferIPv6 != 1 {
		t.Errorf("PreferIPv6 should be 1, got %d", PreferIPv6)
	}
	if OnlyIPv4 != 2 {
		t.Errorf("OnlyIPv4 should be 2, got %d", OnlyIPv4)
	}
	if OnlyIPv6 != 3 {
		t.Errorf("OnlyIPv6 should be 3, got %d", OnlyIPv6)
	}
}

// TestDefaultDCs_Structure tests that default DCs have expected structure.
func TestDefaultDCs_Structure(t *testing.T) {
	// Each DC 1-5 should exist
	for dc := 1; dc <= 5; dc++ {
		addrs, ok := DefaultDCs[dc]
		if !ok {
			t.Errorf("DC %d missing from DefaultDCs", dc)
			continue
		}

		// Should have at least one IPv4 address
		hasIPv4 := false
		for _, addr := range addrs {
			if !addr.IsIPv6() {
				hasIPv4 = true
				break
			}
		}
		if !hasIPv4 {
			t.Errorf("DC %d has no IPv4 addresses", dc)
		}
	}
}

// TestCDNDCs_Structure tests CDN DC structure.
func TestCDNDCs_Structure(t *testing.T) {
	addrs, ok := CDNDCs[203]
	if !ok {
		t.Error("DC 203 missing from CDNDCs")
		return
	}

	if len(addrs) == 0 {
		t.Error("DC 203 should have at least one address")
	}
}

// TestGetProbedAddresses_BeforeInit tests fallback before Init() is called.
func TestGetProbedAddresses_BeforeInit(t *testing.T) {
	// Note: This test assumes probing hasn't been done
	// In practice, another test might have called Init()

	// Reset the probed state for this test
	probedMu.Lock()
	savedProbedDCs := probedDCs
	probedDCs = nil
	probedMu.Unlock()

	defer func() {
		probedMu.Lock()
		probedDCs = savedProbedDCs
		probedMu.Unlock()
	}()

	addrs, known := GetProbedAddresses(2)

	// Should fall back to DCAddresses
	dcAddrs, dcKnown := DCAddresses(2)

	if known != dcKnown {
		t.Error("GetProbedAddresses should fall back to DCAddresses")
	}

	if len(addrs) != len(dcAddrs) {
		t.Errorf("Fallback address count mismatch: got %d, want %d", len(addrs), len(dcAddrs))
	}
}

// TestGetProbedAddresses_NegativeDC tests handling of negative DC IDs after probing.
func TestGetProbedAddresses_NegativeDC(t *testing.T) {
	// Set up mock probed data
	probedMu.Lock()
	savedProbedDCs := probedDCs
	probedDCs = map[int][]Addr{
		2: {{Network: "tcp4", Address: "1.2.3.4:443"}},
	}
	probedMu.Unlock()

	defer func() {
		probedMu.Lock()
		probedDCs = savedProbedDCs
		probedMu.Unlock()
	}()

	addrs, known := GetProbedAddresses(-2)

	if !known {
		t.Error("DC -2 should resolve to DC 2 which is probed")
	}

	if len(addrs) != 1 || addrs[0].Address != "1.2.3.4:443" {
		t.Error("DC -2 should return DC 2's probed addresses")
	}
}

// TestProbeTimeout tests the probe timeout constant.
func TestProbeTimeout(t *testing.T) {
	// ProbeTimeout should be reasonable (5 seconds)
	if ProbeTimeout.Seconds() != 5 {
		t.Errorf("ProbeTimeout should be 5s, got %v", ProbeTimeout)
	}
}

// TestAddressValidation tests that all default addresses are valid.
func TestAddressValidation(t *testing.T) {
	validateAddr := func(addr Addr, dc int) {
		host, port, err := net.SplitHostPort(addr.Address)
		if err != nil {
			t.Errorf("DC %d: invalid address %q: %v", dc, addr.Address, err)
			return
		}

		if port != "443" {
			t.Errorf("DC %d: expected port 443, got %s", dc, port)
		}

		ip := net.ParseIP(host)
		if ip == nil {
			t.Errorf("DC %d: invalid IP %s", dc, host)
		}
	}

	for dc, addrs := range DefaultDCs {
		for _, addr := range addrs {
			validateAddr(addr, dc)
		}
	}

	for dc, addrs := range CDNDCs {
		for _, addr := range addrs {
			validateAddr(addr, dc)
		}
	}
}

// TestSetProbeLogger tests setting the probe logger.
func TestSetProbeLogger(t *testing.T) {
	var logged string
	SetProbeLogger(func(format string, args ...any) {
		logged = format
	})

	// Call logProbe to test
	logProbe("test message")

	if logged != "test message" {
		t.Errorf("Logger not called correctly: got %q", logged)
	}

	// Reset logger
	SetProbeLogger(nil)
}
