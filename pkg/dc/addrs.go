// Package dc manages Telegram datacenter connections.
package dc

import "net"

// Default Telegram DC addresses.
// Merged from tdesktop source + live API for redundancy.
// tdesktop: https://github.com/telegramdesktop/tdesktop/blob/master/Telegram/SourceFiles/mtproto/mtproto_dc_options.cpp
var DefaultDCs = map[int][]Addr{
	1: {
		// tdesktop
		{Network: "tcp4", Address: "149.154.175.50:443"},
		// live API
		{Network: "tcp4", Address: "149.154.175.58:443"},
		// IPv6
		{Network: "tcp6", Address: "[2001:b28:f23d:f001::a]:443"},
	},
	2: {
		// tdesktop
		{Network: "tcp4", Address: "149.154.167.51:443"},
		{Network: "tcp4", Address: "95.161.76.100:443"},
		// live API
		{Network: "tcp4", Address: "149.154.167.41:443"},
		// IPv6
		{Network: "tcp6", Address: "[2001:67c:4e8:f002::a]:443"},
	},
	3: {
		// same in both
		{Network: "tcp4", Address: "149.154.175.100:443"},
		// IPv6
		{Network: "tcp6", Address: "[2001:b28:f23d:f003::a]:443"},
	},
	4: {
		// tdesktop
		{Network: "tcp4", Address: "149.154.167.91:443"},
		// live API
		{Network: "tcp4", Address: "149.154.167.92:443"},
		// IPv6
		{Network: "tcp6", Address: "[2001:67c:4e8:f004::a]:443"},
	},
	5: {
		// tdesktop
		{Network: "tcp4", Address: "149.154.171.5:443"},
		// live API
		{Network: "tcp4", Address: "91.108.56.156:443"},
		// IPv6
		{Network: "tcp6", Address: "[2001:b28:f23f:f005::a]:443"},
	},
}

// CDN/regional DC overrides for special DCs (200+).
var CDNDCs = map[int][]Addr{
	203: {
		{Network: "tcp4", Address: "91.105.192.100:443"},
	},
}

// DefaultDC is the fallback DC when unknown.
const DefaultDC = 2

// IPPreference controls which IP version to prefer.
type IPPreference int

const (
	PreferIPv4 IPPreference = iota
	PreferIPv6
	OnlyIPv4
	OnlyIPv6
)

// Addr represents a datacenter address.
type Addr struct {
	Network string // "tcp4" or "tcp6"
	Address string // "host:port"
}

// IP returns the IP address without port.
func (a Addr) IP() net.IP {
	host, _, _ := net.SplitHostPort(a.Address)
	return net.ParseIP(host)
}

// IsIPv6 returns true if this is an IPv6 address.
func (a Addr) IsIPv6() bool {
	return a.Network == "tcp6"
}

// DCAddresses returns addresses for a given DC.
// Negative DC IDs are media-only variants; we use the absolute value for lookup.
// Returns (addresses, true) if DC is known, (fallback addresses, false) if unknown.
func DCAddresses(dc int) ([]Addr, bool) {
	// Check CDN/special DCs first
	if addrs, ok := CDNDCs[dc]; ok {
		return addrs, true
	}
	// Negative DC = media-only, use absolute value
	absDC := dc
	if absDC < 0 {
		absDC = -absDC
	}
	if addrs, ok := DefaultDCs[absDC]; ok {
		return addrs, true
	}
	// Fallback to DC 2 for unknown DCs
	return DefaultDCs[DefaultDC], false
}

// DCAddressesIPv4 returns only IPv4 addresses for a DC.
func DCAddressesIPv4(dc int) ([]Addr, bool) {
	addrs, known := DCAddresses(dc)
	result := make([]Addr, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsIPv6() {
			result = append(result, a)
		}
	}
	return result, known
}

// DCAddressesIPv6 returns only IPv6 addresses for a DC.
func DCAddressesIPv6(dc int) ([]Addr, bool) {
	addrs, known := DCAddresses(dc)
	result := make([]Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.IsIPv6() {
			result = append(result, a)
		}
	}
	return result, known
}
