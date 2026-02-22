// Package dc manages Telegram datacenter connections.
package dc

import "net"

// Default Telegram DC addresses.
// These are the official Telegram datacenter endpoints.
var DefaultDCs = map[int][]Addr{
	1: {
		{Network: "tcp4", Address: "149.154.175.50:443"},
		{Network: "tcp6", Address: "[2001:b28:f23d:f001::a]:443"},
	},
	2: {
		{Network: "tcp4", Address: "149.154.167.50:443"},
		{Network: "tcp4", Address: "149.154.167.51:443"},
		{Network: "tcp6", Address: "[2001:67c:4e8:f002::a]:443"},
	},
	3: {
		{Network: "tcp4", Address: "149.154.175.100:443"},
		{Network: "tcp6", Address: "[2001:b28:f23d:f003::a]:443"},
	},
	4: {
		{Network: "tcp4", Address: "149.154.167.91:443"},
		{Network: "tcp6", Address: "[2001:67c:4e8:f004::a]:443"},
	},
	5: {
		{Network: "tcp4", Address: "91.108.56.100:443"},
		{Network: "tcp6", Address: "[2001:b28:f23f:f005::a]:443"},
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
func DCAddresses(dc int) []Addr {
	if addrs, ok := DefaultDCs[dc]; ok {
		return addrs
	}
	// Fallback to DC 2 for unknown DCs
	return DefaultDCs[DefaultDC]
}

// DCAddressesIPv4 returns only IPv4 addresses for a DC.
func DCAddressesIPv4(dc int) []Addr {
	addrs := DCAddresses(dc)
	result := make([]Addr, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsIPv6() {
			result = append(result, a)
		}
	}
	return result
}

// DCAddressesIPv6 returns only IPv6 addresses for a DC.
func DCAddressesIPv6(dc int) []Addr {
	addrs := DCAddresses(dc)
	result := make([]Addr, 0, len(addrs))
	for _, a := range addrs {
		if a.IsIPv6() {
			result = append(result, a)
		}
	}
	return result
}
