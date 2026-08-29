package middleend

import (
	"errors"
	"fmt"
	"net/netip"
)

var ErrEndpointSelection = errors.New("select Telegram Middle-End endpoint")

// AddressFamily restricts deterministic endpoint selection.
type AddressFamily uint8

const (
	AddressFamilyAny AddressFamily = iota
	AddressFamilyIPv4
	AddressFamilyIPv6
)

// SelectEndpoint chooses one endpoint without retry or hidden failover. A nil
// dc selects the artifact generation's declared default. Within the requested
// family, index follows artifact order; the combined order is IPv4 then IPv6.
func SelectEndpoint(snapshot ArtifactSnapshot, dc *DCID, family AddressFamily, index int) (DCID, netip.AddrPort, error) {
	selectedDC := snapshot.DefaultDC()
	if dc != nil {
		selectedDC = *dc
	}
	if family != AddressFamilyAny && family != AddressFamilyIPv4 && family != AddressFamilyIPv6 {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: invalid address family %d", ErrEndpointSelection, family)
	}
	if index < 0 {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: endpoint index must be nonnegative", ErrEndpointSelection)
	}

	endpoints := snapshot.Endpoints(selectedDC)
	filtered := endpoints[:0]
	for _, endpoint := range endpoints {
		switch family {
		case AddressFamilyAny:
			filtered = append(filtered, endpoint)
		case AddressFamilyIPv4:
			if endpoint.Addr().Unmap().Is4() {
				filtered = append(filtered, endpoint)
			}
		case AddressFamilyIPv6:
			if endpoint.Addr().Is6() && !endpoint.Addr().Is4In6() {
				filtered = append(filtered, endpoint)
			}
		}
	}
	if index >= len(filtered) {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: DC %d has %d matching endpoints, index %d is unavailable", ErrEndpointSelection, selectedDC, len(filtered), index)
	}
	return selectedDC, filtered[index], nil
}
