package middleend

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
)

var nonPublicAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// DirectAddressTuple validates that an established direct TCP connection has
// a public, exact endpoint tuple suitable for Telegram's address-bound KDF.
func DirectAddressTuple(conn *net.TCPConn, selectedServer netip.AddrPort) (netip.AddrPort, netip.AddrPort, error) {
	return directAddressTuple(conn, selectedServer, netip.Addr{})
}

// DirectNATAddressTuple validates a direct TCP connection and replaces only a
// non-public client IP with publicIP. It always retains the exact kernel TCP
// source port. A public socket endpoint is never changed.
func DirectNATAddressTuple(
	conn *net.TCPConn,
	selectedServer netip.AddrPort,
	publicIP netip.Addr,
) (netip.AddrPort, netip.AddrPort, error) {
	return directAddressTuple(conn, selectedServer, publicIP)
}

func directAddressTuple(
	conn *net.TCPConn,
	selectedServer netip.AddrPort,
	publicIP netip.Addr,
) (netip.AddrPort, netip.AddrPort, error) {
	serverAddr, clientAddr, err := directSocketAddressTuple(conn, selectedServer)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	if err := validatePublicEndpoint("server", serverAddr); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("direct TCP tuple: %w", err)
	}
	translated, err := translateNATClientAddress(clientAddr, publicIP)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("direct TCP tuple: %w", err)
	}
	if err := validatePublicTuple(serverAddr, translated); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("direct NAT TCP tuple: %w", err)
	}
	return serverAddr, translated, nil
}

func translateNATClientAddress(clientAddr netip.AddrPort, publicIP netip.Addr) (netip.AddrPort, error) {
	clientErr := validatePublicEndpoint("client", clientAddr)
	if clientErr == nil {
		return clientAddr, nil
	}
	if !publicIP.IsValid() {
		return netip.AddrPort{}, clientErr
	}
	translated := netip.AddrPortFrom(publicIP.Unmap(), clientAddr.Port())
	if err := validatePublicEndpoint("translated client", translated); err != nil {
		return netip.AddrPort{}, err
	}
	if clientAddr.Addr().Unmap().Is4() != translated.Addr().Is4() {
		return netip.AddrPort{}, fmt.Errorf("%w: translated client address family differs from the TCP socket", ErrTupleNotAuthoritative)
	}
	return translated, nil
}

func directSocketAddressTuple(
	conn *net.TCPConn,
	selectedServer netip.AddrPort,
) (netip.AddrPort, netip.AddrPort, error) {
	if conn == nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("%w: nil direct TCP connection", ErrTupleNotAuthoritative)
	}
	if !selectedServer.IsValid() || selectedServer.Port() == 0 {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("%w: invalid selected server endpoint", ErrTupleNotAuthoritative)
	}
	serverAddr, err := tcpAddrPort(conn.RemoteAddr())
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("%w: direct server: %v", ErrTupleNotAuthoritative, err)
	}
	clientAddr, err := tcpAddrPort(conn.LocalAddr())
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("%w: direct client: %v", ErrTupleNotAuthoritative, err)
	}
	selectedServer = netip.AddrPortFrom(selectedServer.Addr().Unmap(), selectedServer.Port())
	if serverAddr != selectedServer {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("%w: direct remote endpoint differs from the selected artifact endpoint", ErrTupleNotAuthoritative)
	}
	if err := validateAddressTuple(serverAddr, clientAddr); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("%w: direct TCP tuple: %v", ErrTupleNotAuthoritative, err)
	}
	return serverAddr, clientAddr, nil
}

// SOCKS5AddressTuple validates the selected Telegram endpoint and the exact
// BND.ADDR:BND.PORT returned by a successful SOCKS5 CONNECT. It never resolves
// or substitutes a non-IP bound address.
func SOCKS5AddressTuple(selectedServer netip.AddrPort, bound SOCKS5Address) (netip.AddrPort, netip.AddrPort, error) {
	if !selectedServer.IsValid() || selectedServer.Port() == 0 {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("%w: invalid selected server endpoint", ErrTupleNotAuthoritative)
	}
	clientAddr, err := bound.AddrPort()
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("%w: SOCKS5 BND endpoint: %v", ErrTupleNotAuthoritative, err)
	}
	serverAddr := netip.AddrPortFrom(selectedServer.Addr().Unmap(), selectedServer.Port())
	clientAddr = netip.AddrPortFrom(clientAddr.Addr().Unmap(), clientAddr.Port())
	if err := validatePublicTuple(serverAddr, clientAddr); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("SOCKS5 BND tuple: %w", err)
	}
	return serverAddr, clientAddr, nil
}

// ClientProcessID creates the process identifier used by the official RPC
// client. IPv4 is stored as a host-order integer; pure IPv6 uses zero because
// Telegram's packed process_id has no IPv6 field. Client ports are zero.
func ClientProcessID(clientAddr netip.AddrPort, processID int, uptime time.Time) (ProcessID, error) {
	if !clientAddr.IsValid() || clientAddr.Port() == 0 {
		return ProcessID{}, fmt.Errorf("%w: invalid client endpoint", ErrBootstrapState)
	}
	if processID <= 0 {
		return ProcessID{}, fmt.Errorf("%w: process ID must be positive", ErrBootstrapState)
	}
	pid := uint16(processID)
	if pid == 0 {
		return ProcessID{}, fmt.Errorf("%w: process ID truncates to zero", ErrBootstrapState)
	}
	unix := uptime.Unix()
	if unix <= 0 || unix > int64(^uint32(0)>>1) {
		return ProcessID{}, fmt.Errorf("%w: uptime is outside positive int32", ErrBootstrapState)
	}

	result := ProcessID{PID: pid, Uptime: int32(unix)}
	if address := clientAddr.Addr().Unmap(); address.Is4() {
		ipv4 := address.As4()
		result.IP = binary.BigEndian.Uint32(ipv4[:])
	}
	return result, nil
}

func validatePublicTuple(serverAddr, clientAddr netip.AddrPort) error {
	if err := validateAddressTuple(serverAddr, clientAddr); err != nil {
		return fmt.Errorf("%w: %v", ErrTupleNotAuthoritative, err)
	}
	if err := validatePublicEndpoint("server", serverAddr); err != nil {
		return err
	}
	if err := validatePublicEndpoint("client", clientAddr); err != nil {
		return err
	}
	return nil
}

func validatePublicEndpoint(label string, endpoint netip.AddrPort) error {
	address := endpoint.Addr().Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return fmt.Errorf("%w: %s endpoint is not public global-unicast", ErrTupleNotAuthoritative, label)
	}
	for _, prefix := range nonPublicAddressPrefixes {
		if prefix.Contains(address) {
			return fmt.Errorf("%w: %s endpoint uses non-public address space", ErrTupleNotAuthoritative, label)
		}
	}
	return nil
}

func tcpAddrPort(address net.Addr) (netip.AddrPort, error) {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok || tcpAddress == nil {
		return netip.AddrPort{}, fmt.Errorf("address has type %T, want *net.TCPAddr", address)
	}
	addrPort := tcpAddress.AddrPort()
	if !addrPort.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("invalid IP endpoint")
	}
	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), nil
}
