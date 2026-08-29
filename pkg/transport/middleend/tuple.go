package middleend

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
)

var sharedIPv4Prefix = netip.MustParsePrefix("100.64.0.0/10")

// DirectAddressTuple validates that an established direct TCP connection has
// a public, exact endpoint tuple suitable for Telegram's address-bound KDF.
func DirectAddressTuple(conn *net.TCPConn, selectedServer netip.AddrPort) (netip.AddrPort, netip.AddrPort, error) {
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
	if err := validatePublicTuple(serverAddr, clientAddr); err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("direct TCP tuple: %w", err)
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
	if address.Is4() && sharedIPv4Prefix.Contains(address) {
		return fmt.Errorf("%w: %s endpoint uses shared address space", ErrTupleNotAuthoritative, label)
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
