package middleend

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	socks5Version              = 0x05
	socks5CommandConnect       = 0x01
	socks5Reserved             = 0x00
	socks5AuthNone             = 0x00
	socks5AuthUsernamePassword = 0x02
	socks5AuthRejected         = 0xff
	socks5AuthVersion          = 0x01
	socks5AuthSuccess          = 0x00
	socks5ReplySuccess         = 0x00

	maximumSOCKS5NameLength       = 255
	minimumSOCKS5CredentialLength = 1
	maximumSOCKS5CredentialLength = 255
)

var (
	ErrSOCKS5Address        = errors.New("invalid SOCKS5 address")
	ErrSOCKS5Credentials    = errors.New("invalid SOCKS5 credentials")
	ErrSOCKS5Method         = errors.New("invalid SOCKS5 authentication method")
	ErrSOCKS5Authentication = errors.New("SOCKS5 authentication failed")
	ErrSOCKS5Reply          = errors.New("SOCKS5 CONNECT failed")
	ErrSOCKS5BoundAddress   = errors.New("SOCKS5 bound address is not an IP endpoint")
)

// SOCKS5AddressType is an RFC 1928 address type.
type SOCKS5AddressType uint8

const (
	SOCKS5AddressIPv4   SOCKS5AddressType = 0x01
	SOCKS5AddressDomain SOCKS5AddressType = 0x03
	SOCKS5AddressIPv6   SOCKS5AddressType = 0x04
)

// SOCKS5Credentials contains credentials for the RFC 1929 cleartext
// username/password subnegotiation. Both fields must contain 1..255 octets.
type SOCKS5Credentials struct {
	Username string
	Password string
}

// String prevents accidental credential disclosure through ordinary
// formatting.
func (SOCKS5Credentials) String() string {
	return "[redacted]"
}

// GoString prevents accidental credential disclosure through Go-syntax
// formatting.
func (SOCKS5Credentials) GoString() string {
	return "middleend.SOCKS5Credentials([redacted])"
}

// SOCKS5Address preserves the BND.ADDR and BND.PORT fields exactly as the
// SOCKS5 server reports them. IP is set for IPv4 and IPv6 addresses; Name is
// set for domain names.
type SOCKS5Address struct {
	Type SOCKS5AddressType
	IP   netip.Addr
	Name string
	Port uint16
}

// String formats the address without resolving a domain name.
func (a SOCKS5Address) String() string {
	host := a.Name
	if a.IP.IsValid() {
		host = a.IP.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(a.Port)))
}

// AddrPort returns the exact IP tuple without resolving or rewriting it. A
// domain BND.ADDR cannot be converted without losing that property. The caller
// must separately establish that the proxy-reported tuple is authoritative for
// the Middle-End KDF.
func (a SOCKS5Address) AddrPort() (netip.AddrPort, error) {
	validIPType := a.Type == SOCKS5AddressIPv4 && a.IP.Is4() || a.Type == SOCKS5AddressIPv6 && a.IP.Is6()
	if !validIPType {
		return netip.AddrPort{}, fmt.Errorf("%w: address type %d", ErrSOCKS5BoundAddress, a.Type)
	}
	return netip.AddrPortFrom(a.IP, a.Port), nil
}

// SOCKS5ReplyError reports an RFC 1928 CONNECT reply code. It never includes
// proxy credentials.
type SOCKS5ReplyError struct {
	Code byte
}

func (e *SOCKS5ReplyError) Error() string {
	return fmt.Sprintf("%s: %s", ErrSOCKS5Reply, socks5ReplyText(e.Code))
}

func (e *SOCKS5ReplyError) Unwrap() error {
	return ErrSOCKS5Reply
}

// SOCKS5Dialer performs the SOCKS5 handshake on a raw TCP connection. The
// successful result is a concrete *net.TCPConn that can be enrolled in gnet.
type SOCKS5Dialer struct {
	proxyAddress string
	credentials  *SOCKS5Credentials
	dialTCP      socks5TCPDialContextFunc
}

// String prevents accidental disclosure of the dialer's credentials through
// ordinary formatting.
func (SOCKS5Dialer) String() string {
	return "[redacted]"
}

// GoString prevents accidental disclosure of the dialer's credentials through
// Go-syntax formatting.
func (SOCKS5Dialer) GoString() string {
	return "middleend.SOCKS5Dialer([redacted])"
}

type socks5TCPDialContextFunc func(context.Context, string, string) (*net.TCPConn, error)

// NewSOCKS5Dialer validates a SOCKS5 proxy endpoint and optional RFC 1929
// credentials. The proxy address must use host:port syntax.
func NewSOCKS5Dialer(proxyAddress string, credentials *SOCKS5Credentials) (*SOCKS5Dialer, error) {
	if strings.Contains(proxyAddress, "@") {
		return nil, fmt.Errorf("proxy address: %w: credentials must be supplied through SOCKS5Credentials", ErrSOCKS5Address)
	}
	if _, err := encodeSOCKS5Address(proxyAddress); err != nil {
		return nil, fmt.Errorf("proxy address: %w", err)
	}
	if err := validateSOCKS5Credentials(credentials); err != nil {
		return nil, err
	}

	var storedCredentials *SOCKS5Credentials
	if credentials != nil {
		storedCredentials = new(SOCKS5Credentials{
			Username: credentials.Username,
			Password: credentials.Password,
		})
	}

	return &SOCKS5Dialer{
		proxyAddress: proxyAddress,
		credentials:  storedCredentials,
		dialTCP:      defaultSOCKS5TCPDialContext,
	}, nil
}

// DialContext opens a TCP connection to the configured proxy, performs an RFC
// 1928 CONNECT handshake, and returns the proxy's exact BND endpoint. The
// context governs both the TCP dial and every handshake read and write.
func (d *SOCKS5Dialer) DialContext(ctx context.Context, targetAddress string) (*net.TCPConn, SOCKS5Address, error) {
	var zero SOCKS5Address
	if ctx == nil {
		return nil, zero, errors.New("SOCKS5 DialContext: nil context")
	}
	if d == nil || d.dialTCP == nil {
		return nil, zero, errors.New("SOCKS5 DialContext: nil dialer")
	}
	target, err := encodeSOCKS5Address(targetAddress)
	if err != nil {
		return nil, zero, fmt.Errorf("target address: %w", err)
	}

	conn, err := d.dialTCP(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, zero, fmt.Errorf("dial SOCKS5 proxy: %w", err)
	}
	if conn == nil {
		return nil, zero, errors.New("dial SOCKS5 proxy: dialer returned a nil TCP connection")
	}

	succeeded := false
	defer func() {
		if !succeeded {
			_ = conn.Close()
		}
	}()

	// Context cancellation is the single authority for aborting the handshake.
	// Installing the same deadline on the socket creates two independent timers:
	// the socket timeout can win before context records its DeadlineExceeded
	// cause. Closing from AfterFunc also preserves any earlier socket deadline
	// installed by an injected dialer instead of overwriting it.
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})

	bound, err := negotiateSOCKS5(conn, target, d.credentials)
	causeAtCompletion := context.Cause(ctx)
	callbackStopped := stopCancel()
	if err != nil {
		return nil, zero, resolveSOCKS5HandshakeError(err, causeAtCompletion)
	}
	if causeAtCompletion != nil {
		return nil, zero, fmt.Errorf("SOCKS5 handshake canceled: %w", causeAtCompletion)
	}
	if !callbackStopped {
		return nil, zero, fmt.Errorf("SOCKS5 handshake canceled: %w", context.Cause(ctx))
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, zero, fmt.Errorf("SOCKS5 handshake canceled: %w", cause)
	}

	succeeded = true
	return conn, bound, nil
}

func resolveSOCKS5HandshakeError(err, contextCause error) error {
	if isSOCKS5ProtocolError(err) || contextCause == nil {
		return err
	}
	return fmt.Errorf("SOCKS5 handshake canceled: %w", contextCause)
}

func isSOCKS5ProtocolError(err error) bool {
	return errors.Is(err, ErrSOCKS5Method) ||
		errors.Is(err, ErrSOCKS5Authentication) ||
		errors.Is(err, ErrSOCKS5Reply)
}

func defaultSOCKS5TCPDialContext(ctx context.Context, network, address string) (*net.TCPConn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS5 transport has type %T, want *net.TCPConn", conn)
	}
	return tcpConn, nil
}

func validateSOCKS5Credentials(credentials *SOCKS5Credentials) error {
	if credentials == nil {
		return nil
	}
	usernameLength := len(credentials.Username)
	passwordLength := len(credentials.Password)
	if usernameLength < minimumSOCKS5CredentialLength || usernameLength > maximumSOCKS5CredentialLength {
		return fmt.Errorf("%w: username length is outside %d..%d octets", ErrSOCKS5Credentials, minimumSOCKS5CredentialLength, maximumSOCKS5CredentialLength)
	}
	if passwordLength < minimumSOCKS5CredentialLength || passwordLength > maximumSOCKS5CredentialLength {
		return fmt.Errorf("%w: password length is outside %d..%d octets", ErrSOCKS5Credentials, minimumSOCKS5CredentialLength, maximumSOCKS5CredentialLength)
	}
	return nil
}

func negotiateSOCKS5(conn io.ReadWriter, target []byte, credentials *SOCKS5Credentials) (SOCKS5Address, error) {
	var greeting []byte
	if credentials == nil {
		greeting = []byte{socks5Version, 1, socks5AuthNone}
	} else {
		greeting = []byte{socks5Version, 2, socks5AuthNone, socks5AuthUsernamePassword}
	}
	if err := writeAll(conn, greeting); err != nil {
		return SOCKS5Address{}, fmt.Errorf("write SOCKS5 method offer: %w", err)
	}

	var selection [2]byte
	if _, err := io.ReadFull(conn, selection[:]); err != nil {
		return SOCKS5Address{}, fmt.Errorf("read SOCKS5 method selection: %w", err)
	}
	if selection[0] != socks5Version {
		return SOCKS5Address{}, fmt.Errorf("%w: protocol version 0x%02x", ErrSOCKS5Method, selection[0])
	}
	switch selection[1] {
	case socks5AuthNone:
	case socks5AuthUsernamePassword:
		if credentials == nil {
			return SOCKS5Address{}, fmt.Errorf("%w: server selected an unoffered method 0x%02x", ErrSOCKS5Method, selection[1])
		}
		if err := authenticateSOCKS5(conn, credentials); err != nil {
			return SOCKS5Address{}, err
		}
	case socks5AuthRejected:
		return SOCKS5Address{}, fmt.Errorf("%w: server rejected all offered methods", ErrSOCKS5Method)
	default:
		return SOCKS5Address{}, fmt.Errorf("%w: server selected unsupported method 0x%02x", ErrSOCKS5Method, selection[1])
	}

	request := make([]byte, 0, 3+len(target))
	request = append(request, socks5Version, socks5CommandConnect, socks5Reserved)
	request = append(request, target...)
	if err := writeAll(conn, request); err != nil {
		return SOCKS5Address{}, fmt.Errorf("write SOCKS5 CONNECT request: %w", err)
	}

	bound, replyCode, err := readSOCKS5Reply(conn)
	if err != nil {
		return SOCKS5Address{}, err
	}
	if replyCode != socks5ReplySuccess {
		return SOCKS5Address{}, &SOCKS5ReplyError{Code: replyCode}
	}
	return bound, nil
}

func authenticateSOCKS5(conn io.ReadWriter, credentials *SOCKS5Credentials) error {
	request := make([]byte, 0, 3+len(credentials.Username)+len(credentials.Password))
	request = append(request, socks5AuthVersion, byte(len(credentials.Username)))
	request = append(request, credentials.Username...)
	request = append(request, byte(len(credentials.Password)))
	request = append(request, credentials.Password...)
	defer clear(request)

	if err := writeAll(conn, request); err != nil {
		return fmt.Errorf("write SOCKS5 authentication request: %w", err)
	}

	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return fmt.Errorf("read SOCKS5 authentication response: %w", err)
	}
	if response[0] != socks5AuthVersion {
		return fmt.Errorf("%w: protocol version 0x%02x", ErrSOCKS5Authentication, response[0])
	}
	if response[1] != socks5AuthSuccess {
		return fmt.Errorf("%w: server status 0x%02x", ErrSOCKS5Authentication, response[1])
	}
	return nil
}

func encodeSOCKS5Address(address string) ([]byte, error) {
	if strings.Contains(address, "@") {
		return nil, fmt.Errorf("%w: user information is not allowed", ErrSOCKS5Address)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%w: host and port syntax is required", ErrSOCKS5Address)
	}
	if host == "" {
		return nil, fmt.Errorf("%w: empty host", ErrSOCKS5Address)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("%w: port must be in 1..65535", ErrSOCKS5Address)
	}

	encoded := make([]byte, 0, 1+maximumSOCKS5NameLength+2)
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return nil, fmt.Errorf("%w: scoped IPv6 addresses cannot be represented", ErrSOCKS5Address)
		}
		if ip.Is4() {
			ipv4 := ip.As4()
			encoded = append(encoded, byte(SOCKS5AddressIPv4))
			encoded = append(encoded, ipv4[:]...)
		} else {
			ipv6 := ip.As16()
			encoded = append(encoded, byte(SOCKS5AddressIPv6))
			encoded = append(encoded, ipv6[:]...)
		}
	} else {
		if len(host) > maximumSOCKS5NameLength {
			return nil, fmt.Errorf("%w: domain name exceeds %d octets", ErrSOCKS5Address, maximumSOCKS5NameLength)
		}
		encoded = append(encoded, byte(SOCKS5AddressDomain), byte(len(host)))
		encoded = append(encoded, host...)
	}
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(port))
	return encoded, nil
}

func readSOCKS5Reply(reader io.Reader) (SOCKS5Address, byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return SOCKS5Address{}, 0, fmt.Errorf("read SOCKS5 CONNECT reply header: %w", err)
	}
	if header[0] != socks5Version {
		return SOCKS5Address{}, 0, fmt.Errorf("%w: reply protocol version 0x%02x", ErrSOCKS5Reply, header[0])
	}
	if header[2] != socks5Reserved {
		return SOCKS5Address{}, 0, fmt.Errorf("%w: reply reserved field is 0x%02x", ErrSOCKS5Reply, header[2])
	}

	addressType := SOCKS5AddressType(header[3])
	addressLength := 0
	switch addressType {
	case SOCKS5AddressIPv4:
		addressLength = net.IPv4len
	case SOCKS5AddressIPv6:
		addressLength = net.IPv6len
	case SOCKS5AddressDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return SOCKS5Address{}, 0, fmt.Errorf("read SOCKS5 bound domain length: %w", err)
		}
		if length[0] == 0 {
			return SOCKS5Address{}, 0, fmt.Errorf("%w: empty bound domain", ErrSOCKS5Reply)
		}
		addressLength = int(length[0])
	default:
		return SOCKS5Address{}, 0, fmt.Errorf("%w: unsupported bound address type 0x%02x", ErrSOCKS5Reply, header[3])
	}

	payload := make([]byte, addressLength+2)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return SOCKS5Address{}, 0, fmt.Errorf("read SOCKS5 bound address: %w", err)
	}

	bound := SOCKS5Address{
		Type: addressType,
		Port: binary.BigEndian.Uint16(payload[addressLength:]),
	}
	switch addressType {
	case SOCKS5AddressIPv4:
		var raw [4]byte
		copy(raw[:], payload[:addressLength])
		bound.IP = netip.AddrFrom4(raw)
	case SOCKS5AddressIPv6:
		var raw [16]byte
		copy(raw[:], payload[:addressLength])
		bound.IP = netip.AddrFrom16(raw)
	case SOCKS5AddressDomain:
		bound.Name = string(payload[:addressLength])
	}
	return bound, header[1], nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if written > 0 {
			data = data[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unassigned reply code 0x%02x", code)
	}
}
