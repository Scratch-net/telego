package middleend

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSOCKS5DialContextEncodesTargetsAndPreservesBoundAddress(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		wantRequest string
		reply       string
		wantBound   SOCKS5Address
	}{
		{
			name:        "IPv4 target and bound address",
			target:      "192.0.2.10:443",
			wantRequest: "05010001c000020a01bb",
			reply:       "05000001c6336407d431",
			wantBound: SOCKS5Address{
				Type: SOCKS5AddressIPv4,
				IP:   netip.MustParseAddr("198.51.100.7"),
				Port: 54321,
			},
		},
		{
			name:        "IPv6 target and bound address",
			target:      "[2001:db8::5]:8443",
			wantRequest: "0501000420010db800000000000000000000000520fb",
			reply:       "0500000420010db8000000000000000000000009b822",
			wantBound: SOCKS5Address{
				Type: SOCKS5AddressIPv6,
				IP:   netip.MustParseAddr("2001:db8::9"),
				Port: 47138,
			},
		},
		{
			name:        "IPv4-mapped IPv6 stays IPv6",
			target:      "[::ffff:192.0.2.8]:80",
			wantRequest: "0501000400000000000000000000ffffc00002080050",
			reply:       "05000001000000000000",
			wantBound: SOCKS5Address{
				Type: SOCKS5AddressIPv4,
				IP:   netip.MustParseAddr("0.0.0.0"),
			},
		},
		{
			name:        "domain target and bound address",
			target:      "dc.example:443",
			wantRequest: "050100030a64632e6578616d706c6501bb",
			reply:       "050000030b626f756e642e6c6f63616cc000",
			wantBound: SOCKS5Address{
				Type: SOCKS5AddressDomain,
				Name: "bound.local",
				Port: 49152,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantRequest := mustDecodeSOCKS5Hex(t, tc.wantRequest)
			reply := mustDecodeSOCKS5Hex(t, tc.reply)
			marker := []byte("ME-NEXT")
			proxyAddress := startSOCKS5TCPServer(t, func(conn *net.TCPConn) {
				wantGreeting := []byte{socks5Version, 1, socks5AuthNone}
				gotGreeting := make([]byte, len(wantGreeting))
				if _, err := io.ReadFull(conn, gotGreeting); err != nil {
					t.Errorf("read greeting: %v", err)
					return
				}
				if !bytes.Equal(gotGreeting, wantGreeting) {
					t.Errorf("greeting = %x, want %x", gotGreeting, wantGreeting)
					return
				}
				writeBytesOneAtATime(t, conn, []byte{socks5Version, socks5AuthNone})

				gotRequest := make([]byte, len(wantRequest))
				if _, err := io.ReadFull(conn, gotRequest); err != nil {
					t.Errorf("read CONNECT request: %v", err)
					return
				}
				if !bytes.Equal(gotRequest, wantRequest) {
					t.Errorf("CONNECT request = %x, want %x", gotRequest, wantRequest)
					return
				}

				combined := append(bytes.Clone(reply), marker...)
				if err := writeAll(conn, combined); err != nil {
					t.Errorf("write reply and marker: %v", err)
				}
			})

			dialer, err := NewSOCKS5Dialer(proxyAddress, nil)
			if err != nil {
				t.Fatalf("NewSOCKS5Dialer: %v", err)
			}
			conn, bound, err := dialer.DialContext(t.Context(), tc.target)
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer conn.Close()
			if bound != tc.wantBound {
				t.Fatalf("bound address = %+v, want %+v", bound, tc.wantBound)
			}

			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			gotMarker := make([]byte, len(marker))
			if _, err := io.ReadFull(conn, gotMarker); err != nil {
				t.Fatalf("read post-reply marker: %v", err)
			}
			if !bytes.Equal(gotMarker, marker) {
				t.Fatalf("post-reply marker = %q, want %q", gotMarker, marker)
			}
		})
	}
}

func TestSOCKS5DialContextUsernamePassword(t *testing.T) {
	credentials := &SOCKS5Credentials{Username: "alice", Password: "test-password"}
	proxyAddress := startSOCKS5TCPServer(t, func(conn *net.TCPConn) {
		wantGreeting := []byte{socks5Version, 2, socks5AuthNone, socks5AuthUsernamePassword}
		gotGreeting := make([]byte, len(wantGreeting))
		if _, err := io.ReadFull(conn, gotGreeting); err != nil {
			t.Errorf("read greeting: %v", err)
			return
		}
		if !bytes.Equal(gotGreeting, wantGreeting) {
			t.Errorf("greeting = %x, want %x", gotGreeting, wantGreeting)
			return
		}
		if err := writeAll(conn, []byte{socks5Version, socks5AuthUsernamePassword}); err != nil {
			t.Errorf("write method: %v", err)
			return
		}

		wantAuth := append([]byte{socks5AuthVersion, byte(len("alice"))}, "alice"...)
		wantAuth = append(wantAuth, byte(len("test-password")))
		wantAuth = append(wantAuth, "test-password"...)
		gotAuth := make([]byte, len(wantAuth))
		if _, err := io.ReadFull(conn, gotAuth); err != nil {
			t.Errorf("read authentication: %v", err)
			return
		}
		if !bytes.Equal(gotAuth, wantAuth) {
			t.Error("authentication request differs from the RFC 1929 encoding")
			return
		}
		if err := writeAll(conn, []byte{socks5AuthVersion, socks5AuthSuccess}); err != nil {
			t.Errorf("write authentication response: %v", err)
			return
		}

		wantRequest := mustDecodeSOCKS5Hex(t, "050100030a64632e6578616d706c6501bb")
		gotRequest := make([]byte, len(wantRequest))
		if _, err := io.ReadFull(conn, gotRequest); err != nil {
			t.Errorf("read CONNECT request: %v", err)
			return
		}
		if !bytes.Equal(gotRequest, wantRequest) {
			t.Errorf("CONNECT request = %x, want %x", gotRequest, wantRequest)
			return
		}
		if err := writeAll(conn, mustDecodeSOCKS5Hex(t, "05000001cb0071093039")); err != nil {
			t.Errorf("write CONNECT reply: %v", err)
		}
	})

	dialer, err := NewSOCKS5Dialer(proxyAddress, credentials)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	credentials.Username = "mutated"
	credentials.Password = "mutated"

	conn, bound, err := dialer.DialContext(t.Context(), "dc.example:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	wantBound := SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("203.0.113.9"), Port: 12345}
	if bound != wantBound {
		t.Fatalf("bound = %+v, want %+v", bound, wantBound)
	}
}

func TestSOCKS5DialContextAllowsNoAuthWhenCredentialsOffered(t *testing.T) {
	proxyAddress := startSOCKS5TCPServer(t, func(conn *net.TCPConn) {
		greeting := make([]byte, 4)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			t.Errorf("read greeting: %v", err)
			return
		}
		if err := writeAll(conn, []byte{socks5Version, socks5AuthNone}); err != nil {
			t.Errorf("write method: %v", err)
			return
		}
		request := make([]byte, 10)
		if _, err := io.ReadFull(conn, request); err != nil {
			t.Errorf("read CONNECT request: %v", err)
			return
		}
		if err := writeAll(conn, mustDecodeSOCKS5Hex(t, "050000017f0000010438")); err != nil {
			t.Errorf("write CONNECT reply: %v", err)
		}
	})

	dialer, err := NewSOCKS5Dialer(proxyAddress, &SOCKS5Credentials{Username: "user", Password: "pass"})
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	conn, _, err := dialer.DialContext(t.Context(), "192.0.2.1:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	conn.Close()
}

func TestSOCKS5DialContextCancellationClosesHandshake(t *testing.T) {
	greetingRead := make(chan struct{})
	serverObservedClose := make(chan struct{})
	proxyAddress := startSOCKS5TCPServer(t, func(conn *net.TCPConn) {
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			t.Errorf("read greeting: %v", err)
			return
		}
		close(greetingRead)
		var one [1]byte
		if _, err := conn.Read(one[:]); err == nil {
			t.Error("server read succeeded after client cancellation")
		}
		close(serverObservedClose)
	})
	dialer, err := NewSOCKS5Dialer(proxyAddress, nil)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, _, err := dialer.DialContext(ctx, "192.0.2.1:443")
		result <- err
	}()
	select {
	case <-greetingRead:
	case <-time.After(time.Second):
		t.Fatal("server did not receive the SOCKS5 greeting")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialContext did not return after cancellation")
	}
	select {
	case <-serverObservedClose:
	case <-time.After(time.Second):
		t.Fatal("proxy did not observe the closed connection")
	}
}

func TestSOCKS5DialContextDeadlineClosesHandshake(t *testing.T) {
	greetingRead := make(chan struct{})
	serverObservedClose := make(chan struct{})
	proxyAddress := startSOCKS5TCPServer(t, func(conn *net.TCPConn) {
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			t.Errorf("read greeting: %v", err)
			return
		}
		close(greetingRead)
		var one [1]byte
		if _, err := conn.Read(one[:]); err == nil {
			t.Error("server read succeeded after client deadline")
		}
		close(serverObservedClose)
	})
	dialer, err := NewSOCKS5Dialer(proxyAddress, nil)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, _, err := dialer.DialContext(ctx, "192.0.2.1:443")
		result <- err
	}()
	select {
	case <-greetingRead:
	case <-time.After(time.Second):
		t.Fatal("server did not receive the SOCKS5 greeting")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("DialContext error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialContext did not return after its deadline")
	}
	select {
	case <-serverObservedClose:
	case <-time.After(time.Second):
		t.Fatal("proxy did not observe the closed connection")
	}
}

func TestSOCKS5DialContextDeadlineAlwaysReturnsContextCause(t *testing.T) {
	const attempts = 50
	dialer := newPreconnectedStallingSOCKS5Dialer(t, attempts)

	for attempt := range attempts {
		ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		_, _, err := dialer.DialContext(ctx, "192.0.2.1:443")
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("attempt %d: DialContext error = %v, want context.DeadlineExceeded", attempt, err)
		}
	}
}

func TestSOCKS5DialContextExplicitCancelAlwaysReturnsContextCause(t *testing.T) {
	const attempts = 100
	dialer := newPreconnectedStallingSOCKS5Dialer(t, attempts)

	for attempt := range attempts {
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() {
			_, _, err := dialer.DialContext(ctx, "192.0.2.1:443")
			result <- err
		}()
		// The injected connection is already established. Yielding allows the
		// handshake to enter its blocking method-selection read before cancel.
		runtime.Gosched()
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("attempt %d: DialContext error = %v, want context.Canceled", attempt, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("attempt %d: DialContext did not return after cancellation", attempt)
		}
	}
}

func TestSOCKS5DialContextPreservesIndependentSocketTimeout(t *testing.T) {
	proxyAddress := startStallingSOCKS5TCPServer(t, 1, nil)
	dialer, err := NewSOCKS5Dialer(proxyAddress, nil)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	defaultDialTCP := dialer.dialTCP
	dialer.dialTCP = func(ctx context.Context, network, address string) (*net.TCPConn, error) {
		conn, err := defaultDialTCP(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if err := conn.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, _, err = dialer.DialContext(ctx, "192.0.2.1:443")
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialContext masked independent socket timeout with context deadline: %v", err)
	}
	netErr, ok := errors.AsType[net.Error](err)
	if !ok || !netErr.Timeout() {
		t.Fatalf("DialContext error = %v, want independent net.Error timeout", err)
	}
}

func TestResolveSOCKS5HandshakeErrorPreservesProtocolErrors(t *testing.T) {
	protocolErrors := []error{
		fmt.Errorf("method: %w", ErrSOCKS5Method),
		fmt.Errorf("authentication: %w", ErrSOCKS5Authentication),
		fmt.Errorf("reply: %w", ErrSOCKS5Reply),
	}
	for _, protocolErr := range protocolErrors {
		got := resolveSOCKS5HandshakeError(protocolErr, context.DeadlineExceeded)
		if got != protocolErr {
			t.Errorf("resolveSOCKS5HandshakeError(%v) = %v, want original protocol error", protocolErr, got)
		}
	}

	got := resolveSOCKS5HandshakeError(io.ErrUnexpectedEOF, context.Canceled)
	if !errors.Is(got, context.Canceled) {
		t.Fatalf("transport error with cancellation = %v, want context.Canceled", got)
	}
	got = resolveSOCKS5HandshakeError(io.ErrUnexpectedEOF, nil)
	if !errors.Is(got, io.ErrUnexpectedEOF) {
		t.Fatalf("independent transport error = %v, want io.ErrUnexpectedEOF", got)
	}
}

func TestSOCKS5DialContextStopsCancellationAfterSuccess(t *testing.T) {
	proxyAddress := startSOCKS5TCPServer(t, func(conn *net.TCPConn) {
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			t.Errorf("read greeting: %v", err)
			return
		}
		if err := writeAll(conn, []byte{socks5Version, socks5AuthNone}); err != nil {
			t.Errorf("write method: %v", err)
			return
		}
		request := make([]byte, 10)
		if _, err := io.ReadFull(conn, request); err != nil {
			t.Errorf("read CONNECT request: %v", err)
			return
		}
		if err := writeAll(conn, mustDecodeSOCKS5Hex(t, "050000017f0000010438")); err != nil {
			t.Errorf("write CONNECT reply: %v", err)
			return
		}
		var ping [4]byte
		if _, err := io.ReadFull(conn, ping[:]); err != nil {
			t.Errorf("read post-handshake data: %v", err)
			return
		}
		if err := writeAll(conn, ping[:]); err != nil {
			t.Errorf("echo post-handshake data: %v", err)
		}
	})
	dialer, err := NewSOCKS5Dialer(proxyAddress, nil)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	conn, _, err := dialer.DialContext(ctx, "192.0.2.1:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	cancel()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write after context cancellation: %v", err)
	}
	var echo [4]byte
	if _, err := io.ReadFull(conn, echo[:]); err != nil {
		t.Fatalf("read after context cancellation: %v", err)
	}
	if string(echo[:]) != "ping" {
		t.Fatalf("echo = %q, want ping", echo[:])
	}
}

func TestSOCKS5DialContextClosesOnProtocolFailure(t *testing.T) {
	serverObservedClose := make(chan struct{})
	proxyAddress := startSOCKS5TCPServer(t, func(conn *net.TCPConn) {
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			t.Errorf("read greeting: %v", err)
			return
		}
		if err := writeAll(conn, []byte{0x04, socks5AuthNone}); err != nil {
			t.Errorf("write invalid method response: %v", err)
			return
		}
		var one [1]byte
		if _, err := conn.Read(one[:]); err == nil {
			t.Error("server read succeeded after protocol failure")
		}
		close(serverObservedClose)
	})
	dialer, err := NewSOCKS5Dialer(proxyAddress, nil)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	if _, _, err := dialer.DialContext(t.Context(), "192.0.2.1:443"); !errors.Is(err, ErrSOCKS5Method) {
		t.Fatalf("DialContext error = %v, want %v", err, ErrSOCKS5Method)
	}
	select {
	case <-serverObservedClose:
	case <-time.After(time.Second):
		t.Fatal("proxy did not observe the closed connection")
	}
}

func TestNewSOCKS5DialerRejectsInvalidConfiguration(t *testing.T) {
	invalidProxyAddresses := []string{
		"",
		"127.0.0.1",
		":1080",
		"127.0.0.1:0",
		"127.0.0.1:65536",
		"[fe80::1%eth0]:1080",
		strings.Repeat("a", 256) + ":1080",
		"SECRET_MARKER",
		"SECRET_MARKER@127.0.0.1:1080",
		"SECRET_MARKER:password@127.0.0.1:1080",
	}
	for _, address := range invalidProxyAddresses {
		_, err := NewSOCKS5Dialer(address, nil)
		if !errors.Is(err, ErrSOCKS5Address) {
			t.Errorf("NewSOCKS5Dialer(%q) error = %v, want %v", address, err, ErrSOCKS5Address)
		}
		if strings.Contains(err.Error(), "SECRET_MARKER") {
			t.Errorf("NewSOCKS5Dialer error exposed proxy input: %v", err)
		}
		if address != "" && strings.Contains(err.Error(), address) {
			t.Errorf("NewSOCKS5Dialer error exposed malformed proxy address: %v", err)
		}
		if strings.Contains(address, "@") && !strings.Contains(err.Error(), "SOCKS5Credentials") {
			t.Errorf("userinfo error lacks separate-credentials guidance: %v", err)
		}
	}

	invalidCredentials := []*SOCKS5Credentials{
		{Username: "", Password: "password"},
		{Username: "username", Password: ""},
		{Username: strings.Repeat("u", 256), Password: "password"},
		{Username: "username", Password: strings.Repeat("p", 256)},
	}
	for _, credentials := range invalidCredentials {
		_, err := NewSOCKS5Dialer("127.0.0.1:1080", credentials)
		if !errors.Is(err, ErrSOCKS5Credentials) {
			t.Errorf("NewSOCKS5Dialer invalid credential lengths error = %v, want %v", err, ErrSOCKS5Credentials)
		}
		containsUsername := credentials.Username != "" && strings.Contains(err.Error(), credentials.Username)
		containsPassword := credentials.Password != "" && strings.Contains(err.Error(), credentials.Password)
		if err != nil && (containsUsername || containsPassword) {
			t.Errorf("validation error contains credentials: %v", err)
		}
	}
}

func TestSOCKS5CredentialFormattingIsRedacted(t *testing.T) {
	credentials := SOCKS5Credentials{Username: "format-user", Password: "format-password"}
	dialer, err := NewSOCKS5Dialer("127.0.0.1:1080", &credentials)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}

	if got := fmt.Sprintf("%v %+v %#v", credentials, credentials, credentials); got != "[redacted] [redacted] middleend.SOCKS5Credentials([redacted])" {
		t.Fatalf("credential formatting = %q", got)
	}
	if got := fmt.Sprintf("%v %+v %#v", dialer, dialer, dialer); got != "[redacted] [redacted] middleend.SOCKS5Dialer([redacted])" {
		t.Fatalf("dialer formatting = %q", got)
	}
	if got := fmt.Sprintf("%v %+v %#v", *dialer, *dialer, *dialer); got != "[redacted] [redacted] middleend.SOCKS5Dialer([redacted])" {
		t.Fatalf("dereferenced dialer formatting = %q", got)
	}
	var nilDialer *SOCKS5Dialer
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, nilDialer); strings.Contains(got, credentials.Username) || strings.Contains(got, credentials.Password) {
			t.Errorf("nil dialer format %q exposes credentials: %s", format, got)
		}
	}

	enclosing := struct {
		Credentials SOCKS5Credentials
		Dialer      *SOCKS5Dialer
	}{
		Credentials: credentials,
		Dialer:      dialer,
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		formatted := fmt.Sprintf(format, enclosing)
		if strings.Contains(formatted, credentials.Username) || strings.Contains(formatted, credentials.Password) {
			t.Errorf("enclosing format %q exposes credentials: %s", format, formatted)
		}
	}
}

func TestSOCKS5DialContextValidatesTargetBeforeDial(t *testing.T) {
	dialer, err := NewSOCKS5Dialer("127.0.0.1:1080", nil)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	dialCalled := false
	dialer.dialTCP = func(context.Context, string, string) (*net.TCPConn, error) {
		dialCalled = true
		return nil, errors.New("unexpected dial")
	}

	invalidTargets := []string{
		"",
		"192.0.2.1",
		":443",
		"192.0.2.1:0",
		"192.0.2.1:not-a-port",
		"[fe80::1%eth0]:443",
		strings.Repeat("a", 256) + ":443",
		"SECRET_MARKER",
		"SECRET_MARKER:password@192.0.2.1:443",
	}
	for _, target := range invalidTargets {
		_, _, err := dialer.DialContext(t.Context(), target)
		if !errors.Is(err, ErrSOCKS5Address) {
			t.Errorf("DialContext(%q) error = %v, want %v", target, err, ErrSOCKS5Address)
		}
		if strings.Contains(err.Error(), "SECRET_MARKER") {
			t.Errorf("DialContext error exposed target input: %v", err)
		}
		if target != "" && strings.Contains(err.Error(), target) {
			t.Errorf("DialContext error exposed malformed target address: %v", err)
		}
	}
	if dialCalled {
		t.Fatal("dial function called for an invalid target")
	}
	if _, _, err := dialer.DialContext(nil, "192.0.2.1:443"); err == nil {
		t.Fatal("DialContext(nil) succeeded")
	}
}

func TestReadSOCKS5ReplyStrictValidationAndNoReadAhead(t *testing.T) {
	tests := []struct {
		name      string
		wire      string
		wantBound SOCKS5Address
		wantCode  byte
		wantErr   error
	}{
		{
			name: "IPv4",
			wire: "05000001c6336401ffffaabb",
			wantBound: SOCKS5Address{
				Type: SOCKS5AddressIPv4,
				IP:   netip.MustParseAddr("198.51.100.1"),
				Port: 65535,
			},
		},
		{
			name: "IPv6",
			wire: "0500000420010db800000000000000000000000101bbaabb",
			wantBound: SOCKS5Address{
				Type: SOCKS5AddressIPv6,
				IP:   netip.MustParseAddr("2001:db8::1"),
				Port: 443,
			},
		},
		{
			name: "domain",
			wire: "0500000303782e790438aabb",
			wantBound: SOCKS5Address{
				Type: SOCKS5AddressDomain,
				Name: "x.y",
				Port: 1080,
			},
		},
		{
			name: "failure code is returned after endpoint",
			wire: "05050001000000000000aabb",
			wantBound: SOCKS5Address{
				Type: SOCKS5AddressIPv4,
				IP:   netip.MustParseAddr("0.0.0.0"),
			},
			wantCode: 0x05,
		},
		{name: "wrong version", wire: "04000001000000000000", wantErr: ErrSOCKS5Reply},
		{name: "nonzero reserved", wire: "05000101000000000000", wantErr: ErrSOCKS5Reply},
		{name: "unsupported address type", wire: "05000002000000000000", wantErr: ErrSOCKS5Reply},
		{name: "empty domain", wire: "05000003000000", wantErr: ErrSOCKS5Reply},
		{name: "truncated header", wire: "050000", wantErr: io.ErrUnexpectedEOF},
		{name: "truncated IPv4", wire: "05000001c00002", wantErr: io.ErrUnexpectedEOF},
		{name: "truncated IPv6", wire: "0500000420010db8", wantErr: io.ErrUnexpectedEOF},
		{name: "truncated domain", wire: "0500000303782e", wantErr: io.ErrUnexpectedEOF},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wire := mustDecodeSOCKS5Hex(t, tc.wire)
			reader := bytes.NewReader(wire)
			bound, code, err := readSOCKS5Reply(reader)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("readSOCKS5Reply error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readSOCKS5Reply: %v", err)
			}
			if bound != tc.wantBound {
				t.Fatalf("bound = %+v, want %+v", bound, tc.wantBound)
			}
			if code != tc.wantCode {
				t.Fatalf("reply code = 0x%02x, want 0x%02x", code, tc.wantCode)
			}
			if reader.Len() != 2 {
				t.Fatalf("parser consumed bytes after the reply: remaining = %d, want 2", reader.Len())
			}
		})
	}
}

func TestSOCKS5ReplyErrorMapping(t *testing.T) {
	wantText := map[byte]string{
		0x01: "general server failure",
		0x02: "connection not allowed by ruleset",
		0x03: "network unreachable",
		0x04: "host unreachable",
		0x05: "connection refused",
		0x06: "TTL expired",
		0x07: "command not supported",
		0x08: "address type not supported",
		0x09: "unassigned reply code 0x09",
	}
	for code, text := range wantText {
		err := &SOCKS5ReplyError{Code: code}
		if !errors.Is(err, ErrSOCKS5Reply) {
			t.Errorf("reply 0x%02x does not wrap %v", code, ErrSOCKS5Reply)
		}
		if !strings.Contains(err.Error(), text) {
			t.Errorf("reply 0x%02x error = %q, want text %q", code, err, text)
		}
		matched, ok := errors.AsType[*SOCKS5ReplyError](err)
		if !ok || matched.Code != code {
			t.Errorf("reply 0x%02x typed error = %+v, %v", code, matched, ok)
		}
	}
}

func TestSOCKS5AuthenticationErrorsDoNotExposeCredentials(t *testing.T) {
	credentials := &SOCKS5Credentials{Username: "private-user", Password: "private-password"}
	tests := []struct {
		name     string
		response []byte
	}{
		{name: "wrong version", response: []byte{socks5Version, socks5AuthUsernamePassword, 0x02, 0x00}},
		{name: "rejected", response: []byte{socks5Version, socks5AuthUsernamePassword, socks5AuthVersion, 0x01}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rw := &recordingReadWriter{Reader: bytes.NewReader(tc.response)}
			_, err := negotiateSOCKS5(rw, []byte{byte(SOCKS5AddressIPv4), 192, 0, 2, 1, 1, 187}, credentials)
			if !errors.Is(err, ErrSOCKS5Authentication) {
				t.Fatalf("negotiateSOCKS5 error = %v, want %v", err, ErrSOCKS5Authentication)
			}
			if strings.Contains(err.Error(), credentials.Username) || strings.Contains(err.Error(), credentials.Password) {
				t.Fatalf("authentication error exposes credentials: %v", err)
			}
		})
	}
}

func TestSOCKS5RejectsUnofferedAndUnsupportedMethods(t *testing.T) {
	tests := []struct {
		name        string
		selection   byte
		credentials *SOCKS5Credentials
	}{
		{name: "username password not offered", selection: socks5AuthUsernamePassword},
		{name: "no acceptable methods", selection: socks5AuthRejected},
		{name: "unsupported method", selection: 0x01},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rw := &recordingReadWriter{Reader: bytes.NewReader([]byte{socks5Version, tc.selection})}
			_, err := negotiateSOCKS5(rw, []byte{byte(SOCKS5AddressIPv4), 192, 0, 2, 1, 1, 187}, tc.credentials)
			if !errors.Is(err, ErrSOCKS5Method) {
				t.Fatalf("negotiateSOCKS5 error = %v, want %v", err, ErrSOCKS5Method)
			}
		})
	}
}

func TestSOCKS5AddressAddrPort(t *testing.T) {
	ipv4 := SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("198.51.100.4"), Port: 4321}
	got, err := ipv4.AddrPort()
	if err != nil {
		t.Fatalf("IPv4 AddrPort: %v", err)
	}
	if want := netip.MustParseAddrPort("198.51.100.4:4321"); got != want {
		t.Fatalf("IPv4 AddrPort = %v, want %v", got, want)
	}
	if ipv4.String() != "198.51.100.4:4321" {
		t.Fatalf("IPv4 String = %q", ipv4.String())
	}

	domain := SOCKS5Address{Type: SOCKS5AddressDomain, Name: "bound.example", Port: 443}
	if _, err := domain.AddrPort(); !errors.Is(err, ErrSOCKS5BoundAddress) {
		t.Fatalf("domain AddrPort error = %v, want %v", err, ErrSOCKS5BoundAddress)
	}
	if domain.String() != "bound.example:443" {
		t.Fatalf("domain String = %q", domain.String())
	}

	mismatched := SOCKS5Address{Type: SOCKS5AddressIPv4, IP: netip.MustParseAddr("2001:db8::1"), Port: 443}
	if _, err := mismatched.AddrPort(); !errors.Is(err, ErrSOCKS5BoundAddress) {
		t.Fatalf("mismatched AddrPort error = %v, want %v", err, ErrSOCKS5BoundAddress)
	}
}

func TestWriteAllHandlesShortWrites(t *testing.T) {
	writer := new(oneByteWriter)
	if err := writeAll(writer, []byte("short writes")); err != nil {
		t.Fatalf("writeAll: %v", err)
	}
	if writer.String() != "short writes" {
		t.Fatalf("written data = %q", writer.String())
	}
	if err := writeAll(zeroWriter{}, []byte("x")); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("zero-progress error = %v, want %v", err, io.ErrNoProgress)
	}
}

func FuzzReadSOCKS5Reply(f *testing.F) {
	f.Add(mustDecodeSOCKS5Hex(f, "05000001c633640101bb"))
	f.Add(mustDecodeSOCKS5Hex(f, "0500000420010db800000000000000000000000101bb"))
	f.Add(mustDecodeSOCKS5Hex(f, "0500000303782e7901bb"))
	f.Add([]byte{0x05, 0x00, 0x00, 0x03, 0x00})

	f.Fuzz(func(t *testing.T, wire []byte) {
		_, _, _ = readSOCKS5Reply(bytes.NewReader(wire))
	})
}

type recordingReadWriter struct {
	Reader io.Reader
	writes bytes.Buffer
}

func (rw *recordingReadWriter) Read(data []byte) (int, error) {
	return rw.Reader.Read(data)
}

func (rw *recordingReadWriter) Write(data []byte) (int, error) {
	return rw.writes.Write(data)
}

type oneByteWriter struct {
	bytes.Buffer
}

func (w *oneByteWriter) Write(data []byte) (int, error) {
	if len(data) > 1 {
		data = data[:1]
	}
	return w.Buffer.Write(data)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) {
	return 0, nil
}

func startSOCKS5TCPServer(t *testing.T, handler func(*net.TCPConn)) string {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.AcceptTCP()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("AcceptTCP: %v", err)
			}
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Errorf("server SetDeadline: %v", err)
			return
		}
		handler(conn)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return listener.Addr().String()
}

func startStallingSOCKS5TCPServer(t *testing.T, attempts int, greetingRead chan<- struct{}) string {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for attempt := range attempts {
			conn, err := listener.AcceptTCP()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("attempt %d: AcceptTCP: %v", attempt, err)
				}
				return
			}
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Errorf("attempt %d: server SetDeadline: %v", attempt, err)
				conn.Close()
				return
			}
			var greeting [3]byte
			if _, err := io.ReadFull(conn, greeting[:]); err != nil {
				t.Errorf("attempt %d: read greeting: %v", attempt, err)
				conn.Close()
				return
			}
			if greetingRead != nil {
				greetingRead <- struct{}{}
			}
			var one [1]byte
			if _, err := conn.Read(one[:]); err == nil {
				t.Errorf("attempt %d: server read succeeded while handshake should be stalled", attempt)
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return listener.Addr().String()
}

func newPreconnectedStallingSOCKS5Dialer(t *testing.T, attempts int) *SOCKS5Dialer {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	clients := make([]*net.TCPConn, 0, attempts)
	servers := make([]*net.TCPConn, 0, attempts)
	for range attempts {
		client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatalf("DialTCP: %v", err)
		}
		server, err := listener.AcceptTCP()
		if err != nil {
			client.Close()
			t.Fatalf("AcceptTCP: %v", err)
		}
		clients = append(clients, client)
		servers = append(servers, server)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("listener Close: %v", err)
	}
	t.Cleanup(func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
		for _, conn := range servers {
			_ = conn.Close()
		}
	})

	dialer, err := NewSOCKS5Dialer("127.0.0.1:1080", nil)
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	next := 0
	dialer.dialTCP = func(context.Context, string, string) (*net.TCPConn, error) {
		if next >= len(clients) {
			return nil, errors.New("preconnected SOCKS5 test dialer exhausted")
		}
		conn := clients[next]
		next++
		return conn, nil
	}
	return dialer
}

func writeBytesOneAtATime(t *testing.T, writer io.Writer, data []byte) {
	t.Helper()
	for _, value := range data {
		if err := writeAll(writer, []byte{value}); err != nil {
			t.Errorf("write byte: %v", err)
			return
		}
	}
}

func mustDecodeSOCKS5Hex(tb testing.TB, value string) []byte {
	tb.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		tb.Fatalf("decode hex: %v", err)
	}
	return decoded
}
