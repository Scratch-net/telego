package tlsfront

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCheckCertificateVerification(t *testing.T) {
	for _, tc := range []struct {
		name          string
		host          string
		trust         bool
		before, after time.Duration
		valid         bool
	}{
		{name: "valid", host: "test.example.com", trust: true, before: -time.Hour, after: time.Hour, valid: true},
		{name: "hostname mismatch", host: "wrong.example.com", trust: true, before: -time.Hour, after: time.Hour},
		{name: "unknown authority", host: "test.example.com", before: -time.Hour, after: time.Hour},
		{name: "expired", host: "test.example.com", trust: true, before: -2 * time.Hour, after: -time.Hour},
		{name: "future", host: "test.example.com", trust: true, before: time.Hour, after: 2 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := generateTestCert(time.Now().Add(tc.before), time.Now().Add(tc.after))
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if tc.trust {
				roots.AddCert(leaf)
			}
			port, closeServer := startTestTLSServer(t, cert)
			defer closeServer()
			report, err := CheckCertificate(t.Context(), CertificateCheck{Address: fmt.Sprintf("127.0.0.1:%d", port), ServerName: tc.host, Roots: roots})
			if (err == nil) != tc.valid {
				t.Fatalf("report=%+v error=%v", report, err)
			}
			if tc.valid && (!report.NotAfter.Equal(leaf.NotAfter) || report.Subject != leaf.Subject.String()) {
				t.Fatal("certificate metadata changed")
			}
		})
	}
}

func TestCheckCertificateDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(io.Discard, conn)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	_, err = CheckCertificate(ctx, CertificateCheck{Address: listener.Addr().String(), ServerName: "test.example.com"})
	if err == nil {
		t.Fatal("stalled TLS handshake passed")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("diagnostic connection did not close")
	}
}

func TestCheckCertificateProxyProtocol(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			cert, err := generateTestCert(time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				var prefix []byte
				if version == 1 {
					for len(prefix) < 108 {
						var b [1]byte
						if _, err = io.ReadFull(conn, b[:]); err != nil {
							done <- err
							return
						}
						prefix = append(prefix, b[0])
						if b[0] == '\n' {
							break
						}
					}
					src, dst := conn.RemoteAddr().(*net.TCPAddr), conn.LocalAddr().(*net.TCPAddr)
					want := fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", src.IP, dst.IP, src.Port, dst.Port)
					if string(prefix) != want {
						done <- fmt.Errorf("unexpected v1 preface %q", prefix)
						return
					}
				} else {
					prefix = make([]byte, 16)
					if _, err = io.ReadFull(conn, prefix); err != nil {
						done <- err
						return
					}
					if !bytes.Equal(prefix[:12], []byte("\r\n\r\n\x00\r\nQUIT\n")) || prefix[12] != 0x21 || prefix[13] != 0x11 || binary.BigEndian.Uint16(prefix[14:]) != 12 {
						done <- fmt.Errorf("invalid v2 preface %x", prefix)
						return
					}
					body := make([]byte, 12)
					if _, err = io.ReadFull(conn, body); err != nil {
						done <- err
						return
					}
				}
				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				done <- tlsConn.Handshake()
			}()
			_, err = CheckCertificate(t.Context(), CertificateCheck{Address: listener.Addr().String(), ServerName: "test.example.com", Roots: roots, ProxyProtocol: version})
			if err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil && !strings.Contains(err.Error(), "closed") {
				t.Fatal(err)
			}
		})
	}
}

func TestCheckCertificateKeyExchange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		curves []tls.CurveID
		want   tls.CurveID
	}{
		{name: "post-quantum", curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, want: tls.X25519MLKEM768},
		{name: "classical", curves: []tls.CurveID{tls.X25519}, want: tls.X25519},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.NotFoundHandler())
			server.TLS = &tls.Config{CurvePreferences: tc.curves}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			report, err := CheckCertificate(t.Context(), CertificateCheck{
				Address: server.Listener.Addr().String(), ServerName: "example.com", Roots: roots,
			})
			if err != nil {
				t.Fatal(err)
			}
			if report.CurveID != tc.want {
				t.Fatalf("key exchange %v, want %v", report.CurveID, tc.want)
			}
		})
	}
}

func TestCheckMaskHostAddress(t *testing.T) {
	public := netip.MustParseAddr("203.0.113.7")
	for _, tc := range []struct {
		name    string
		records []string
		match   bool
	}{
		{name: "match", records: []string{"2001:db8::1", "203.0.113.7"}, match: true},
		{name: "mapped", records: []string{"::ffff:203.0.113.7"}, match: true},
		{name: "mismatch", records: []string{"198.51.100.1", "2001:db8::1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(_ context.Context, network, host string) ([]netip.Addr, error) {
				if network != "ip" || host != "mask.example.com" {
					t.Fatalf("lookup %s %s", network, host)
				}
				var addrs []netip.Addr
				for _, record := range tc.records {
					addrs = append(addrs, netip.MustParseAddr(record))
				}
				return addrs, nil
			}
			addrs, match, err := CheckMaskHostAddress(t.Context(), lookup, "mask.example.com", public)
			if err != nil || match != tc.match || len(addrs) != len(tc.records) {
				t.Fatalf("addrs=%v match=%v err=%v", addrs, match, err)
			}
		})
	}
	lookupErr := errors.New("no such host")
	failing := func(context.Context, string, string) ([]netip.Addr, error) { return nil, lookupErr }
	if _, _, err := CheckMaskHostAddress(t.Context(), failing, "mask.example.com", public); !errors.Is(err, lookupErr) {
		t.Fatal(err)
	}
}

func TestSelfTarget(t *testing.T) {
	records := map[string][]string{
		"mask.example.com":  {"203.0.113.7"},
		"other.example.com": {"198.51.100.1"},
		"localhost":         {"127.0.0.1", "::1"},
		"bind.example.com":  {"192.0.2.10"},
		"self.example.com":  {"192.0.2.10"},
	}
	lookup := func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" {
			t.Fatalf("lookup network %s", network)
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{addr}, nil
		}
		values, ok := records[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var addrs []netip.Addr
		for _, value := range values {
			addrs = append(addrs, netip.MustParseAddr(value))
		}
		return addrs, nil
	}
	local := func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"), netip.MustParseAddr("10.0.0.5")}, nil
	}
	public := netip.MustParseAddr("203.0.113.7")
	for _, tc := range []struct {
		name string
		host string
		port int
		bind string
		own  []netip.Addr
		want string
	}{
		{name: "public IP on bind port", host: "mask.example.com", port: 443, bind: "0.0.0.0:443", own: []netip.Addr{public}, want: "203.0.113.7"},
		{name: "public IP on other port", host: "mask.example.com", port: 8443, bind: "0.0.0.0:443", own: []netip.Addr{public}},
		{name: "public IP unknown", host: "mask.example.com", port: 443, bind: "0.0.0.0:443"},
		{name: "loopback with wildcard bind", host: "localhost", port: 443, bind: ":443", want: "127.0.0.1"},
		{name: "interface address with tcp prefix", host: "10.0.0.5", port: 443, bind: "tcp://[::]:443", want: "10.0.0.5"},
		{name: "loopback with specific bind", host: "127.0.0.1", port: 443, bind: "10.0.0.5:443"},
		{name: "bind host name", host: "self.example.com", port: 443, bind: "bind.example.com:443", want: "192.0.2.10"},
		{name: "remote host", host: "other.example.com", port: 443, bind: "0.0.0.0:443", own: []netip.Addr{public}},
		{name: "unix socket", host: "127.0.0.1", port: 443, bind: "unix:///run/telego.sock"},
		{name: "unix path", host: "127.0.0.1", port: 443, bind: "/run/telego.sock"},
		{name: "invalid own address", host: "other.example.com", port: 443, bind: "10.0.0.5:443", own: []netip.Addr{{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, match, err := SelfTarget(t.Context(), lookup, local, tc.host, tc.port, tc.bind, tc.own...)
			if err != nil {
				t.Fatal(err)
			}
			if match != (tc.want != "") || (match && addr.String() != tc.want) {
				t.Fatalf("addr=%v match=%v, want %q", addr, match, tc.want)
			}
		})
	}
	if _, _, err := SelfTarget(t.Context(), lookup, local, "missing.example.com", 443, "0.0.0.0:443"); err == nil {
		t.Fatal("unresolved target did not fail")
	}
	if _, _, err := SelfTarget(t.Context(), lookup, local, "127.0.0.1", 443, "443"); err == nil {
		t.Fatal("invalid bind address did not fail")
	}
}
