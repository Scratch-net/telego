package tlsfront

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// CertificateCheck selects a TLS endpoint independently from its SNI hostname.
type CertificateCheck struct {
	Address       string
	ServerName    string
	ProxyProtocol int
	Roots         *x509.CertPool
}

// CertificateReport describes a certificate after normal TLS verification.
type CertificateReport struct {
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	Version   uint16
	CurveID   tls.CurveID
}

// doctorCurves offers X25519MLKEM768 first with classical fallbacks. The
// explicit list keeps the result independent from GODEBUG=tlsmlkem.
var doctorCurves = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}

// CheckCertificate verifies trust, hostname, validity, and server authentication.
// It does not use the runtime certificate cache or disable TLS verification.
func CheckCertificate(ctx context.Context, check CertificateCheck) (CertificateReport, error) {
	var report CertificateReport
	if check.ServerName == "" || check.ProxyProtocol < 0 || check.ProxyProtocol > 2 {
		return report, errors.New("invalid TLS certificate diagnostic target")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", check.Address)
	if err != nil {
		return report, fmt.Errorf("dial TLS endpoint: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return report, err
	}
	if check.ProxyProtocol != 0 {
		header, err := diagnosticProxyHeader(conn, check.ProxyProtocol)
		if err != nil {
			return report, err
		}
		if n, err := conn.Write(header); err != nil || n != len(header) {
			return report, fmt.Errorf("write diagnostic PROXY preface: %w", errors.Join(err, errors.New("incomplete preface")))
		}
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: check.ServerName, RootCAs: check.Roots, MinVersion: tls.VersionTLS12, CurvePreferences: doctorCurves,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return report, fmt.Errorf("verify TLS certificate: %w", err)
	}
	state := tlsConn.ConnectionState()
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return report, errors.New("TLS endpoint supplied no verified certificate")
	}
	leaf := state.PeerCertificates[0]
	return CertificateReport{
		Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(),
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Version: state.Version, CurveID: state.CurveID,
	}, nil
}

// LookupNetIPFunc has the signature of (*net.Resolver).LookupNetIP.
type LookupNetIPFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// CheckMaskHostAddress returns the A and AAAA records of host and reports
// whether one of them is publicIP.
func CheckMaskHostAddress(ctx context.Context, lookup LookupNetIPFunc, host string, publicIP netip.Addr) ([]netip.Addr, bool, error) {
	addrs, err := lookup(ctx, "ip", host)
	if err != nil {
		return nil, false, fmt.Errorf("resolve mask host: %w", err)
	}
	match := false
	for i, addr := range addrs {
		addrs[i] = addr.Unmap()
		match = match || addrs[i] == publicIP.Unmap()
	}
	return addrs, match, nil
}

func diagnosticProxyHeader(conn net.Conn, version int) ([]byte, error) {
	src, srcOK := conn.LocalAddr().(*net.TCPAddr)
	dst, dstOK := conn.RemoteAddr().(*net.TCPAddr)
	if !srcOK || !dstOK {
		return nil, errors.New("PROXY diagnostic requires TCP addresses")
	}
	family, srcIP, dstIP := byte(0x21), src.IP.To16(), dst.IP.To16()
	name := "TCP6"
	if src.IP.To4() != nil && dst.IP.To4() != nil {
		family, srcIP, dstIP, name = 0x11, src.IP.To4(), dst.IP.To4(), "TCP4"
	}
	if version == 1 {
		return fmt.Appendf(nil, "PROXY %s %s %s %d %d\r\n", name, srcIP, dstIP, src.Port, dst.Port), nil
	}
	header := []byte{'\r', '\n', '\r', '\n', 0, '\r', '\n', 'Q', 'U', 'I', 'T', '\n', 0x21, family, 0, 0}
	binary.BigEndian.PutUint16(header[14:16], uint16(2*len(srcIP)+4))
	header = append(header, srcIP...)
	header = append(header, dstIP...)
	header = binary.BigEndian.AppendUint16(header, uint16(src.Port))
	return binary.BigEndian.AppendUint16(header, uint16(dst.Port)), nil
}
