package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/scratch-net/telego/pkg/config"
	"github.com/scratch-net/telego/pkg/log"
	"github.com/scratch-net/telego/pkg/tlsfront"
)

// DoctorCmd verifies the configured TLS fallback endpoint.
type DoctorCmd struct {
	Config     string        `short:"c" help:"Path to config file" type:"existingfile" required:""`
	Timeout    time.Duration `help:"TLS diagnostic timeout (maximum 30s)" default:"10s"`
	CertSource bool          `help:"Verify the certificate source instead of the probe fallback endpoint"`
}

func (c *DoctorCmd) Run() error {
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		return errors.New("doctor timeout must be greater than zero and at most 30s")
	}
	file, err := config.Load(c.Config)
	if err != nil {
		return err
	}
	cfg, err := file.ToGProxyConfig()
	if err != nil {
		return err
	}
	host, port, proxyProtocol, scope := cfg.SpliceHost, cfg.SplicePort, cfg.SpliceProxyProtocol, "probe_fallback"
	if c.CertSource {
		host, port, proxyProtocol, scope = cfg.CertHost, cfg.CertPort, 0, "certificate_source"
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	report, err := tlsfront.CheckCertificate(ctx, tlsfront.CertificateCheck{
		Address: address, ServerName: cfg.MaskHost, ProxyProtocol: proxyProtocol,
	})
	if err != nil {
		return fmt.Errorf("%s TLS endpoint %s (SNI %s): %w", scope, address, cfg.MaskHost, err)
	}
	log.Info().Str("scope", scope).Str("address", address).Str("server_name", cfg.MaskHost).
		Bool("verified", true).Str("subject", report.Subject).Str("issuer", report.Issuer).
		Time("not_before", report.NotBefore).Time("not_after", report.NotAfter).
		Msg("TLS endpoint certificate passed verification")
	if report.CurveID != tls.X25519MLKEM768 {
		log.Warn().Str("scope", scope).Str("address", address).Str("server_name", cfg.MaskHost).
			Str("key_exchange", report.CurveID.String()).
			Msg("TLS endpoint does not negotiate X25519MLKEM768; TSPU is reported to block iOS clients for such mask hosts")
	}
	ctx, cancel = context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	publicIP, source, err := doctorPublicIP(ctx, file.MiddleEnd.NATIP, getPublicIP)
	if err != nil {
		log.Info().Err(err).Msg("Mask host DNS check skipped: the proxy public IP is unknown")
		return nil
	}
	addrs, match, err := tlsfront.CheckMaskHostAddress(ctx, net.DefaultResolver.LookupNetIP, cfg.MaskHost, publicIP)
	if err != nil {
		log.Warn().Err(err).Str("mask_host", cfg.MaskHost).Msg("Mask host DNS check failed")
	} else if !match {
		log.Warn().Str("mask_host", cfg.MaskHost).Str("public_ip", publicIP.String()).Str("public_ip_source", source).
			Str("records", fmt.Sprint(addrs)).
			Msg("Mask host A/AAAA records do not include the proxy public IP; TSPU is reported to check this")
	}
	return nil
}

// doctorPublicIP uses middle-end.nat-ip when it is set. Otherwise it uses the
// STUN lookup of --link and stops waiting when ctx ends.
func doctorPublicIP(ctx context.Context, natIP string, discover func() (string, error)) (netip.Addr, string, error) {
	if natIP = strings.TrimSpace(natIP); natIP != "" {
		ip, err := netip.ParseAddr(natIP)
		return ip, "middle-end.nat-ip", err
	}
	type result struct {
		ip  string
		err error
	}
	done := make(chan result, 1)
	go func() {
		ip, err := discover()
		done <- result{ip, err}
	}()
	select {
	case <-ctx.Done():
		return netip.Addr{}, "stun", ctx.Err()
	case r := <-done:
		if r.err != nil {
			return netip.Addr{}, "stun", r.err
		}
		ip, err := netip.ParseAddr(r.ip)
		return ip, "stun", err
	}
}
