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
	"github.com/scratch-net/telego/pkg/dc"
	"github.com/scratch-net/telego/pkg/gproxy"
	"github.com/scratch-net/telego/pkg/log"
	"github.com/scratch-net/telego/pkg/tlsfront"
)

// DoctorCmd verifies the configured TLS fallback endpoints.
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
	bind := cfg.BindAddr
	if bind == "" {
		bind = defaultBindAddr
	}
	ipCtx, ipCancel := context.WithTimeout(context.Background(), c.Timeout)
	defer ipCancel()
	publicIP, source, ipErr := doctorPublicIP(ipCtx, file.MiddleEnd.NATIP, doctorDiscoverPublicIP)
	var own []netip.Addr
	if ipErr == nil {
		own = append(own, publicIP)
	}
	// Check for a loop before the TLS dial: a target that is telego itself
	// would splice the diagnostic connection back into telego again and again.
	for _, target := range fallbackTargets(&cfg) {
		addr, match, err := tlsfront.SelfTarget(ipCtx, net.DefaultResolver.LookupNetIP, tlsfront.LocalAddrs, target.host, target.port, bind, own...)
		if err != nil {
			log.Warn().Err(err).Str("scope", target.scope).Msg("Fallback loop check failed")
		} else if match {
			return fmt.Errorf("%s target %s resolves to %s, which is the telego listener %s; set %s to a different server",
				target.scope, net.JoinHostPort(target.host, strconv.Itoa(target.port)), addr, bind, target.option)
		}
	}
	domains := doctorDomains(&cfg)
	var errs []error
	for _, domain := range domains {
		if err := c.checkEndpoint(domain); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	doctorCheckDCs(cfg.Socks5Addr)
	if ipErr != nil {
		log.Info().Err(ipErr).Msg("Mask host DNS check skipped: the proxy public IP is unknown")
		return nil
	}
	for _, domain := range domains {
		ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
		addrs, match, err := tlsfront.CheckMaskHostAddress(ctx, net.DefaultResolver.LookupNetIP, domain.host, publicIP)
		cancel()
		if err != nil {
			log.Warn().Err(err).Str("mask_host", domain.host).Msg("Mask host DNS check failed")
		} else if !match {
			log.Warn().Str("mask_host", domain.host).Str("public_ip", publicIP.String()).Str("public_ip_source", source).
				Str("records", fmt.Sprint(addrs)).
				Msg("Mask host A/AAAA records do not include the proxy public IP; TSPU is reported to check this")
		}
	}
	return nil
}

// checkEndpoint verifies the probe fallback, or with --cert-source the
// certificate source, of one cover domain.
func (c *DoctorCmd) checkEndpoint(domain doctorDomain) error {
	host, port, proxyProtocol, scope := domain.spliceHost, domain.splicePort, domain.spliceProxyProtocol, "probe_fallback"
	if c.CertSource {
		host, port, proxyProtocol, scope = domain.certHost, domain.certPort, 0, "certificate_source"
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	report, err := tlsfront.CheckCertificate(ctx, tlsfront.CertificateCheck{
		Address: address, ServerName: domain.host, ProxyProtocol: proxyProtocol,
	})
	if err != nil {
		return fmt.Errorf("%s TLS endpoint %s (SNI %s): %w", scope, address, domain.host, err)
	}
	log.Info().Str("scope", scope).Str("address", address).Str("server_name", domain.host).
		Bool("verified", true).Str("subject", report.Subject).Str("issuer", report.Issuer).
		Time("not_before", report.NotBefore).Time("not_after", report.NotAfter).
		Msg("TLS endpoint certificate passed verification")
	if report.CurveID != tls.X25519MLKEM768 {
		log.Warn().Str("scope", scope).Str("address", address).Str("server_name", domain.host).
			Str("key_exchange", report.CurveID.String()).
			Msg("TLS endpoint does not negotiate X25519MLKEM768; TSPU is reported to block iOS clients for such mask hosts")
	}
	return nil
}

// doctorCheckDCs runs the MTProto check (req_pq_multi, resPQ) against every
// known DC address and warns for each DC without a passing address.
// It does not make the command fail.
func doctorCheckDCs(socks5 string) {
	if err := dc.SetProbeSocks5(socks5); err != nil {
		log.Warn().Err(err).Msg("DC check skipped: invalid SOCKS5 address")
		return
	}
	results := dc.Check()
	reachable := 0
	for _, result := range results {
		passed := false
		var errs []string
		for _, r := range result.Results {
			passed = passed || r.Success
			if !r.Success {
				errs = append(errs, r.Addr.Address+": "+r.Error)
			}
		}
		if !passed {
			log.Warn().Int("dc", result.DCID).Strs("errors", errs).
				Msg("No address of this DC answered the MTProto check; a middlebox may block or reset it")
		} else {
			reachable++
		}
	}
	log.Info().Int("reachable", reachable).Int("dcs", len(results)).Str("socks5", socks5).
		Msg("DC MTProto check finished")
}

// doctorDiscoverPublicIP is replaced in tests to avoid STUN traffic.
var doctorDiscoverPublicIP = getPublicIP

type fallbackTarget struct {
	scope, option, host string
	port                int
}

// doctorDomain is one cover domain with its resolved endpoints. option is
// the config table that sets them.
type doctorDomain struct {
	host, option                              string
	spliceHost, certHost                      string
	splicePort, spliceProxyProtocol, certPort int
}

// doctorDomains returns mask-host first, then each extra cover domain.
func doctorDomains(cfg *gproxy.Config) []doctorDomain {
	domains := []doctorDomain{{
		host: cfg.MaskHost, option: "tls-fronting",
		spliceHost: cfg.SpliceHost, splicePort: cfg.SplicePort, spliceProxyProtocol: cfg.SpliceProxyProtocol,
		certHost: cfg.CertHost, certPort: cfg.CertPort,
	}}
	for i, domain := range cfg.Domains {
		domains = append(domains, doctorDomain{
			host: domain.Host, option: fmt.Sprintf("tls-fronting.domains[%d]", i),
			spliceHost: domain.SpliceHost, splicePort: domain.SplicePort, spliceProxyProtocol: domain.SpliceProxyProtocol,
			certHost: domain.CertHost, certPort: domain.CertPort,
		})
	}
	return domains
}

// fallbackTargets returns the splice and certificate targets of every cover
// domain. A certificate target equal to its splice target is listed once.
func fallbackTargets(cfg *gproxy.Config) []fallbackTarget {
	var targets []fallbackTarget
	for _, domain := range doctorDomains(cfg) {
		targets = append(targets, fallbackTarget{"probe_fallback", domain.option + ".splice-host and splice-port", domain.spliceHost, domain.splicePort})
		if domain.certHost != domain.spliceHost || domain.certPort != domain.splicePort {
			targets = append(targets, fallbackTarget{"certificate_source", domain.option + ".cert-host and cert-port", domain.certHost, domain.certPort})
		}
	}
	return targets
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
