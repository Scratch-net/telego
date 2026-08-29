// Command meprobe validates one complete Telegram Middle-End link and one
// ping/pong exchange. It is a diagnostic and does not start a proxy listener.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

const (
	defaultArtifactTimeout = 15 * time.Second
	defaultLinkTimeout     = 3 * time.Second

	socksUsernameEnvironment = "TELEGO_MEPROBE_SOCKS_USERNAME"
	socksPasswordEnvironment = "TELEGO_MEPROBE_SOCKS_PASSWORD"
)

type options struct {
	dc              string
	family          string
	endpointIndex   int
	socksAddress    string
	httpProxy       string
	artifactTimeout time.Duration
	linkTimeout     time.Duration
}

func (options) String() string {
	return "meprobe.options{redacted}"
}

func (options) GoString() string {
	return "meprobe.options{redacted}"
}

type validatedOptions struct {
	dc            *middleend.DCID
	family        middleend.AddressFamily
	httpProxy     *url.URL
	socksDialer   *middleend.SOCKS5Dialer
	endpointIndex int
}

func (validatedOptions) String() string {
	return "meprobe.validatedOptions{redacted}"
}

func (validatedOptions) GoString() string {
	return "meprobe.validatedOptions{redacted}"
}

type runtimeDependencies struct {
	newArtifactSource func(*http.Client) (middleend.ArtifactSource, error)
	newHTTPTransport  func() *http.Transport
	lookupEnv         func(string) (string, bool)
}

var defaultRuntimeDependencies = runtimeDependencies{
	newArtifactSource: func(client *http.Client) (middleend.ArtifactSource, error) {
		return middleend.NewHTTPArtifactSource(client)
	},
	newHTTPTransport: func() *http.Transport {
		return http.DefaultTransport.(*http.Transport).Clone()
	},
	lookupEnv: os.LookupEnv,
}

func main() {
	if err := runMain(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "meprobe: %v\n", err)
		os.Exit(1)
	}
}

func runMain(arguments []string) error {
	flags := flag.NewFlagSet("meprobe", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var config options
	flags.StringVar(&config.dc, "dc", "", "signed DC ID; empty uses Telegram's declared default")
	flags.StringVar(&config.family, "family", "any", "endpoint family: any, 4, or 6")
	flags.IntVar(&config.endpointIndex, "endpoint-index", 0, "zero-based endpoint index after family filtering")
	flags.StringVar(&config.socksAddress, "socks", "", "SOCKS5 host:port for the ME TCP link; credentials come only from TELEGO_MEPROBE_SOCKS_USERNAME/PASSWORD")
	flags.StringVar(&config.httpProxy, "http-proxy", "", "proxy URL for artifact HTTPS requests; http, https, socks5, and socks5h are valid; userinfo is rejected")
	flags.DurationVar(&config.artifactTimeout, "artifact-timeout", defaultArtifactTimeout, "deadline for one artifact generation fetch")
	flags.DurationVar(&config.linkTimeout, "link-timeout", defaultLinkTimeout, "deadline for dial, handshake, and ping/pong")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not supported")
	}
	if config.artifactTimeout <= 0 || config.linkTimeout <= 0 {
		return errors.New("timeouts must be positive")
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(rootCtx, config, os.Stdout)
}

func run(ctx context.Context, config options, output io.Writer) error {
	return runWithDependencies(ctx, config, output, defaultRuntimeDependencies)
}

func runWithDependencies(ctx context.Context, config options, output io.Writer, dependencies runtimeDependencies) error {
	validated, err := validateOptions(config, dependencies.lookupEnv)
	if err != nil {
		return err
	}
	if dependencies.newArtifactSource == nil {
		return errors.New("artifact source factory is nil")
	}
	if dependencies.newHTTPTransport == nil {
		return errors.New("HTTP transport factory is nil")
	}

	transport := dependencies.newHTTPTransport()
	if transport == nil {
		return errors.New("HTTP transport factory returned nil")
	}
	defer transport.CloseIdleConnections()
	transport.Proxy = nil
	if validated.httpProxy != nil {
		transport.Proxy = http.ProxyURL(validated.httpProxy)
	}
	source, err := dependencies.newArtifactSource(&http.Client{Transport: transport})
	if err != nil {
		return fmt.Errorf("initialize artifact source: %w", err)
	}
	cache, err := middleend.NewArtifactCache(source, config.artifactTimeout)
	if err != nil {
		return fmt.Errorf("initialize artifact cache: %w", err)
	}
	artifactCtx, cancelArtifacts := context.WithTimeout(ctx, config.artifactTimeout)
	err = cache.Refresh(artifactCtx)
	cancelArtifacts()
	if err != nil {
		return fmt.Errorf("fetch artifacts: %w", err)
	}
	snapshot, ok := cache.Snapshot()
	if !ok {
		return errors.New("artifact refresh completed without a snapshot")
	}

	selectedDC, endpoint, err := middleend.SelectEndpoint(snapshot, validated.dc, validated.family, validated.endpointIndex)
	if err != nil {
		return err
	}

	linkCtx, cancelLink := context.WithTimeout(ctx, config.linkTimeout)
	defer cancelLink()
	conn, serverAddr, clientAddr, transportName, err := dialLink(linkCtx, endpoint, validated.socksDialer)
	if err != nil {
		return err
	}
	defer conn.Close()

	now := time.Now()
	if now.Unix() <= 0 || now.Unix() > int64(^uint32(0)>>1) {
		return errors.New("current time is outside the Middle-End int32 timestamp range")
	}
	processID, err := middleend.ClientProcessID(clientAddr, os.Getpid(), now)
	if err != nil {
		return err
	}
	bootstrap, err := middleend.NewClientBootstrap(middleend.ClientBootstrapConfig{
		Secret:          snapshot.Secret(),
		ServerAddr:      serverAddr,
		ClientAddr:      clientAddr,
		LocalProcessID:  processID,
		ClientTimestamp: int32(now.Unix()),
	})
	if err != nil {
		return fmt.Errorf("initialize link bootstrap: %w", err)
	}
	link, err := middleend.BootstrapBlocking(linkCtx, conn, bootstrap)
	if err != nil {
		return fmt.Errorf("ME handshake: %w", err)
	}
	defer link.Close()

	var pingBytes [8]byte
	if _, err := rand.Read(pingBytes[:]); err != nil {
		return fmt.Errorf("generate ping ID: %w", err)
	}
	if err := link.Ping(linkCtx, binary.LittleEndian.Uint64(pingBytes[:])); err != nil {
		return fmt.Errorf("ME ping/pong: %w", err)
	}
	familyName := "ipv6"
	if endpoint.Addr().Unmap().Is4() {
		familyName = "ipv4"
	}
	_, err = fmt.Fprintf(output, "ME probe ok: dc=%d family=%s transport=%s\n", selectedDC, familyName, transportName)
	return err
}

func dialLink(ctx context.Context, endpoint netip.AddrPort, socksDialer *middleend.SOCKS5Dialer) (*net.TCPConn, netip.AddrPort, netip.AddrPort, string, error) {
	if socksDialer == nil {
		network := "tcp6"
		if endpoint.Addr().Unmap().Is4() {
			network = "tcp4"
		}
		connection, err := (&net.Dialer{}).DialContext(ctx, network, endpoint.String())
		if err != nil {
			return nil, netip.AddrPort{}, netip.AddrPort{}, "", fmt.Errorf("direct dial: %w", err)
		}
		tcpConn, ok := connection.(*net.TCPConn)
		if !ok {
			_ = connection.Close()
			return nil, netip.AddrPort{}, netip.AddrPort{}, "", fmt.Errorf("direct dial returned %T, want *net.TCPConn", connection)
		}
		serverAddr, clientAddr, err := middleend.DirectAddressTuple(tcpConn, endpoint)
		if err != nil {
			_ = tcpConn.Close()
			return nil, netip.AddrPort{}, netip.AddrPort{}, "", err
		}
		return tcpConn, serverAddr, clientAddr, "direct", nil
	}

	conn, bound, err := socksDialer.DialContext(ctx, endpoint.String())
	if err != nil {
		return nil, netip.AddrPort{}, netip.AddrPort{}, "", fmt.Errorf("SOCKS5 dial: %w", err)
	}
	serverAddr, clientAddr, err := middleend.SOCKS5AddressTuple(endpoint, bound)
	if err != nil {
		_ = conn.Close()
		return nil, netip.AddrPort{}, netip.AddrPort{}, "", err
	}
	return conn, serverAddr, clientAddr, "socks5", nil
}

func parseDC(value string) (*middleend.DCID, error) {
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 16)
	if err != nil {
		return nil, errors.New("DC must be a signed 16-bit integer")
	}
	return new(middleend.DCID(parsed)), nil
}

func parseFamily(value string) (middleend.AddressFamily, error) {
	switch strings.ToLower(value) {
	case "any":
		return middleend.AddressFamilyAny, nil
	case "4", "ipv4":
		return middleend.AddressFamilyIPv4, nil
	case "6", "ipv6":
		return middleend.AddressFamilyIPv6, nil
	default:
		return 0, errors.New("family must be any, 4, or 6")
	}
}

func validateOptions(config options, lookupEnv func(string) (string, bool)) (validatedOptions, error) {
	var validated validatedOptions
	if config.artifactTimeout <= 0 || config.linkTimeout <= 0 {
		return validated, errors.New("timeouts must be positive")
	}
	if config.endpointIndex < 0 {
		return validated, errors.New("endpoint index must be nonnegative")
	}
	if lookupEnv == nil {
		return validated, errors.New("environment lookup is nil")
	}

	var err error
	validated.dc, err = parseDC(config.dc)
	if err != nil {
		return validatedOptions{}, err
	}
	validated.family, err = parseFamily(config.family)
	if err != nil {
		return validatedOptions{}, err
	}
	validated.endpointIndex = config.endpointIndex
	if strings.Contains(config.socksAddress, "@") {
		return validatedOptions{}, fmt.Errorf("%w: proxy address must not contain credentials; use TELEGO_MEPROBE_SOCKS_USERNAME and TELEGO_MEPROBE_SOCKS_PASSWORD", middleend.ErrSOCKS5Address)
	}
	if config.httpProxy != "" {
		validated.httpProxy, err = url.Parse(config.httpProxy)
		if err != nil || validated.httpProxy.Scheme == "" || validated.httpProxy.Host == "" ||
			validated.httpProxy.Path != "" || validated.httpProxy.RawQuery != "" || validated.httpProxy.Fragment != "" {
			return validatedOptions{}, errors.New("invalid artifact proxy URL")
		}
		switch strings.ToLower(validated.httpProxy.Scheme) {
		case "http", "https", "socks5", "socks5h":
		default:
			return validatedOptions{}, errors.New("artifact proxy URL scheme must be http, https, socks5, or socks5h")
		}
		if validated.httpProxy.User != nil {
			return validatedOptions{}, errors.New("artifact proxy credentials must not be supplied on the command line")
		}
	}

	credentials, err := socksCredentials(lookupEnv)
	if err != nil {
		return validatedOptions{}, err
	}
	if config.socksAddress != "" {
		validated.socksDialer, err = middleend.NewSOCKS5Dialer(config.socksAddress, credentials)
		if err != nil {
			return validatedOptions{}, fmt.Errorf("initialize SOCKS5 dialer: %w", err)
		}
	}
	return validated, nil
}

func socksCredentialsFromEnvironment() (*middleend.SOCKS5Credentials, error) {
	return socksCredentials(os.LookupEnv)
}

func socksCredentials(lookupEnv func(string) (string, bool)) (*middleend.SOCKS5Credentials, error) {
	username, hasUsername := lookupEnv(socksUsernameEnvironment)
	password, hasPassword := lookupEnv(socksPasswordEnvironment)
	if !hasUsername && !hasPassword {
		return nil, nil
	}
	if !hasUsername || !hasPassword {
		return nil, errors.New("both SOCKS5 credential environment variables must be set")
	}
	if username == "" || password == "" {
		return nil, errors.New("SOCKS5 credential environment variables must be nonempty")
	}
	return &middleend.SOCKS5Credentials{Username: username, Password: password}, nil
}
