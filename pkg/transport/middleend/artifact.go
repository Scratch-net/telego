package middleend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// TelegramArtifactRefreshInterval follows the operational guidance in the
	// official MTProxy README to update the proxy configuration once per day.
	// Telegram does not publish an expiry time for these artifacts, so an older
	// last-known-good snapshot remains usable when a refresh fails.
	TelegramArtifactRefreshInterval = 24 * time.Hour

	// MaxProxyConfigSize, MaxProxyTargets, and MaxProxyClusters match the parser limits in
	// common/parse-config.c and mtproto/mtproto-config.h at the pinned official
	// MTProxy commit f36d8af769ffaeac36978d38c2c0f6d1104c2137.
	MaxProxyConfigSize = 16 << 20
	MaxProxyTargets    = 4096
	MaxProxyClusters   = 1024

	telegramProxySecretURL   = "https://core.telegram.org/getProxySecret"
	telegramProxyConfigURL   = "https://core.telegram.org/getProxyConfig"
	telegramProxyConfigV6URL = "https://core.telegram.org/getProxyConfigV6"
	maxConfigDirectiveSize   = len("proxy_for")
	maxDCIDTokenSize         = len("-32768")
	maxEndpointTokenSize     = 70
)

var (
	ErrArtifactFetch       = errors.New("fetch Telegram Middle-End artifacts")
	ErrInvalidProxyConfig  = errors.New("invalid Telegram proxy configuration")
	ErrIncompleteArtifacts = errors.New("incomplete Telegram Middle-End artifacts")
	ErrInvalidArtifactAPI  = errors.New("invalid Telegram artifact API configuration")
	ErrArtifactCacheClosed = errors.New("artifact cache is closed")
)

// DCID is Telegram's signed data-center identifier. Positive and negative
// identifiers are separate routing clusters in the official proxy config.
type DCID int16

// RawArtifacts is one all-or-nothing fetch of Telegram's public Middle-End
// secret and IPv4/IPv6 proxy configurations.
type RawArtifacts struct {
	Secret     []byte
	IPv4Config []byte
	IPv6Config []byte
}

// String redacts the opaque secret and full configuration bodies.
func (RawArtifacts) String() string {
	return "middleend.RawArtifacts{redacted}"
}

// GoString redacts the opaque secret and full configuration bodies for %#v.
func (RawArtifacts) GoString() string {
	return "middleend.RawArtifacts{redacted}"
}

// ArtifactSource fetches all three public Telegram Middle-End artifacts. An
// implementation must honor cancellation of ctx and must not return a partial
// success.
type ArtifactSource interface {
	Fetch(ctx context.Context) (RawArtifacts, error)
}

// HTTPArtifactSource fetches artifacts from Telegram's official HTTPS
// endpoints. Apply a deadline to ctx; ArtifactCache does this on every refresh.
type HTTPArtifactSource struct {
	client *http.Client
	urls   artifactURLs
}

type artifactURLs struct {
	secret string
	ipv4   string
	ipv6   string
}

var officialArtifactURLs = artifactURLs{
	secret: telegramProxySecretURL,
	ipv4:   telegramProxyConfigURL,
	ipv6:   telegramProxyConfigV6URL,
}

// NewHTTPArtifactSource creates a source pinned to Telegram's official public
// artifact endpoints. The caller owns client and its transport.
func NewHTTPArtifactSource(client *http.Client) (*HTTPArtifactSource, error) {
	return newHTTPArtifactSource(client, officialArtifactURLs)
}

func newHTTPArtifactSource(client *http.Client, urls artifactURLs) (*HTTPArtifactSource, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: nil HTTP client", ErrInvalidArtifactAPI)
	}
	if urls.secret == "" || urls.ipv4 == "" || urls.ipv6 == "" {
		return nil, fmt.Errorf("%w: all artifact URLs are required", ErrInvalidArtifactAPI)
	}
	return &HTTPArtifactSource{client: client, urls: urls}, nil
}

// Fetch retrieves all artifacts. It returns no data unless all three responses
// have status 200 and fit their protocol-derived size limits.
func (s *HTTPArtifactSource) Fetch(ctx context.Context) (RawArtifacts, error) {
	var raw RawArtifacts
	if ctx == nil {
		return raw, fmt.Errorf("%w: nil context", ErrInvalidArtifactAPI)
	}
	if s == nil || s.client == nil {
		return raw, fmt.Errorf("%w: uninitialized HTTP source", ErrInvalidArtifactAPI)
	}

	var err error
	raw.Secret, err = s.fetchOne(ctx, "secret", s.urls.secret, MaximumSecretSize)
	if err != nil {
		return RawArtifacts{}, err
	}
	raw.IPv4Config, err = s.fetchOne(ctx, "IPv4 config", s.urls.ipv4, MaxProxyConfigSize)
	if err != nil {
		return RawArtifacts{}, err
	}
	raw.IPv6Config, err = s.fetchOne(ctx, "IPv6 config", s.urls.ipv6, MaxProxyConfigSize)
	if err != nil {
		return RawArtifacts{}, err
	}
	return raw, nil
}

func (s *HTTPArtifactSource) fetchOne(ctx context.Context, name, url string, limit int) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: create %s request: %w", ErrArtifactFetch, name, err)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrArtifactFetch, name, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s returned HTTP %d", ErrArtifactFetch, name, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %w", ErrArtifactFetch, name, err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrArtifactFetch, name, limit)
	}
	return data, nil
}

// ArtifactSnapshot is an immutable, validated artifact generation. Accessors
// return defensive copies of secret and endpoint slices.
type ArtifactSnapshot struct {
	secret    []byte
	defaultDC DCID
	endpoints map[DCID][]netip.AddrPort
	fetchedAt time.Time
}

// String redacts the infrastructure secret and endpoint generation.
func (ArtifactSnapshot) String() string {
	return "middleend.ArtifactSnapshot{redacted}"
}

// GoString redacts the infrastructure secret and endpoint generation for %#v.
func (ArtifactSnapshot) GoString() string {
	return "middleend.ArtifactSnapshot{redacted}"
}

// Secret returns an independent copy of Telegram's infrastructure secret.
func (s ArtifactSnapshot) Secret() []byte {
	return slices.Clone(s.secret)
}

// DefaultDC returns the effective default across both configurations. It is
// cluster zero when neither configuration declares a default.
func (s ArtifactSnapshot) DefaultDC() DCID {
	return s.defaultDC
}

// Endpoints returns the IPv4 endpoints followed by the IPv6 endpoints for dc.
func (s ArtifactSnapshot) Endpoints(dc DCID) []netip.AddrPort {
	return slices.Clone(s.endpoints[dc])
}

// DCIDs returns the signed DC identifiers in ascending order.
func (s ArtifactSnapshot) DCIDs() []DCID {
	return slices.Sorted(maps.Keys(s.endpoints))
}

// FetchedAt returns when this complete generation was published.
func (s ArtifactSnapshot) FetchedAt() time.Time {
	return s.fetchedAt
}

func (s ArtifactSnapshot) clone() ArtifactSnapshot {
	clone := ArtifactSnapshot{
		secret:    slices.Clone(s.secret),
		defaultDC: s.defaultDC,
		endpoints: make(map[DCID][]netip.AddrPort, len(s.endpoints)),
		fetchedAt: s.fetchedAt,
	}
	for dc, endpoints := range s.endpoints {
		clone.endpoints[dc] = slices.Clone(endpoints)
	}
	return clone
}

// ArtifactCache validates and atomically publishes complete artifact
// generations. A failed refresh leaves the last-known-good snapshot unchanged.
type ArtifactCache struct {
	state *artifactCacheState
}

type artifactCacheState struct {
	source         ArtifactSource
	refreshTimeout time.Duration
	now            func() time.Time
	rootContext    context.Context
	cancelRoot     context.CancelFunc
	refreshMu      sync.Mutex
	inFlight       *artifactRefresh
	closing        bool
	operations     sync.WaitGroup
	closeOnce      sync.Once
	done           chan struct{}
	current        atomic.Pointer[ArtifactSnapshot]
}

// String prevents accidental disclosure of the cached artifact generation.
func (ArtifactCache) String() string {
	return "middleend.ArtifactCache{redacted}"
}

// GoString prevents accidental disclosure of the cached artifact generation.
func (ArtifactCache) GoString() string {
	return "middleend.ArtifactCache{redacted}"
}

type artifactRefresh struct {
	done chan struct{}
	err  error
}

// NewArtifactCache creates a cache with a required positive per-refresh
// timeout. The timeout covers all three source operations and parsing.
func NewArtifactCache(source ArtifactSource, refreshTimeout time.Duration) (*ArtifactCache, error) {
	return newArtifactCache(source, refreshTimeout, time.Now)
}

func newArtifactCache(source ArtifactSource, refreshTimeout time.Duration, now func() time.Time) (*ArtifactCache, error) {
	if nilArtifactSource(source) {
		return nil, fmt.Errorf("%w: nil artifact source", ErrInvalidArtifactAPI)
	}
	if refreshTimeout <= 0 {
		return nil, fmt.Errorf("%w: refresh timeout must be positive", ErrInvalidArtifactAPI)
	}
	if now == nil {
		return nil, fmt.Errorf("%w: nil clock", ErrInvalidArtifactAPI)
	}
	rootContext, cancelRoot := context.WithCancel(context.Background())
	return &ArtifactCache{
		state: &artifactCacheState{
			source:         source,
			refreshTimeout: refreshTimeout,
			now:            now,
			rootContext:    rootContext,
			cancelRoot:     cancelRoot,
			done:           make(chan struct{}),
		},
	}, nil
}

func nilArtifactSource(source ArtifactSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Refresh fetches and validates a complete generation before publishing it.
// Overlapping calls share one bounded source operation. Each caller waits with
// its own context. The operation owns its timeout and can complete even if its
// initiating caller cancels, so one caller cannot cancel work for other waiters.
func (c *ArtifactCache) Refresh(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidArtifactAPI)
	}
	if cause := context.Cause(ctx); cause != nil {
		return fmt.Errorf("%w: %w", ErrArtifactFetch, cause)
	}
	if c == nil || c.state == nil {
		return fmt.Errorf("%w: uninitialized artifact cache", ErrInvalidArtifactAPI)
	}
	state := c.state

	state.refreshMu.Lock()
	if state.closing {
		state.refreshMu.Unlock()
		return ErrArtifactCacheClosed
	}
	refresh := state.inFlight
	if refresh == nil {
		refresh = &artifactRefresh{done: make(chan struct{})}
		state.inFlight = refresh
		state.operations.Add(1)
		go c.runRefresh(refresh)
	}
	state.refreshMu.Unlock()

	select {
	case <-refresh.done:
		return refresh.err
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrArtifactFetch, context.Cause(ctx))
	}
}

func (c *ArtifactCache) runRefresh(refresh *artifactRefresh) {
	state := c.state
	defer state.operations.Done()
	refreshCtx, cancel := context.WithTimeout(state.rootContext, state.refreshTimeout)
	defer cancel()

	err := c.fetchAndPublish(refreshCtx)
	state.refreshMu.Lock()
	refresh.err = err
	if state.inFlight == refresh {
		state.inFlight = nil
	}
	close(refresh.done)
	state.refreshMu.Unlock()
}

// Close cancels and joins the current shared refresh. It does not discard the
// last-known-good snapshot. Calls are concurrent and idempotent; no refresh can
// start after shutdown begins.
func (c *ArtifactCache) Close() error {
	if c == nil || c.state == nil {
		return nil
	}
	state := c.state
	state.closeOnce.Do(func() {
		state.refreshMu.Lock()
		state.closing = true
		state.cancelRoot()
		state.refreshMu.Unlock()
		state.operations.Wait()
		close(state.done)
	})
	<-state.done
	return nil
}

func (c *ArtifactCache) fetchAndPublish(ctx context.Context) error {
	state := c.state
	raw, err := state.source.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("%w: source: %w", ErrArtifactFetch, err)
	}
	if cause := context.Cause(ctx); cause != nil {
		return fmt.Errorf("%w: %w", ErrArtifactFetch, cause)
	}
	snapshot, err := parseArtifactSnapshot(raw, state.now())
	if err != nil {
		return err
	}
	if cause := context.Cause(ctx); cause != nil {
		return fmt.Errorf("%w: %w", ErrArtifactFetch, cause)
	}
	state.current.Store(&snapshot)
	return nil
}

// Snapshot returns an independent copy of the current generation.
func (c *ArtifactCache) Snapshot() (ArtifactSnapshot, bool) {
	if c == nil || c.state == nil {
		return ArtifactSnapshot{}, false
	}
	current := c.state.current.Load()
	if current == nil {
		return ArtifactSnapshot{}, false
	}
	return current.clone(), true
}

// RefreshDue reports whether no snapshot exists or the official daily refresh
// interval has elapsed. Due snapshots remain usable; Telegram publishes no
// artifact expiry time.
func (c *ArtifactCache) RefreshDue(now time.Time) bool {
	if c == nil || c.state == nil {
		return true
	}
	current := c.state.current.Load()
	return current == nil || !now.Before(current.fetchedAt.Add(TelegramArtifactRefreshInterval))
}

func parseArtifactSnapshot(raw RawArtifacts, fetchedAt time.Time) (ArtifactSnapshot, error) {
	secret, err := parseArtifactSecret(raw.Secret)
	if err != nil {
		return ArtifactSnapshot{}, err
	}
	ipv4, err := parseProxyConfig(raw.IPv4Config, configIPv4)
	if err != nil {
		return ArtifactSnapshot{}, fmt.Errorf("%w: IPv4: %w", ErrIncompleteArtifacts, err)
	}
	ipv6, err := parseProxyConfig(raw.IPv6Config, configIPv6)
	if err != nil {
		return ArtifactSnapshot{}, fmt.Errorf("%w: IPv6: %w", ErrIncompleteArtifacts, err)
	}
	if ipv4.hasDefault && ipv6.hasDefault && ipv6.defaultDC != ipv4.defaultDC {
		return ArtifactSnapshot{}, fmt.Errorf("%w: IPv4 and IPv6 default DCs differ", ErrIncompleteArtifacts)
	}

	defaultDC := DCID(0)
	switch {
	case ipv4.hasDefault:
		defaultDC = ipv4.defaultDC
	case ipv6.hasDefault:
		defaultDC = ipv6.defaultDC
	}

	dcs := make(map[DCID]struct{}, len(ipv4.endpoints)+len(ipv6.endpoints))
	for dc := range ipv4.endpoints {
		dcs[dc] = struct{}{}
	}
	for dc := range ipv6.endpoints {
		dcs[dc] = struct{}{}
	}
	if len(dcs) == 0 || len(dcs) > MaxProxyClusters {
		return ArtifactSnapshot{}, fmt.Errorf("%w: combined cluster count %d is outside 1..%d", ErrIncompleteArtifacts, len(dcs), MaxProxyClusters)
	}
	if _, ok := dcs[defaultDC]; !ok {
		return ArtifactSnapshot{}, fmt.Errorf("%w: default DC %d has no endpoint", ErrIncompleteArtifacts, defaultDC)
	}

	endpoints := make(map[DCID][]netip.AddrPort, len(dcs))
	for dc := range dcs {
		combined := make([]netip.AddrPort, 0, len(ipv4.endpoints[dc])+len(ipv6.endpoints[dc]))
		combined = append(combined, ipv4.endpoints[dc]...)
		combined = append(combined, ipv6.endpoints[dc]...)
		if len(combined) == 0 {
			return ArtifactSnapshot{}, fmt.Errorf("%w: DC %d has no endpoint", ErrIncompleteArtifacts, dc)
		}
		endpoints[dc] = combined
	}
	return ArtifactSnapshot{
		secret:    secret,
		defaultDC: defaultDC,
		endpoints: endpoints,
		fetchedAt: fetchedAt,
	}, nil
}

func parseArtifactSecret(secret []byte) ([]byte, error) {
	if len(secret) < MinimumSecretSize || len(secret) > MaximumSecretSize {
		return nil, fmt.Errorf("%w: secret length %d is outside %d..%d", ErrIncompleteArtifacts, len(secret), MinimumSecretSize, MaximumSecretSize)
	}
	if _, err := SecretKeySelector(secret); err != nil {
		return nil, fmt.Errorf("%w: unusable secret: %w", ErrIncompleteArtifacts, err)
	}
	return slices.Clone(secret), nil
}

type configFamily uint8

const (
	configIPv4 configFamily = iota + 1
	configIPv6
)

type parsedProxyConfig struct {
	defaultDC  DCID
	hasDefault bool
	endpoints  map[DCID][]netip.AddrPort
}

func parseProxyConfig(data []byte, family configFamily) (parsedProxyConfig, error) {
	if len(data) == 0 || len(data) > MaxProxyConfigSize {
		return parsedProxyConfig{}, fmt.Errorf("%w: size %d is outside 1..%d", ErrInvalidProxyConfig, len(data), MaxProxyConfigSize)
	}
	if family != configIPv4 && family != configIPv6 {
		return parsedProxyConfig{}, fmt.Errorf("%w: unsupported address family %d", ErrInvalidProxyConfig, family)
	}

	parser := proxyConfigParser{data: data, line: 1}
	config := parsedProxyConfig{endpoints: make(map[DCID][]netip.AddrPort)}
	seenDCs := make(map[DCID]bool)
	var lastDC DCID
	haveLastDC := false
	targets := 0
	for {
		parser.skipSpaceAndComments()
		if parser.done() {
			break
		}
		directive, err := parser.identifier()
		if err != nil {
			return parsedProxyConfig{}, err
		}
		switch directive {
		case "default":
			if config.hasDefault {
				return parsedProxyConfig{}, parser.errorf("duplicate default directive")
			}
			if err := parser.requireHorizontalSpace(); err != nil {
				return parsedProxyConfig{}, err
			}
			dc, err := parser.dcID()
			if err != nil {
				return parsedProxyConfig{}, err
			}
			if err := parser.semicolon(); err != nil {
				return parsedProxyConfig{}, err
			}
			config.defaultDC = dc
			config.hasDefault = true
		case "proxy_for":
			if targets == MaxProxyTargets {
				return parsedProxyConfig{}, parser.errorf("more than %d proxy targets", MaxProxyTargets)
			}
			if err := parser.requireHorizontalSpace(); err != nil {
				return parsedProxyConfig{}, err
			}
			dc, err := parser.dcID()
			if err != nil {
				return parsedProxyConfig{}, err
			}
			if err := parser.requireHorizontalSpace(); err != nil {
				return parsedProxyConfig{}, err
			}
			endpoint, err := parser.endpoint(family)
			if err != nil {
				return parsedProxyConfig{}, err
			}
			if err := parser.semicolon(); err != nil {
				return parsedProxyConfig{}, err
			}
			if err := addProxyTarget(&config, seenDCs, &lastDC, &haveLastDC, dc, endpoint, &parser); err != nil {
				return parsedProxyConfig{}, err
			}
			targets++
		case "proxy":
			if targets == MaxProxyTargets {
				return parsedProxyConfig{}, parser.errorf("more than %d proxy targets", MaxProxyTargets)
			}
			if err := parser.requireHorizontalSpace(); err != nil {
				return parsedProxyConfig{}, err
			}
			endpoint, err := parser.endpoint(family)
			if err != nil {
				return parsedProxyConfig{}, err
			}
			if err := parser.semicolon(); err != nil {
				return parsedProxyConfig{}, err
			}
			if err := addProxyTarget(&config, seenDCs, &lastDC, &haveLastDC, 0, endpoint, &parser); err != nil {
				return parsedProxyConfig{}, err
			}
			targets++
		default:
			return parsedProxyConfig{}, parser.errorf("unsupported directive %q", directive)
		}
	}
	if targets == 0 {
		return parsedProxyConfig{}, parser.errorf("no proxy directives")
	}
	return config, nil
}

func addProxyTarget(
	config *parsedProxyConfig,
	seenDCs map[DCID]bool,
	lastDC *DCID,
	haveLastDC *bool,
	dc DCID,
	endpoint netip.AddrPort,
	parser *proxyConfigParser,
) error {
	if !seenDCs[dc] && len(seenDCs) == MaxProxyClusters {
		return parser.errorf("more than %d proxy clusters", MaxProxyClusters)
	}
	if seenDCs[dc] && (!*haveLastDC || dc != *lastDC) {
		return parser.errorf("proxy targets for DC %d are intermixed", dc)
	}
	config.endpoints[dc] = append(config.endpoints[dc], endpoint)
	seenDCs[dc] = true
	*lastDC = dc
	*haveLastDC = true
	return nil
}

type proxyConfigParser struct {
	data []byte
	pos  int
	line int
}

func (p *proxyConfigParser) done() bool {
	return p.pos == len(p.data)
}

func (p *proxyConfigParser) skipSpaceAndComments() {
	for !p.done() {
		switch p.data[p.pos] {
		case ' ', '\t', '\r':
			p.pos++
		case '\n':
			p.pos++
			p.line++
		case '#':
			for !p.done() && p.data[p.pos] != '\n' {
				p.pos++
			}
		default:
			return
		}
	}
}

func (p *proxyConfigParser) requireHorizontalSpace() error {
	if p.done() || (p.data[p.pos] != ' ' && p.data[p.pos] != '\t') {
		return p.errorf("space or tab expected")
	}
	for !p.done() && (p.data[p.pos] == ' ' || p.data[p.pos] == '\t') {
		p.pos++
	}
	return nil
}

func (p *proxyConfigParser) identifier() (string, error) {
	start := p.pos
	for !p.done() {
		b := p.data[p.pos]
		if (b < 'a' || b > 'z') && b != '_' {
			break
		}
		p.pos++
	}
	if p.pos == start {
		return "", p.errorf("directive expected")
	}
	if p.pos-start > maxConfigDirectiveSize {
		return "", p.errorf("directive is too long")
	}
	return string(p.data[start:p.pos]), nil
}

func (p *proxyConfigParser) dcID() (DCID, error) {
	start := p.pos
	if !p.done() && p.data[p.pos] == '-' {
		p.pos++
	}
	digitStart := p.pos
	for !p.done() && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == digitStart {
		return 0, p.errorf("signed DC identifier expected")
	}
	if p.pos-start > maxDCIDTokenSize {
		return 0, p.errorf("DC identifier is too long")
	}
	value, err := strconv.ParseInt(string(p.data[start:p.pos]), 10, 16)
	if err != nil {
		return 0, p.errorf("DC identifier is outside int16 range")
	}
	dc := DCID(value)
	return dc, nil
}

func (p *proxyConfigParser) endpoint(family configFamily) (netip.AddrPort, error) {
	start := p.pos
	for !p.done() {
		switch p.data[p.pos] {
		case ' ', '\t', '\r', '\n', ';', '#':
			goto parse
		default:
			p.pos++
		}
	}

parse:
	if p.pos == start {
		return netip.AddrPort{}, p.errorf("proxy endpoint expected")
	}
	if p.pos-start > maxEndpointTokenSize {
		return netip.AddrPort{}, p.errorf("proxy endpoint is too long")
	}
	endpoint, err := netip.ParseAddrPort(string(p.data[start:p.pos]))
	if err != nil {
		return netip.AddrPort{}, p.errorf("invalid proxy endpoint: %v", err)
	}
	address := endpoint.Addr()
	if address.Zone() != "" || address.IsUnspecified() || endpoint.Port() == 0 {
		return netip.AddrPort{}, p.errorf("unusable proxy endpoint %s", endpoint)
	}
	if family == configIPv4 && !address.Is4() {
		return netip.AddrPort{}, p.errorf("IPv4 config contains non-IPv4 endpoint %s", endpoint)
	}
	if family == configIPv6 && (!address.Is6() || address.Is4In6()) {
		return netip.AddrPort{}, p.errorf("IPv6 config contains non-IPv6 endpoint %s", endpoint)
	}
	return endpoint, nil
}

func (p *proxyConfigParser) semicolon() error {
	p.skipSpaceAndComments()
	if p.done() || p.data[p.pos] != ';' {
		return p.errorf("semicolon expected")
	}
	p.pos++
	return nil
}

func (p *proxyConfigParser) errorf(format string, args ...any) error {
	return fmt.Errorf("%w at line %d: %s", ErrInvalidProxyConfig, p.line, fmt.Sprintf(format, args...))
}
