package middleend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

var (
	// ErrInvalidGnetGenerationFactory reports a missing dependency, invalid
	// snapshot, or unsafe construction limit.
	ErrInvalidGnetGenerationFactory = errors.New("invalid Middle-End gnet generation factory")
	// ErrGnetGenerationDial reports that every endpoint allowed by the
	// IPv4-first policy failed for one exact signed DC.
	ErrGnetGenerationDial = errors.New("dial Middle-End generation")
)

// GnetGenerationFactoryConfig contains every production dependency and bound
// used to construct one whole fixed-binding generation. It has no defaults.
// LinksPerDC is the fixed active-link pool size for every signed DC. Snapshot is
// immutable. Runtime is shared by all generations and must outlive every manager
// returned by the factory.
type GnetGenerationFactoryConfig struct {
	Runtime             *GnetClientRuntime
	Snapshot            ArtifactSnapshot
	SOCKS5              *SOCKS5Dialer
	NATResolver         *NATResolver
	EndpointDialTimeout time.Duration
	DialConcurrency     int
	LinksPerDC          int
	LinkLimits          LinkLimits
	BindingLimits       FixedBindingLimits
}

// String redacts the artifact secret, SOCKS credentials, runtime, and limits.
func (GnetGenerationFactoryConfig) String() string {
	return "middleend.GnetGenerationFactoryConfig{redacted}"
}

// GoString redacts the artifact secret, SOCKS credentials, runtime, and limits.
func (c GnetGenerationFactoryConfig) GoString() string { return c.String() }

// GnetGenerationFactory constructs whole generations over one shared gnet
// client runtime. Build calls are serialized. Successful selections advance a
// per-DC round-robin cursor within each address family. Every Build tries all
// IPv4 candidates before any IPv6 candidate, regardless of cursor position.
type GnetGenerationFactory struct {
	state *gnetGenerationFactoryState
}

type gnetGenerationFactoryState struct {
	snapshot            ArtifactSnapshot
	dialer              generationEndpointDialer
	linkBuilder         generationLinkBuilder
	endpointDialTimeout time.Duration
	dialConcurrency     int
	linksPerDC          int
	linkLimits          LinkLimits
	bindingLimits       FixedBindingLimits
	processID           int
	processStartedAt    time.Time
	now                 func() time.Time

	buildMu sync.Mutex
	next    map[DCID]generationEndpointCursor
	repairs chan struct{}
}

type generationEndpointCursor struct {
	ipv4 int
	ipv6 int
}

type generationEndpointCandidate struct {
	endpoint netip.AddrPort
	family   AddressFamily
	position int
	count    int
}

type generationSlotResult struct {
	slot     FixedBindingSlot
	selected generationEndpointCandidate
	err      error
}

type generationSlotJob struct {
	index  int
	dcID   DCID
	cursor generationEndpointCursor
}

type generationEndpointDialer interface {
	Dial(context.Context, netip.AddrPort, time.Duration) (*net.TCPConn, netip.AddrPort, netip.AddrPort, error)
}

type generationLinkBuilder interface {
	NewClientLink(*net.TCPConn, *ClientBootstrap, LinkLimits) (ClientLink, error)
}

type productionGenerationDialer struct {
	socks5 *SOCKS5Dialer
	nat    *NATResolver
}

// NewGnetGenerationFactory validates and retains one immutable artifact
// snapshot. Build can be used directly as FixedBindingGenerationFactory.
func NewGnetGenerationFactory(config GnetGenerationFactoryConfig) (*GnetGenerationFactory, error) {
	if config.Runtime == nil {
		return nil, fmt.Errorf("%w: nil gnet runtime", ErrInvalidGnetGenerationFactory)
	}
	return newGnetGenerationFactory(
		config,
		productionGenerationDialer{socks5: config.SOCKS5, nat: config.NATResolver},
		config.Runtime,
		os.Getpid(),
		time.Now(),
		time.Now,
	)
}

func newGnetGenerationFactory(
	config GnetGenerationFactoryConfig,
	dialer generationEndpointDialer,
	linkBuilder generationLinkBuilder,
	processID int,
	processStartedAt time.Time,
	now func() time.Time,
) (*GnetGenerationFactory, error) {
	if dialer == nil || linkBuilder == nil || now == nil {
		return nil, fmt.Errorf("%w: nil internal dependency", ErrInvalidGnetGenerationFactory)
	}
	if err := validateGnetGenerationFactoryLimits(config); err != nil {
		return nil, err
	}
	if processID <= 0 {
		return nil, fmt.Errorf("%w: process ID must be positive", ErrInvalidGnetGenerationFactory)
	}
	if processStartedAt.Unix() <= 0 || processStartedAt.Unix() > int64(^uint32(0)>>1) {
		return nil, fmt.Errorf("%w: process start time is outside positive int32", ErrInvalidGnetGenerationFactory)
	}
	secret := config.Snapshot.Secret()
	defer clear(secret)
	if _, err := SecretKeySelector(secret); err != nil {
		return nil, fmt.Errorf("%w: artifact secret: %w", ErrInvalidGnetGenerationFactory, err)
	}
	dcIDs := config.Snapshot.DCIDs()
	if len(dcIDs) == 0 || len(dcIDs) > MaxProxyClusters {
		return nil, fmt.Errorf("%w: snapshot DC count must be in [1,%d]", ErrInvalidGnetGenerationFactory, MaxProxyClusters)
	}
	if config.LinksPerDC > MaxProxyTargets/len(dcIDs) {
		return nil, fmt.Errorf(
			"%w: %d DCs times %d links exceed %d total targets",
			ErrInvalidGnetGenerationFactory,
			len(dcIDs),
			config.LinksPerDC,
			MaxProxyTargets,
		)
	}
	for _, dcID := range dcIDs {
		endpoints := config.Snapshot.Endpoints(dcID)
		if len(endpoints) == 0 {
			return nil, fmt.Errorf("%w: signed DC %d has no endpoint", ErrInvalidGnetGenerationFactory, dcID)
		}
		for _, endpoint := range endpoints {
			if !endpoint.IsValid() || endpoint.Port() == 0 {
				return nil, fmt.Errorf("%w: signed DC %d has an invalid endpoint", ErrInvalidGnetGenerationFactory, dcID)
			}
		}
	}

	return &GnetGenerationFactory{state: &gnetGenerationFactoryState{
		snapshot:            config.Snapshot.clone(),
		dialer:              dialer,
		linkBuilder:         linkBuilder,
		endpointDialTimeout: config.EndpointDialTimeout,
		dialConcurrency:     config.DialConcurrency,
		linksPerDC:          config.LinksPerDC,
		linkLimits:          config.LinkLimits,
		bindingLimits:       config.BindingLimits,
		processID:           processID,
		processStartedAt:    processStartedAt,
		now:                 now,
		next:                make(map[DCID]generationEndpointCursor, len(dcIDs)),
		repairs:             make(chan struct{}, config.DialConcurrency),
	}}, nil
}

func validateGnetGenerationFactoryLimits(config GnetGenerationFactoryConfig) error {
	if config.EndpointDialTimeout <= 0 {
		return fmt.Errorf("%w: endpoint dial timeout must be positive", ErrInvalidGnetGenerationFactory)
	}
	if config.DialConcurrency <= 0 || config.DialConcurrency > MaxProxyClusters {
		return fmt.Errorf("%w: dial concurrency must be in [1,%d]", ErrInvalidGnetGenerationFactory, MaxProxyClusters)
	}
	if config.LinksPerDC <= 0 {
		return fmt.Errorf("%w: links per DC must be positive", ErrInvalidGnetGenerationFactory)
	}
	if err := config.LinkLimits.Validate(); err != nil {
		return fmt.Errorf("%w: link limits: %w", ErrInvalidGnetGenerationFactory, err)
	}
	if err := config.BindingLimits.Validate(); err != nil {
		return fmt.Errorf("%w: binding limits: %w", ErrInvalidGnetGenerationFactory, err)
	}
	return nil
}

// String redacts the snapshot, endpoint state, runtime, dialer, and limits.
func (*GnetGenerationFactory) String() string {
	return "middleend.GnetGenerationFactory{redacted}"
}

// GoString redacts the snapshot, endpoint state, runtime, dialer, and limits.
func (f *GnetGenerationFactory) GoString() string { return f.String() }

// Build constructs one unstarted manager with LinksPerDC gnet links for every
// exact signed DC in the snapshot. Replicas start at consecutive round-robin
// positions so multi-endpoint DCs receive deterministic endpoint diversity. TCP
// and tuple failures fall through the complete IPv4-first endpoint list. A
// failure closes every link already constructed; no partial generation escapes.
func (f *GnetGenerationFactory) Build(ctx context.Context) (*FixedBindingManager, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidGnetGenerationFactory)
	}
	if cause := context.Cause(ctx); cause != nil {
		return nil, fmt.Errorf("%w: %w", ErrGnetGenerationDial, cause)
	}
	if f == nil || f.state == nil {
		return nil, fmt.Errorf("%w: uninitialized factory", ErrInvalidGnetGenerationFactory)
	}
	state := f.state
	state.buildMu.Lock()
	defer state.buildMu.Unlock()

	dcIDs := state.snapshot.DCIDs()
	totalSlots := len(dcIDs) * state.linksPerDC
	results := make([]generationSlotResult, totalSlots)
	jobs := make(chan generationSlotJob, totalSlots)
	for dcIndex, dcID := range dcIDs {
		cursor := state.next[dcID]
		for replica := range state.linksPerDC {
			jobs <- generationSlotJob{
				index:  dcIndex*state.linksPerDC + replica,
				dcID:   dcID,
				cursor: offsetGenerationEndpointCursor(cursor, replica),
			}
		}
	}
	close(jobs)

	workerCount := min(state.dialConcurrency, totalSlots)
	var workers sync.WaitGroup
	for range workerCount {
		workers.Go(func() {
			for job := range jobs {
				results[job.index] = state.buildSlot(ctx, job.dcID, job.cursor)
			}
		})
	}
	workers.Wait()

	for index, result := range results {
		if result.err == nil {
			continue
		}
		closeGenerationSlots(results)
		dcID := dcIDs[index/state.linksPerDC]
		replica := index%state.linksPerDC + 1
		return nil, fmt.Errorf("%w: signed DC %d link %d: %w", ErrGnetGenerationDial, dcID, replica, result.err)
	}

	slots := make([]FixedBindingSlot, len(results))
	for index, result := range results {
		slots[index] = result.slot
	}
	manager, err := newFixedBindingManager(slots, state.bindingLimits, state.buildReplacementLink)
	if err != nil {
		closeGenerationSlots(results)
		return nil, fmt.Errorf("construct Middle-End generation manager: %w", err)
	}
	for index, result := range results {
		dcID := dcIDs[index/state.linksPerDC]
		state.advanceCursor(dcID, result.selected)
	}
	return manager, nil
}

func (s *gnetGenerationFactoryState) buildReplacementLink(ctx context.Context, dcID DCID) (FixedBindingSlot, error) {
	select {
	case s.repairs <- struct{}{}:
		defer func() { <-s.repairs }()
	case <-ctx.Done():
		return FixedBindingSlot{}, fmt.Errorf("%w: reserve replacement dial: %w", ErrGnetGenerationDial, context.Cause(ctx))
	}

	s.buildMu.Lock()
	endpoints := s.snapshot.Endpoints(dcID)
	if len(endpoints) == 0 {
		s.buildMu.Unlock()
		return FixedBindingSlot{}, fmt.Errorf("%w: signed DC %d has no endpoint", ErrGnetGenerationDial, dcID)
	}
	cursor := s.next[dcID]
	s.next[dcID] = nextGenerationRepairCursor(cursor, endpoints)
	s.buildMu.Unlock()

	result := s.buildSlot(ctx, dcID, cursor)
	if result.err != nil {
		return FixedBindingSlot{}, fmt.Errorf("%w: signed DC %d replacement: %w", ErrGnetGenerationDial, dcID, result.err)
	}
	return result.slot, nil
}

func nextGenerationRepairCursor(cursor generationEndpointCursor, endpoints []netip.AddrPort) generationEndpointCursor {
	var ipv4Count, ipv6Count int
	for _, endpoint := range endpoints {
		if endpoint.Addr().Unmap().Is4() {
			ipv4Count++
		} else {
			ipv6Count++
		}
	}
	if ipv4Count > 0 {
		cursor.ipv4 = (cursor.ipv4 + 1) % ipv4Count
	}
	if ipv6Count > 0 {
		cursor.ipv6 = (cursor.ipv6 + 1) % ipv6Count
	}
	return cursor
}

func offsetGenerationEndpointCursor(cursor generationEndpointCursor, offset int) generationEndpointCursor {
	cursor.ipv4 += offset
	cursor.ipv6 += offset
	return cursor
}

func (s *gnetGenerationFactoryState) buildSlot(ctx context.Context, dcID DCID, cursor generationEndpointCursor) generationSlotResult {
	candidates := generationEndpointOrder(s.snapshot.Endpoints(dcID), cursor)
	var lastErr error
	for _, candidate := range candidates {
		conn, serverAddr, clientAddr, err := s.dialer.Dial(ctx, candidate.endpoint, s.endpointDialTimeout)
		if err != nil {
			lastErr = err
			continue
		}
		if conn == nil {
			lastErr = errors.New("dialer returned a nil TCP connection")
			continue
		}

		now := s.now()
		if now.Unix() <= 0 || now.Unix() > int64(^uint32(0)>>1) {
			_ = conn.Close()
			return generationSlotResult{err: errors.New("current time is outside the Middle-End int32 timestamp range")}
		}
		processID, err := ClientProcessID(clientAddr, s.processID, s.processStartedAt)
		if err != nil {
			_ = conn.Close()
			return generationSlotResult{err: fmt.Errorf("initialize process identity: %w", err)}
		}
		secret := s.snapshot.Secret()
		bootstrap, err := NewClientBootstrap(ClientBootstrapConfig{
			Secret:          secret,
			ServerAddr:      serverAddr,
			ClientAddr:      clientAddr,
			LocalProcessID:  processID,
			ClientTimestamp: int32(now.Unix()),
		})
		clear(secret)
		if err != nil {
			_ = conn.Close()
			return generationSlotResult{err: fmt.Errorf("initialize bootstrap: %w", err)}
		}
		link, err := s.linkBuilder.NewClientLink(conn, bootstrap, s.linkLimits)
		if err != nil {
			_ = conn.Close()
			return generationSlotResult{err: fmt.Errorf("construct gnet link: %w", err)}
		}
		return generationSlotResult{
			slot:     FixedBindingSlot{DCID: dcID, SourceIP: clientAddr.Addr().Unmap(), Link: link},
			selected: candidate,
		}
	}
	if lastErr == nil {
		lastErr = errors.New("snapshot contains no usable endpoint")
	}
	return generationSlotResult{err: lastErr}
}

func (s *gnetGenerationFactoryState) advanceCursor(dcID DCID, selected generationEndpointCandidate) {
	cursor := s.next[dcID]
	switch selected.family {
	case AddressFamilyIPv4:
		cursor.ipv4 = (selected.position + 1) % selected.count
	case AddressFamilyIPv6:
		cursor.ipv6 = (selected.position + 1) % selected.count
	}
	s.next[dcID] = cursor
}

func generationEndpointOrder(endpoints []netip.AddrPort, cursor generationEndpointCursor) []generationEndpointCandidate {
	var ipv4, ipv6 []netip.AddrPort
	for _, endpoint := range endpoints {
		if endpoint.Addr().Unmap().Is4() {
			ipv4 = append(ipv4, endpoint)
		} else {
			ipv6 = append(ipv6, endpoint)
		}
	}
	ordered := make([]generationEndpointCandidate, 0, len(endpoints))
	ordered = appendRotatedEndpointFamily(ordered, ipv4, cursor.ipv4, AddressFamilyIPv4)
	ordered = appendRotatedEndpointFamily(ordered, ipv6, cursor.ipv6, AddressFamilyIPv6)
	return ordered
}

func appendRotatedEndpointFamily(
	destination []generationEndpointCandidate,
	endpoints []netip.AddrPort,
	cursor int,
	family AddressFamily,
) []generationEndpointCandidate {
	if len(endpoints) == 0 {
		return destination
	}
	start := cursor % len(endpoints)
	for offset := range len(endpoints) {
		position := (start + offset) % len(endpoints)
		destination = append(destination, generationEndpointCandidate{
			endpoint: endpoints[position],
			family:   family,
			position: position,
			count:    len(endpoints),
		})
	}
	return destination
}

func closeGenerationSlots(results []generationSlotResult) {
	for _, result := range results {
		if !nilClientLink(result.slot.Link) {
			_ = result.slot.Link.Close()
		}
	}
}

func (d productionGenerationDialer) Dial(
	ctx context.Context,
	endpoint netip.AddrPort,
	connectTimeout time.Duration,
) (*net.TCPConn, netip.AddrPort, netip.AddrPort, error) {
	dialContext, cancelDial := context.WithTimeout(ctx, connectTimeout)
	defer cancelDial()
	if d.socks5 != nil {
		conn, bound, err := d.socks5.DialContext(dialContext, endpoint.String())
		if err != nil {
			return nil, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("SOCKS5 CONNECT: %w", err)
		}
		serverAddr, clientAddr, err := SOCKS5AddressTuple(endpoint, bound)
		if err != nil {
			_ = conn.Close()
			return nil, netip.AddrPort{}, netip.AddrPort{}, err
		}
		return conn, serverAddr, clientAddr, nil
	}

	network := "tcp6"
	if endpoint.Addr().Unmap().Is4() {
		network = "tcp4"
	}
	connection, err := (&net.Dialer{}).DialContext(dialContext, network, endpoint.String())
	if err != nil {
		return nil, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("direct CONNECT: %w", err)
	}
	conn, ok := connection.(*net.TCPConn)
	if !ok {
		_ = connection.Close()
		return nil, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("direct CONNECT returned %T, want *net.TCPConn", connection)
	}
	cancelDial()
	serverAddr, clientAddr, tupleErr := DirectAddressTuple(conn, endpoint)
	if tupleErr == nil {
		return conn, serverAddr, clientAddr, nil
	}
	rawServer, rawClient, rawErr := directSocketAddressTuple(conn, endpoint)
	if rawErr != nil || validatePublicEndpoint("server", rawServer) != nil || validatePublicEndpoint("client", rawClient) == nil || d.nat == nil {
		_ = conn.Close()
		return nil, netip.AddrPort{}, netip.AddrPort{}, tupleErr
	}
	publicIP, err := d.nat.Resolve(ctx, addressFamily(rawClient.Addr()))
	if err != nil {
		_ = conn.Close()
		return nil, netip.AddrPort{}, netip.AddrPort{}, fmt.Errorf("direct NAT tuple: %w", err)
	}
	serverAddr, clientAddr, err = DirectNATAddressTuple(conn, endpoint, publicIP)
	if err != nil {
		_ = conn.Close()
		return nil, netip.AddrPort{}, netip.AddrPort{}, err
	}
	return conn, serverAddr, clientAddr, nil
}

var _ FixedBindingGenerationFactory = (*GnetGenerationFactory)(nil).Build
var _ generationLinkBuilder = (*GnetClientRuntime)(nil)
