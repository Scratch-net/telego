package middleend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type generationFactoryTestDialer struct {
	mu       sync.Mutex
	attempts []netip.AddrPort
	failures map[netip.AddrPort]error
	clients  map[netip.AddrPort]netip.AddrPort
	entered  chan netip.AddrPort
	release  <-chan struct{}
	active   atomic.Int32
	maximum  atomic.Int32
}

func (d *generationFactoryTestDialer) Dial(
	ctx context.Context,
	endpoint netip.AddrPort,
	connectTimeout time.Duration,
) (*net.TCPConn, netip.AddrPort, netip.AddrPort, error) {
	dialContext, cancelDial := context.WithTimeout(ctx, connectTimeout)
	defer cancelDial()
	d.mu.Lock()
	d.attempts = append(d.attempts, endpoint)
	failure := d.failures[endpoint]
	d.mu.Unlock()

	active := d.active.Add(1)
	defer d.active.Add(-1)
	for {
		maximum := d.maximum.Load()
		if active <= maximum || d.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	if d.entered != nil {
		d.entered <- endpoint
	}
	if d.release != nil {
		select {
		case <-d.release:
		case <-dialContext.Done():
			return nil, netip.AddrPort{}, netip.AddrPort{}, context.Cause(dialContext)
		}
	}
	if failure != nil {
		return nil, netip.AddrPort{}, netip.AddrPort{}, failure
	}
	client := d.clients[endpoint]
	if !client.IsValid() {
		client = netip.MustParseAddrPort("8.8.8.8:40000")
	}
	return new(net.TCPConn), endpoint, client, nil
}

func (d *generationFactoryTestDialer) snapshotAttempts() []netip.AddrPort {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.attempts)
}

type generationFactoryTestLinkBuilder struct {
	mu         sync.Mutex
	links      []*fixedBindingFakeLink
	bootstraps []ClientBootstrapConfig
	startErrs  []error
}

func (b *generationFactoryTestLinkBuilder) NewClientLink(
	conn *net.TCPConn,
	bootstrap *ClientBootstrap,
	_ LinkLimits,
) (ClientLink, error) {
	_ = conn.Close()
	link := newFixedBindingFakeLink()
	b.mu.Lock()
	if len(b.startErrs) > len(b.links) {
		link.startErr = b.startErrs[len(b.links)]
	}
	b.links = append(b.links, link)
	b.bootstraps = append(b.bootstraps, bootstrap.config)
	b.mu.Unlock()
	return link, nil
}

func (b *generationFactoryTestLinkBuilder) snapshotLinks() []*fixedBindingFakeLink {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.links)
}

func generationFactoryTestConfig(snapshot ArtifactSnapshot) GnetGenerationFactoryConfig {
	return GnetGenerationFactoryConfig{
		Snapshot:            snapshot,
		EndpointDialTimeout: time.Second,
		DialConcurrency:     2,
		LinksPerDC:          1,
		LinkLimits: LinkLimits{
			MaxPendingSubmissions:     8,
			MaxPendingSubmissionBytes: 8 << 20,
			MaxPendingEvents:          8,
			MaxPendingEventBytes:      8 << 20,
		},
		BindingLimits: fixedBindingTestLimits(),
	}
}

func generationFactoryTestSnapshot(endpoints map[DCID][]netip.AddrPort) ArtifactSnapshot {
	secret := make([]byte, MinimumSecretSize)
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	return ArtifactSnapshot{
		secret:    secret,
		defaultDC: 2,
		endpoints: endpoints,
		fetchedAt: time.Unix(1_700_000_000, 0),
	}
}

func newGenerationFactoryForTest(
	t *testing.T,
	snapshot ArtifactSnapshot,
	dialer generationEndpointDialer,
	builder generationLinkBuilder,
	configure func(*GnetGenerationFactoryConfig),
) *GnetGenerationFactory {
	t.Helper()
	config := generationFactoryTestConfig(snapshot)
	if configure != nil {
		configure(&config)
	}
	factory, err := newGnetGenerationFactory(
		config,
		dialer,
		builder,
		1234,
		time.Unix(1_699_999_000, 0),
		func() time.Time { return time.Unix(1_700_000_000, 0) },
	)
	if err != nil {
		t.Fatalf("newGnetGenerationFactory: %v", err)
	}
	return factory
}

func TestGnetGenerationFactoryConfigValidationAndRedaction(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.0.2.1:8888")
	snapshot := generationFactoryTestSnapshot(map[DCID][]netip.AddrPort{1: {endpoint}})
	config := generationFactoryTestConfig(snapshot)
	if _, err := NewGnetGenerationFactory(config); !errors.Is(err, ErrInvalidGnetGenerationFactory) {
		t.Fatalf("NewGnetGenerationFactory nil runtime error = %v", err)
	}

	dialer := &generationFactoryTestDialer{}
	builder := &generationFactoryTestLinkBuilder{}
	tests := []struct {
		name      string
		configure func(*GnetGenerationFactoryConfig)
		processID int
		startedAt time.Time
		now       func() time.Time
	}{
		{name: "dial timeout", configure: func(c *GnetGenerationFactoryConfig) { c.EndpointDialTimeout = 0 }, processID: 1, startedAt: time.Unix(1, 0), now: time.Now},
		{name: "dial concurrency zero", configure: func(c *GnetGenerationFactoryConfig) { c.DialConcurrency = 0 }, processID: 1, startedAt: time.Unix(1, 0), now: time.Now},
		{name: "dial concurrency ceiling", configure: func(c *GnetGenerationFactoryConfig) { c.DialConcurrency = MaxProxyClusters + 1 }, processID: 1, startedAt: time.Unix(1, 0), now: time.Now},
		{name: "links per DC", configure: func(c *GnetGenerationFactoryConfig) { c.LinksPerDC = 0 }, processID: 1, startedAt: time.Unix(1, 0), now: time.Now},
		{name: "links per DC ceiling", configure: func(c *GnetGenerationFactoryConfig) { c.LinksPerDC = MaxProxyTargets + 1 }, processID: 1, startedAt: time.Unix(1, 0), now: time.Now},
		{name: "link limits", configure: func(c *GnetGenerationFactoryConfig) { c.LinkLimits = LinkLimits{} }, processID: 1, startedAt: time.Unix(1, 0), now: time.Now},
		{name: "binding limits", configure: func(c *GnetGenerationFactoryConfig) { c.BindingLimits = FixedBindingLimits{} }, processID: 1, startedAt: time.Unix(1, 0), now: time.Now},
		{name: "process ID", processID: 0, startedAt: time.Unix(1, 0), now: time.Now},
		{name: "process start", processID: 1, startedAt: time.Time{}, now: time.Now},
		{name: "clock", processID: 1, startedAt: time.Unix(1, 0), now: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := config
			if test.configure != nil {
				test.configure(&candidate)
			}
			if _, err := newGnetGenerationFactory(candidate, dialer, builder, test.processID, test.startedAt, test.now); !errors.Is(err, ErrInvalidGnetGenerationFactory) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	empty := config
	empty.Snapshot = ArtifactSnapshot{}
	if _, err := newGnetGenerationFactory(empty, dialer, builder, 1, time.Unix(1, 0), time.Now); !errors.Is(err, ErrInvalidGnetGenerationFactory) {
		t.Fatalf("empty snapshot error = %v", err)
	}

	for _, value := range []any{config, &config, (*GnetGenerationFactory)(nil)} {
		formatted := fmt.Sprintf("%v %#v", value, value)
		if strings.Contains(formatted, endpoint.String()) || strings.Contains(formatted, "01020304") {
			t.Fatalf("format exposed nested state: %s", formatted)
		}
	}
}

func TestGenerationEndpointOrderIsIPv4FirstAndRotatesWithinFamilies(t *testing.T) {
	v4a := netip.MustParseAddrPort("192.0.2.1:8888")
	v4b := netip.MustParseAddrPort("192.0.2.2:8888")
	v6a := netip.MustParseAddrPort("[2001:db8::1]:8888")
	v6b := netip.MustParseAddrPort("[2001:db8::2]:8888")
	ordered := generationEndpointOrder(
		[]netip.AddrPort{v6a, v4a, v6b, v4b},
		generationEndpointCursor{ipv4: 1, ipv6: 1},
	)
	got := make([]netip.AddrPort, len(ordered))
	for index, candidate := range ordered {
		got[index] = candidate.endpoint
	}
	want := []netip.AddrPort{v4b, v4a, v6b, v6a}
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestGnetGenerationFactoryFallsBackAndRoundRobinsSuccessfulEndpoints(t *testing.T) {
	v4a := netip.MustParseAddrPort("192.0.2.1:8888")
	v4b := netip.MustParseAddrPort("192.0.2.2:8888")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:8888")
	snapshot := generationFactoryTestSnapshot(map[DCID][]netip.AddrPort{1: {v6, v4a, v4b}})
	dialer := &generationFactoryTestDialer{failures: map[netip.AddrPort]error{v4a: errors.New("unreachable")}}
	builder := &generationFactoryTestLinkBuilder{}
	factory := newGenerationFactoryForTest(t, snapshot, dialer, builder, nil)

	manager, err := factory.Build(t.Context())
	if err != nil {
		t.Fatalf("first Build: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if got, want := dialer.snapshotAttempts(), []netip.AddrPort{v4a, v4b}; !slices.Equal(got, want) {
		t.Fatalf("first attempts = %v, want %v", got, want)
	}

	dialer.mu.Lock()
	delete(dialer.failures, v4a)
	dialer.attempts = nil
	dialer.mu.Unlock()
	manager, err = factory.Build(t.Context())
	if err != nil {
		t.Fatalf("second Build: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got, want := dialer.snapshotAttempts(), []netip.AddrPort{v4a}; !slices.Equal(got, want) {
		t.Fatalf("second attempts = %v, want %v", got, want)
	}
}

func TestGnetGenerationFactoryRepairsOneSlotWithNextEndpoint(t *testing.T) {
	v4a := netip.MustParseAddrPort("192.0.2.1:8888")
	v4b := netip.MustParseAddrPort("192.0.2.2:8888")
	clientA := netip.MustParseAddrPort("8.8.8.8:40000")
	clientB := netip.MustParseAddrPort("9.9.9.9:50000")
	snapshot := generationFactoryTestSnapshot(map[DCID][]netip.AddrPort{2: {v4a, v4b}})
	dialer := &generationFactoryTestDialer{clients: map[netip.AddrPort]netip.AddrPort{
		v4a: clientA,
		v4b: clientB,
	}}
	builder := &generationFactoryTestLinkBuilder{}
	factory := newGenerationFactoryForTest(t, snapshot, dialer, builder, nil)

	manager, err := factory.Build(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	initialBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind initial slot: %v", err)
	}
	if got := initialBinding.SourceIP(); got != clientA.Addr() {
		t.Fatalf("initial binding source IP = %s, want %s", got, clientA.Addr())
	}
	links := builder.snapshotLinks()
	links[0].peerClose(errors.New("replace first endpoint"))
	waitFixedBindingCondition(t, func() bool { return manager.Snapshot().Slots[0].Failed })
	if err := manager.state.repairFailedSlots(t.Context()); err != nil {
		t.Fatalf("repair failed slot: %v", err)
	}

	if got, want := dialer.snapshotAttempts(), []netip.AddrPort{v4a, v4b}; !slices.Equal(got, want) {
		t.Fatalf("dial attempts = %v, want %v", got, want)
	}
	links = builder.snapshotLinks()
	if len(links) != 2 {
		t.Fatalf("constructed links = %d, want 2", len(links))
	}
	starts, _, _, _, _ := links[1].stats()
	if starts != 1 || manager.Snapshot().SlotRepairSuccesses != 1 {
		t.Fatalf("replacement starts/snapshot = %d/%+v", starts, manager.Snapshot())
	}
	repairedBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind repaired slot: %v", err)
	}
	if got := repairedBinding.SourceIP(); got != clientB.Addr() {
		t.Fatalf("repaired binding source IP = %s, want %s", got, clientB.Addr())
	}
	if err := repairedBinding.Close(); err != nil {
		t.Fatalf("Close repaired binding: %v", err)
	}
}

func TestGnetGenerationFactoryBuildsEndpointDiversePerDCPool(t *testing.T) {
	v4a := netip.MustParseAddrPort("192.0.2.1:8888")
	v4b := netip.MustParseAddrPort("192.0.2.2:8888")
	v4c := netip.MustParseAddrPort("192.0.2.3:8888")
	snapshot := generationFactoryTestSnapshot(map[DCID][]netip.AddrPort{2: {v4a, v4b, v4c}})
	dialer := &generationFactoryTestDialer{clients: map[netip.AddrPort]netip.AddrPort{
		v4a: netip.MustParseAddrPort("8.8.8.8:40000"),
		v4b: netip.MustParseAddrPort("9.9.9.9:40001"),
		v4c: netip.MustParseAddrPort("1.1.1.1:40002"),
	}}
	builder := &generationFactoryTestLinkBuilder{}
	factory := newGenerationFactoryForTest(t, snapshot, dialer, builder, func(config *GnetGenerationFactoryConfig) {
		config.LinksPerDC = 2
		config.DialConcurrency = 1
	})

	first, err := factory.Build(t.Context())
	if err != nil {
		t.Fatalf("first Build: %v", err)
	}
	if got := len(first.state.slotGroups[2]); got != 2 {
		t.Fatalf("first pool links = %d, want 2", got)
	}
	if err := first.Start(t.Context()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	firstBinding, err := first.Bind(2)
	if err != nil {
		t.Fatalf("first Bind: %v", err)
	}
	secondBinding, err := first.Bind(2)
	if err != nil {
		t.Fatalf("second Bind: %v", err)
	}
	if firstBinding.SourceIP() != dialer.clients[v4a].Addr() || secondBinding.SourceIP() != dialer.clients[v4b].Addr() {
		t.Fatalf("pooled source IPs = %s/%s", firstBinding.SourceIP(), secondBinding.SourceIP())
	}
	if err := firstBinding.Close(); err != nil {
		t.Fatalf("Close first binding: %v", err)
	}
	if err := secondBinding.Close(); err != nil {
		t.Fatalf("Close second binding: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if got, want := dialer.snapshotAttempts(), []netip.AddrPort{v4a, v4b}; !slices.Equal(got, want) {
		t.Fatalf("first attempts = %v, want %v", got, want)
	}

	dialer.mu.Lock()
	dialer.attempts = nil
	dialer.mu.Unlock()
	second, err := factory.Build(t.Context())
	if err != nil {
		t.Fatalf("second Build: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got, want := dialer.snapshotAttempts(), []netip.AddrPort{v4c, v4a}; !slices.Equal(got, want) {
		t.Fatalf("second attempts = %v, want %v", got, want)
	}
}

func TestGnetGenerationFactoryAdvancesEndpointBeforeManagerStart(t *testing.T) {
	v4a := netip.MustParseAddrPort("192.0.2.1:8888")
	v4b := netip.MustParseAddrPort("192.0.2.2:8888")
	snapshot := generationFactoryTestSnapshot(map[DCID][]netip.AddrPort{1: {v4a, v4b}})
	dialer := &generationFactoryTestDialer{}
	builder := &generationFactoryTestLinkBuilder{startErrs: []error{errors.New("bootstrap failed")}}
	factory := newGenerationFactoryForTest(t, snapshot, dialer, builder, nil)

	manager, err := factory.Build(t.Context())
	if err != nil {
		t.Fatalf("first Build: %v", err)
	}
	if err := manager.Start(t.Context()); !errors.Is(err, ErrFixedBindingInitialFailure) {
		t.Fatalf("first Start error = %v", err)
	}

	manager, err = factory.Build(t.Context())
	if err != nil {
		t.Fatalf("second Build: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got, want := dialer.snapshotAttempts(), []netip.AddrPort{v4a, v4b}; !slices.Equal(got, want) {
		t.Fatalf("attempts = %v, want %v", got, want)
	}
}

func TestGnetGenerationFactoryBoundsDialConcurrency(t *testing.T) {
	endpoints := make(map[DCID][]netip.AddrPort)
	for index := range 6 {
		dcID := DCID(index + 1)
		endpoint := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}), 8888)
		endpoints[dcID] = []netip.AddrPort{endpoint}
	}
	release := make(chan struct{})
	dialer := &generationFactoryTestDialer{
		entered: make(chan netip.AddrPort, len(endpoints)),
		release: release,
	}
	builder := &generationFactoryTestLinkBuilder{}
	factory := newGenerationFactoryForTest(t, generationFactoryTestSnapshot(endpoints), dialer, builder, func(config *GnetGenerationFactoryConfig) {
		config.DialConcurrency = 2
	})

	type buildResult struct {
		manager *FixedBindingManager
		err     error
	}
	result := make(chan buildResult, 1)
	go func() {
		manager, err := factory.Build(t.Context())
		result <- buildResult{manager: manager, err: err}
	}()
	for range 2 {
		select {
		case <-dialer.entered:
		case <-t.Context().Done():
			t.Fatal("timed out waiting for bounded dial workers")
		}
	}
	select {
	case endpoint := <-dialer.entered:
		t.Fatalf("third dial started before a worker was released: %s", endpoint)
	case <-time.After(25 * time.Millisecond):
	}
	if maximum := dialer.maximum.Load(); maximum != 2 {
		t.Fatalf("maximum concurrent dials = %d, want 2", maximum)
	}
	close(release)
	built := <-result
	if built.err != nil {
		t.Fatalf("Build: %v", built.err)
	}
	if err := built.manager.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestGnetGenerationFactoryClosesPartialGeneration(t *testing.T) {
	dc1 := netip.MustParseAddrPort("192.0.2.1:8888")
	dc2 := netip.MustParseAddrPort("192.0.2.2:8888")
	dialer := &generationFactoryTestDialer{failures: map[netip.AddrPort]error{dc2: errors.New("refused")}}
	builder := &generationFactoryTestLinkBuilder{}
	factory := newGenerationFactoryForTest(
		t,
		generationFactoryTestSnapshot(map[DCID][]netip.AddrPort{1: {dc1}, 2: {dc2}}),
		dialer,
		builder,
		func(config *GnetGenerationFactoryConfig) { config.DialConcurrency = 1 },
	)
	manager, err := factory.Build(t.Context())
	if manager != nil || !errors.Is(err, ErrGnetGenerationDial) {
		t.Fatalf("Build = (%v, %v)", manager, err)
	}
	links := builder.snapshotLinks()
	if len(links) != 1 {
		t.Fatalf("constructed links = %d, want 1", len(links))
	}
	links[0].mu.Lock()
	closeCalls := links[0].closeCalls
	links[0].mu.Unlock()
	if closeCalls != 1 {
		t.Fatalf("partial link Close calls = %d, want 1", closeCalls)
	}
}

func TestGnetGenerationFactoryEndpointTimeoutCancelsEveryWorker(t *testing.T) {
	endpoints := map[DCID][]netip.AddrPort{
		1: {netip.MustParseAddrPort("192.0.2.1:8888")},
		2: {netip.MustParseAddrPort("192.0.2.2:8888")},
	}
	release := make(chan struct{})
	dialer := &generationFactoryTestDialer{release: release}
	builder := &generationFactoryTestLinkBuilder{}
	factory := newGenerationFactoryForTest(t, generationFactoryTestSnapshot(endpoints), dialer, builder, func(config *GnetGenerationFactoryConfig) {
		config.EndpointDialTimeout = 20 * time.Millisecond
	})
	started := time.Now()
	manager, err := factory.Build(t.Context())
	if manager != nil || !errors.Is(err, ErrGnetGenerationDial) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Build = (%v, %v)", manager, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Build took %v after endpoint deadlines", elapsed)
	}
	if active := dialer.active.Load(); active != 0 {
		t.Fatalf("active dials after Build = %d", active)
	}
}
