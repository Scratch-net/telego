package middleend

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type stalledGenerationDialer struct {
	first    netip.AddrPort
	winner   netip.AddrPort
	client   netip.AddrPort
	active   atomic.Int32
	fallback atomic.Bool
}

func (d *stalledGenerationDialer) Dial(ctx context.Context, endpoint netip.AddrPort, _ time.Duration) (*net.TCPConn, netip.AddrPort, netip.AddrPort, error) {
	d.active.Add(1)
	defer d.active.Add(-1)
	if endpoint == d.first {
		<-ctx.Done()
		return nil, netip.AddrPort{}, netip.AddrPort{}, context.Cause(ctx)
	}
	if endpoint != d.winner {
		d.fallback.Store(true)
		return nil, netip.AddrPort{}, netip.AddrPort{}, errors.New("unexpected family or DC")
	}
	return new(net.TCPConn), endpoint, d.client, nil
}

func TestGenerationStaggeredDialPreservesSignedDCAndSelectedTuple(t *testing.T) {
	first := netip.MustParseAddrPort("192.0.2.1:8888")
	winner := netip.MustParseAddrPort("192.0.2.2:8888")
	ipv6 := netip.MustParseAddrPort("[2001:db8::1]:8888")
	client := netip.MustParseAddrPort("9.9.9.9:45000")
	dialer := &stalledGenerationDialer{first: first, winner: winner, client: client}
	builder := new(generationFactoryTestLinkBuilder)
	factory := newGenerationFactoryForTest(t, generationFactoryTestSnapshot(map[DCID][]netip.AddrPort{-2: {first, winner, ipv6}}), dialer, builder, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	manager, err := factory.Build(ctx)
	if err != nil {
		t.Fatalf("stalled first endpoint prevented healthy fallback: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	if dialer.active.Load() != 0 || dialer.fallback.Load() {
		t.Fatal("dial retained a loser or crossed the address-family boundary")
	}
	if len(builder.bootstraps) != 1 || builder.bootstraps[0].ServerAddr != winner || builder.bootstraps[0].ClientAddr != client {
		t.Fatalf("bootstrap did not preserve selected endpoint and bound tuple: %+v", builder.bootstraps)
	}
	if slots := manager.Snapshot().Slots; len(slots) != 1 || slots[0].DCID != -2 {
		t.Fatalf("signed DC changed: %+v", slots)
	}
}

func TestGenerationStaggeredDialKeepsGlobalBudget(t *testing.T) {
	endpoints := map[DCID][]netip.AddrPort{
		-2: {netip.MustParseAddrPort("192.0.2.1:8888"), netip.MustParseAddrPort("192.0.2.2:8888")},
		2:  {netip.MustParseAddrPort("192.0.2.3:8888"), netip.MustParseAddrPort("192.0.2.4:8888")},
	}
	dialer := &generationFactoryTestDialer{entered: make(chan netip.AddrPort, 4), release: make(chan struct{})}
	factory := newGenerationFactoryForTest(t, generationFactoryTestSnapshot(endpoints), dialer, new(generationFactoryTestLinkBuilder), nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		manager, err := factory.Build(ctx)
		if manager != nil {
			_ = manager.Close()
		}
		done <- err
	}()
	for range 2 {
		select {
		case <-dialer.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("initial attempts did not start")
		}
	}
	select {
	case <-dialer.entered:
		t.Fatal("fallback exceeded the global dial budget")
	case <-time.After(350 * time.Millisecond):
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want canceled", err)
	}
	if dialer.maximum.Load() != 2 || dialer.active.Load() != 0 {
		t.Fatalf("maximum/remaining attempts = %d/%d", dialer.maximum.Load(), dialer.active.Load())
	}
}
