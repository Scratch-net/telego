package gproxy

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	errorx "github.com/panjf2000/gnet/v2/pkg/errors"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestPreparedFrontingServesLogicalTLSBeforePublicBoot(t *testing.T) {
	mask := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(mask.Close)
	address := mask.Listener.Addr().(*net.TCPAddr)
	key := []byte("0123456789abcdef")
	handler := NewProxyHandler(&Config{
		Secrets:           []Secret{{Name: "test", Key: key, Host: "example.com"}},
		TimeSkewTolerance: time.Minute,
		MaskHost:          "example.com",
		FetchRealCert:     true,
		CertHost:          address.IP.String(),
		CertPort:          address.Port,
	}, &testLogger{})
	handler.prepareFrontends()
	t.Cleanup(func() { _ = handler.stopServing() })
	certFetcher, helloFetcher := handler.certFetcher, handler.serverHelloFetcher
	if certFetcher == nil || helloFetcher == nil {
		t.Fatal("fronting dependencies were not initialized before publication")
	}
	// Closing the fixture proves that both preparation fetches completed and
	// the early logical handshake can use the caches without startup work.
	mask.Close()
	if cert, err := certFetcher.FetchCert(address.IP.String(), address.Port); err != nil || len(cert.Chain) == 0 {
		t.Fatalf("certificate cache was not warmed: %v", err)
	}
	if hello, _, err := helloFetcher.GetServerHelloTemplate(); err != nil || len(hello) == 0 {
		t.Fatalf("ServerHello cache was not warmed: %v", err)
	}
	stream := newLogicalTestStream(t, handler, nil)
	stream.fakeTLSHello(t, key)
	handler.OnBoot(gnet.Engine{})
	if handler.certFetcher != certFetcher || handler.serverHelloFetcher != helloFetcher {
		t.Fatal("public boot replaced already-published fronting dependencies")
	}
}

type startupReadinessSource struct {
	readyCalls atomic.Int32
	started    chan struct{}
	ready      chan struct{}
	done       chan struct{}
}

func (*startupReadinessSource) BindReady(middleend.DCID) (*middleend.ClientBinding, error) {
	return nil, errors.New("test source has no binding")
}

func (s *startupReadinessSource) Ready() <-chan struct{} {
	if s.readyCalls.Add(1) == 1 {
		close(s.started)
	}
	return s.ready
}

func (*startupReadinessSource) TryNextReady() *middleend.ClientReadyToken { return nil }
func (s *startupReadinessSource) Done() <-chan struct{}                   { return s.done }

func TestPreparedMiddleEndHasOneConsumerAndStopsOnPublicStartupFailure(t *testing.T) {
	source := &startupReadinessSource{
		started: make(chan struct{}), ready: make(chan struct{}), done: make(chan struct{}),
	}
	frontend := middleEndTestFrontendConfig(t, nil)
	frontend.Source = source
	handler, err := NewProxyHandlerWithMiddleEnd(&Config{}, &testLogger{}, frontend)
	if err != nil {
		t.Fatal(err)
	}
	handler.prepareFrontends()
	t.Cleanup(func() { _ = handler.stopServing() })
	select {
	case <-source.started:
	case <-time.After(3 * time.Second):
		t.Fatal("ME consumer still depends on public OnBoot")
	}
	// Existing embedders can still call OnBoot; preparation and callback must
	// share the same startOnce, not consume readiness on separate goroutines.
	for range 3 {
		handler.OnBoot(gnet.Engine{})
	}
	if err := handler.runPublicEngine(handler, "tulip://howdy"); !errors.Is(err, errorx.ErrUnsupportedProtocol) {
		t.Fatalf("expected pre-boot public startup failure, got %v", err)
	}
	// runPublicEngine has joined the consumer, so this is a terminal count,
	// not a timing-based assertion that another consumer has not started yet.
	if calls := source.readyCalls.Load(); calls != 1 {
		t.Fatalf("readiness consumer started %d times", calls)
	}
	select {
	case <-handler.middleEnd.stopCh:
	default:
		t.Fatal("failed public startup left the ME consumer running")
	}
	if handler.upstreamContext.Err() == nil {
		t.Fatal("failed public startup did not reject further logical admission")
	}
}
