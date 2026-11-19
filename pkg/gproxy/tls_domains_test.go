package gproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/tlsfront"
	"github.com/scratch-net/telego/pkg/transport/faketls"
)

var (
	maskKey  = []byte("0123456789abcdef")
	coverKey = []byte("fedcba9876543210")
)

func coverDomainConfig() *Config {
	return &Config{
		Secrets: []Secret{
			{Name: "mask", Key: maskKey, Host: "mask.example"},
			{Name: "cover", Key: coverKey, Host: "cover.example"},
		},
		MaskHost:            "mask.example",
		CertHost:            "mask.example",
		CertPort:            443,
		FakeCertSize:        1000,
		SpliceProxyProtocol: 1,
		TimeSkewTolerance:   time.Minute,
		Domains: []TLSDomain{{
			Host: "cover.example", CertHost: "cover.example", CertPort: 443,
			SpliceHost: "cover.example", SplicePort: 8443, FakeCertSize: 2000,
		}},
	}
}

// runClientHello feeds one ClientHello record to a fresh connection.
func runClientHello(handler *ProxyHandler, payload []byte) (*testMockGnetConn, *ConnContext) {
	connection := newTestMockGnetConn()
	ctx := NewConnContext()
	ctx.SetState(StateReadTLSPayload)
	ctx.tlsPayloadLen = len(payload)
	connection.SetContext(ctx)
	connection.SetReadData(buildTLSRecord(faketls.RecordTypeHandshake, payload))
	handler.handleTLSPayload(connection, ctx)
	return connection, ctx
}

// Each secret gets the ServerHello profile of its own cover domain.
func TestCoverDomainSelectsServerHelloProfile(t *testing.T) {
	mask := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	mask.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	mask.StartTLS()
	t.Cleanup(mask.Close)
	address := mask.Listener.Addr().(*net.TCPAddr)

	handler := NewProxyHandler(coverDomainConfig(), &testLogger{})
	if len(handler.domains) != 1 {
		t.Fatalf("domains = %d, want 1", len(handler.domains))
	}
	handler.serverHelloFetcher = tlsfront.NewServerHelloFetcher(address.IP.String(), address.Port)
	handler.domains[0].serverHelloFetcher = tlsfront.NewServerHelloFetcherSNI(address.IP.String(), address.Port, "cover.example")
	for _, fetcher := range []*tlsfront.ServerHelloFetcher{handler.serverHelloFetcher, handler.domains[0].serverHelloFetcher} {
		if err := fetcher.Refresh(); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		key      []byte
		host     string
		certSize int
	}{
		{maskKey, "mask.example", 1000},
		{coverKey, "cover.example", 2000},
		// Without SNI, the matched secret selects the profile.
		{coverKey, "", 2000},
	} {
		connection, ctx := runClientHello(handler, buildValidClientHello(tc.key, tc.host, bytes.Repeat([]byte{7}, 32)))
		if ctx.State() != StateReadO2Frame {
			t.Fatalf("%q: state = %v, want ReadO2Frame", tc.host, ctx.State())
		}
		if got := fakeCertRecordLen(t, connection.GetWrittenData()); got != tc.certSize {
			t.Fatalf("%q: fake cert record = %d bytes, want %d", tc.host, got, tc.certSize)
		}
	}
}

// fakeCertRecordLen returns the payload length of the first ApplicationData
// record of a FakeTLS ServerHello response.
func fakeCertRecordLen(t *testing.T, response []byte) int {
	t.Helper()
	for pos := 0; pos+5 <= len(response); {
		length := int(binary.BigEndian.Uint16(response[pos+3 : pos+5]))
		if response[pos] == faketls.RecordTypeApplicationData {
			return length
		}
		pos += 5 + length
	}
	t.Fatal("no ApplicationData record in response")
	return 0
}

// A fallback whose SNI names a cover domain goes to that domain's target
// with its own PROXY setting. Other fallbacks keep the old targets.
func TestCoverDomainSpliceTarget(t *testing.T) {
	cfg := coverDomainConfig()
	// Without a default splice host, startSplice closes the connection and
	// leaves the one-shot target in the context for inspection.
	cfg.SpliceHost = ""
	handler := NewProxyHandler(cfg, &testLogger{})
	handler.maskSafelist = map[string]string{"safe.example": "safe.example:443"}
	unknown := []byte("unknown-secret!!")

	for _, tc := range []struct {
		name, host, wantAddr string
		wantProtocol         int
	}{
		{"cover domain", "cover.example", "cover.example:8443", 0},
		{"cover domain case", "COVER.Example", "cover.example:8443", 0},
		{"mask host", "mask.example", "", 0},
		{"safelist", "safe.example", "safe.example:443", -1},
		{"unknown", "other.example", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ctx := runClientHello(handler, buildValidClientHello(unknown, tc.host, nil))
			addr, protocol := ctx.consumeSpliceTarget()
			if addr != tc.wantAddr || protocol != tc.wantProtocol {
				t.Fatalf("target = %q/%d, want %q/%d", addr, protocol, tc.wantAddr, tc.wantProtocol)
			}
		})
	}

	t.Run("replay", func(t *testing.T) {
		payload := buildValidClientHello(coverKey, "cover.example", nil)
		if _, ctx := runClientHello(handler, payload); ctx.State() != StateReadO2Frame {
			t.Fatalf("first hello state = %v", ctx.State())
		}
		_, ctx := runClientHello(handler, payload)
		if addr, protocol := ctx.consumeSpliceTarget(); addr != "cover.example:8443" || protocol != 0 {
			t.Fatalf("replay target = %q/%d", addr, protocol)
		}
	})
}

func TestSpliceTargetSelection(t *testing.T) {
	handler := NewProxyHandler(&Config{SpliceHost: "127.0.0.1", SplicePort: 8080, SpliceProxyProtocol: 2}, &testLogger{})
	ctx := NewConnContext()
	if addr, protocol := handler.spliceTarget(ctx); addr != "127.0.0.1:8080" || protocol != 2 {
		t.Fatalf("default = %s/%d", addr, protocol)
	}
	// The safelist keeps the configured PROXY version.
	ctx.SetSpliceOverride("safe.example:443")
	if addr, protocol := handler.spliceTarget(ctx); addr != "safe.example:443" || protocol != 2 {
		t.Fatalf("safelist = %s/%d", addr, protocol)
	}
	ctx.setSpliceTarget("cover.example:443", 0)
	if addr, protocol := handler.spliceTarget(ctx); addr != "cover.example:443" || protocol != 0 {
		t.Fatalf("cover domain = %s/%d", addr, protocol)
	}
	// The override is one-shot.
	if addr, protocol := handler.spliceTarget(ctx); addr != "127.0.0.1:8080" || protocol != 2 {
		t.Fatalf("after override = %s/%d", addr, protocol)
	}
}

// The default configuration has no extra domains and no lookups succeed.
func TestNoCoverDomainsByDefault(t *testing.T) {
	handler := NewProxyHandler(&Config{MaskHost: "mask.example"}, &testLogger{})
	if handler.domains != nil || handler.domainFor("mask.example") != nil || handler.domainFor("") != nil {
		t.Fatal("default config created cover domains")
	}
	handler.prepareDomains()
	handler.startDomainRefresh()
	handler.stopDomainRefresh()
}

// prepareDomains fetches the template and certificate of each cover domain
// from its cert target with the domain as SNI.
func TestPrepareDomainsFetchesWithDomainSNI(t *testing.T) {
	names := make(chan string, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			names <- hello.ServerName
			return nil, nil
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	address := server.Listener.Addr().(*net.TCPAddr)

	handler := NewProxyHandler(&Config{CertRefreshHours: 1, Domains: []TLSDomain{{
		Host: "cover.example", CertHost: address.IP.String(), CertPort: address.Port,
		SpliceHost: "cover.example", SplicePort: 443,
	}}}, &testLogger{})
	handler.prepareDomains()
	domain := handler.domains[0]
	if _, err := domain.serverHelloFetcher.Template(); err != nil {
		t.Fatal(err)
	}
	if cert := domain.certFetcher.CachedCert(address.IP.String(), address.Port); cert == nil {
		t.Fatal("no cached certificate")
	}
	for range 2 {
		if name := <-names; name != "cover.example" {
			t.Fatalf("SNI = %q, want cover.example", name)
		}
	}
	handler.startDomainRefresh()
	handler.stopDomainRefresh()
}
