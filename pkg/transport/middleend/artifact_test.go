package middleend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseArtifactSnapshot(t *testing.T) {
	raw := fixtureArtifacts(t)
	fetchedAt := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	snapshot, err := parseArtifactSnapshot(raw, fetchedAt)
	if err != nil {
		t.Fatalf("parse artifact snapshot: %v", err)
	}

	if got, want := snapshot.DefaultDC(), DCID(2); got != want {
		t.Fatalf("default DC = %d, want %d", got, want)
	}
	if got := snapshot.FetchedAt(); !got.Equal(fetchedAt) {
		t.Fatalf("fetched at = %v, want %v", got, fetchedAt)
	}
	wantDCIDs := []DCID{-203, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 203}
	if got, want := snapshot.DCIDs(), wantDCIDs; !slices.Equal(got, want) {
		t.Fatalf("DC IDs = %v, want %v", got, want)
	}

	dc4 := snapshot.Endpoints(4)
	wantDC4 := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.14:8888"),
		netip.MustParseAddrPort("203.0.113.44:8888"),
		netip.MustParseAddrPort("[2001:db8:1::14]:8888"),
	}
	if !slices.Equal(dc4, wantDC4) {
		t.Fatalf("DC 4 endpoints = %v, want %v", dc4, wantDC4)
	}
	if got := snapshot.Endpoints(-203); len(got) != 1 || !got[0].Addr().Is4() {
		t.Fatalf("DC -203 endpoints = %v, want one IPv4 endpoint", got)
	}
	if got := snapshot.Endpoints(99); got != nil {
		t.Fatalf("unsupported DC endpoints = %v, want nil", got)
	}
}

func TestArtifactSnapshotDefensiveCopies(t *testing.T) {
	raw := fixtureArtifacts(t)
	snapshot, err := parseArtifactSnapshot(raw, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("parse artifact snapshot: %v", err)
	}
	originalSecretByte := snapshot.Secret()[0]
	raw.Secret[0] ^= 0xff
	if got := snapshot.Secret()[0]; got != originalSecretByte {
		t.Fatalf("snapshot secret changed through raw input: got %x, want %x", got, originalSecretByte)
	}

	secret := snapshot.Secret()
	secret[0] ^= 0xff
	if got := snapshot.Secret()[0]; got != originalSecretByte {
		t.Fatalf("snapshot secret changed through accessor: got %x, want %x", got, originalSecretByte)
	}

	endpoints := snapshot.Endpoints(1)
	originalEndpoint := endpoints[0]
	endpoints[0] = netip.MustParseAddrPort("192.0.2.250:1")
	if got := snapshot.Endpoints(1)[0]; got != originalEndpoint {
		t.Fatalf("snapshot endpoint changed through accessor: got %s, want %s", got, originalEndpoint)
	}

	dcs := snapshot.DCIDs()
	dcs[0] = 1
	if got := snapshot.DCIDs()[0]; got != -203 {
		t.Fatalf("snapshot DC list changed through accessor: first = %d", got)
	}

}

func TestArtifactFormattingRedactsPayloads(t *testing.T) {
	const (
		secretMarker = "SECRET_MATERIAL_MUST_NOT_APPEAR"
		configMarker = "FULL_CONFIG_BODY_MUST_NOT_APPEAR"
	)
	raw := RawArtifacts{
		Secret:     []byte(secretMarker),
		IPv4Config: []byte(configMarker + "_V4"),
		IPv6Config: []byte(configMarker + "_V6"),
	}
	snapshot := ArtifactSnapshot{
		secret:    []byte(secretMarker),
		defaultDC: 2,
		endpoints: map[DCID][]netip.AddrPort{2: {netip.MustParseAddrPort("192.0.2.1:443")}},
		fetchedAt: time.Unix(1, 0),
	}
	type enclosing struct {
		Raw      RawArtifacts
		RawPtr   *RawArtifacts
		Snapshot ArtifactSnapshot
		SnapPtr  *ArtifactSnapshot
	}

	values := map[string]any{
		"raw value":      raw,
		"raw pointer":    &raw,
		"snapshot value": snapshot,
		"snapshot ptr":   &snapshot,
		"enclosing value": enclosing{
			Raw: raw, RawPtr: &raw, Snapshot: snapshot, SnapPtr: &snapshot,
		},
		"enclosing pointer": &enclosing{
			Raw: raw, RawPtr: &raw, Snapshot: snapshot, SnapPtr: &snapshot,
		},
	}
	for name, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, secretMarker) || strings.Contains(output, configMarker) {
				t.Fatalf("%s with %s leaked payload: %s", name, format, output)
			}
			if !strings.Contains(output, "redacted") {
				t.Fatalf("%s with %s was not visibly redacted: %s", name, format, output)
			}
			if len(output) > 256 {
				t.Fatalf("%s with %s produced %d bytes", name, format, len(output))
			}
		}
	}

	var nilRaw *RawArtifacts
	var nilSnapshot *ArtifactSnapshot
	for name, value := range map[string]any{"nil raw": nilRaw, "nil snapshot": nilSnapshot} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, secretMarker) || strings.Contains(output, configMarker) {
				t.Fatalf("%s with %s leaked payload: %s", name, format, output)
			}
		}
	}
}

func TestParseArtifactSecretBounds(t *testing.T) {
	for _, size := range []int{MinimumSecretSize, MaximumSecretSize} {
		secret := deterministicSecret(size)
		got, err := parseArtifactSecret(secret)
		if err != nil {
			t.Fatalf("parse %d-byte secret: %v", size, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("parsed %d-byte secret differs", size)
		}
		got[0] ^= 0xff
		if bytes.Equal(got, secret) {
			t.Fatalf("parsed %d-byte secret aliases input", size)
		}
	}

	for _, size := range []int{0, MinimumSecretSize - 1, MaximumSecretSize + 1} {
		if _, err := parseArtifactSecret(deterministicSecret(size)); !errors.Is(err, ErrIncompleteArtifacts) {
			t.Fatalf("parse %d-byte secret error = %v, want ErrIncompleteArtifacts", size, err)
		}
	}
	zeroSelector := bytes.Repeat([]byte{0x44}, MinimumSecretSize)
	clear(zeroSelector[:4])
	if _, err := parseArtifactSecret(zeroSelector); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("zero-selector secret error = %v, want ErrInvalidSecret", err)
	}
}

func TestParseProxyConfigWhitespaceCommentsAndSignedIDs(t *testing.T) {
	data := []byte("# first\r\n\tdefault 203 ; # default\nproxy_for\t-203\t192.0.2.1:443 # endpoint\n;\nproxy_for 203 198.51.100.2:8888;\n")
	config, err := parseProxyConfig(data, configIPv4)
	if err != nil {
		t.Fatalf("parse proxy config: %v", err)
	}
	if !config.hasDefault || config.defaultDC != 203 {
		t.Fatalf("default = (%t, %d), want (true, 203)", config.hasDefault, config.defaultDC)
	}
	if got := config.endpoints[-203]; len(got) != 1 || got[0] != netip.MustParseAddrPort("192.0.2.1:443") {
		t.Fatalf("DC -203 endpoints = %v", got)
	}
	if got := config.endpoints[203]; len(got) != 1 || got[0] != netip.MustParseAddrPort("198.51.100.2:8888") {
		t.Fatalf("DC 203 endpoints = %v", got)
	}
}

func TestParseProxyConfigRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		family configFamily
	}{
		{name: "empty", data: "", family: configIPv4},
		{name: "comments only", data: "# no targets\n", family: configIPv4},
		{name: "unknown directive", data: "upstream 192.0.2.1:80;", family: configIPv4},
		{name: "long directive", data: "proxy_for_extra 1 192.0.2.1:80;", family: configIPv4},
		{name: "missing semicolon", data: "proxy_for 1 192.0.2.1:80", family: configIPv4},
		{name: "missing semicolon separator", data: "proxy_for 1 192.0.2.1:80 default 1;", family: configIPv4},
		{name: "newline before DC", data: "proxy_for\n1 192.0.2.1:80;", family: configIPv4},
		{name: "newline before endpoint", data: "proxy_for 1\n192.0.2.1:80;", family: configIPv4},
		{name: "plus sign", data: "proxy_for +1 192.0.2.1:80;", family: configIPv4},
		{name: "int16 overflow", data: "proxy_for 32768 192.0.2.1:80;", family: configIPv4},
		{name: "long DC token", data: "proxy_for 111111111111111111 192.0.2.1:80;", family: configIPv4},
		{name: "hostname", data: "proxy_for 1 example.com:80;", family: configIPv4},
		{name: "long endpoint", data: "proxy_for 1 " + strings.Repeat("1", 71) + ";", family: configIPv4},
		{name: "zero port", data: "proxy_for 1 192.0.2.1:0;", family: configIPv4},
		{name: "unspecified IPv4", data: "proxy_for 1 0.0.0.0:80;", family: configIPv4},
		{name: "IPv6 in IPv4", data: "proxy_for 1 [2001:db8::1]:80;", family: configIPv4},
		{name: "IPv4 in IPv6", data: "proxy_for 1 192.0.2.1:80;", family: configIPv6},
		{name: "IPv4 mapped in IPv6", data: "proxy_for 1 [::ffff:192.0.2.1]:80;", family: configIPv6},
		{name: "zoned IPv6", data: "proxy_for 1 [fe80::1%eth0]:80;", family: configIPv6},
		{name: "duplicate default", data: "default 1; default 2; proxy_for 1 192.0.2.1:80;", family: configIPv4},
		{name: "intermixed DC targets", data: "proxy_for 1 192.0.2.1:80; proxy_for 2 192.0.2.2:80; proxy_for 1 192.0.2.3:80;", family: configIPv4},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseProxyConfig([]byte(test.data), test.family); !errors.Is(err, ErrInvalidProxyConfig) {
				t.Fatalf("error = %v, want ErrInvalidProxyConfig", err)
			}
		})
	}

	tooLarge := bytes.Repeat([]byte{'#'}, MaxProxyConfigSize+1)
	if _, err := parseProxyConfig(tooLarge, configIPv4); !errors.Is(err, ErrInvalidProxyConfig) {
		t.Fatalf("oversized config error = %v, want ErrInvalidProxyConfig", err)
	}
	if _, err := parseProxyConfig([]byte("proxy_for 1 192.0.2.1:80;"), 99); !errors.Is(err, ErrInvalidProxyConfig) {
		t.Fatalf("invalid family error = %v, want ErrInvalidProxyConfig", err)
	}
}

func TestParseProxyConfigAcceptsSignedInt16Clusters(t *testing.T) {
	for _, dc := range []DCID{-32768, -203, -6, 0, 6, 203, 1234, 32767} {
		t.Run(fmt.Sprintf("dc_%d", dc), func(t *testing.T) {
			data := fmt.Appendf(nil, "proxy_for %d 192.0.2.1:80;", dc)
			config, err := parseProxyConfig(data, configIPv4)
			if err != nil {
				t.Fatalf("parse DC %d: %v", dc, err)
			}
			if got := config.endpoints[dc]; len(got) != 1 {
				t.Fatalf("DC %d endpoints = %v, want one", dc, got)
			}
		})
	}

	config, err := parseProxyConfig([]byte("proxy 192.0.2.2:443;"), configIPv4)
	if err != nil {
		t.Fatalf("parse implicit DC 0 proxy: %v", err)
	}
	if got := config.endpoints[0]; len(got) != 1 {
		t.Fatalf("implicit DC 0 endpoints = %v, want one", got)
	}
}

func TestParseProxyConfigClusterLimit(t *testing.T) {
	var config strings.Builder
	for index := range MaxProxyClusters {
		dc := index - MaxProxyClusters/2
		_, _ = fmt.Fprintf(&config, "proxy_for %d 192.0.2.1:80;\n", dc)
	}
	parsed, err := parseProxyConfig([]byte(config.String()), configIPv4)
	if err != nil {
		t.Fatalf("parse config at cluster limit: %v", err)
	}
	if got := len(parsed.endpoints); got != MaxProxyClusters {
		t.Fatalf("clusters = %d, want %d", got, MaxProxyClusters)
	}
	_, _ = fmt.Fprintf(&config, "proxy_for %d 192.0.2.1:80;\n", MaxProxyClusters/2)
	if _, err := parseProxyConfig([]byte(config.String()), configIPv4); !errors.Is(err, ErrInvalidProxyConfig) {
		t.Fatalf("over-limit error = %v, want ErrInvalidProxyConfig", err)
	}
}

func TestParseProxyConfigTargetLimit(t *testing.T) {
	line := "proxy_for 1 192.0.2.1:80;\n"
	atLimit := strings.Repeat(line, MaxProxyTargets)
	config, err := parseProxyConfig([]byte(atLimit), configIPv4)
	if err != nil {
		t.Fatalf("parse config at target limit: %v", err)
	}
	if got := len(config.endpoints[1]); got != MaxProxyTargets {
		t.Fatalf("targets = %d, want %d", got, MaxProxyTargets)
	}
	if _, err := parseProxyConfig([]byte(atLimit+line), configIPv4); !errors.Is(err, ErrInvalidProxyConfig) {
		t.Fatalf("over-limit error = %v, want ErrInvalidProxyConfig", err)
	}
}

func TestParseArtifactSnapshotRejectsPartialGeneration(t *testing.T) {
	raw := fixtureArtifacts(t)
	tests := []struct {
		name   string
		mutate func(*RawArtifacts)
	}{
		{name: "no IPv4 default", mutate: func(raw *RawArtifacts) {
			raw.IPv4Config = bytes.Replace(raw.IPv4Config, []byte("default 2;"), []byte("# no default"), 1)
		}},
		{name: "default has no endpoint", mutate: func(raw *RawArtifacts) {
			raw.IPv4Config = bytes.Replace(raw.IPv4Config, []byte("default 2;"), []byte("default 1234;"), 1)
		}},
		{name: "mismatched IPv6 default", mutate: func(raw *RawArtifacts) {
			raw.IPv6Config = append([]byte("default 3;\n"), raw.IPv6Config...)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := RawArtifacts{
				Secret:     slices.Clone(raw.Secret),
				IPv4Config: slices.Clone(raw.IPv4Config),
				IPv6Config: slices.Clone(raw.IPv6Config),
			}
			test.mutate(&candidate)
			if _, err := parseArtifactSnapshot(candidate, time.Unix(1, 0)); !errors.Is(err, ErrIncompleteArtifacts) {
				t.Fatalf("error = %v, want ErrIncompleteArtifacts", err)
			}
		})
	}
}

func TestParseArtifactSnapshotAcceptsAdditiveAndAsymmetricClusters(t *testing.T) {
	t.Run("extra signed DC", func(t *testing.T) {
		raw := fixtureArtifacts(t)
		raw.IPv4Config = append(raw.IPv4Config, []byte("proxy_for 1234 203.0.113.123:443;\n")...)
		snapshot, err := parseArtifactSnapshot(raw, time.Unix(1, 0))
		if err != nil {
			t.Fatalf("parse extra DC: %v", err)
		}
		if got := snapshot.Endpoints(1234); len(got) != 1 || got[0] != netip.MustParseAddrPort("203.0.113.123:443") {
			t.Fatalf("DC 1234 endpoints = %v", got)
		}
	})

	t.Run("withdraw one IPv6 cluster", func(t *testing.T) {
		raw := fixtureArtifacts(t)
		raw.IPv6Config = bytes.Replace(raw.IPv6Config, []byte("proxy_for -5 [2001:db8::15]:8888;"), []byte("# withdrawn -5"), 1)
		snapshot, err := parseArtifactSnapshot(raw, time.Unix(1, 0))
		if err != nil {
			t.Fatalf("parse withdrawn IPv6 cluster: %v", err)
		}
		if got := snapshot.Endpoints(-5); len(got) != 1 || !got[0].Addr().Is4() {
			t.Fatalf("DC -5 endpoints = %v, want one IPv4 endpoint", got)
		}
	})

	t.Run("withdraw entire cluster", func(t *testing.T) {
		raw := fixtureArtifacts(t)
		raw.IPv4Config = bytes.Replace(raw.IPv4Config, []byte("proxy_for -203 192.0.2.203:443;"), []byte("# withdrawn -203"), 1)
		snapshot, err := parseArtifactSnapshot(raw, time.Unix(1, 0))
		if err != nil {
			t.Fatalf("parse withdrawn cluster: %v", err)
		}
		if got := snapshot.Endpoints(-203); got != nil {
			t.Fatalf("withdrawn DC -203 endpoints = %v, want nil", got)
		}
	})

	t.Run("IPv6 supplies default", func(t *testing.T) {
		raw := fixtureArtifacts(t)
		raw.IPv4Config = bytes.Replace(raw.IPv4Config, []byte("default 2;"), []byte("# default moved"), 1)
		raw.IPv6Config = append([]byte("default 2;\n"), raw.IPv6Config...)
		snapshot, err := parseArtifactSnapshot(raw, time.Unix(1, 0))
		if err != nil {
			t.Fatalf("parse IPv6 default: %v", err)
		}
		if got := snapshot.DefaultDC(); got != 2 {
			t.Fatalf("default DC = %d, want 2", got)
		}
	})

	t.Run("default endpoint supplied by other family", func(t *testing.T) {
		raw := RawArtifacts{
			Secret:     deterministicSecret(32),
			IPv4Config: []byte("default 2; proxy_for 1 192.0.2.1:443;"),
			IPv6Config: []byte("proxy_for 2 [2001:db8::2]:443;"),
		}
		snapshot, err := parseArtifactSnapshot(raw, time.Unix(1, 0))
		if err != nil {
			t.Fatalf("parse cross-family default endpoint: %v", err)
		}
		if got := snapshot.Endpoints(2); len(got) != 1 || !got[0].Addr().Is6() {
			t.Fatalf("default DC endpoints = %v, want one IPv6 endpoint", got)
		}
	})

	t.Run("implicit default zero", func(t *testing.T) {
		raw := RawArtifacts{
			Secret:     deterministicSecret(32),
			IPv4Config: []byte("proxy 192.0.2.1:443;"),
			IPv6Config: []byte("proxy [2001:db8::1]:443;"),
		}
		snapshot, err := parseArtifactSnapshot(raw, time.Unix(1, 0))
		if err != nil {
			t.Fatalf("parse implicit default: %v", err)
		}
		if got := snapshot.DefaultDC(); got != 0 {
			t.Fatalf("default DC = %d, want 0", got)
		}
	})
}

func TestParseArtifactSnapshotCombinedClusterLimit(t *testing.T) {
	var ipv4 strings.Builder
	ipv4.WriteString("default -1000;\n")
	for dc := -1000; dc < -400; dc++ {
		_, _ = fmt.Fprintf(&ipv4, "proxy_for %d 192.0.2.1:443;\n", dc)
	}
	var ipv6 strings.Builder
	for dc := 1000; dc < 1600; dc++ {
		_, _ = fmt.Fprintf(&ipv6, "proxy_for %d [2001:db8::1]:443;\n", dc)
	}
	raw := RawArtifacts{
		Secret:     deterministicSecret(32),
		IPv4Config: []byte(ipv4.String()),
		IPv6Config: []byte(ipv6.String()),
	}
	if _, err := parseArtifactSnapshot(raw, time.Unix(1, 0)); !errors.Is(err, ErrIncompleteArtifacts) {
		t.Fatalf("combined over-limit error = %v, want ErrIncompleteArtifacts", err)
	}
}

func TestHTTPArtifactSourceFetch(t *testing.T) {
	raw := fixtureArtifacts(t)
	var mu sync.Mutex
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests[request.URL.Path]++
		mu.Unlock()
		switch request.URL.Path {
		case "/secret":
			_, _ = writer.Write(raw.Secret)
		case "/v4":
			_, _ = writer.Write(raw.IPv4Config)
		case "/v6":
			_, _ = writer.Write(raw.IPv6Config)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	source, err := newHTTPArtifactSource(server.Client(), artifactURLs{
		secret: server.URL + "/secret",
		ipv4:   server.URL + "/v4",
		ipv6:   server.URL + "/v6",
	})
	if err != nil {
		t.Fatalf("new HTTP artifact source: %v", err)
	}
	got, err := source.Fetch(t.Context())
	if err != nil {
		t.Fatalf("fetch artifacts: %v", err)
	}
	if !bytes.Equal(got.Secret, raw.Secret) || !bytes.Equal(got.IPv4Config, raw.IPv4Config) || !bytes.Equal(got.IPv6Config, raw.IPv6Config) {
		t.Fatal("fetched artifacts differ from responses")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/secret", "/v4", "/v6"} {
		if got := requests[path]; got != 1 {
			t.Fatalf("requests to %s = %d, want 1", path, got)
		}
	}
}

func TestHTTPArtifactSourceRejectsStatusAndOversize(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()
		source, err := newHTTPArtifactSource(server.Client(), artifactURLs{secret: server.URL, ipv4: server.URL, ipv6: server.URL})
		if err != nil {
			t.Fatalf("new HTTP artifact source: %v", err)
		}
		got, err := source.Fetch(t.Context())
		if !errors.Is(err, ErrArtifactFetch) {
			t.Fatalf("error = %v, want ErrArtifactFetch", err)
		}
		if got.Secret != nil || got.IPv4Config != nil || got.IPv6Config != nil {
			t.Fatalf("partial result = %+v, want empty", got)
		}
	})

	t.Run("oversize secret", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write(bytes.Repeat([]byte{1}, MaximumSecretSize+1))
		}))
		defer server.Close()
		source, err := newHTTPArtifactSource(server.Client(), artifactURLs{secret: server.URL, ipv4: server.URL, ipv6: server.URL})
		if err != nil {
			t.Fatalf("new HTTP artifact source: %v", err)
		}
		if _, err := source.Fetch(t.Context()); !errors.Is(err, ErrArtifactFetch) {
			t.Fatalf("error = %v, want ErrArtifactFetch", err)
		}
	})
}

func TestHTTPArtifactSourceHonorsCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
	}))
	defer server.Close()
	source, err := newHTTPArtifactSource(server.Client(), artifactURLs{secret: server.URL, ipv4: server.URL, ipv6: server.URL})
	if err != nil {
		t.Fatalf("new HTTP artifact source: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := source.Fetch(ctx)
		done <- err
	}()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestArtifactCacheAtomicLastKnownGood(t *testing.T) {
	raw := fixtureArtifacts(t)
	source := &sequenceArtifactSource{results: []artifactSourceResult{
		{raw: raw},
		{raw: RawArtifacts{Secret: deterministicSecret(MinimumSecretSize)}},
	}}
	fetchedAt := time.Date(2026, time.August, 29, 8, 0, 0, 0, time.UTC)
	cache, err := newArtifactCache(source, time.Second, func() time.Time { return fetchedAt })
	if err != nil {
		t.Fatalf("new artifact cache: %v", err)
	}
	if _, ok := cache.Snapshot(); ok {
		t.Fatal("empty cache has a snapshot")
	}
	if !cache.RefreshDue(fetchedAt) {
		t.Fatal("empty cache is not due for refresh")
	}
	if err := cache.Refresh(t.Context()); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	first, ok := cache.Snapshot()
	if !ok {
		t.Fatal("successful refresh did not publish snapshot")
	}
	if cache.RefreshDue(fetchedAt.Add(TelegramArtifactRefreshInterval - time.Nanosecond)) {
		t.Fatal("snapshot became due before daily interval")
	}
	if !cache.RefreshDue(fetchedAt.Add(TelegramArtifactRefreshInterval)) {
		t.Fatal("snapshot is not due at daily interval")
	}

	if err := cache.Refresh(t.Context()); !errors.Is(err, ErrIncompleteArtifacts) {
		t.Fatalf("invalid refresh error = %v, want ErrIncompleteArtifacts", err)
	}
	lastKnownGood, ok := cache.Snapshot()
	if !ok {
		t.Fatal("failed refresh removed snapshot")
	}
	if !lastKnownGood.FetchedAt().Equal(first.FetchedAt()) || !bytes.Equal(lastKnownGood.Secret(), first.Secret()) {
		t.Fatal("failed refresh changed last-known-good snapshot")
	}
}

func TestArtifactCacheTimeout(t *testing.T) {
	source := artifactSourceFunc(func(ctx context.Context) (RawArtifacts, error) {
		<-ctx.Done()
		return RawArtifacts{}, context.Cause(ctx)
	})
	cache, err := NewArtifactCache(source, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("new artifact cache: %v", err)
	}
	if err := cache.Refresh(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("refresh error = %v, want context.DeadlineExceeded", err)
	}
	if _, ok := cache.Snapshot(); ok {
		t.Fatal("timed-out refresh published a snapshot")
	}
}

func TestArtifactCacheDiscardsSuccessAfterTimeout(t *testing.T) {
	raw := fixtureArtifacts(t)
	source := artifactSourceFunc(func(ctx context.Context) (RawArtifacts, error) {
		<-ctx.Done()
		return raw, nil
	})
	cache, err := NewArtifactCache(source, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("new artifact cache: %v", err)
	}
	if err := cache.Refresh(t.Context()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("refresh error = %v, want context.DeadlineExceeded", err)
	}
	if _, ok := cache.Snapshot(); ok {
		t.Fatal("source success after timeout published a snapshot")
	}
}

func TestArtifactCacheCanceledWhileWaitingForRefresh(t *testing.T) {
	raw := fixtureArtifacts(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	source := artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return raw, nil
	})
	cache, err := NewArtifactCache(source, time.Second)
	if err != nil {
		t.Fatalf("new artifact cache: %v", err)
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- cache.Refresh(t.Context()) }()
	<-started

	waitCtx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if err := cache.Refresh(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting refresh error = %v, want context.DeadlineExceeded", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls while first refresh blocked = %d, want 1", got)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first refresh: %v", err)
	}
}

func TestArtifactCacheLeaderCancellationDoesNotCancelSharedRefresh(t *testing.T) {
	raw := fixtureArtifacts(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	source := artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		calls.Add(1)
		close(started)
		<-release
		return raw, nil
	})
	cache, err := NewArtifactCache(source, time.Second)
	if err != nil {
		t.Fatalf("new artifact cache: %v", err)
	}

	leaderCtx, cancelLeader := context.WithCancel(t.Context())
	leaderDone := make(chan error, 1)
	go func() { leaderDone <- cache.Refresh(leaderCtx) }()
	<-started
	cancelLeader()
	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}

	waiterObserved := make(chan struct{})
	waiterCtx := &observedDoneContext{Context: t.Context(), observed: waiterObserved}
	waiterDone := make(chan error, 1)
	go func() { waiterDone <- cache.Refresh(waiterCtx) }()
	<-waiterObserved
	close(release)
	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter refresh: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want 1", got)
	}
	if _, ok := cache.Snapshot(); !ok {
		t.Fatal("shared refresh did not publish snapshot")
	}
}

func TestArtifactCacheCoalescesOutageBurstAndPreservesLastKnownGood(t *testing.T) {
	raw := fixtureArtifacts(t)
	outage := errors.New("artifact service unavailable")
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	source := artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		switch calls.Add(1) {
		case 1:
			return raw, nil
		case 2:
			close(started)
			<-release
			return RawArtifacts{}, outage
		default:
			return raw, nil
		}
	})
	fetchedAt := time.Unix(123, 0)
	cache, err := newArtifactCache(source, time.Second, func() time.Time { return fetchedAt })
	if err != nil {
		t.Fatalf("new artifact cache: %v", err)
	}
	if err := cache.Refresh(t.Context()); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	lastKnownGood, ok := cache.Snapshot()
	if !ok {
		t.Fatal("initial refresh did not publish snapshot")
	}

	const waiters = 32
	results := make(chan error, waiters)
	observed := make([]chan struct{}, waiters)
	for index := range waiters {
		observed[index] = make(chan struct{})
		waitCtx := &observedDoneContext{Context: t.Context(), observed: observed[index]}
		go func() { results <- cache.Refresh(waitCtx) }()
	}
	<-started
	for _, waiterObserved := range observed {
		<-waiterObserved
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("source calls before releasing outage = %d, want 2 total", got)
	}
	close(release)
	for range waiters {
		if err := <-results; !errors.Is(err, outage) {
			t.Fatalf("shared outage error = %v, want outage", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("source calls after outage burst = %d, want 2 total", got)
	}
	afterOutage, ok := cache.Snapshot()
	if !ok || !afterOutage.FetchedAt().Equal(lastKnownGood.FetchedAt()) || !bytes.Equal(afterOutage.Secret(), lastKnownGood.Secret()) {
		t.Fatal("coalesced outage changed last-known-good snapshot")
	}

	if err := cache.Refresh(t.Context()); err != nil {
		t.Fatalf("refresh after outage: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("source calls after retry = %d, want 3 total", got)
	}
}

func TestArtifactCachePreCanceledContextDoesNotStartRefresh(t *testing.T) {
	var calls atomic.Int32
	source := artifactSourceFunc(func(context.Context) (RawArtifacts, error) {
		calls.Add(1)
		return fixtureArtifacts(t), nil
	})
	cache, err := NewArtifactCache(source, time.Second)
	if err != nil {
		t.Fatalf("new artifact cache: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := cache.Refresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh error = %v, want context.Canceled", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("source calls = %d, want 0", got)
	}
}

func TestArtifactCacheCloseCancelsAndJoinsSharedRefresh(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	var calls atomic.Int32
	source := artifactSourceFunc(func(ctx context.Context) (RawArtifacts, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		close(stopped)
		return RawArtifacts{}, context.Cause(ctx)
	})
	cache, err := NewArtifactCache(source, time.Hour)
	if err != nil {
		t.Fatalf("new artifact cache: %v", err)
	}
	refreshDone := make(chan error, 1)
	go func() { refreshDone <- cache.Refresh(t.Context()) }()
	<-started

	const closers = 8
	closeResults := make(chan error, closers)
	for range closers {
		go func() { closeResults <- cache.Close() }()
	}
	for range closers {
		if err := <-closeResults; err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Close returned before the artifact source stopped")
	}
	if err := <-refreshDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh error = %v, want context.Canceled", err)
	}
	if err := cache.Refresh(t.Context()); !errors.Is(err, ErrArtifactCacheClosed) {
		t.Fatalf("refresh after Close error = %v, want ErrArtifactCacheClosed", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("source calls = %d, want 1", got)
	}
}

func TestArtifactConstructorsRejectInvalidConfiguration(t *testing.T) {
	if _, err := NewHTTPArtifactSource(nil); !errors.Is(err, ErrInvalidArtifactAPI) {
		t.Fatalf("nil HTTP client error = %v, want ErrInvalidArtifactAPI", err)
	}
	client := &http.Client{}
	if _, err := newHTTPArtifactSource(client, artifactURLs{}); !errors.Is(err, ErrInvalidArtifactAPI) {
		t.Fatalf("empty URLs error = %v, want ErrInvalidArtifactAPI", err)
	}
	if _, err := NewArtifactCache(nil, time.Second); !errors.Is(err, ErrInvalidArtifactAPI) {
		t.Fatalf("nil source error = %v, want ErrInvalidArtifactAPI", err)
	}
	if _, err := NewArtifactCache(artifactSourceFunc(nil), 0); !errors.Is(err, ErrInvalidArtifactAPI) {
		t.Fatalf("zero timeout error = %v, want ErrInvalidArtifactAPI", err)
	}
}

func fixtureArtifacts(t *testing.T) RawArtifacts {
	t.Helper()
	return RawArtifacts{
		Secret:     deterministicSecret(128),
		IPv4Config: readArtifactFixture(t, "ipv4.conf"),
		IPv6Config: readArtifactFixture(t, "ipv6.conf"),
	}
}

func deterministicSecret(size int) []byte {
	secret := make([]byte, size)
	for index := range size {
		secret[index] = byte(index%251 + 1)
	}
	return secret
}

func readArtifactFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/artifacts/" + name)
	if err != nil {
		t.Fatalf("read artifact fixture %s: %v", name, err)
	}
	return data
}

type artifactSourceFunc func(context.Context) (RawArtifacts, error)

func (f artifactSourceFunc) Fetch(ctx context.Context) (RawArtifacts, error) {
	if f == nil {
		return RawArtifacts{}, fmt.Errorf("nil artifact source function")
	}
	return f(ctx)
}

type artifactSourceResult struct {
	raw RawArtifacts
	err error
}

type sequenceArtifactSource struct {
	mu      sync.Mutex
	results []artifactSourceResult
	next    int
}

type observedDoneContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

func (s *sequenceArtifactSource) Fetch(context.Context) (RawArtifacts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.next == len(s.results) {
		return RawArtifacts{}, io.EOF
	}
	result := s.results[s.next]
	s.next++
	return result.raw, result.err
}
