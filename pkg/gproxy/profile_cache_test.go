package gproxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scratch-net/telego/pkg/tlsfront"
)

func TestLoadProfileCacheServesSavedTemplate(t *testing.T) {
	dir := t.TempDir()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	addr := server.Listener.Addr().(*net.TCPAddr)
	first := tlsfront.NewServerHelloFetcher(addr.IP.String(), addr.Port)
	first.EnableDiskCache(dir)
	if err := first.Refresh(); err != nil {
		t.Fatal(err)
	}
	server.Close()

	logger := &testLogger{}
	handler := NewProxyHandler(&Config{ProfileCacheDir: dir}, logger)
	handler.serverHelloFetcher = tlsfront.NewServerHelloFetcher(addr.IP.String(), addr.Port)
	handler.loadProfileCache()
	if _, err := handler.serverHelloFetcher.Template(); err != nil {
		t.Fatalf("cached template was not loaded: %v", err)
	}
	if !loggedFormat(logger, "Loaded TLS front profile cache") {
		t.Fatal("cache load was not logged")
	}

	// An empty directory is off: nothing is loaded.
	off := NewProxyHandler(&Config{}, &testLogger{})
	off.serverHelloFetcher = tlsfront.NewServerHelloFetcher(addr.IP.String(), addr.Port)
	off.loadProfileCache()
	if _, err := off.serverHelloFetcher.Template(); err == nil {
		t.Fatal("cache loaded without profile-cache-dir")
	}
}

func startProfileCacheTLSServer(t *testing.T) *net.TCPAddr {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.Listener.Addr().(*net.TCPAddr)
}

// The default directory is created when it is missing and then used like an
// explicit one.
func TestLoadProfileCacheDefaultDirCreated(t *testing.T) {
	addr := startProfileCacheTLSServer(t)
	dir := filepath.Join(t.TempDir(), "state", "telego")
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{ProfileCacheDir: dir, ProfileCacheDefault: true}, logger)
	handler.serverHelloFetcher = tlsfront.NewServerHelloFetcher(addr.IP.String(), addr.Port)
	handler.loadProfileCache()
	if err := handler.serverHelloFetcher.Refresh(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("default cache dir entries = %v, err = %v; want one saved profile", entries, err)
	}
	if len(logger.warnings) != 0 {
		t.Fatalf("warnings = %q", logger.warnings)
	}
}

// A default directory that cannot be created turns the cache off for the run
// with one info line. Later refreshes do not try again and do not warn.
func TestLoadProfileCacheDefaultDirUnavailable(t *testing.T) {
	addr := startProfileCacheTLSServer(t)
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A path below a regular file fails for every user, including root.
	dir := filepath.Join(parent, "telego")
	logger := &testLogger{}
	handler := NewProxyHandler(&Config{ProfileCacheDir: dir, ProfileCacheDefault: true}, logger)
	handler.serverHelloFetcher = tlsfront.NewServerHelloFetcher(addr.IP.String(), addr.Port)
	handler.loadProfileCache()
	for range 2 {
		if err := handler.serverHelloFetcher.Refresh(); err != nil {
			t.Fatal(err)
		}
	}
	cacheLines := 0
	for _, line := range logger.infos {
		if strings.Contains(line, "profile cache") {
			cacheLines++
		}
	}
	if cacheLines != 1 || !loggedFormat(logger, "profile cache is off for this run") {
		t.Fatalf("infos = %q; want one cache-off line", logger.infos)
	}
	if len(logger.warnings) != 0 {
		t.Fatalf("warnings = %q", logger.warnings)
	}

	// The same directory set explicitly keeps the warning on a failed save.
	explicit := &testLogger{}
	handler = NewProxyHandler(&Config{ProfileCacheDir: dir}, explicit)
	handler.serverHelloFetcher = tlsfront.NewServerHelloFetcher(addr.IP.String(), addr.Port)
	handler.loadProfileCache()
	if err := handler.serverHelloFetcher.Refresh(); err != nil {
		t.Fatal(err)
	}
	if !loggedFormat(explicit, "Failed to save TLS front profile cache") {
		t.Fatalf("explicit dir did not warn: warnings = %q", explicit.warnings)
	}
}
