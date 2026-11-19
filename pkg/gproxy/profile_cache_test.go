package gproxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
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

	// Off by default: nothing is loaded.
	off := NewProxyHandler(&Config{}, &testLogger{})
	off.serverHelloFetcher = tlsfront.NewServerHelloFetcher(addr.IP.String(), addr.Port)
	off.loadProfileCache()
	if _, err := off.serverHelloFetcher.Template(); err == nil {
		t.Fatal("cache loaded without profile-cache-dir")
	}
}
