package tlsfront

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fetchRealProfile fetches a TLS 1.3 profile from a local server, saves it to
// dir, and stops the server.
func fetchRealProfile(t *testing.T, dir string) (host string, port int, saved *ServerHelloFetcher) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	addr := server.Listener.Addr().(*net.TCPAddr)
	fetcher := NewServerHelloFetcher(addr.IP.String(), addr.Port)
	fetcher.EnableDiskCache(dir)
	var saveErr error
	fetcher.OnDiskCacheError(func(err error) { saveErr = err })
	if err := fetcher.Refresh(); err != nil {
		t.Fatal(err)
	}
	if saveErr != nil {
		t.Fatal(saveErr)
	}
	server.Close()
	return addr.IP.String(), addr.Port, fetcher
}

func TestDiskCacheServesProfileWhenFetchFails(t *testing.T) {
	dir := t.TempDir()
	host, port, saved := fetchRealProfile(t, dir)
	info, err := os.Stat(diskProfilePath(dir, host, port))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file mode = %v, want 0600", info.Mode().Perm())
	}

	restarted := NewServerHelloFetcher(host, port)
	restarted.EnableDiskCache(dir)
	if _, err := restarted.LoadDiskCache(); err != nil {
		t.Fatal(err)
	}
	// Age the profile so the startup refresh dials the stopped server.
	restarted.lastFetch = time.Now().Add(-time.Hour)
	if err := restarted.Refresh(); err == nil {
		t.Fatal("refresh succeeded with the server stopped")
	}
	template, err := restarted.Template()
	if err != nil || template == nil {
		t.Fatalf("cached template was not served: %v", err)
	}
	if restarted.CertRecordLen() != saved.CertRecordLen() || saved.CertRecordLen() == 0 {
		t.Fatalf("cert record length = %d, want %d", restarted.CertRecordLen(), saved.CertRecordLen())
	}
	want, _, _ := saved.GetServerHelloTemplate()
	got, _, _ := restarted.GetServerHelloTemplate()
	if !bytes.Equal(got, want) {
		t.Fatal("cached ServerHello differs from the saved one")
	}
}

func TestDiskCacheOffLoadsNothing(t *testing.T) {
	fetcher := NewServerHelloFetcher("example.com", 443)
	if _, err := fetcher.LoadDiskCache(); err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.Template(); err == nil {
		t.Fatal("template without a cache or fetch")
	}
}

func TestDiskCacheMissingFile(t *testing.T) {
	fetcher := NewServerHelloFetcher("example.com", 443)
	fetcher.EnableDiskCache(t.TempDir())
	if _, err := fetcher.LoadDiskCache(); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want not exist", err)
	}
}

func TestDiskCacheRejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	host, port, _ := fetchRealProfile(t, dir)
	path := diskProfilePath(dir, host, port)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var base diskProfile
	if err := json.Unmarshal(good, &base); err != nil {
		t.Fatal(err)
	}
	encode := func(edit func(*diskProfile)) []byte {
		profile := base
		profile.ServerHello = bytes.Clone(base.ServerHello)
		edit(&profile)
		data, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"truncated", good[:len(good)/2]},
		{"empty", nil},
		{"trailing data", append(bytes.Clone(good), []byte(` {}`)...)},
		{"unknown field", bytes.Replace(good, []byte(`{`), []byte(`{"extra":1,`), 1)},
		{"oversized", append(bytes.Clone(good), bytes.Repeat([]byte(" "), diskProfileMaxBytes)...)},
		{"version", encode(func(p *diskProfile) { p.Version = 2 })},
		{"other host", encode(func(p *diskProfile) { p.Host = "other.example" })},
		{"other port", encode(func(p *diskProfile) { p.Port++ })},
		{"too old", encode(func(p *diskProfile) { p.FetchedAt = time.Now().Add(-diskProfileMaxAge - time.Hour) })},
		{"future", encode(func(p *diskProfile) { p.FetchedAt = time.Now().Add(time.Hour) })},
		{"negative cert length", encode(func(p *diskProfile) { p.CertRecordLen = -1 })},
		{"large cert length", encode(func(p *diskProfile) { p.CertRecordLen = maxCertRecordLen + 1 })},
		{"TLS 1.2 ServerHello", encode(func(p *diskProfile) { p.ServerHello = validServerHelloRecord() })},
		{"garbage ServerHello", encode(func(p *diskProfile) { p.ServerHello = []byte{0x16, 3, 3, 0, 1, 2} })},
		{"ServerHello with trailing record", encode(func(p *diskProfile) {
			p.ServerHello = append(p.ServerHello, 0x14, 3, 3, 0, 1, 1)
		})},
		{"cut ServerHello", encode(func(p *diskProfile) { p.ServerHello = p.ServerHello[:len(p.ServerHello)-1] })},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			fetcher := NewServerHelloFetcher(host, port)
			fetcher.EnableDiskCache(dir)
			if _, err := fetcher.LoadDiskCache(); err == nil {
				t.Fatal("invalid cache file was accepted")
			}
			if _, err := fetcher.Template(); err == nil {
				t.Fatal("invalid cache file published a template")
			}
			if fetcher.CertRecordLen() != 0 {
				t.Fatal("invalid cache file published a cert record length")
			}
		})
	}
}

func TestDiskCacheSavesAtMostHourly(t *testing.T) {
	dir := t.TempDir()
	host, port, fetcher := fetchRealProfile(t, dir)
	path := diskProfilePath(dir, host, port)
	read := func() time.Time {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var profile diskProfile
		if err := json.Unmarshal(data, &profile); err != nil {
			t.Fatal(err)
		}
		return profile.FetchedAt
	}
	first := read()
	record, _, _ := fetcher.GetServerHelloTemplate()
	fetcher.persist(record, 100, first.Add(time.Minute))
	if got := read(); !got.Equal(first) {
		t.Fatal("profile was saved again within the save interval")
	}
	later := first.Add(diskProfileSaveInterval)
	fetcher.persist(record, 100, later)
	if got := read(); !got.Equal(later) {
		t.Fatalf("saved fetch time = %v, want %v", got, later)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("cache dir has %d entries, want only the profile", len(entries))
	}
}

func TestDiskCacheSaveFailureKeepsRefresh(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	addr := server.Listener.Addr().(*net.TCPAddr)
	fetcher := NewServerHelloFetcher(addr.IP.String(), addr.Port)
	fetcher.EnableDiskCache(filepath.Join(blocker, "cache"))
	var saveErr error
	fetcher.OnDiskCacheError(func(err error) { saveErr = err })
	if err := fetcher.Refresh(); err != nil {
		t.Fatalf("refresh failed because of the cache: %v", err)
	}
	if saveErr == nil {
		t.Fatal("cache write failure was not reported")
	}
	if _, err := fetcher.Template(); err != nil {
		t.Fatal(err)
	}
}

// A fetched profile is never replaced by an older file.
func TestDiskCacheDoesNotReplaceFetchedProfile(t *testing.T) {
	dir := t.TempDir()
	_, _, fetcher := fetchRealProfile(t, dir)
	before, _, _ := fetcher.GetServerHelloTemplate()
	if _, err := fetcher.LoadDiskCache(); err == nil {
		t.Fatal("cache load replaced a fetched profile")
	}
	after, _, _ := fetcher.GetServerHelloTemplate()
	if !bytes.Equal(before, after) {
		t.Fatal("fetched profile changed")
	}
}

func TestCheckDiskCacheDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := CheckDiskCacheDir(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("dir = %v, err = %v; want a 0700 directory", info, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("check left entries %v, err = %v", entries, err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckDiskCacheDir(filepath.Join(file, "telego")); err == nil {
		t.Fatal("check accepted a path below a regular file")
	}
}
