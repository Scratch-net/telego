package tlsfront

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func validServerHelloRecord() []byte {
	// TLS 1.2 ServerHello without extensions or a session ID.
	record := make([]byte, 47)
	copy(record, []byte{0x16, 3, 3, 0, 42, 2, 0, 0, 38, 3, 3})
	record[44], record[45] = 0xc0, 0x2f
	return record
}

func TestServerHelloRecordValidation(t *testing.T) {
	valid := validServerHelloRecord()
	for size := range len(valid) {
		if _, err := findServerHelloRandomOffset(valid[:size]); err == nil {
			t.Fatalf("accepted truncated record of %d bytes", size)
		}
	}
	for _, test := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{"zero record", func(b []byte) []byte { b[4] = 0; return b }},
		{"short record with trailing bytes", func(b []byte) []byte { b[4] = 1; return b }},
		{"wrong type", func(b []byte) []byte { b[5] = 1; return b }},
		{"handshake length", func(b []byte) []byte { b[8]--; return b }},
		{"record version", func(b []byte) []byte { b[1] = 2; return b }},
		{"session ID length", func(b []byte) []byte { b[43] = 33; return b }},
		{"compression", func(b []byte) []byte { b[46] = 1; return b }},
		{"HelloRetryRequest", func(b []byte) []byte {
			random := sha256.Sum256([]byte("HelloRetryRequest"))
			copy(b[11:43], random[:])
			return b
		}},
		{"extension length", func(b []byte) []byte {
			b = append(b, 0, 4)
			b[4], b[8] = 44, 40
			return b
		}},
		{"extension payload", func(b []byte) []byte {
			b = append(b, 0, 4, 0, 43, 0, 2)
			b[4], b[8] = 48, 44
			return b
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := findServerHelloRandomOffset(test.edit(bytes.Clone(valid))); err == nil {
				t.Fatal("accepted malformed ServerHello")
			}
		})
	}
	if offset, err := findServerHelloRandomOffset(valid); err != nil || offset != 11 {
		t.Fatalf("valid record: offset=%d error=%v", offset, err)
	}
}

// The peer reads a complete ClientHello before replying or waiting. This keeps
// refresh tests independent of TCP packet boundaries and scheduler timing.
func templateTestPeer(t *testing.T, response []byte, hold <-chan struct{}) (*ServerHelloFetcher, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	addr := listener.Addr().(*net.TCPAddr)
	entered := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var header [5]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(header[3:]))); err != nil {
			return
		}
		close(entered)
		if hold != nil {
			select {
			case <-hold:
			case <-t.Context().Done():
			}
			return
		}
		_, _ = conn.Write(response)
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	fetcher := NewServerHelloFetcher(addr.IP.String(), addr.Port)
	fetcher.timeout = 3 * time.Second
	return fetcher, entered
}

func TestServerHelloRefreshRejectsMalformedUpstream(t *testing.T) {
	for _, data := range [][]byte{
		{0x16, 3, 3, 0, 0},
		append([]byte{0x16, 3, 3, 0, 1, 2}, make([]byte, 37)...),
	} {
		fetcher, _ := templateTestPeer(t, data, nil)
		if err := fetcher.Refresh(); err == nil {
			t.Fatal("malformed upstream response accepted")
		}
		if _, _, err := fetcher.GetServerHelloTemplate(); err == nil {
			t.Fatal("failed refresh populated the cache")
		}
	}
}

func TestServerHelloCacheReadsDuringBlockedRefresh(t *testing.T) {
	hold := make(chan struct{})
	release := sync.OnceFunc(func() { close(hold) })
	fetcher, entered := templateTestPeer(t, nil, hold)
	t.Cleanup(release)
	valid := validServerHelloRecord()
	fetcher.cachedFull = bytes.Clone(valid)
	fetcher.randomOffset = 11
	fetcher.certRecordLen = 1234
	fetcher.lastFetch = time.Now().Add(-time.Hour)
	refreshDone := make(chan error, 1)
	go func() { refreshDone <- fetcher.Refresh() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not reach the peer")
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		got, offset, err := fetcher.GetServerHelloTemplate()
		if err != nil || offset != 11 || !bytes.Equal(got, valid) || fetcher.CertRecordLen() != 1234 {
			t.Error("refresh changed the last good cache before completion")
		}
		if len(got) > 0 {
			got[0] = 0 // Caller mutation must not corrupt the cached record.
		}
	}()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		release()
		<-readDone
		t.Fatal("cache read waited for network refresh")
	}
	release()
	if err := <-refreshDone; err == nil {
		t.Fatal("incomplete handshake unexpectedly refreshed cache")
	}
	got, _, err := fetcher.GetServerHelloTemplate()
	if err != nil || !bytes.Equal(got, valid) {
		t.Fatal("failed refresh or caller mutation destroyed the last good template")
	}
}

func TestServerHelloRefreshRealTLS(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			server.StartTLS()
			t.Cleanup(server.Close)
			addr := server.Listener.Addr().(*net.TCPAddr)
			fetcher := NewServerHelloFetcher(addr.IP.String(), addr.Port)
			if err := fetcher.Refresh(); err != nil {
				t.Fatal(err)
			}
			server.Close()
			fetcher.lastFetch = time.Now().Add(-time.Hour)
			got, offset, err := fetcher.GetServerHelloTemplate()
			if err != nil || offset != 11 || len(got) != 5+int(binary.BigEndian.Uint16(got[3:5])) {
				t.Fatalf("invalid cached record: offset=%d error=%v", offset, err)
			}
		})
	}
}

func TestServerHelloRefreshRejectsHelloRetryRequest(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	addr := server.Listener.Addr().(*net.TCPAddr)
	for _, test := range []struct {
		name   string
		cached []byte
	}{
		{"empty cache", nil},
		{"stale cache", validServerHelloRecord()},
	} {
		t.Run(test.name, func(t *testing.T) {
			fetcher := NewServerHelloFetcher(addr.IP.String(), addr.Port)
			if test.cached != nil {
				fetcher.cachedFull = bytes.Clone(test.cached)
				fetcher.randomOffset = 11
				fetcher.certRecordLen = 1234
				fetcher.lastFetch = time.Now().Add(-time.Hour)
			}
			lastFetch := fetcher.lastFetch
			// The default Go client has no initial P-256 share. A successful
			// handshake therefore includes a retry before the final ServerHello.
			if err := fetcher.Refresh(); err == nil || !strings.Contains(err.Error(), "HelloRetryRequest") {
				t.Fatalf("Refresh error = %v, want unusable HelloRetryRequest template", err)
			}
			got, offset, err := fetcher.GetServerHelloTemplate()
			if test.cached == nil {
				if err == nil || got != nil {
					t.Fatal("HelloRetryRequest populated an empty template cache")
				}
			} else if err != nil || offset != 11 || !bytes.Equal(got, test.cached) || fetcher.CertRecordLen() != 1234 {
				t.Fatal("HelloRetryRequest replaced the last good template")
			}
			if fetcher.lastFetch != lastFetch {
				t.Fatal("HelloRetryRequest marked the cache as refreshed")
			}
		})
	}
}

func TestFirstAppDataRecordRequiresCompletePayload(t *testing.T) {
	data := append(validServerHelloRecord(), 0x17, 3, 3, 0, 2, 1)
	if got := firstAppDataRecordLen(data); got != 0 {
		t.Fatalf("partial application record length = %d", got)
	}
	if got := firstAppDataRecordLen(append(data, 2)); got != 2 {
		t.Fatalf("complete application record length = %d", got)
	}
}

func FuzzServerHelloRecord(f *testing.F) {
	f.Add(validServerHelloRecord())
	f.Add([]byte{0x16, 3, 3, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		offset, err := findServerHelloRandomOffset(data)
		if err == nil {
			recordEnd := 5 + int(binary.BigEndian.Uint16(data[3:5]))
			if offset < 11 || offset+32 > recordEnd || recordEnd > len(data) {
				t.Fatal("accepted a random field outside the first record")
			}
		}
	})
}
