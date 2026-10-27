package tlsfront

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestRefreshWorkerStartStopIsIdempotent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var worker refreshWorker
		var calls atomic.Int32
		refresh := func(context.Context) { calls.Add(1) }
		for range 3 {
			worker.start(time.Minute, refresh)
		}
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("repeated start launched extra workers")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("periodic refresh did not run once")
		}
		worker.stop()
		worker.stop()
		worker.start(time.Minute, refresh)
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("refresh continued after joined stop")
		}
		var stopped refreshWorker
		stopped.stop()
		stopped.start(time.Minute, refresh)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("stop-before-start admitted a worker")
		}
	})
}

func TestRefreshWorkersCancelStalledTLSAndKeepCache(t *testing.T) {
	for _, kind := range []string{"certificate", "server hello"} {
		t.Run(kind, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			entered, peerDone := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(peerDone)
				conn, err := listener.AcceptTCP()
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Read(make([]byte, 4096)); err != nil {
					return
				}
				close(entered)
				_, _ = io.Copy(io.Discard, conn)
			}()
			t.Cleanup(func() { _ = listener.Close(); <-peerDone })
			addr := listener.Addr().(*net.TCPAddr)
			var start, stop, checkCache func()
			if kind == "certificate" {
				fetcher := NewCertFetcher(5, "example.com")
				stale := &CachedCert{ExpiresAt: time.Now().Add(-time.Hour)}
				fetcher.cache[addr.String()] = stale
				start = func() { fetcher.StartBackgroundRefresh(addr.IP.String(), addr.Port) }
				stop = fetcher.StopBackgroundRefresh
				checkCache = func() {
					if fetcher.CachedCert(addr.IP.String(), addr.Port) != stale {
						t.Fatal("canceled fetch discarded the last certificate")
					}
				}
			} else {
				fetcher := NewServerHelloFetcher(addr.IP.String(), addr.Port)
				fetcher.cachedFull = bytes.Clone(validServerHelloRecord())
				fetcher.randomOffset = 11
				fetcher.lastFetch = time.Now().Add(-time.Hour)
				start, stop = fetcher.StartBackgroundRefresh, fetcher.StopBackgroundRefresh
				checkCache = func() {
					got, offset, err := fetcher.GetServerHelloTemplate()
					if err != nil || offset != 11 || !bytes.Equal(got, validServerHelloRecord()) {
						t.Fatal("canceled fetch discarded the last template")
					}
				}
			}
			t.Cleanup(stop)
			start()
			start()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("fetch did not start its TLS handshake")
			}
			stopped := make(chan struct{})
			go func() { stop(); close(stopped) }()
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("stop did not cancel and join the stalled fetch")
			}
			select {
			case <-peerDone:
			case <-time.After(time.Second):
				t.Fatal("canceled fetch retained its network socket")
			}
			stop()
			checkCache()
		})
	}
}
