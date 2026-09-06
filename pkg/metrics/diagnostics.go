package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	diagnosticsPrefix            = "/debug/pprof/"
	diagnosticsRequestTimeout    = 20 * time.Second
	diagnosticsMaxBytes          = 8 << 20
	diagnosticsDefaultCPUSeconds = 10
	diagnosticsMaxCPUSeconds     = 15
)

// Profiles operate on process-wide runtime state. Reject concurrent requests
// even if a caller constructs more than one private metrics server.
var diagnosticsCollection sync.Mutex

var errDiagnosticsTooLarge = errors.New("profile exceeded the 8 MiB response limit")

func validateDiagnosticsConfig(cfg Config) error {
	if !cfg.Diagnostics {
		return nil
	}
	if !diagnosticsLoopbackAddress(cfg.BindAddr) {
		return errors.New("metrics diagnostics require a literal loopback IP and a port from 1 to 65535")
	}
	if strings.HasPrefix(cfg.Path, strings.TrimSuffix(diagnosticsPrefix, "/")) {
		return errors.New("metrics path conflicts with the reserved diagnostics paths")
	}
	// Invalid custom patterns must return an error instead of panicking during
	// private mux construction. Disabled diagnostics preserve existing behavior.
	if cfg.Path != "" && (!strings.HasPrefix(cfg.Path, "/") || strings.ContainsAny(cfg.Path, " %{}\t\r\n")) {
		return errors.New("metrics path must be an absolute HTTP path without patterns or escapes")
	}
	return nil
}

func diagnosticsLoopbackAddress(address string) bool {
	addr, err := netip.ParseAddrPort(address)
	return err == nil && addr.Port() != 0 && addr.Addr().Zone() == "" && addr.Addr().Unmap().IsLoopback()
}

type diagnostics struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func newDiagnostics() *diagnostics {
	ctx, cancel := context.WithCancel(context.Background())
	return &diagnostics{ctx: ctx, cancel: cancel}
}

func (d *diagnostics) register(mux *http.ServeMux) {
	// Do not import net/http/pprof: its init registers unrelated handlers on
	// the process default mux. Only these exact endpoints are available here.
	for _, name := range []string{"goroutineleak", "heap", "allocs", "goroutine", "profile"} {
		mux.HandleFunc("GET "+diagnosticsPrefix+name, func(w http.ResponseWriter, r *http.Request) {
			d.serveProfile(name, w, r)
		})
	}
	mux.Handle(diagnosticsPrefix, http.NotFoundHandler())
}

func (d *diagnostics) serveProfile(name string, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "diagnostics require GET", http.StatusMethodNotAllowed)
		return
	}
	if !diagnosticsLoopbackAddress(r.Host) || !diagnosticsLoopbackAddress(r.RemoteAddr) {
		http.Error(w, "diagnostics require a literal loopback host and peer", http.StatusForbidden)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.URL.RawQuery) > 128 {
		http.Error(w, "invalid diagnostics request", http.StatusBadRequest)
		return
	}
	seconds, err := diagnosticsQuery(name, r.URL.RawQuery)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if d.ctx.Err() != nil {
		http.Error(w, "diagnostics are shutting down", http.StatusServiceUnavailable)
		return
	}
	if !diagnosticsCollection.TryLock() {
		http.Error(w, "another profile is active", http.StatusServiceUnavailable)
		return
	}
	defer diagnosticsCollection.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), diagnosticsRequestTimeout)
	defer cancel()
	stop := context.AfterFunc(d.ctx, cancel)
	defer stop()
	if ctx.Err() != nil || d.ctx.Err() != nil {
		http.Error(w, "diagnostics request was canceled", http.StatusServiceUnavailable)
		return
	}
	buffer := &diagnosticsBuffer{ctx: ctx}
	if name == "profile" {
		err = collectCPUProfile(ctx, buffer, time.Duration(seconds)*time.Second)
	} else {
		debug := 0
		if name == "goroutineleak" {
			// Go 1.27 performs a fresh leak-detection GC in this WriteTo call.
			// debug=2 would include all goroutines, so it is never accepted.
			debug = 1
		}
		err = pprof.Lookup(name).WriteTo(buffer, debug)
	}
	if err == nil {
		err = buffer.err
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, errDiagnosticsTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "profile collection failed: "+err.Error(), status)
		return
	}
	contentType := "application/octet-stream"
	if name == "goroutineleak" {
		contentType = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(buffer.data)))
	_, _ = w.Write(buffer.data)
}

func diagnosticsQuery(name, raw string) (int, error) {
	query, err := url.ParseQuery(raw)
	if err != nil {
		return 0, errors.New("invalid diagnostics query")
	}
	seconds := diagnosticsDefaultCPUSeconds
	for key, values := range query {
		if len(values) != 1 {
			return 0, errors.New("diagnostics query values must occur once")
		}
		switch {
		case name == "profile" && key == "seconds":
			seconds, err = strconv.Atoi(values[0])
			if err != nil || seconds < 1 || seconds > diagnosticsMaxCPUSeconds {
				return 0, errors.New("CPU profile seconds must be from 1 to 15")
			}
		case name == "goroutineleak" && key == "debug" && values[0] == "1":
		case name != "goroutineleak" && name != "profile" && key == "debug" && values[0] == "0":
		default:
			return 0, fmt.Errorf("unsupported diagnostics query parameter %q", key)
		}
	}
	return seconds, nil
}

func collectCPUProfile(ctx context.Context, buffer *diagnosticsBuffer, duration time.Duration) error {
	if err := pprof.StartCPUProfile(buffer); err != nil {
		return err
	}
	defer pprof.StopCPUProfile()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Grow only as needed, never beyond the response limit. Runtime profiling
// itself can allocate working memory before it calls this bounded writer.
type diagnosticsBuffer struct {
	ctx  context.Context
	data []byte
	err  error
}

func (b *diagnosticsBuffer) Write(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if err := b.ctx.Err(); err != nil {
		b.err = err
		return 0, err
	}
	if len(p) > diagnosticsMaxBytes-len(b.data) {
		b.err = errDiagnosticsTooLarge
		return 0, b.err
	}
	needed := len(b.data) + len(p)
	if needed > cap(b.data) {
		capacity := min(diagnosticsMaxBytes, max(needed, 2*cap(b.data)))
		data := make([]byte, len(b.data), capacity)
		copy(data, b.data)
		b.data = data
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
