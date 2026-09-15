//go:build linux && me_pressure_investigation

package gproxy

// This opt-in process harness deliberately keeps the ME peer and load generator
// outside the server process. Build both test binaries before applying a cgroup
// limit. The KDF addresses advertised by the peer are explicit test fixtures;
// they do not claim to describe the loopback TCP endpoints.

import (
	"bytes"
	"context"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/webproxy"
)

var (
	pressureProcessRole          = flag.String("me-pressure-role", "", "opt-in process role: server or driver")
	pressureProcessPeer          = flag.String("me-pressure-peer", "", "ME peer readiness JSON path")
	pressureProcessReady         = flag.String("me-pressure-ready", "", "server readiness JSON path")
	pressureProcessResult        = flag.String("me-pressure-result", "", "process result JSON path")
	pressureProcessProgress      = flag.String("me-pressure-progress", "", "optional atomic driver progress JSON path")
	pressureProcessLinks         = flag.Int("me-pressure-links", 4, "physical links per generation (1, 4, or 48)")
	pressureProcessPool          = flag.Int("me-pressure-pool", 2*pressureProcessQ+MiddleEndResponseProcessingBytes(), "explicit response pool bytes; default reserves 2Q ordinary plus one complete encode")
	pressureProcessScenario      = flag.String("me-pressure-scenario", "native", "native, http, ws, rotation, exhaustion, or rotation_exhaustion")
	pressureProcessClients       = flag.Int("me-pressure-clients", 4, "client streams, 1..1000")
	pressureProcessBatch         = flag.Int("me-pressure-batch", 32, "command concurrency; 0 means synchronized all-client barrier")
	pressureProcessSize          = flag.Int("me-pressure-size", 64<<10, "response packet bytes")
	pressureProcessWaves         = flag.Int("me-pressure-waves", 3, "successive fully drained waves")
	pressureProcessPause         = flag.Duration("me-pressure-pause", 500*time.Millisecond, "paused-reader interval per wave")
	pressureProcessAllPaused     = flag.Bool("me-pressure-all-paused", false, "pause every native reader; default mixes fast and paused clients")
	pressureProcessReceiveBuffer = flag.Int("me-pressure-receive-buffer", 64<<10, "native client SO_RCVBUF request (4096..65536)")
	pressureProcessSendBuffer    = flag.Int("me-pressure-send-buffer", 4096, "native server SO_SNDBUF request; 0 keeps production/default socket setting")
	pressureProcessTimeout       = flag.Duration("me-pressure-timeout", 2*time.Minute, "driver operation timeout")
)

const pressureProcessQ = 32*1024*1024 + 16*1024

var pressureProcessKey = []byte("0123456789abcdef")

type pressurePeerReady struct {
	DataAddress, ControlAddress, KDFServerAddr, KDFClientAddr, SecretHex, ClientNonceHex string
	PID, MaxLinks, CommandBytes                                                          int
	LocalProcessID                                                                       middleend.ProcessID
	ClientTimestamp                                                                      int32
}

type pressureServerReady struct {
	RequestedNativeSendBuffer                                                   int
	PID                                                                         int
	NativeAddress, HTTPAddress, WSAddress, ControlAddress                       string
	LinksPerGeneration, EventLoops, ResponseBudgetBytes, ProcessingReserveBytes int
	Topology                                                                    string
	Startup                                                                     pressureProcessSnapshot
}

type pressureProcessSnapshot struct {
	ActiveWarmedSlots, RetiringWarmedSlots                                       int
	At                                                                           time.Time
	PID, Goroutines, PhysicalLinks, ActiveSlots, RetiringSlots, ResidentBindings int
	HeapAlloc, HeapInuse, HeapSys, TotalAlloc, Mallocs, Frees, NumGC             uint64
	Pool                                                                         middleend.ResponseBudgetSnapshot
	Frontend                                                                     MiddleEndFrontendStats
	QueuedBytes, QueuedItems                                                     int
	Evictions                                                                    [middleend.ResponsePressureLimitCount]uint64
	ReclaimedBytes                                                               [middleend.ResponsePressureLimitCount]uint64
	Selections                                                                   [middleend.ResponsePressureSelectionReasonCount]uint64
	SlotFailures, AffectedBindings                                               uint64
	HTTP, WS                                                                     webproxy.Capacity
}

type pressureProcessServer struct {
	pool                         *middleend.ResponseBudget
	runtime                      *middleend.GnetClientRuntime
	supervisor                   *middleend.FixedBindingGenerationSupervisor
	factory                      middleend.FixedBindingGenerationFactory
	handler                      *ProxyHandler
	engine                       atomic.Pointer[gnet.Engine]
	engineDone                   chan error
	httpManager, wsManager       *webproxy.Manager
	httpServer, wsServer         *webproxy.HTTPServer
	httpCapability, wsCapability webproxy.Capability
	linksMu                      sync.Mutex
	links                        []middleend.ClientLink
	shutdown                     chan struct{}
	shutdownOnce                 sync.Once
}

// TestMiddleEndPressureProcess is a process entry point, not a normal test.
// Both roles use this same precompiled binary; only server enters the cgroup.
func TestMiddleEndPressureProcess(t *testing.T) {
	if *pressureProcessRole == "" {
		t.Skip("set -me-pressure-role=server or driver")
	}
	var err error
	switch *pressureProcessRole {
	case "server":
		err = runPressureProcessServer(t)
	case "driver":
		err = runPressureProcessDriver(t)
	default:
		err = fmt.Errorf("unknown process role %q", *pressureProcessRole)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func pressureWriteJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if path == "" {
		return errors.New("JSON output path is required")
	}
	if err := os.WriteFile(path+".tmp", append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func pressureReadJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func pressureUnusedAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := l.Addr().String()
	return address, l.Close()
}

func pressureProcessLimits() middleend.FixedBindingLimits {
	return middleend.FixedBindingLimits{
		MaxResidentBindings: 10000, MaxResidentBindingsPerSlot: 2500,
		MaxPendingRequestItemsPerBinding: 1, MaxPendingRequestBytesPerBinding: middleend.MaxRPCPayloadSize,
		MaxPendingRequestItemsPerSlot: 4096, MaxPendingRequestBytesPerSlot: pressureProcessQ,
		MaxPendingRequestItems: 4096, MaxPendingRequestBytes: pressureProcessQ,
		MaxPendingControlItemsPerSlot: 4096, MaxPendingControlBytesPerSlot: 4096 * middleend.KeepalivePayloadSize,
		MaxPendingControlItems: 4096, MaxPendingControlBytes: 4096 * middleend.KeepalivePayloadSize,
		// Required legacy compatibility fields; ignored by shared response mode.
		MaxPendingResponseItemsPerBinding: 768, MaxPendingResponseBytesPerBinding: 2 << 20,
		MaxPendingResponseItemsPerSlot: 4096, MaxPendingResponseBytesPerSlot: pressureProcessQ,
		MaxPendingResponseItems: 4096, MaxPendingResponseBytes: pressureProcessQ,
	}
}

func runPressureProcessServer(t *testing.T) (resultErr error) {
	if *pressureProcessSendBuffer < 0 || *pressureProcessSendBuffer > 65536 {
		return errors.New("native send buffer must be 0..65536")
	}
	if *pressureProcessLinks != 1 && *pressureProcessLinks != 4 && *pressureProcessLinks != 48 {
		return errors.New("physical topology must be 1, 4, or 48 links")
	}
	var peer pressurePeerReady
	if err := pressureReadJSON(*pressureProcessPeer, &peer); err != nil {
		return err
	}
	if peer.CommandBytes != 56 {
		return fmt.Errorf("peer command bytes=%d, want 56", peer.CommandBytes)
	}
	secret, err := hex.DecodeString(peer.SecretHex)
	if err != nil {
		return err
	}
	nonce, err := hex.DecodeString(peer.ClientNonceHex)
	if err != nil {
		return err
	}
	serverAddr, err := netip.ParseAddrPort(peer.KDFServerAddr)
	if err != nil {
		return err
	}
	clientAddr, err := netip.ParseAddrPort(peer.KDFClientAddr)
	if err != nil {
		return err
	}
	s := &pressureProcessServer{shutdown: make(chan struct{}), engineDone: make(chan error, 1)}
	s.pool, err = middleend.NewResponseBudget(middleend.ResponseBudgetConfig{
		LimitBytes: *pressureProcessPool, ProcessingReserveBytes: MiddleEndResponseProcessingBytes(),
	})
	if err != nil {
		return err
	}
	s.runtime, err = middleend.NewGnetClientRuntime(middleend.GnetClientRuntimeConfig{EventLoops: 2})
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if s.httpManager != nil {
			resultErr = errors.Join(resultErr, s.httpManager.Shutdown(ctx))
		}
		if s.wsManager != nil {
			resultErr = errors.Join(resultErr, s.wsManager.Shutdown(ctx))
		}
		if s.httpServer != nil {
			resultErr = errors.Join(resultErr, s.httpServer.Stop(ctx))
		}
		if s.wsServer != nil {
			resultErr = errors.Join(resultErr, s.wsServer.Stop(ctx))
		}
		if engine := s.engine.Load(); engine != nil {
			resultErr = errors.Join(resultErr, engine.Stop(ctx))
			select {
			case err := <-s.engineDone:
				resultErr = errors.Join(resultErr, err)
			case <-ctx.Done():
				resultErr = errors.Join(resultErr, ctx.Err())
			}
		} else if s.handler != nil {
			resultErr = errors.Join(resultErr, s.handler.stopServing())
		}
		if s.supervisor != nil {
			resultErr = errors.Join(resultErr, s.supervisor.Close())
		}
		resultErr = errors.Join(resultErr, s.runtime.Stop(ctx))
		final := s.snapshot()
		if final.Pool.UsedBytes != 0 || final.Pool.Allocations != 0 || final.Pool.Participants != 0 ||
			final.HTTP.PendingBytes != 0 || final.WS.PendingBytes != 0 || final.HTTP.Streams != 0 || final.WS.Streams != 0 ||
			final.HTTP.PendingItems != 0 || final.WS.PendingItems != 0 || final.HTTP.BackendDials != 0 || final.WS.BackendDials != 0 ||
			final.PhysicalLinks != 0 || final.Frontend.InputBytes != 0 || final.Frontend.OutputBytes != 0 || final.Frontend.MiddleEndBindingsActive != 0 {
			resultErr = errors.Join(resultErr, fmt.Errorf("final cleanup retained resources: %+v", final))
		}
		if *pressureProcessResult != "" {
			resultErr = errors.Join(resultErr, pressureWriteJSON(*pressureProcessResult, final))
		}
	}()
	s.factory = func(ctx context.Context) (*middleend.FixedBindingManager, error) {
		slots := make([]middleend.FixedBindingSlot, 0, *pressureProcessLinks)
		cleanup := func() {
			for _, slot := range slots {
				_ = slot.Link.Close()
			}
		}
		for i := range *pressureProcessLinks {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", peer.DataAddress)
			if err != nil {
				cleanup()
				return nil, err
			}
			bootstrap, err := middleend.NewClientBootstrap(middleend.ClientBootstrapConfig{
				Secret: secret, ServerAddr: serverAddr, ClientAddr: clientAddr,
				LocalProcessID: peer.LocalProcessID, ClientTimestamp: peer.ClientTimestamp,
				NonceSource: bytes.NewReader(nonce),
			})
			if err != nil {
				_ = conn.Close()
				cleanup()
				return nil, err
			}
			link, err := s.runtime.NewClientLink(conn.(*net.TCPConn), bootstrap, middleend.LinkLimits{
				MaxPendingSubmissions: 4096, MaxPendingSubmissionBytes: 2 << 20,
				MaxPendingEvents: 4096, MaxPendingEventBytes: 2 << 20,
			})
			if err != nil {
				_ = conn.Close()
				cleanup()
				return nil, err
			}
			dc := middleend.DCID(2)
			if *pressureProcessLinks == 48 {
				// Twelve signed DC groups, four links each; native clients use DC2.
				dc = middleend.DCID(i/4 + 1)
				if dc > 6 {
					dc = -(dc - 6)
				}
			}
			slots = append(slots, middleend.FixedBindingSlot{DCID: dc, SourceIP: clientAddr.Addr(), Link: link})
			s.linksMu.Lock()
			s.links = append(s.links, link)
			s.linksMu.Unlock()
		}
		manager, err := middleend.NewFixedBindingManagerWithResponseBudget(slots, pressureProcessLimits(), s.pool)
		if err != nil {
			cleanup()
		}
		return manager, err
	}
	s.supervisor, err = middleend.NewFixedBindingGenerationSupervisor(middleend.GenerationSupervisorConfig{
		PreparationTimeout: 15 * time.Second, ProbeInterval: 5 * time.Second, ProbeFailureTimeout: 20 * time.Second,
		RepairBackoffInitial: time.Second, RepairBackoffMaximum: 5 * time.Second,
	})
	if err != nil {
		return err
	}
	if err := s.supervisor.Start(t.Context(), s.factory); err != nil {
		return err
	}
	address, err := pressureUnusedAddress()
	if err != nil {
		return err
	}
	cfg := DefaultConfig()
	cfg.BindAddr, cfg.NumEventLoop, cfg.Multicore, cfg.ReusePort = address, 2, false, false
	cfg.Secrets = []Secret{{Name: "pressure-process", Key: pressureProcessKey, Host: "example.com"}}
	cfg.TimeSkewTolerance, cfg.MaxWriteBuffer = time.Minute, 4<<20
	s.handler, err = NewProxyHandlerWithMiddleEnd(&cfg, pressureProcessLogger{}, MiddleEndFrontendConfig{
		Source: s.supervisor, PrecommitFailure: MiddleEndPrecommitClose,
		ResponseBudget: s.pool, MaxPendingClientBytes: middleend.MaxMEFrameSize,
		MaxPendingClientBytesTotal: pressureProcessQ, MaxPendingOutputBytesTotal: pressureProcessQ,
		OutputRetryInitial: 25 * time.Millisecond, OutputRetryMax: 120 * time.Millisecond, OutputStallTimeout: 100 * time.Second,
	})
	if err != nil {
		return err
	}
	ready := make(chan struct{})
	wrapper := &engineCaptureHandler{ProxyHandler: s.handler, engPtr: &s.engine, ready: ready}
	opts := publicGnetOptions(&cfg)
	if *pressureProcessSendBuffer != 0 {
		opts = append(opts, gnet.WithSocketSendBuffer(*pressureProcessSendBuffer))
	}
	go func() { s.engineDone <- s.handler.runPublicEngine(wrapper, "tcp://"+address, opts...) }()
	select {
	case <-ready:
	case err := <-s.engineDone:
		return fmt.Errorf("native engine startup: %w", err)
	case <-t.Context().Done():
		return t.Context().Err()
	}
	httpAddress, err := s.startWEB(t.Context(), false)
	if err != nil {
		return err
	}
	wsAddress, err := s.startWEB(t.Context(), true)
	if err != nil {
		return err
	}
	control, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /snapshot", func(w http.ResponseWriter, _ *http.Request) { pressureServeJSON(w, s.snapshot()) })
	mux.HandleFunc("POST /rotate", func(w http.ResponseWriter, r *http.Request) {
		if err := s.supervisor.Rotate(r.Context(), s.factory); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		pressureServeJSON(w, s.snapshot())
	})
	mux.HandleFunc("POST /bootstrap", func(w http.ResponseWriter, r *http.Request) {
		manager, capability := s.httpManager, s.httpCapability
		if r.URL.Query().Get("carrier") == "ws" {
			manager, capability = s.wsManager, s.wsCapability
		}
		token, err := manager.IssueBootstrap(capability, "127.0.0.1")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		pressureServeJSON(w, struct{ Token string }{token})
	})
	mux.HandleFunc("POST /shutdown", func(w http.ResponseWriter, _ *http.Request) {
		pressureServeJSON(w, s.snapshot())
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		s.shutdownOnce.Do(func() { close(s.shutdown) })
	})
	controlServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = controlServer.Serve(control) }()
	defer controlServer.Close()
	topology := "DC2 only"
	if *pressureProcessLinks == 48 {
		topology = "12 signed DC groups (-6..-1,+1..+6), 4 links each; clients use DC2"
	}
	if err := pressureWriteJSON(*pressureProcessReady, pressureServerReady{
		RequestedNativeSendBuffer: *pressureProcessSendBuffer,
		PID:                       os.Getpid(), NativeAddress: address, HTTPAddress: httpAddress, WSAddress: wsAddress,
		ControlAddress: control.Addr().String(), LinksPerGeneration: *pressureProcessLinks, EventLoops: 2,
		ResponseBudgetBytes: *pressureProcessPool, ProcessingReserveBytes: MiddleEndResponseProcessingBytes(),
		Topology: topology, Startup: s.snapshot(),
	}); err != nil {
		return err
	}
	select {
	case <-s.shutdown:
		return nil
	case <-t.Context().Done():
		return t.Context().Err()
	case err := <-s.engineDone:
		s.engine.Store(nil)
		return fmt.Errorf("native engine stopped: %w", err)
	}
}

func pressureServeJSON(w http.ResponseWriter, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func (s *pressureProcessServer) snapshot() pressureProcessSnapshot {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	x := pressureProcessSnapshot{At: time.Now(), PID: os.Getpid(), Goroutines: runtime.NumGoroutine(),
		HeapAlloc: memory.HeapAlloc, HeapInuse: memory.HeapInuse, HeapSys: memory.HeapSys,
		TotalAlloc: memory.TotalAlloc, Mallocs: memory.Mallocs, Frees: memory.Frees, NumGC: uint64(memory.NumGC), Pool: s.pool.Snapshot()}
	if s.handler != nil {
		x.Frontend = s.handler.MiddleEndFrontendStats()
	}
	if s.supervisor != nil {
		state := s.supervisor.Snapshot()
		x.Evictions, x.ReclaimedBytes, x.Selections = state.ResponsePressureEvictions, state.ResponsePressureReclaimedBytes, state.ResponsePressureSelections
		x.SlotFailures, x.AffectedBindings = state.SlotFailures, state.SlotFailureAffectedBindings
		for i, manager := range []*middleend.FixedBindingManagerSnapshot{state.Active, state.Retiring} {
			if manager == nil {
				continue
			}
			if i == 0 {
				x.ActiveSlots = len(manager.Slots)
			} else {
				x.RetiringSlots = len(manager.Slots)
			}
			for _, slot := range manager.Slots {
				if slot.ResponseBytesHighWater >= middleend.MaxClientPacketSize {
					if i == 0 {
						x.ActiveWarmedSlots++
					} else {
						x.RetiringWarmedSlots++
					}
				}
			}
			x.ResidentBindings += manager.ResidentBindings
			x.QueuedBytes += manager.ResponseBytes
			x.QueuedItems += manager.ResponseItems
		}
	}
	s.linksMu.Lock()
	for _, link := range s.links {
		select {
		case <-link.Done():
		default:
			x.PhysicalLinks++
		}
	}
	s.linksMu.Unlock()
	if s.httpManager != nil {
		x.HTTP = s.httpManager.Capacity()
	}
	if s.wsManager != nil {
		x.WS = s.wsManager.Capacity()
	}
	return x
}

func (s *pressureProcessServer) startWEB(ctx context.Context, websocket bool) (string, error) {
	profiles, err := webproxy.DeriveProfiles("pressure-process", "proxy.example.com", pressureProcessKey)
	if err != nil {
		return "", err
	}
	config := webproxy.DefaultManagerConfig(profiles[:], "")
	if websocket {
		config.Carrier = webproxy.CarrierWebSocket
	}
	if !websocket {
		config.Timeouts.LongPoll = 50 * time.Millisecond
	}
	config.BackendFactory = func(options webproxy.BackendOpenOptions) (webproxy.Backend, error) {
		address, err := netip.ParseAddr(options.ClientIP)
		if err != nil {
			return nil, err
		}
		return s.handler.OpenLogicalStream(LogicalStreamOptions{
			Owner: options.Owner, ClientAddr: netip.AddrPortFrom(address, 0),
			LocalAddr:     &net.TCPAddr{IP: net.IPv4zero, Port: 443},
			MaxInputBytes: options.MaxInputBytes, MaxInputItems: options.MaxInputItems,
			MaxOutputBytes: options.MaxOutputBytes, MaxOutputItems: options.MaxOutputItems,
			InputBudget:  LogicalQueueBudget{Reserve: options.InputBudget.Reserve, Release: options.InputBudget.Release},
			OutputBudget: LogicalQueueBudget{Reserve: options.OutputBudget.Reserve, Release: options.OutputBudget.Release},
			Notify:       options.Notify, OnOpened: options.OnOpened, OnClosed: options.OnClosed,
		})
	}
	manager, err := webproxy.NewManager(config)
	if err != nil {
		return "", err
	}
	if websocket {
		s.wsManager, s.wsCapability = manager, profiles[0].Capability()
	} else {
		s.httpManager, s.httpCapability = manager, profiles[0].Capability()
	}
	address, err := pressureUnusedAddress()
	if err != nil {
		return "", err
	}
	server, err := webproxy.NewHTTPServer(webproxy.HTTPServerConfig{Bind: address, Hostname: "proxy.example.com", Manager: manager, NumEventLoop: 2})
	if err != nil {
		return "", err
	}
	if websocket {
		s.wsServer = server
	} else {
		s.httpServer = server
	}
	return address, server.Start(ctx)
}

// Do not retain per-packet formatted logs in a memory measurement process.
type pressureProcessLogger struct{}

func (pressureProcessLogger) DebugEnabled() bool { return false }

func (pressureProcessLogger) Debug(string, ...any) {}
func (pressureProcessLogger) Info(string, ...any)  {}
func (pressureProcessLogger) Warn(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
}
func (pressureProcessLogger) Error(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
}

// Bound control response reads too: a broken harness must fail, not allocate
// unbounded memory while measuring the server.
func pressureControl(ctx context.Context, ready pressureServerReady, method, path string, result any) error {
	request, err := http.NewRequestWithContext(ctx, method, "http://"+ready.ControlAddress+path, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("control %s: %d %s", path, response.StatusCode, data)
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(data, result)
}
