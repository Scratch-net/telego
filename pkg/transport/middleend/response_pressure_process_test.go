//go:build linux && me_pressure_investigation

package middleend

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const responsePressureCommandMagic = "MPR1"
const responsePressureCommandBytes = EncryptedMessageHeaderSize
const responsePressureMaximumCount = 4096
const responsePressureMaximumLinks = 512

var responsePressurePeerCLI struct {
	readyPath    string
	links        int
	maxRecords   uint64
	socketBuffer int
	timeout      time.Duration
}

func init() {
	flag.StringVar(&responsePressurePeerCLI.readyPath, "me-pressure-peer-ready", "", "Run the isolated ME pressure peer and atomically publish readiness here")
	flag.IntVar(&responsePressurePeerCLI.links, "me-pressure-peer-links", 256, "Maximum total accepted pressure peer links (1..512)")
	flag.Uint64Var(&responsePressurePeerCLI.maxRecords, "me-pressure-peer-max-records", 4_000_000, "Maximum processed RPC records per link, including probes and cleanup")
	flag.IntVar(&responsePressurePeerCLI.socketBuffer, "me-pressure-peer-socket-buffer", 64<<10, "Requested peer TCP read/write buffer bytes")
	flag.DurationVar(&responsePressurePeerCLI.timeout, "me-pressure-peer-timeout", 20*time.Minute, "Maximum peer process lifetime")
}

// All key material below is a deterministic public test fixture. The KDF
// addresses deliberately differ from the loopback TCP socket addresses.
type responsePressurePeerReady struct {
	DataAddress      string
	ControlAddress   string
	PID              int
	KDFServerAddr    string
	KDFClientAddr    string
	SecretHex        string
	LocalProcessID   ProcessID
	ClientTimestamp  int32
	ClientNonceHex   string
	MaxLinks         int
	MaxPacketSize    int
	MaxResponseCount int
	CommandBytes     int
}

type responsePressurePeerSnapshot struct {
	AcceptedLinks     uint64
	ReadyLinks        int64
	ClosedLinks       uint64
	RejectedLinks     uint64
	Commands          uint64
	CompletedCommands uint64
	Responses         uint64
	ResponseBytes     uint64
	Acknowledgements  uint64
	Records           uint64
	BytesRead         uint64
	BytesWritten      uint64
	Errors            uint64
	TransportErrors   uint64
	FirstError        string
}

type responsePressurePeerState struct {
	counts          engineBenchmarkPeerCounters
	accepted        atomic.Uint64
	ready           atomic.Int64
	closed          atomic.Uint64
	rejected        atomic.Uint64
	commands        atomic.Uint64
	completed       atomic.Uint64
	responses       atomic.Uint64
	responseBytes   atomic.Uint64
	acks            atomic.Uint64
	errors          atomic.Uint64
	transportErrors atomic.Uint64
	mu              sync.Mutex
	peers           []*fakeMiddleEndPeer
	firstError      string
}

func (s *responsePressurePeerState) snapshot() responsePressurePeerSnapshot {
	s.mu.Lock()
	firstError := s.firstError
	s.mu.Unlock()
	return responsePressurePeerSnapshot{
		AcceptedLinks: s.accepted.Load(), ReadyLinks: s.ready.Load(), ClosedLinks: s.closed.Load(), RejectedLinks: s.rejected.Load(),
		Commands: s.commands.Load(), CompletedCommands: s.completed.Load(), Responses: s.responses.Load(), ResponseBytes: s.responseBytes.Load(), Acknowledgements: s.acks.Load(),
		Records: s.counts.records.Load(), BytesRead: s.counts.bytesRead.Load(), BytesWritten: s.counts.bytesWritten.Load(),
		Errors: s.errors.Load(), TransportErrors: s.transportErrors.Load(), FirstError: firstError,
	}
}

func (s *responsePressurePeerState) recordError(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		s.transportErrors.Add(1)
		return
	}
	s.errors.Add(1)
	s.mu.Lock()
	if s.firstError == "" {
		s.firstError = err.Error()
		if len(s.firstError) > 2048 {
			s.firstError = s.firstError[:2048]
		}
	}
	s.mu.Unlock()
}

func (s *responsePressurePeerState) respond(request ProxyRequest, send func([]byte) error) (bool, error) {
	if !bytes.HasPrefix(request.Packet, []byte(responsePressureCommandMagic)) {
		return false, nil
	}
	if len(request.Packet) != responsePressureCommandBytes {
		return true, fmt.Errorf("pressure command must contain exactly %d bytes", responsePressureCommandBytes)
	}
	size := binary.LittleEndian.Uint32(request.Packet[4:8])
	count := binary.LittleEndian.Uint32(request.Packet[8:12])
	sequence := binary.LittleEndian.Uint32(request.Packet[12:16])
	if size > MaxClientPacketSize || size%4 != 0 || count == 0 || count > responsePressureMaximumCount || uint64(sequence)+uint64(count)-1 > math.MaxUint32 {
		return true, errors.New("pressure command exceeds packet, count, or sequence bounds")
	}
	s.commands.Add(1)
	// The generator retains one packet and emits each RPC separately. It never
	// constructs an aggregate response batch proportional to count.
	packet := make([]byte, size)
	for index := range count {
		id := sequence + index
		if size == 0 {
			if err := send((SimpleAck{ConnectionID: request.ConnectionID, ConfirmKey: id}).MarshalBinary()); err != nil {
				return true, err
			}
			s.acks.Add(1)
			continue
		}
		binary.LittleEndian.PutUint32(packet, id)
		for offset := 4; offset < len(packet); offset++ {
			packet[offset] = byte(id) + byte(offset)
		}
		payload, err := (ProxyAnswer{Flags: ProxyAnswerFlagFlush, ConnectionID: request.ConnectionID, Packet: packet}).MarshalBinary()
		if err != nil {
			return true, err
		}
		if err := send(payload); err != nil {
			return true, err
		}
		s.responses.Add(1)
		s.responseBytes.Add(uint64(size))
	}
	s.completed.Add(1)
	return true, nil
}

func TestResponsePressurePeerProcess(t *testing.T) {
	if responsePressurePeerCLI.readyPath == "" {
		t.Skip("isolated peer requires -me-pressure-peer-ready")
	}
	if err := runResponsePressurePeer(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func runResponsePressurePeer(parent context.Context) error {
	config := responsePressurePeerCLI
	if config.links < 1 || config.links > responsePressureMaximumLinks || config.maxRecords < 1 || config.maxRecords > 100_000_000 ||
		config.socketBuffer < 4096 || config.socketBuffer > 4<<20 || config.timeout <= 0 || config.timeout > time.Hour {
		return errors.New("invalid bounded pressure peer settings")
	}
	bootstrap := testBootstrapConfig()
	var nonce [16]byte
	if _, err := io.ReadFull(bootstrap.NonceSource, nonce[:]); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, config.timeout)
	defer cancel()
	data, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer data.Close()
	control, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer control.Close()
	state := &responsePressurePeerState{peers: make([]*fakeMiddleEndPeer, 0, config.links)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, state.snapshot())
	})
	mux.HandleFunc("GET /barrier", func(w http.ResponseWriter, request *http.Request) {
		barrierContext, cancelBarrier := context.WithTimeout(request.Context(), 25*time.Second)
		defer cancelBarrier()
		links, err := strconv.ParseUint(request.URL.Query().Get("ready_links"), 10, 32)
		if err != nil || links > uint64(config.links) {
			http.Error(w, "invalid ready_links", http.StatusBadRequest)
			return
		}
		completed, err := strconv.ParseUint(request.URL.Query().Get("completed_commands"), 10, 64)
		if err != nil {
			http.Error(w, "invalid completed_commands", http.StatusBadRequest)
			return
		}
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for state.ready.Load() < int64(links) || state.completed.Load() < completed {
			select {
			case <-ctx.Done():
				return
			case <-barrierContext.Done():
				http.Error(w, "barrier deadline expired", http.StatusRequestTimeout)
				return
			case <-ticker.C:
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, state.snapshot())
	})
	mux.HandleFunc("POST /quit", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{}\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		cancel()
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 4096}
	var workers sync.WaitGroup
	workers.Go(func() {
		if err := server.Serve(control); err != nil && !errors.Is(err, http.ErrServerClosed) {
			state.recordError(err)
			cancel()
		}
	})
	acceptDone := make(chan struct{})
	workers.Go(func() {
		defer close(acceptDone)
		for {
			connection, err := data.Accept()
			if err != nil {
				if ctx.Err() == nil {
					state.recordError(err)
					cancel()
				}
				return
			}
			if state.accepted.Load() >= uint64(config.links) {
				state.rejected.Add(1)
				_ = connection.Close()
				continue
			}
			if err := configureBenchmarkSocket(connection.(*net.TCPConn), config.socketBuffer); err != nil {
				_ = connection.Close()
				state.recordError(err)
				cancel()
				return
			}
			wrapped := &engineBenchmarkCountingPeerConn{Conn: connection, counters: &state.counts}
			peer := newFakeMiddleEndPeer(wrapped, fakePeerConfig{
				discardRecords: true, maxOperations: config.maxRecords, recordCounter: &state.counts.records,
				respond: state.respond, fragmentPattern: []int{64 << 10},
			})
			state.mu.Lock()
			state.peers = append(state.peers, peer)
			state.mu.Unlock()
			state.accepted.Add(1)
			peer.start()
			workers.Go(func() {
				ready := false
				select {
				case <-peer.ready:
					state.ready.Add(1)
					ready = true
				case <-peer.stopped:
				}
				<-peer.stopped
				if ready {
					state.ready.Add(-1)
				}
				state.closed.Add(1)
				state.recordError(<-peer.done)
			})
		}
	})
	ready := responsePressurePeerReady{
		DataAddress: data.Addr().String(), ControlAddress: control.Addr().String(), PID: os.Getpid(),
		KDFServerAddr: bootstrap.ServerAddr.String(), KDFClientAddr: bootstrap.ClientAddr.String(), SecretHex: hex.EncodeToString(bootstrap.Secret),
		LocalProcessID: bootstrap.LocalProcessID, ClientTimestamp: bootstrap.ClientTimestamp, ClientNonceHex: hex.EncodeToString(nonce[:]),
		MaxLinks: config.links, MaxPacketSize: MaxClientPacketSize, MaxResponseCount: responsePressureMaximumCount,
		CommandBytes: responsePressureCommandBytes,
	}
	readyErr := writeBenchmarkJSON(config.readyPath, ready)
	if readyErr != nil {
		cancel()
	}
	<-ctx.Done()
	_ = data.Close()
	<-acceptDone // no more peer registrations after this point
	state.mu.Lock()
	for _, peer := range state.peers {
		peer.stopHolding()
		_ = peer.conn.Close()
	}
	state.mu.Unlock()
	_ = server.Close()
	workers.Wait()
	if readyErr != nil {
		return readyErr
	}
	if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		return fmt.Errorf("pressure peer lifetime expired: %w", context.Cause(ctx))
	}
	if snapshot := state.snapshot(); snapshot.Errors != 0 {
		return fmt.Errorf("pressure peer recorded %d protocol errors: %s", snapshot.Errors, snapshot.FirstError)
	}
	return nil
}

func responsePressureCommand(size, count, sequence uint32) []byte {
	packet := make([]byte, responsePressureCommandBytes)
	copy(packet, responsePressureCommandMagic)
	binary.LittleEndian.PutUint32(packet[4:8], size)
	binary.LittleEndian.PutUint32(packet[8:12], count)
	binary.LittleEndian.PutUint32(packet[12:16], sequence)
	return packet
}

func TestResponsePressurePeerGeneratorRealWire(t *testing.T) {
	state := new(responsePressurePeerState)
	runtime := newTestGnetRuntime(t)
	connection, peer := dialFakeMiddleEnd(t, fakePeerConfig{respond: state.respond, maxOperations: 8192})
	link, err := runtime.NewClientLink(connection.(*net.TCPConn), newTestBootstrap(t), LinkLimits{
		MaxPendingSubmissions: 8, MaxPendingSubmissionBytes: 8192,
		MaxPendingEvents: 8, MaxPendingEventBytes: 4 * MaxMEFrameSize,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = link.Close() })
	if err := link.Start(newHarnessContext(t)); err != nil {
		t.Fatal(err)
	}
	for index, command := range []struct{ size, count, sequence uint32 }{{64 << 10, 3, 7}, {MaxClientPacketSize, 1, 100}, {0, 2, 200}} {
		packet := responsePressureCommand(command.size, command.count, command.sequence)
		payload, err := (ProxyRequest{
			Flags:        ProxyRequestFlagMagic | ProxyRequestFlagExternalMode2 | ProxyRequestFlagIntermediate,
			ConnectionID: 17, RemoteAddr: netip.MustParseAddrPort("192.0.2.1:20000"), ProxyAddr: netip.MustParseAddrPort("192.0.2.2:443"), Packet: packet,
		}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if err := link.TrySubmit(LinkSubmission{SubmissionID: uint64(index + 1), ConnectionID: 17, Payload: payload}); err != nil {
			t.Fatal(err)
		}
		for response := range command.count {
			event := receiveLinkEvent(t, link)
			sequence := command.sequence + response
			if command.size == 0 {
				if event.Kind != LinkEventSimpleAck || event.ConfirmKey != sequence || event.ConnectionID != 17 {
					t.Fatalf("ACK response: %+v", event)
				}
			} else {
				if event.Kind != LinkEventProxyAnswer || len(event.Packet) != int(command.size) || event.ConnectionID != 17 || binary.LittleEndian.Uint32(event.Packet) != sequence {
					t.Fatal("response kind, identity, length, or sequence changed")
				}
				for offset := 4; offset < len(event.Packet); offset++ {
					if event.Packet[offset] != byte(sequence)+byte(offset) {
						t.Fatalf("response corrupt at byte %d", offset)
					}
				}
			}
			event.Release()
		}
	}
	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatal(err)
	}
	if snapshot := state.snapshot(); snapshot.Commands != 3 || snapshot.CompletedCommands != 3 || snapshot.Responses != 4 || snapshot.Acknowledgements != 2 || snapshot.ResponseBytes != 3*(64<<10)+MaxClientPacketSize {
		t.Fatalf("generator counters: %+v", snapshot)
	}
}

func TestResponsePressurePeerRejectsUnboundedCommandsAndRecords(t *testing.T) {
	state := new(responsePressurePeerState)
	for _, packet := range [][]byte{
		[]byte(responsePressureCommandMagic), responsePressureCommand(1, 1, 1),
		responsePressureCommand(MaxClientPacketSize+4, 1, 1), responsePressureCommand(4, 0, 1),
		responsePressureCommand(4, responsePressureMaximumCount+1, 1), responsePressureCommand(4, 2, math.MaxUint32),
	} {
		handled, err := state.respond(ProxyRequest{Packet: packet}, func([]byte) error { t.Fatal("invalid command emitted output"); return nil })
		if !handled || err == nil || state.commands.Load() != 0 {
			t.Fatal("invalid command bypassed bounds")
		}
	}
	peer := newFakeMiddleEndPeer(nil, fakePeerConfig{discardRecords: true, maxOperations: 3})
	for range 3 {
		if err := peer.record(fakePeerRecord{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := peer.record(fakePeerRecord{}); !errors.Is(err, errFakePeerRecordLimit) || len(peer.records) != 0 {
		t.Fatal("discarded records bypassed configured operation bound")
	}
}

func TestResponsePressurePeerProcessControl(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(t.TempDir(), "ready.json")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestResponsePressurePeerProcess$", "-me-pressure-peer-ready="+readyPath, "-me-pressure-peer-links=112", "-me-pressure-peer-timeout=8s")
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	var ready responsePressurePeerReady
	for {
		err := readBenchmarkJSON(readyPath, &ready)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) || ctx.Err() != nil {
			t.Fatalf("peer readiness: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	if ready.PID != command.Process.Pid || ready.MaxLinks != 112 || ready.CommandBytes != EncryptedMessageHeaderSize ||
		ready.KDFServerAddr != bootstrapTestServer.String() || ready.KDFClientAddr != bootstrapTestClient.String() ||
		ready.SecretHex != hex.EncodeToString(bootstrapTestSecret) || ready.DataAddress == ready.KDFServerAddr {
		t.Fatalf("peer fixture/readiness contract changed: %+v", ready)
	}
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + ready.ControlAddress + "/barrier?ready_links=0&completed_commands=0")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot responsePressurePeerSnapshot
	err = json.UnmarshalRead(io.LimitReader(response.Body, 4096), &snapshot)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || snapshot.AcceptedLinks != 0 || snapshot.Errors != 0 {
		t.Fatalf("peer status: %+v, %v", snapshot, err)
	}
	response, err = client.Post("http://"+ready.ControlAddress+"/quit", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("peer quit status: %d", response.StatusCode)
	}
	err = command.Wait()
	waited = true
	if err != nil {
		t.Fatalf("peer process: %v\n%s", err, output.String())
	}
}
