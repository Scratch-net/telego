//go:build linux

package middleend

import (
	"bytes"
	"context"
	"encoding/binary"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	benchmarkPeerReset byte = iota + 1
	benchmarkPeerSnapshot
	benchmarkPeerQuit
)

type engineBenchmarkPeerReady struct {
	DataAddress     string
	ControlAddress  string
	EffectiveCPUSet string
	GOMAXPROCS      int
}

type engineBenchmarkPeerSnapshot struct {
	BytesRead           uint64
	BytesWritten        uint64
	Records             uint64
	EffectiveSendBuffer int
	EffectiveReadBuffer int
	EffectiveNoDelay    bool
}

func runIsolatedEngineObservation(
	t *testing.T,
	engine string,
	config engineBenchmarkRunConfig,
	scenario engineBenchmarkScenario,
) (engineTrialMetrics, engineBenchmarkRawObservation) {
	t.Helper()
	throughput := runIsolatedEnginePhase(t, engine, "throughput", config, scenario)
	resource := runIsolatedEnginePhase(t, engine, "resource", config, scenario)
	metrics := throughput.Metrics
	metrics.P50 = resource.Metrics.P50
	metrics.P95 = resource.Metrics.P95
	metrics.P99 = resource.Metrics.P99
	metrics.LatencySamples = resource.Metrics.LatencySamples
	metrics.ResourceDuration = resource.Metrics.ResourceDuration
	metrics.ResourceCycles = resource.Metrics.ResourceCycles
	metrics.ResourceRequests = resource.Metrics.ResourceRequests
	metrics.ResourceRawBytesRead = resource.Metrics.ResourceRawBytesRead
	metrics.ResourceRawBytesWritten = resource.Metrics.ResourceRawBytesWritten
	metrics.ResourceMallocs = resource.Metrics.ResourceMallocs
	metrics.ResourceTotalAllocBytes = resource.Metrics.ResourceTotalAllocBytes
	metrics.AllocsPerRequest = resource.Metrics.AllocsPerRequest
	metrics.AllocatedBytesPerRequest = resource.Metrics.AllocatedBytesPerRequest
	metrics.AbsoluteGoroutineDelta = resource.Metrics.AbsoluteGoroutineDelta
	metrics.GoroutineBaseline = resource.Metrics.GoroutineBaseline
	metrics.GoroutinePeak = resource.Metrics.GoroutinePeak
	metrics.HeapBytesHighWater = resource.Metrics.HeapBytesHighWater
	metrics.HeapBytesWorkerBaseline = resource.Metrics.HeapBytesWorkerBaseline
	metrics.HeapBytesAllocationBaseline = resource.Metrics.HeapBytesAllocationBaseline
	metrics.HeapBytesPeak = resource.Metrics.HeapBytesPeak
	metrics.SubmissionHighWater = resource.Metrics.SubmissionHighWater
	metrics.SubmissionBytesHighWater = resource.Metrics.SubmissionBytesHighWater
	metrics.EventHighWater = resource.Metrics.EventHighWater
	metrics.EventBytesHighWater = resource.Metrics.EventBytesHighWater
	raw := throughput.Raw
	raw.ResourceWarmupCycles = resource.Raw.ResourceWarmupCycles
	raw.ResourceAnswers = resource.Raw.ResourceAnswers
	raw.ResourceAcknowledgements = resource.Raw.ResourceAcknowledgements
	raw.ResourcePeerRecords = resource.Raw.ResourcePeerRecords
	raw.GoroutineBaseline = resource.Raw.GoroutineBaseline
	raw.GoroutineHighWater = resource.Raw.GoroutineHighWater
	raw.GoroutineAfterCleanup = resource.Raw.GoroutineAfterCleanup
	raw.HeapBytesWorkerBaseline = resource.Raw.HeapBytesWorkerBaseline
	raw.HeapBytesAllocationBaseline = resource.Raw.HeapBytesAllocationBaseline
	if raw.EffectiveWorkerSendBuffer != resource.Raw.EffectiveWorkerSendBuffer ||
		raw.EffectiveWorkerReadBuffer != resource.Raw.EffectiveWorkerReadBuffer ||
		raw.EffectivePeerSendBuffer != resource.Raw.EffectivePeerSendBuffer ||
		raw.EffectivePeerReadBuffer != resource.Raw.EffectivePeerReadBuffer ||
		raw.EffectiveWorkerNoDelay != resource.Raw.EffectiveWorkerNoDelay ||
		raw.EffectivePeerNoDelay != resource.Raw.EffectivePeerNoDelay ||
		raw.EffectiveWorkerCPUSet != resource.Raw.EffectiveWorkerCPUSet ||
		raw.EffectivePeerCPUSet != resource.Raw.EffectivePeerCPUSet ||
		raw.PeerGOMAXPROCS != resource.Raw.PeerGOMAXPROCS {
		t.Fatal("throughput and resource workers did not enforce identical controls")
	}
	return metrics, raw
}

func runIsolatedEnginePhase(
	t *testing.T,
	engine string,
	phase string,
	config engineBenchmarkRunConfig,
	scenario engineBenchmarkScenario,
) engineBenchmarkWorkerResult {
	t.Helper()
	temporaryDirectory := t.TempDir()
	readyPath := filepath.Join(temporaryDirectory, "peer-ready.json")
	workerPath := filepath.Join(temporaryDirectory, "worker-result.json")
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve benchmark test binary: %v", err)
	}

	observationContext, cancelObservation := context.WithTimeout(t.Context(), config.ObservationTimeout)
	defer cancelObservation()
	peerArguments := []string{
		"-test.run=^TestEngineComparisonRunner$", "-test.count=1",
		"-mebench-peer=true",
		"-mebench-peer-ready-output=" + readyPath,
		fmt.Sprintf("-mebench-peer-links=%d", benchmarkPeerLinkCount(phase, scenario.Links)),
		fmt.Sprintf("-mebench-worker-slow-read-chunk=%d", scenario.SlowReadChunk),
		"-mebench-worker-slow-read-delay=" + scenario.SlowReadDelay.String(),
		fmt.Sprintf("-mebench-socket-buffer=%d", config.SocketBuffer),
		"-mebench-peer-cpus=" + config.PeerCPUSet,
		"-mebench-observation-timeout=" + config.ObservationTimeout.String(),
	}
	peerCommandArguments := append([]string{"--cpu-list", config.PeerCPUSet, executable}, peerArguments...)
	peerCommand := exec.CommandContext(observationContext, config.TasksetPath, peerCommandArguments...)
	var peerOutput bytes.Buffer
	peerCommand.Stdout = &peerOutput
	peerCommand.Stderr = &peerOutput
	if err := peerCommand.Start(); err != nil {
		t.Fatalf("start isolated benchmark peer: %v", err)
	}
	peerWaited := false
	defer func() {
		if peerWaited {
			return
		}
		_ = peerCommand.Process.Kill()
		_ = peerCommand.Wait()
	}()
	ready := waitEngineBenchmarkPeerReady(t, observationContext, readyPath)
	if ready.EffectiveCPUSet != config.PeerCPUSet || ready.GOMAXPROCS != len(mustParseCPUSet(t, config.PeerCPUSet)) {
		t.Fatalf("peer scheduling controls = CPUs %q GOMAXPROCS %d", ready.EffectiveCPUSet, ready.GOMAXPROCS)
	}

	workerArguments := []string{
		"-test.run=^TestEngineComparisonRunner$", "-test.count=1",
		"-mebench-worker=true",
		"-mebench-worker-engine=" + engine,
		"-mebench-worker-phase=" + phase,
		fmt.Sprintf("-mebench-worker-links=%d", scenario.Links),
		"-mebench-worker-output=" + workerPath,
		"-mebench-worker-data-address=" + ready.DataAddress,
		"-mebench-worker-control-address=" + ready.ControlAddress,
		fmt.Sprintf("-mebench-gomaxprocs=%d", config.GOMAXPROCS),
		fmt.Sprintf("-mebench-event-loops=%d", config.EventLoops),
		"-mebench-warmup=" + config.Warmup.String(),
		fmt.Sprintf("-mebench-warmup-cycles=%d", config.WarmupCycles),
		"-mebench-duration=" + config.MeasurementDuration.String(),
		fmt.Sprintf("-mebench-resource-cycles=%d", config.ResourceCycles),
		"-mebench-heap-sample-interval=" + config.HeapSampleInterval.String(),
		fmt.Sprintf("-mebench-socket-buffer=%d", config.SocketBuffer),
		"-mebench-worker-cpus=" + config.WorkerCPUSet,
		"-mebench-peer-cpus=" + config.PeerCPUSet,
		"-mebench-observation-timeout=" + config.ObservationTimeout.String(),
	}
	workerCommandArguments := append([]string{"--cpu-list", config.WorkerCPUSet, executable}, workerArguments...)
	workerCommand := exec.CommandContext(observationContext, config.TasksetPath, workerCommandArguments...)
	workerOutput, workerErr := workerCommand.CombinedOutput()
	if workerErr != nil {
		t.Fatalf("isolated %s worker failed: %v\n%s", engine, workerErr, workerOutput)
	}
	if err := peerCommand.Wait(); err != nil {
		t.Fatalf("isolated peer failed after %s worker: %v\n%s", engine, err, peerOutput.String())
	}
	peerWaited = true

	var result engineBenchmarkWorkerResult
	if err := readBenchmarkJSON(workerPath, &result); err != nil {
		t.Fatalf("read isolated %s result: %v", engine, err)
	}
	result.Raw.EffectivePeerCPUSet = ready.EffectiveCPUSet
	result.Raw.PeerGOMAXPROCS = ready.GOMAXPROCS
	return result
}

func benchmarkPeerLinkCount(phase string, links int) int {
	if phase == "resource" {
		count, ok := checkedMulInt(2, links)
		if !ok {
			return 0
		}
		return count
	}
	return links
}

func waitEngineBenchmarkPeerReady(t testing.TB, ctx context.Context, path string) engineBenchmarkPeerReady {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var ready engineBenchmarkPeerReady
		err := readBenchmarkJSON(path, &ready)
		if err == nil {
			return ready
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read peer readiness: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for peer readiness: %v", context.Cause(ctx))
		case <-ticker.C:
		}
	}
}

func runEngineBenchmarkPeer(t *testing.T) {
	if engineBenchmarkCLI.peerReadyOutput == "" || engineBenchmarkCLI.peerLinks <= 0 || engineBenchmarkCLI.peerLinks > 8 ||
		engineBenchmarkCLI.socketBuffer <= 0 || engineBenchmarkCLI.observationTimeout <= 0 {
		t.Fatal("incomplete isolated peer controls")
	}
	if engineBenchmarkCLI.workerSlowReadChunk < 0 || engineBenchmarkCLI.workerSlowReadDelay < 0 ||
		(engineBenchmarkCLI.workerSlowReadChunk == 0) != (engineBenchmarkCLI.workerSlowReadDelay == 0) {
		t.Fatal("slow-reader chunk and delay must both be zero or both positive")
	}
	effectiveCPUSet := verifyProcessThreadCPUSet(t, engineBenchmarkCLI.peerCPUSet)
	peerCPUCount := len(mustParseCPUSet(t, effectiveCPUSet))
	runtime.GOMAXPROCS(peerCPUCount)

	dataListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen isolated peer data: %v", err)
	}
	defer dataListener.Close()
	controlListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen isolated peer control: %v", err)
	}
	defer controlListener.Close()
	ready := engineBenchmarkPeerReady{
		DataAddress: dataListener.Addr().String(), ControlAddress: controlListener.Addr().String(),
		EffectiveCPUSet: effectiveCPUSet, GOMAXPROCS: peerCPUCount,
	}
	if err := writeBenchmarkJSON(engineBenchmarkCLI.peerReadyOutput, ready); err != nil {
		t.Fatalf("write isolated peer readiness: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), engineBenchmarkCLI.observationTimeout)
	defer cancel()
	counters := new(engineBenchmarkPeerCounters)
	peers := make(chan *fakeMiddleEndPeer, engineBenchmarkCLI.peerLinks)
	acceptResult := make(chan error, 1)
	go func() {
		for range engineBenchmarkCLI.peerLinks {
			connection, err := dataListener.AcceptTCP()
			if err != nil {
				acceptResult <- err
				return
			}
			if err := configureBenchmarkSocket(connection, engineBenchmarkCLI.socketBuffer); err != nil {
				_ = connection.Close()
				acceptResult <- err
				return
			}
			sendBuffer, readBuffer, noDelay, err := benchmarkSocketControls(connection)
			if err != nil {
				_ = connection.Close()
				acceptResult <- err
				return
			}
			if !counters.setPeerControls(sendBuffer, readBuffer, noDelay) {
				_ = connection.Close()
				acceptResult <- errors.New("effective peer socket buffers changed between links")
				return
			}
			wrapped := &engineBenchmarkCountingPeerConn{
				Conn: connection, counters: counters,
				readChunk: engineBenchmarkCLI.workerSlowReadChunk,
				readDelay: engineBenchmarkCLI.workerSlowReadDelay,
			}
			peer := newFakeMiddleEndPeer(wrapped, fakePeerConfig{
				discardRecords: true, recordCounter: &counters.records,
			})
			peer.start()
			peers <- peer
		}
		close(peers)
		acceptResult <- nil
	}()

	if err := controlListener.SetDeadline(time.Now().Add(engineBenchmarkCLI.observationTimeout)); err != nil {
		t.Fatalf("set isolated peer control deadline: %v", err)
	}
	controlConnection, err := controlListener.AcceptTCP()
	if err != nil {
		t.Fatalf("accept isolated peer control: %v", err)
	}
	defer controlConnection.Close()
	if err := serveEngineBenchmarkPeerControl(ctx, controlConnection, counters); err != nil {
		t.Fatalf("serve isolated peer control: %v", err)
	}
	_ = dataListener.Close()
	if err := <-acceptResult; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept isolated peer links: %v", err)
	}
	acceptedPeers := 0
	for peer := range peers {
		acceptedPeers++
		peer.stopHolding()
		_ = peer.conn.Close()
		select {
		case <-peer.stopped:
			if peerErr := <-peer.done; peerErr != nil {
				t.Fatalf("isolated fake peer: %v", peerErr)
			}
		case <-ctx.Done():
			t.Fatalf("wait isolated fake peer: %v", context.Cause(ctx))
		}
	}
	if acceptedPeers != engineBenchmarkCLI.peerLinks {
		t.Fatalf("accepted %d peer links, want %d", acceptedPeers, engineBenchmarkCLI.peerLinks)
	}
	verifyProcessThreadCPUSet(t, engineBenchmarkCLI.peerCPUSet)
}

type engineBenchmarkPeerCounters struct {
	bytesRead    atomic.Uint64
	bytesWritten atomic.Uint64
	records      atomic.Uint64
	mu           sync.Mutex
	sendBuffer   int
	readBuffer   int
	noDelay      bool
}

func (c *engineBenchmarkPeerCounters) reset() {
	c.bytesRead.Store(0)
	c.bytesWritten.Store(0)
	c.records.Store(0)
}

func (c *engineBenchmarkPeerCounters) setPeerControls(sendBuffer int, readBuffer int, noDelay bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendBuffer == 0 {
		c.sendBuffer = sendBuffer
		c.readBuffer = readBuffer
		c.noDelay = noDelay
		return true
	}
	return c.sendBuffer == sendBuffer && c.readBuffer == readBuffer && c.noDelay == noDelay
}

func (c *engineBenchmarkPeerCounters) snapshot() engineBenchmarkPeerSnapshot {
	c.mu.Lock()
	sendBuffer, readBuffer, noDelay := c.sendBuffer, c.readBuffer, c.noDelay
	c.mu.Unlock()
	return engineBenchmarkPeerSnapshot{
		BytesRead: c.bytesRead.Load(), BytesWritten: c.bytesWritten.Load(), Records: c.records.Load(),
		EffectiveSendBuffer: sendBuffer, EffectiveReadBuffer: readBuffer,
		EffectiveNoDelay: noDelay,
	}
}

type engineBenchmarkCountingPeerConn struct {
	net.Conn
	counters  *engineBenchmarkPeerCounters
	readChunk int
	readDelay time.Duration
}

func (c *engineBenchmarkCountingPeerConn) Read(buffer []byte) (int, error) {
	if c.readDelay > 0 {
		time.Sleep(c.readDelay)
	}
	if c.readChunk > 0 && len(buffer) > c.readChunk {
		buffer = buffer[:c.readChunk]
	}
	read, err := c.Conn.Read(buffer)
	c.counters.bytesRead.Add(uint64(read))
	return read, err
}

func (c *engineBenchmarkCountingPeerConn) Write(buffer []byte) (int, error) {
	written, err := c.Conn.Write(buffer)
	c.counters.bytesWritten.Add(uint64(written))
	return written, err
}

func serveEngineBenchmarkPeerControl(ctx context.Context, connection net.Conn, counters *engineBenchmarkPeerCounters) error {
	for {
		if deadline, ok := ctx.Deadline(); ok {
			if err := connection.SetDeadline(deadline); err != nil {
				return err
			}
		}
		var command [1]byte
		if _, err := io.ReadFull(connection, command[:]); err != nil {
			return err
		}
		switch command[0] {
		case benchmarkPeerReset:
			counters.reset()
			if _, err := connection.Write([]byte{0}); err != nil {
				return err
			}
		case benchmarkPeerSnapshot:
			snapshot := counters.snapshot()
			response := make([]byte, 34)
			binary.LittleEndian.PutUint64(response[1:9], snapshot.BytesRead)
			binary.LittleEndian.PutUint64(response[9:17], snapshot.BytesWritten)
			binary.LittleEndian.PutUint64(response[17:25], snapshot.Records)
			binary.LittleEndian.PutUint32(response[25:29], uint32(snapshot.EffectiveSendBuffer))
			binary.LittleEndian.PutUint32(response[29:33], uint32(snapshot.EffectiveReadBuffer))
			if snapshot.EffectiveNoDelay {
				response[33] = 1
			}
			if _, err := connection.Write(response); err != nil {
				return err
			}
		case benchmarkPeerQuit:
			_, err := connection.Write([]byte{0})
			return err
		default:
			return fmt.Errorf("unknown benchmark peer control %d", command[0])
		}
	}
}

type engineBenchmarkPeerClient struct {
	connection net.Conn
}

func dialEngineBenchmarkPeerControl(t testing.TB, ctx context.Context, address string) *engineBenchmarkPeerClient {
	t.Helper()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	if err != nil {
		t.Fatalf("dial isolated peer control: %v", err)
	}
	return &engineBenchmarkPeerClient{connection: connection}
}

func (c *engineBenchmarkPeerClient) reset(t testing.TB) {
	t.Helper()
	if _, err := c.connection.Write([]byte{benchmarkPeerReset}); err != nil {
		t.Fatalf("reset isolated peer counters: %v", err)
	}
	var response [1]byte
	if _, err := io.ReadFull(c.connection, response[:]); err != nil || response[0] != 0 {
		t.Fatalf("acknowledge isolated peer reset: byte=%d error=%v", response[0], err)
	}
}

func (c *engineBenchmarkPeerClient) snapshot(t testing.TB) engineBenchmarkPeerSnapshot {
	t.Helper()
	if _, err := c.connection.Write([]byte{benchmarkPeerSnapshot}); err != nil {
		t.Fatalf("request isolated peer snapshot: %v", err)
	}
	var response [34]byte
	if _, err := io.ReadFull(c.connection, response[:]); err != nil || response[0] != 0 {
		t.Fatalf("read isolated peer snapshot: byte=%d error=%v", response[0], err)
	}
	return engineBenchmarkPeerSnapshot{
		BytesRead:           binary.LittleEndian.Uint64(response[1:9]),
		BytesWritten:        binary.LittleEndian.Uint64(response[9:17]),
		Records:             binary.LittleEndian.Uint64(response[17:25]),
		EffectiveSendBuffer: int(binary.LittleEndian.Uint32(response[25:29])),
		EffectiveReadBuffer: int(binary.LittleEndian.Uint32(response[29:33])),
		EffectiveNoDelay:    response[33] == 1,
	}
}

func (c *engineBenchmarkPeerClient) quit(t testing.TB) {
	t.Helper()
	if _, err := c.connection.Write([]byte{benchmarkPeerQuit}); err != nil {
		t.Fatalf("quit isolated peer: %v", err)
	}
	var response [1]byte
	if _, err := io.ReadFull(c.connection, response[:]); err != nil || response[0] != 0 {
		t.Fatalf("acknowledge isolated peer quit: byte=%d error=%v", response[0], err)
	}
	if err := c.connection.Close(); err != nil {
		t.Fatalf("close isolated peer control: %v", err)
	}
}

func runEngineBenchmarkWorker(t *testing.T) {
	if engineBenchmarkCLI.workerEngine != "blocking" && engineBenchmarkCLI.workerEngine != "gnet" {
		t.Fatal("isolated worker engine must be blocking or gnet")
	}
	if engineBenchmarkCLI.workerPhase != "throughput" && engineBenchmarkCLI.workerPhase != "resource" {
		t.Fatal("isolated worker phase must be throughput or resource")
	}
	if engineBenchmarkCLI.workerLinks <= 0 || engineBenchmarkCLI.workerLinks > 4 ||
		engineBenchmarkCLI.workerOutput == "" || engineBenchmarkCLI.workerDataAddress == "" ||
		engineBenchmarkCLI.workerControlAddress == "" || engineBenchmarkCLI.gomaxprocs <= 0 ||
		engineBenchmarkCLI.eventLoops <= 0 || engineBenchmarkCLI.eventLoops > MaxGnetClientEventLoops || engineBenchmarkCLI.warmup <= 0 ||
		engineBenchmarkCLI.warmupCycles <= 0 || engineBenchmarkCLI.warmupCycles > MaxLinkQueueItems || engineBenchmarkCLI.duration <= 0 ||
		engineBenchmarkCLI.resourceCycles <= 0 || engineBenchmarkCLI.heapSampleInterval <= 0 ||
		engineBenchmarkCLI.socketBuffer <= 0 || engineBenchmarkCLI.observationTimeout <= 0 {
		t.Fatal("incomplete isolated worker controls")
	}
	effectiveCPUSet := verifyProcessThreadCPUSet(t, engineBenchmarkCLI.workerCPUSet)
	if engineBenchmarkCLI.gomaxprocs > len(mustParseCPUSet(t, effectiveCPUSet)) {
		t.Fatalf("GOMAXPROCS %d exceeds effective worker CPU set %q", engineBenchmarkCLI.gomaxprocs, effectiveCPUSet)
	}
	runtime.GOMAXPROCS(engineBenchmarkCLI.gomaxprocs)
	ctx, cancel := context.WithTimeout(t.Context(), engineBenchmarkCLI.observationTimeout)
	defer cancel()
	control := dialEngineBenchmarkPeerControl(t, ctx, engineBenchmarkCLI.workerControlAddress)
	workload := deterministicLinkWorkload(t)
	if err := validateEngineBenchmarkWorkerScale(engineBenchmarkCLI.resourceCycles, len(workload.items)); err != nil {
		t.Fatal(err)
	}
	limits := limitsForWorkload(workload)
	expectedRead, expectedWritten := expectedBenchmarkCycleBytes(t, workload)
	bootstrapBytes := uint64(expectedBenchmarkBootstrapBytes()) * uint64(engineBenchmarkCLI.workerLinks)
	var result engineBenchmarkWorkerResult
	if engineBenchmarkCLI.workerPhase == "throughput" {
		result = runEngineBenchmarkThroughputPhase(t, ctx, control, workload, limits, expectedRead, expectedWritten, bootstrapBytes, effectiveCPUSet)
	} else {
		result = runEngineBenchmarkResourcePhase(t, ctx, control, workload, limits, expectedRead, expectedWritten, bootstrapBytes, effectiveCPUSet)
	}
	control.quit(t)
	verifyProcessThreadCPUSet(t, engineBenchmarkCLI.workerCPUSet)
	if err := writeBenchmarkJSON(engineBenchmarkCLI.workerOutput, result); err != nil {
		t.Fatalf("write isolated worker result: %v", err)
	}
}

func validateEngineBenchmarkWorkerScale(resourceCycles int, requestsPerCycle int) error {
	requests, ok := checkedMulInt(resourceCycles, requestsPerCycle)
	if !ok {
		return errors.New("worker resource request count overflows int")
	}
	if requests > engineBenchmarkMaxLatencySamplesPerResourceObservation {
		return fmt.Errorf("worker retained latency samples %d exceed per-observation ceiling %d",
			requests, engineBenchmarkMaxLatencySamplesPerResourceObservation)
	}
	return nil
}

func runEngineBenchmarkThroughputPhase(
	t *testing.T,
	ctx context.Context,
	control *engineBenchmarkPeerClient,
	workload linkWorkload,
	limits LinkLimits,
	expectedRead uint64,
	expectedWritten uint64,
	bootstrapBytes uint64,
	effectiveCPUSet string,
) engineBenchmarkWorkerResult {
	goroutineBaseline := runtime.NumGoroutine()
	topology := newEngineBenchmarkTopology(t, ctx, engineBenchmarkCLI.workerEngine, workload, limits)
	validateBenchmarkBootstrapSnapshot(t, control.snapshot(t), bootstrapBytes)
	control.reset(t)
	warmupCycles := runEngineBenchmarkWarmup(t, ctx, topology, workload)
	control.reset(t)
	started := time.Now()
	cycles, answers, acknowledgements := 0, 0, 0
	for time.Since(started) < engineBenchmarkCLI.duration || cycles == 0 {
		cycleAnswers, cycleAcknowledgements, _ := topology.runCycle(t, ctx, workload, false)
		answers += cycleAnswers
		acknowledgements += cycleAcknowledgements
		cycles++
	}
	duration := time.Since(started)
	snapshot := control.snapshot(t)
	requests, ok := checkedMulInt(cycles, len(workload.items))
	wantPeerWritten, writtenOK := checkedMulUint64(expectedRead, uint64(cycles))
	wantPeerRead, readOK := checkedMulUint64(expectedWritten, uint64(cycles))
	if !ok || !writtenOK || !readOK {
		t.Fatal("throughput phase counters overflow")
	}
	if snapshot.BytesWritten != wantPeerWritten || snapshot.BytesRead != wantPeerRead ||
		snapshot.Records != uint64(requests) || answers != requests || acknowledgements != requests {
		t.Fatal("throughput phase protocol or event counters do not match completed cycles")
	}
	effectiveSend, effectiveRead := topology.effectiveSendBuffer, topology.effectiveReadBuffer
	topology.close(t, ctx)
	runtime.GC()
	runtime.Gosched()
	if got := runtime.NumGoroutine(); got != goroutineBaseline {
		t.Fatalf("throughput worker goroutines after cleanup = %d, want %d", got, goroutineBaseline)
	}
	return engineBenchmarkWorkerResult{
		Metrics: engineTrialMetrics{
			Duration: duration, CompletedCycles: cycles, CompletedRequests: requests,
			SustainableRequestsPerSec: float64(requests) / duration.Seconds(),
			BytesRead:                 expectedRead, BytesWritten: expectedWritten,
			RawBytesRead: snapshot.BytesWritten, RawBytesWritten: snapshot.BytesRead,
		},
		Raw: engineBenchmarkRawObservation{
			ThroughputWarmupCycles: warmupCycles,
			ThroughputAnswers:      answers, ThroughputAcknowledgements: acknowledgements,
			ThroughputPeerRecords:     snapshot.Records,
			EffectiveWorkerSendBuffer: effectiveSend, EffectiveWorkerReadBuffer: effectiveRead,
			EffectivePeerSendBuffer: snapshot.EffectiveSendBuffer, EffectivePeerReadBuffer: snapshot.EffectiveReadBuffer,
			EffectiveWorkerNoDelay: topology.effectiveNoDelay, EffectivePeerNoDelay: snapshot.EffectiveNoDelay,
			EffectiveWorkerCPUSet: effectiveCPUSet,
		},
	}
}

func runEngineBenchmarkResourcePhase(
	t *testing.T,
	ctx context.Context,
	control *engineBenchmarkPeerClient,
	workload linkWorkload,
	limits LinkLimits,
	expectedRead uint64,
	expectedWritten uint64,
	bootstrapBytes uint64,
	effectiveCPUSet string,
) engineBenchmarkWorkerResult {
	warmupTopology := newEngineBenchmarkTopology(t, ctx, engineBenchmarkCLI.workerEngine, workload, limits)
	validateBenchmarkBootstrapSnapshot(t, control.snapshot(t), bootstrapBytes)
	control.reset(t)
	warmupCycles := runEngineBenchmarkWarmup(t, ctx, warmupTopology, workload)
	warmupTopology.close(t, ctx)
	control.reset(t)

	runtime.GC()
	var workerBaseline runtime.MemStats
	runtime.ReadMemStats(&workerBaseline)
	goroutineBaseline := runtime.NumGoroutine()
	resourceTopology := newEngineBenchmarkTopology(t, ctx, engineBenchmarkCLI.workerEngine, workload, limits)
	validateBenchmarkBootstrapSnapshot(t, control.snapshot(t), bootstrapBytes)
	control.reset(t)
	sampler := prepareEngineBenchmarkResourceSampler(engineBenchmarkCLI.heapSampleInterval)
	runtime.GC()
	var allocationBaseline runtime.MemStats
	runtime.ReadMemStats(&allocationBaseline)
	sampler.activate(goroutineBaseline, allocationBaseline.HeapAlloc)
	started := time.Now()
	requestCapacity, ok := checkedMulInt(engineBenchmarkCLI.resourceCycles, len(workload.items))
	if !ok {
		t.Fatal("resource latency capacity overflows int")
	}
	latencies := make([]time.Duration, 0, min(requestCapacity, MaxLinkQueueItems))
	answers, acknowledgements := 0, 0
	for range engineBenchmarkCLI.resourceCycles {
		cycleAnswers, cycleAcknowledgements, cycleLatencies := resourceTopology.runCycle(t, ctx, workload, true)
		answers += cycleAnswers
		acknowledgements += cycleAcknowledgements
		latencies = append(latencies, cycleLatencies...)
	}
	duration := time.Since(started)
	snapshot := control.snapshot(t)
	queueSnapshot := resourceTopology.snapshot()
	var memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryAfter)
	sampler.stop()
	requests := requestCapacity
	wantPeerWritten, writtenOK := checkedMulUint64(expectedRead, uint64(engineBenchmarkCLI.resourceCycles))
	wantPeerRead, readOK := checkedMulUint64(expectedWritten, uint64(engineBenchmarkCLI.resourceCycles))
	if !writtenOK || !readOK {
		t.Fatal("resource phase byte counters overflow")
	}
	if snapshot.BytesWritten != wantPeerWritten || snapshot.BytesRead != wantPeerRead ||
		snapshot.Records != uint64(requests) || answers != requests || acknowledgements != requests {
		t.Fatal("resource phase protocol or event counters do not match fixed cycles")
	}
	effectiveSend, effectiveRead := resourceTopology.effectiveSendBuffer, resourceTopology.effectiveReadBuffer
	resourceTopology.close(t, ctx)
	runtime.GC()
	runtime.Gosched()
	goroutineAfterCleanup := runtime.NumGoroutine()
	if goroutineAfterCleanup != goroutineBaseline {
		t.Fatalf("resource worker goroutines after cleanup = %d, want %d", goroutineAfterCleanup, goroutineBaseline)
	}
	p50, p95, p99 := nearestRankLatencyQuantiles(latencies)
	mallocDelta := memoryAfter.Mallocs - allocationBaseline.Mallocs
	totalAllocDelta := memoryAfter.TotalAlloc - allocationBaseline.TotalAlloc
	heapPeak := max(sampler.heapHighWater(), memoryAfter.HeapAlloc)
	if heapPeak < workerBaseline.HeapAlloc {
		t.Fatalf("resource heap peak %d is below pre-topology worker baseline %d", heapPeak, workerBaseline.HeapAlloc)
	}
	goroutinePeak := goroutineBaseline + sampler.goroutineDelta()
	return engineBenchmarkWorkerResult{
		Metrics: engineTrialMetrics{
			P50: p50, P95: p95, P99: p99, LatencySamples: latencies,
			ResourceDuration: duration, ResourceCycles: engineBenchmarkCLI.resourceCycles, ResourceRequests: requests,
			ResourceRawBytesRead: snapshot.BytesWritten, ResourceRawBytesWritten: snapshot.BytesRead,
			ResourceMallocs: mallocDelta, ResourceTotalAllocBytes: totalAllocDelta,
			AllocsPerRequest:         float64(mallocDelta) / float64(requests),
			AllocatedBytesPerRequest: float64(totalAllocDelta) / float64(requests),
			AbsoluteGoroutineDelta:   sampler.goroutineDelta(), GoroutineBaseline: goroutineBaseline, GoroutinePeak: goroutinePeak,
			HeapBytesHighWater:      heapPeak - workerBaseline.HeapAlloc,
			HeapBytesWorkerBaseline: workerBaseline.HeapAlloc, HeapBytesAllocationBaseline: allocationBaseline.HeapAlloc,
			HeapBytesPeak:            heapPeak,
			SubmissionHighWater:      queueSnapshot.SubmissionHighWater,
			SubmissionBytesHighWater: queueSnapshot.SubmissionBytesHighWater,
			EventHighWater:           queueSnapshot.EventHighWater, EventBytesHighWater: queueSnapshot.EventBytesHighWater,
		},
		Raw: engineBenchmarkRawObservation{
			ResourceWarmupCycles: warmupCycles,
			ResourceAnswers:      answers, ResourceAcknowledgements: acknowledgements,
			ResourcePeerRecords: snapshot.Records,
			GoroutineBaseline:   goroutineBaseline, GoroutineHighWater: goroutinePeak,
			GoroutineAfterCleanup:   goroutineAfterCleanup,
			HeapBytesWorkerBaseline: workerBaseline.HeapAlloc, HeapBytesAllocationBaseline: allocationBaseline.HeapAlloc,
			EffectiveWorkerSendBuffer: effectiveSend, EffectiveWorkerReadBuffer: effectiveRead,
			EffectivePeerSendBuffer: snapshot.EffectiveSendBuffer, EffectivePeerReadBuffer: snapshot.EffectiveReadBuffer,
			EffectiveWorkerNoDelay: resourceTopology.effectiveNoDelay, EffectivePeerNoDelay: snapshot.EffectiveNoDelay,
			EffectiveWorkerCPUSet: effectiveCPUSet,
		},
	}
}

func runEngineBenchmarkWarmup(
	t testing.TB,
	ctx context.Context,
	topology *engineBenchmarkTopology,
	workload linkWorkload,
) int {
	t.Helper()
	started := time.Now()
	cycles := 0
	for cycles < engineBenchmarkCLI.warmupCycles || time.Since(started) < engineBenchmarkCLI.warmup {
		topology.runCycle(t, ctx, workload, false)
		cycles++
	}
	return cycles
}

func expectedBenchmarkBootstrapBytes() int {
	nonceFrame := NoncePacketSize + FullFrameOverhead
	handshakeFrame := encryptedFrameSize(HandshakePacketSize)
	return nonceFrame + handshakeFrame
}

func validateBenchmarkBootstrapSnapshot(t testing.TB, snapshot engineBenchmarkPeerSnapshot, expected uint64) {
	t.Helper()
	if snapshot.BytesRead != expected || snapshot.BytesWritten != expected || snapshot.Records != 0 {
		t.Fatalf("bootstrap peer counters read=%d written=%d records=%d, want %d/%d/0",
			snapshot.BytesRead, snapshot.BytesWritten, snapshot.Records, expected, expected)
	}
}

type engineBenchmarkTopology struct {
	engine              string
	links               []ClientLink
	runtime             *GnetClientRuntime
	events              chan engineBenchmarkEventResult
	pending             engineBenchmarkPending
	eventWait           sync.WaitGroup
	backpressure        atomic.Uint64
	effectiveSendBuffer int
	effectiveReadBuffer int
	effectiveNoDelay    bool
	nextSubmissionID    atomic.Uint64
	eventContext        context.Context
	cancelEvents        context.CancelFunc
}

type engineBenchmarkPendingItem struct {
	started    time.Time
	wantPacket []byte
}

type engineBenchmarkPending struct {
	mu    sync.Mutex
	items map[int64]engineBenchmarkPendingItem
}

type engineBenchmarkEventResult struct {
	kind         LinkEventKind
	connectionID int64
	latency      time.Duration
	err          error
}

func newEngineBenchmarkTopology(
	t *testing.T,
	ctx context.Context,
	engine string,
	workload linkWorkload,
	limits LinkLimits,
) *engineBenchmarkTopology {
	t.Helper()
	topology := &engineBenchmarkTopology{
		engine: engine, links: make([]ClientLink, 0, engineBenchmarkCLI.workerLinks),
		events:  make(chan engineBenchmarkEventResult, len(workload.items)*2),
		pending: engineBenchmarkPending{items: make(map[int64]engineBenchmarkPendingItem, 4)},
	}
	topology.eventContext, topology.cancelEvents = context.WithCancel(ctx)
	if engine == "gnet" {
		gnetRuntime, err := NewGnetClientRuntime(GnetClientRuntimeConfig{EventLoops: engineBenchmarkCLI.eventLoops})
		if err != nil {
			t.Fatalf("create isolated gnet runtime: %v", err)
		}
		topology.runtime = gnetRuntime
	}
	for range engineBenchmarkCLI.workerLinks {
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", engineBenchmarkCLI.workerDataAddress)
		if err != nil {
			topology.close(t, ctx)
			t.Fatalf("dial isolated peer data: %v", err)
		}
		tcpConnection, ok := connection.(*net.TCPConn)
		if !ok {
			_ = connection.Close()
			topology.close(t, ctx)
			t.Fatalf("isolated data connection type = %T", connection)
		}
		if err := configureBenchmarkSocket(tcpConnection, engineBenchmarkCLI.socketBuffer); err != nil {
			_ = tcpConnection.Close()
			topology.close(t, ctx)
			t.Fatalf("configure isolated worker socket: %v", err)
		}
		sendBuffer, readBuffer, noDelay, err := benchmarkSocketControls(tcpConnection)
		if err != nil {
			_ = tcpConnection.Close()
			topology.close(t, ctx)
			t.Fatalf("read isolated worker socket buffers: %v", err)
		}
		if topology.effectiveSendBuffer == 0 {
			topology.effectiveSendBuffer, topology.effectiveReadBuffer, topology.effectiveNoDelay = sendBuffer, readBuffer, noDelay
		} else if topology.effectiveSendBuffer != sendBuffer || topology.effectiveReadBuffer != readBuffer || topology.effectiveNoDelay != noDelay {
			_ = tcpConnection.Close()
			topology.close(t, ctx)
			t.Fatal("effective isolated worker socket buffers changed between links")
		}
		var link ClientLink
		if engine == "blocking" {
			link, err = NewBlockingClientLinkEngine(tcpConnection, newTestBootstrap(t), limits)
		} else {
			link, err = topology.runtime.NewClientLink(tcpConnection, newTestBootstrap(t), limits)
		}
		if err != nil {
			_ = tcpConnection.Close()
			topology.close(t, ctx)
			t.Fatalf("construct isolated %s link: %v", engine, err)
		}
		if err := link.Start(ctx); err != nil {
			topology.close(t, ctx)
			t.Fatalf("start isolated %s link: %v", engine, err)
		}
		topology.links = append(topology.links, link)
		topology.eventWait.Go(func() { topology.consumeEvents(link) })
	}
	return topology
}

func (t *engineBenchmarkTopology) consumeEvents(link ClientLink) {
	for event := range link.Events() {
		result := engineBenchmarkEventResult{kind: event.Kind, connectionID: event.ConnectionID}
		switch event.Kind {
		case LinkEventProxyAnswer:
			pending, ok := t.pending.take(event.ConnectionID)
			if !ok {
				result.err = fmt.Errorf("answer for connection %d has no in-flight request", event.ConnectionID)
			} else if !bytes.Equal(event.Packet, pending.wantPacket) {
				result.err = fmt.Errorf("answer packet mismatch for connection %d", event.ConnectionID)
			} else {
				result.latency = time.Since(pending.started)
			}
		case LinkEventSimpleAck:
			result.err = validateEngineBenchmarkAcknowledgement(event)
		default:
			result.err = fmt.Errorf("unexpected benchmark event kind %d", event.Kind)
		}
		select {
		case t.events <- result:
		case <-t.eventContext.Done():
			return
		}
	}
}

func validateEngineBenchmarkAcknowledgement(event LinkEvent) error {
	if event.ConnectionID == 0 || event.ConfirmKey != uint32(event.ConnectionID) {
		return fmt.Errorf("invalid acknowledgement for connection %d", event.ConnectionID)
	}
	return nil
}

func (p *engineBenchmarkPending) register(connectionID int64, item engineBenchmarkPendingItem) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.items[connectionID]; exists {
		return fmt.Errorf("connection %d already has an in-flight request", connectionID)
	}
	p.items[connectionID] = item
	return nil
}

func (p *engineBenchmarkPending) remove(connectionID int64) {
	p.mu.Lock()
	delete(p.items, connectionID)
	p.mu.Unlock()
}

func (p *engineBenchmarkPending) take(connectionID int64) (engineBenchmarkPendingItem, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	item, ok := p.items[connectionID]
	delete(p.items, connectionID)
	return item, ok
}

func (p *engineBenchmarkPending) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.items)
}

func (t *engineBenchmarkTopology) runCycle(
	test testing.TB,
	ctx context.Context,
	workload linkWorkload,
	retainLatencies bool,
) (int, int, []time.Duration) {
	test.Helper()
	latencies := make([]time.Duration, 0)
	if retainLatencies {
		latencies = make([]time.Duration, 0, len(workload.items))
	}
	answers := 0
	acknowledgements := 0
	for offset := 0; offset < len(workload.items); offset += 4 {
		round := workload.items[offset : offset+4]
		for _, item := range round {
			link := t.links[item.sessionIndex%len(t.links)]
			payload := bytes.Clone(item.submission.Payload)
			for {
				started := time.Now()
				if err := t.pending.register(item.submission.ConnectionID, engineBenchmarkPendingItem{
					started: started, wantPacket: item.wantPacket,
				}); err != nil {
					test.Fatal(err)
				}
				submission := LinkSubmission{
					SubmissionID: t.nextSubmissionID.Add(1),
					ConnectionID: item.submission.ConnectionID,
					Payload:      payload,
				}
				err := link.TrySubmit(submission)
				if err == nil {
					break
				}
				t.pending.remove(item.submission.ConnectionID)
				if !errors.Is(err, ErrLinkBackpressure) {
					test.Fatalf("submit isolated benchmark request: %v", err)
				}
				t.backpressure.Add(1)
				select {
				case <-ctx.Done():
					test.Fatalf("retry isolated benchmark request: %v", context.Cause(ctx))
				default:
					runtime.Gosched()
				}
			}
		}
		results := make([]engineBenchmarkEventResult, 0, len(round)*2)
		for range len(round) * 2 {
			select {
			case result := <-t.events:
				if result.err != nil {
					test.Fatal(result.err)
				}
				results = append(results, result)
			case <-ctx.Done():
				test.Fatalf("wait isolated benchmark event: %v", context.Cause(ctx))
			}
		}
		expectedIDs := make([]int64, 0, len(round))
		for _, item := range round {
			expectedIDs = append(expectedIDs, item.submission.ConnectionID)
		}
		roundAnswers, roundAcknowledgements, roundLatencies, err := validateEngineBenchmarkRoundEvents(expectedIDs, results)
		if err != nil {
			test.Fatal(err)
		}
		answers += roundAnswers
		acknowledgements += roundAcknowledgements
		if retainLatencies {
			latencies = append(latencies, roundLatencies...)
		}
		if len(t.events) != 0 {
			test.Fatalf("benchmark round retained %d unexpected events", len(t.events))
		}
	}
	if pending := t.pending.count(); pending != 0 {
		test.Fatalf("benchmark cycle retained %d in-flight requests", pending)
	}
	return answers, acknowledgements, latencies
}

func validateEngineBenchmarkRoundEvents(
	expectedConnectionIDs []int64,
	results []engineBenchmarkEventResult,
) (int, int, []time.Duration, error) {
	type kinds struct{ answer, acknowledgement bool }
	seen := make(map[int64]kinds, len(expectedConnectionIDs))
	for _, connectionID := range expectedConnectionIDs {
		if connectionID == 0 {
			return 0, 0, nil, errors.New("expected zero benchmark connection ID")
		}
		if _, duplicate := seen[connectionID]; duplicate {
			return 0, 0, nil, fmt.Errorf("duplicate expected benchmark connection ID %d", connectionID)
		}
		seen[connectionID] = kinds{}
	}
	latencies := make([]time.Duration, 0, len(expectedConnectionIDs))
	answers, acknowledgements := 0, 0
	for _, result := range results {
		state, expected := seen[result.connectionID]
		if !expected {
			return 0, 0, nil, fmt.Errorf("event for unexpected benchmark connection ID %d", result.connectionID)
		}
		switch result.kind {
		case LinkEventProxyAnswer:
			if state.answer {
				return 0, 0, nil, fmt.Errorf("duplicate answer for benchmark connection ID %d", result.connectionID)
			}
			state.answer = true
			answers++
			latencies = append(latencies, result.latency)
		case LinkEventSimpleAck:
			if state.acknowledgement {
				return 0, 0, nil, fmt.Errorf("duplicate acknowledgement for benchmark connection ID %d", result.connectionID)
			}
			state.acknowledgement = true
			acknowledgements++
		default:
			return 0, 0, nil, fmt.Errorf("unexpected benchmark event kind %d", result.kind)
		}
		seen[result.connectionID] = state
	}
	for connectionID, state := range seen {
		if !state.answer || !state.acknowledgement {
			return 0, 0, nil, fmt.Errorf("benchmark connection ID %d answer/ack=%t/%t", connectionID, state.answer, state.acknowledgement)
		}
	}
	return answers, acknowledgements, latencies, nil
}

func (t *engineBenchmarkTopology) snapshot() LinkSnapshot {
	var result LinkSnapshot
	for _, link := range t.links {
		snapshot := link.Snapshot()
		result.SubmissionHighWater = max(result.SubmissionHighWater, snapshot.SubmissionHighWater)
		result.SubmissionBytesHighWater = max(result.SubmissionBytesHighWater, snapshot.SubmissionBytesHighWater)
		result.EventHighWater = max(result.EventHighWater, snapshot.EventHighWater)
		result.EventBytesHighWater = max(result.EventBytesHighWater, snapshot.EventBytesHighWater)
	}
	return result
}

func (t *engineBenchmarkTopology) close(test testing.TB, ctx context.Context) {
	test.Helper()
	for _, link := range t.links {
		if err := link.Close(); err != nil {
			test.Errorf("close isolated %s link: %v", t.engine, err)
		}
	}
	for _, link := range t.links {
		select {
		case <-link.Done():
		case <-ctx.Done():
			test.Fatalf("wait isolated %s link: %v", t.engine, context.Cause(ctx))
		}
	}
	t.cancelEvents()
	eventsDone := make(chan struct{})
	go func() {
		t.eventWait.Wait()
		close(eventsDone)
	}()
	select {
	case <-eventsDone:
	case <-ctx.Done():
		test.Fatalf("wait isolated %s event consumers: %v", t.engine, context.Cause(ctx))
	case <-time.After(benchmarkStopTimeout):
		test.Fatalf("wait isolated %s event consumers: timeout", t.engine)
	}
	if len(t.events) != 0 {
		test.Fatalf("isolated %s shutdown retained %d events", t.engine, len(t.events))
	}
	if t.runtime != nil {
		if err := t.runtime.Stop(ctx); err != nil {
			test.Fatalf("stop isolated gnet runtime: %v", err)
		}
	}
	t.links = nil
}

type engineBenchmarkResourceSampler struct {
	stopSignal     chan struct{}
	done           chan struct{}
	activateSignal chan struct{}
	ready          chan struct{}
	heap           atomic.Uint64
	goroutines     atomic.Int64
	baseline       int
}

func prepareEngineBenchmarkResourceSampler(interval time.Duration) *engineBenchmarkResourceSampler {
	sampler := &engineBenchmarkResourceSampler{
		stopSignal: make(chan struct{}), done: make(chan struct{}), activateSignal: make(chan struct{}), ready: make(chan struct{}),
	}
	go func() {
		defer close(sampler.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		close(sampler.ready)
		<-sampler.activateSignal
		for {
			sampler.sample()
			select {
			case <-ticker.C:
			case <-sampler.stopSignal:
				sampler.sample()
				return
			}
		}
	}()
	<-sampler.ready
	return sampler
}

func (s *engineBenchmarkResourceSampler) activate(baseline int, heap uint64) {
	s.baseline = baseline
	s.heap.Store(heap)
	close(s.activateSignal)
}

func (s *engineBenchmarkResourceSampler) sample() {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	for current := s.heap.Load(); memory.HeapAlloc > current && !s.heap.CompareAndSwap(current, memory.HeapAlloc); current = s.heap.Load() {
	}
	difference := runtime.NumGoroutine() - s.baseline
	if difference < 0 {
		difference = -difference
	}
	for current := s.goroutines.Load(); int64(difference) > current && !s.goroutines.CompareAndSwap(current, int64(difference)); current = s.goroutines.Load() {
	}
}

func (s *engineBenchmarkResourceSampler) stop() {
	close(s.stopSignal)
	<-s.done
}

func (s *engineBenchmarkResourceSampler) heapHighWater() uint64 {
	return s.heap.Load()
}

func (s *engineBenchmarkResourceSampler) goroutineDelta() int {
	return int(s.goroutines.Load())
}

func configureBenchmarkSocket(connection *net.TCPConn, requested int) error {
	if err := connection.SetNoDelay(true); err != nil {
		return fmt.Errorf("set TCP_NODELAY: %w", err)
	}
	if err := connection.SetWriteBuffer(requested); err != nil {
		return fmt.Errorf("set socket write buffer: %w", err)
	}
	if err := connection.SetReadBuffer(requested); err != nil {
		return fmt.Errorf("set socket read buffer: %w", err)
	}
	return nil
}

func benchmarkSocketControls(connection *net.TCPConn) (send int, receive int, noDelay bool, err error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, 0, false, err
	}
	var controlErr error
	if err := raw.Control(func(descriptor uintptr) {
		send, controlErr = unix.GetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_SNDBUF)
		if controlErr != nil {
			return
		}
		receive, controlErr = unix.GetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if controlErr != nil {
			return
		}
		var noDelayValue int
		noDelayValue, controlErr = unix.GetsockoptInt(int(descriptor), unix.IPPROTO_TCP, unix.TCP_NODELAY)
		noDelay = noDelayValue == 1
	}); err != nil {
		return 0, 0, false, err
	}
	return send, receive, noDelay, controlErr
}

func verifyProcessThreadCPUSet(t testing.TB, value string) string {
	t.Helper()
	requested := mustParseCPUSet(t, value)
	want := canonicalCPUSet(requested)
	processStatus, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("read process affinity: %v", err)
	}
	if got := cpuSetFromProcStatus(t, processStatus); got != want {
		t.Fatalf("effective process CPU affinity %q, want %q", got, want)
	}
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatalf("list process threads: %v", err)
	}
	verified := 0
	for _, task := range tasks {
		status, err := os.ReadFile(filepath.Join("/proc/self/task", task.Name(), "status"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("read thread %s affinity: %v", task.Name(), err)
		}
		if got := cpuSetFromProcStatus(t, status); got != want {
			t.Fatalf("thread %s CPU affinity %q, want %q", task.Name(), got, want)
		}
		verified++
	}
	if verified == 0 {
		t.Fatal("no process threads were available for affinity verification")
	}
	return want
}

func cpuSetFromProcStatus(t testing.TB, status []byte) string {
	t.Helper()
	for line := range strings.SplitSeq(string(status), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok && name == "Cpus_allowed_list" {
			cpus, err := parseCPUSet(strings.TrimSpace(value))
			if err != nil {
				t.Fatalf("parse /proc CPU affinity: %v", err)
			}
			return canonicalCPUSet(cpus)
		}
	}
	t.Fatal("process status has no Cpus_allowed_list")
	return ""
}

func mustParseCPUSet(t testing.TB, value string) map[int]struct{} {
	t.Helper()
	result, err := parseCPUSet(value)
	if err != nil {
		t.Fatalf("parse CPU set: %v", err)
	}
	return result
}

func writeBenchmarkJSON(path string, value any) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".mebench-child-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	// DefaultOptionsV1 gives time.Duration its numeric representation while
	// the v2 encoder keeps deterministic output for the child artifact.
	if err := json.MarshalWrite(temporary, value, jsonv1.DefaultOptionsV1(), json.Deterministic(true)); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	closed = true
	return os.Rename(temporaryPath, path)
}

func readBenchmarkJSON(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return readBenchmarkJSONFile(file, value)
}

type engineBenchmarkCountingReader struct {
	reader   io.Reader
	consumed int64
}

func (r *engineBenchmarkCountingReader) Read(buffer []byte) (int, error) {
	count, err := r.reader.Read(buffer)
	r.consumed += int64(count)
	return count, err
}

func readBenchmarkJSONFile(file *os.File, value any) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().IsRegular() && info.Size() > engineBenchmarkMaxJSONBytes {
		return fmt.Errorf("benchmark JSON exceeds schema-derived safety ceiling %d bytes", engineBenchmarkMaxJSONBytes)
	}
	limited := io.LimitReader(file, int64(engineBenchmarkMaxJSONBytes)+1)
	counting := &engineBenchmarkCountingReader{reader: limited}
	decodeErr := json.UnmarshalRead(counting, value, jsonv1.DefaultOptionsV1(), json.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false))
	if counting.consumed > engineBenchmarkMaxJSONBytes {
		return fmt.Errorf("benchmark JSON exceeds schema-derived safety ceiling %d bytes", engineBenchmarkMaxJSONBytes)
	}
	return decodeErr
}

func TestEngineBenchmarkByteFormula(t *testing.T) {
	if got := expectedBenchmarkBootstrapBytes(); got != 92 {
		t.Fatalf("bootstrap bytes per direction = %d, want 92", got)
	}
	read, written := expectedBenchmarkCycleBytes(t, deterministicLinkWorkload(t))
	if written != 6_555_136 || read != 6_554_624 {
		t.Fatalf("cycle bytes read=%d written=%d, want 6554624/6555136", read, written)
	}
}

func TestNearestRankLatencyQuantiles(t *testing.T) {
	samples := []time.Duration{9, 1, 8, 2, 7, 3, 6, 4, 5, 10} // nanoseconds
	p50, p95, p99 := nearestRankLatencyQuantiles(samples)
	if p50 != 5 || p95 != 10 || p99 != 10 {
		t.Fatalf("nearest-rank quantiles = %s/%s/%s", p50, p95, p99)
	}
	if !slices.Equal(samples, []time.Duration{9, 1, 8, 2, 7, 3, 6, 4, 5, 10}) {
		t.Fatal("quantile calculation modified raw latency samples")
	}
}

func TestValidateEngineBenchmarkRoundEvents(t *testing.T) {
	valid := []engineBenchmarkEventResult{
		{kind: LinkEventSimpleAck, connectionID: 1001},
		{kind: LinkEventProxyAnswer, connectionID: 1000, latency: time.Nanosecond},
		{kind: LinkEventProxyAnswer, connectionID: 1001, latency: 2 * time.Nanosecond},
		{kind: LinkEventSimpleAck, connectionID: 1000},
	}
	answers, acknowledgements, latencies, err := validateEngineBenchmarkRoundEvents([]int64{1000, 1001}, valid)
	if err != nil || answers != 2 || acknowledgements != 2 || len(latencies) != 2 {
		t.Fatalf("valid round = answers %d acknowledgements %d latencies %d error %v", answers, acknowledgements, len(latencies), err)
	}
	tests := []struct {
		name    string
		results []engineBenchmarkEventResult
	}{
		{name: "duplicate answer", results: append(slices.Clone(valid[:2]), valid[1:]...)},
		{name: "duplicate acknowledgement", results: append(slices.Clone(valid), engineBenchmarkEventResult{kind: LinkEventSimpleAck, connectionID: 1000})},
		{name: "missing acknowledgement", results: valid[:3]},
		{name: "wrong identity", results: append(slices.Clone(valid[:3]), engineBenchmarkEventResult{kind: LinkEventSimpleAck, connectionID: 9999})},
		{name: "wrong kind", results: append(slices.Clone(valid[:3]), engineBenchmarkEventResult{kind: LinkEventPing, connectionID: 1000})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, err := validateEngineBenchmarkRoundEvents([]int64{1000, 1001}, test.results); err == nil {
				t.Fatal("malformed round was accepted")
			}
		})
	}
	if err := validateEngineBenchmarkAcknowledgement(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 1000, ConfirmKey: 999}); err == nil {
		t.Fatal("acknowledgement with wrong ConfirmKey was accepted")
	}
	if err := validateEngineBenchmarkAcknowledgement(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 0}); err == nil {
		t.Fatal("acknowledgement with zero ConnectionID was accepted")
	}
}
