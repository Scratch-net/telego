//go:build linux

package middleend

import (
	"bytes"
	"context"
	"crypto/sha256"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	engineBenchmarkReportVersion      = "middleend-link-engine-benchmark-v4"
	benchmarkStopTimeout              = 10 * time.Second
	benchmarkResourceAttribution      = "fresh-resource-worker-process:engine-plus-submission-driver;separate-peer-process;sampler-infrastructure-before-post-topology-allocation-baseline;goroutine-and-heap-high-water-include-one-sampler;heap-peak-delta-from-pre-topology-worker-baseline"
	sharedProtocolBenchmarkExpression = "^(BenchmarkClientBootstrapReadyEncode|BenchmarkClientBootstrapReadyFeed)$"
	sharedProtocolAffinityAttestation = "taskset-before-go-runtime;all-process-threads-verified-at-each-benchmark-start-and-end"
	// Each allowed phase child receives an 8 KiB encoded-evidence budget. A
	// golden test keeps the fixed worker-result envelope below 4 KiB; the other
	// half is reserved for retained decimal time.Duration samples (20 digits and
	// one delimiter). The complete JSON ceiling is therefore 32 MiB at the
	// MaxLinkQueueItems child-observation ceiling, not the queue's 512 MiB payload
	// allowance.
	engineBenchmarkJSONBytesPerChild                       = 8 * 1024
	engineBenchmarkFixedJSONBytesPerChild                  = engineBenchmarkJSONBytesPerChild / 2
	engineBenchmarkLatencyJSONBytesPerChild                = engineBenchmarkJSONBytesPerChild / 2
	engineBenchmarkMaxJSONBytes                            = MaxLinkQueueItems * engineBenchmarkJSONBytesPerChild
	engineBenchmarkMaxLatencyJSONBytes                     = MaxLinkQueueItems * engineBenchmarkLatencyJSONBytesPerChild
	engineBenchmarkMaxEncodedDurationBytes                 = 21
	engineBenchmarkMaxLatencySamplesPerResourceObservation = engineBenchmarkLatencyJSONBytesPerChild / engineBenchmarkMaxEncodedDurationBytes
)

var engineBenchmarkCLI struct {
	output               string
	cpuPolicy            string
	minimumImprovement   string
	maximumRegression    string
	trials               int
	gomaxprocs           int
	eventLoops           int
	warmup               time.Duration
	duration             time.Duration
	resourceCycles       int
	multiLinks           int
	slowReadChunk        int
	slowReadDelay        time.Duration
	warmupCycles         int
	heapSampleInterval   time.Duration
	socketBuffer         int
	workerCPUSet         string
	peerCPUSet           string
	observationTimeout   time.Duration
	baselineIterations   int
	purpose              string
	verifyReport         string
	worker               bool
	peer                 bool
	workerEngine         string
	workerPhase          string
	workerLinks          int
	workerSlowReadChunk  int
	workerSlowReadDelay  time.Duration
	workerOutput         string
	workerDataAddress    string
	workerControlAddress string
	peerReadyOutput      string
	peerLinks            int
}

func init() {
	flag.StringVar(&engineBenchmarkCLI.output, "mebench-output", "", "required path for the raw JSON report")
	flag.StringVar(&engineBenchmarkCLI.cpuPolicy, "mebench-cpu-policy", "", "required description of the fixed CPU policy")
	flag.StringVar(&engineBenchmarkCLI.minimumImprovement, "mebench-min-improvement", "", "required comma-separated metric=fraction policy")
	flag.StringVar(&engineBenchmarkCLI.maximumRegression, "mebench-max-regression", "", "required comma-separated metric=fraction policy")
	flag.IntVar(&engineBenchmarkCLI.trials, "mebench-trials", 0, "required paired trial count (minimum 10)")
	flag.IntVar(&engineBenchmarkCLI.gomaxprocs, "mebench-gomaxprocs", 0, "required GOMAXPROCS value")
	flag.IntVar(&engineBenchmarkCLI.eventLoops, "mebench-event-loops", 0, "required gnet event-loop count")
	flag.DurationVar(&engineBenchmarkCLI.warmup, "mebench-warmup", 0, "required warmup duration per observation")
	flag.DurationVar(&engineBenchmarkCLI.duration, "mebench-duration", 0, "required minimum measurement duration per observation")
	flag.IntVar(&engineBenchmarkCLI.resourceCycles, "mebench-resource-cycles", 0, "required fixed resource/latency cycles per observation")
	flag.IntVar(&engineBenchmarkCLI.multiLinks, "mebench-multi-links", 0, "required multi-link scenario count")
	flag.IntVar(&engineBenchmarkCLI.slowReadChunk, "mebench-slow-read-chunk", 0, "required slow-peer read chunk")
	flag.DurationVar(&engineBenchmarkCLI.slowReadDelay, "mebench-slow-read-delay", 0, "required slow-peer delay before each read")
	flag.IntVar(&engineBenchmarkCLI.warmupCycles, "mebench-warmup-cycles", 0, "required minimum complete warmup cycles")
	flag.DurationVar(&engineBenchmarkCLI.heapSampleInterval, "mebench-heap-sample-interval", 0, "required resource-phase heap sample interval")
	flag.IntVar(&engineBenchmarkCLI.socketBuffer, "mebench-socket-buffer", 0, "required requested worker send and peer receive socket buffer")
	flag.StringVar(&engineBenchmarkCLI.workerCPUSet, "mebench-worker-cpus", "", "required worker CPU affinity list")
	flag.StringVar(&engineBenchmarkCLI.peerCPUSet, "mebench-peer-cpus", "", "required peer CPU affinity list, disjoint from worker")
	flag.DurationVar(&engineBenchmarkCLI.observationTimeout, "mebench-observation-timeout", 0, "required hard timeout for one isolated observation")
	flag.IntVar(&engineBenchmarkCLI.baselineIterations, "mebench-baseline-iterations", 0, "required iteration count for each shared-protocol baseline")
	flag.StringVar(&engineBenchmarkCLI.purpose, "mebench-purpose", "", "required report purpose: smoke or decision")
	flag.StringVar(&engineBenchmarkCLI.verifyReport, "mebench-verify-report", "", "strictly verify an existing report against the current source and test binary")
	flag.BoolVar(&engineBenchmarkCLI.worker, "mebench-worker", false, "internal isolated observation worker")
	flag.BoolVar(&engineBenchmarkCLI.peer, "mebench-peer", false, "internal isolated fake-peer worker")
	flag.StringVar(&engineBenchmarkCLI.workerEngine, "mebench-worker-engine", "", "internal worker engine")
	flag.StringVar(&engineBenchmarkCLI.workerPhase, "mebench-worker-phase", "", "internal worker phase")
	flag.IntVar(&engineBenchmarkCLI.workerLinks, "mebench-worker-links", 0, "internal worker link count")
	flag.IntVar(&engineBenchmarkCLI.workerSlowReadChunk, "mebench-worker-slow-read-chunk", 0, "internal worker slow-read chunk")
	flag.DurationVar(&engineBenchmarkCLI.workerSlowReadDelay, "mebench-worker-slow-read-delay", 0, "internal worker slow-read delay")
	flag.StringVar(&engineBenchmarkCLI.workerOutput, "mebench-worker-output", "", "internal worker output")
	flag.StringVar(&engineBenchmarkCLI.workerDataAddress, "mebench-worker-data-address", "", "internal peer data address")
	flag.StringVar(&engineBenchmarkCLI.workerControlAddress, "mebench-worker-control-address", "", "internal peer control address")
	flag.StringVar(&engineBenchmarkCLI.peerReadyOutput, "mebench-peer-ready-output", "", "internal peer ready output")
	flag.IntVar(&engineBenchmarkCLI.peerLinks, "mebench-peer-links", 0, "internal total accepted peer links")
}

type engineBenchmarkRunConfig struct {
	Purpose             string
	Output              string
	CPUPolicy           string
	Policy              engineDecisionPolicy
	GOMAXPROCS          int
	EventLoops          int
	Warmup              time.Duration
	MeasurementDuration time.Duration
	ResourceCycles      int
	MultiLinks          int
	SlowReadChunk       int
	SlowReadDelay       time.Duration
	WarmupCycles        int
	HeapSampleInterval  time.Duration
	SocketBuffer        int
	WorkerCPUSet        string
	PeerCPUSet          string
	ObservationTimeout  time.Duration
	BaselineIterations  int
	TasksetPath         string
}

type engineBenchmarkSource struct {
	Commit      string
	Dirty       bool
	Fingerprint string
}

type engineBenchmarkEnvironment struct {
	ExecutablePath     string
	GoVersion          string
	GOOS               string
	GOARCH             string
	Machine            string
	CPUPolicy          string
	GOMAXPROCS         int
	EventLoops         int
	BinaryHash         string
	BuildSettings      []string
	Kernel             string
	GOGC               string
	GOMEMLIMIT         string
	GODEBUG            string
	WorkerCPUSet       string
	PeerCPUSet         string
	TasksetPath        string
	TasksetVersion     string
	BaselineIterations int
}

type engineSharedProtocolBaseline struct {
	Operation           string
	PayloadSize         int
	GOMAXPROCS          int
	Iterations          int
	NanosecondsPerOp    float64
	AllocatedBytesPerOp uint64
	AllocationsPerOp    uint64
}

type engineSharedProtocolBaselineReport struct {
	Commit                string
	SourceFingerprint     string
	BinaryHash            string
	GoVersion             string
	TestBinaryPath        string
	TasksetPath           string
	BenchmarkExpression   string
	Iterations            int
	GOMAXPROCS            int
	WorkerCPUSet          string
	EffectiveWorkerCPUSet string
	AffinityAttestation   string
	Command               []string
	RawOutput             string
	Results               []engineSharedProtocolBaseline
}

type engineBenchmarkScenario struct {
	Name          string
	Links         int
	SlowReadChunk int
	SlowReadDelay time.Duration
}

type engineBenchmarkRawObservation struct {
	ThroughputWarmupCycles      int
	ResourceWarmupCycles        int
	ThroughputAnswers           int
	ThroughputAcknowledgements  int
	ResourceAnswers             int
	ResourceAcknowledgements    int
	ThroughputPeerRecords       uint64
	ResourcePeerRecords         uint64
	GoroutineBaseline           int
	GoroutineHighWater          int
	GoroutineAfterCleanup       int
	HeapBytesWorkerBaseline     uint64
	HeapBytesAllocationBaseline uint64
	EffectiveWorkerSendBuffer   int
	EffectiveWorkerReadBuffer   int
	EffectivePeerSendBuffer     int
	EffectivePeerReadBuffer     int
	EffectiveWorkerNoDelay      bool
	EffectivePeerNoDelay        bool
	EffectiveWorkerCPUSet       string
	EffectivePeerCPUSet         string
	PeerGOMAXPROCS              int
}

type engineBenchmarkWorkerResult struct {
	Metrics engineTrialMetrics
	Raw     engineBenchmarkRawObservation
}

type engineBenchmarkRawPair struct {
	PairIndex   int
	FirstEngine string
	Blocking    engineBenchmarkRawObservation
	Gnet        engineBenchmarkRawObservation
}

type engineBenchmarkScenarioReport struct {
	Scenario    engineBenchmarkScenario
	Measurement engineMeasurement
	RawTrials   []engineBenchmarkRawPair
	Selection   engineSelection
}

type engineBenchmarkCorrectnessGate struct {
	Passed            bool
	BlockingPassed    bool
	GnetPassed        bool
	TestBinaryHash    string
	TestBinaryPath    string
	SourceFingerprint string
	Tests             [2]string
}

type engineBenchmarkReport struct {
	SchemaVersion           string
	Purpose                 string
	CreatedAt               time.Time
	Source                  engineBenchmarkSource
	Environment             engineBenchmarkEnvironment
	SharedProtocolBaselines engineSharedProtocolBaselineReport
	Correctness             engineBenchmarkCorrectnessGate
	ConfiguredMultiLinks    int
	ConfiguredSlowReadChunk int
	ConfiguredSlowReadDelay time.Duration
	Scenarios               []engineBenchmarkScenarioReport
	OverallSelection        engineSelection
}

func TestEngineComparisonRunner(t *testing.T) {
	if engineBenchmarkCLI.peer {
		runEngineBenchmarkPeer(t)
		return
	}
	if engineBenchmarkCLI.worker {
		runEngineBenchmarkWorker(t)
		return
	}
	if engineBenchmarkCLI.verifyReport != "" {
		if engineBenchmarkCLI.output != "" {
			t.Fatal("-mebench-verify-report and -mebench-output are mutually exclusive")
		}
		report, err := readEngineBenchmarkReportStrict(engineBenchmarkCLI.verifyReport)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateEngineBenchmarkReport(report); err != nil {
			t.Fatalf("validate benchmark report: %v", err)
		}
		if err := validateEngineBenchmarkCurrentProvenance(report); err != nil {
			t.Fatalf("validate current benchmark provenance: %v", err)
		}
		t.Logf("Middle-End engine benchmark report verified: %s", engineBenchmarkCLI.verifyReport)
		return
	}
	if engineBenchmarkCLI.output == "" {
		t.Skip("set -mebench-output and every required benchmark policy/control flag to run")
	}
	config, err := parseEngineBenchmarkRunConfig()
	if err != nil {
		t.Fatal(err)
	}
	tasksetPath, tasksetVersion, err := inspectEngineBenchmarkTaskset()
	if err != nil {
		t.Fatalf("inspect taskset: %v", err)
	}
	config.TasksetPath = tasksetPath

	previousGOMAXPROCS := runtime.GOMAXPROCS(config.GOMAXPROCS)
	t.Cleanup(func() { runtime.GOMAXPROCS(previousGOMAXPROCS) })

	source, err := inspectEngineBenchmarkSource()
	if err != nil {
		t.Fatalf("inspect benchmark source: %v", err)
	}
	machine, err := inspectEngineBenchmarkMachine()
	if err != nil {
		t.Fatalf("inspect benchmark machine: %v", err)
	}
	binaryHash, buildSettings, kernel, err := inspectEngineBenchmarkBinary()
	if err != nil {
		t.Fatalf("inspect benchmark binary: %v", err)
	}
	executablePath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve benchmark executable: %v", err)
	}
	executablePath = filepath.Clean(executablePath)
	sharedProtocolBaselines := runEngineSharedProtocolBaselines(t, config, source, binaryHash)

	blockingCorrect := runBlockingBenchmarkCorrectness(t)
	gnetCorrect := runGnetBenchmarkCorrectness(t, config.EventLoops)
	if !blockingCorrect || !gnetCorrect {
		t.Fatalf("correctness gate failed: blocking=%t gnet=%t", blockingCorrect, gnetCorrect)
	}

	workload := deterministicLinkWorkload(t)
	limits := limitsForWorkload(workload)
	expectedRead, expectedWritten := expectedBenchmarkCycleBytes(t, workload)
	scenarios := []engineBenchmarkScenario{
		{Name: "single-link-normal", Links: 1},
		{Name: "multi-link-normal", Links: config.MultiLinks},
		{Name: "single-link-slow-reader", Links: 1, SlowReadChunk: config.SlowReadChunk, SlowReadDelay: config.SlowReadDelay},
		{Name: "multi-link-slow-reader", Links: config.MultiLinks, SlowReadChunk: config.SlowReadChunk, SlowReadDelay: config.SlowReadDelay},
	}

	report := engineBenchmarkReport{
		SchemaVersion: engineBenchmarkReportVersion,
		Purpose:       config.Purpose,
		CreatedAt:     time.Now().UTC(),
		Source:        source,
		Environment: engineBenchmarkEnvironment{
			ExecutablePath: executablePath,
			GoVersion:      runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
			Machine: machine, CPUPolicy: config.CPUPolicy,
			GOMAXPROCS: config.GOMAXPROCS, EventLoops: config.EventLoops,
			BinaryHash: binaryHash, BuildSettings: buildSettings, Kernel: kernel,
			GOGC: os.Getenv("GOGC"), GOMEMLIMIT: os.Getenv("GOMEMLIMIT"), GODEBUG: os.Getenv("GODEBUG"),
			WorkerCPUSet: config.WorkerCPUSet, PeerCPUSet: config.PeerCPUSet,
			TasksetPath: tasksetPath, TasksetVersion: tasksetVersion,
			BaselineIterations: config.BaselineIterations,
		},
		SharedProtocolBaselines: sharedProtocolBaselines,
		OverallSelection:        engineSelectionNone,
		Correctness: engineBenchmarkCorrectnessGate{
			Passed: blockingCorrect && gnetCorrect, BlockingPassed: blockingCorrect, GnetPassed: gnetCorrect,
			TestBinaryHash: binaryHash, TestBinaryPath: executablePath, SourceFingerprint: source.Fingerprint,
			Tests: [2]string{"benchmark-correctness/blocking", "benchmark-correctness/gnet"},
		},
		ConfiguredMultiLinks: config.MultiLinks, ConfiguredSlowReadChunk: config.SlowReadChunk,
		ConfiguredSlowReadDelay: config.SlowReadDelay,
		Scenarios:               make([]engineBenchmarkScenarioReport, 0, len(scenarios)),
	}
	for _, scenario := range scenarios {
		scenarioReport := runEngineBenchmarkScenario(t, config, source, machine, workload, limits, scenario, expectedRead, expectedWritten, blockingCorrect, gnetCorrect)
		report.Scenarios = append(report.Scenarios, scenarioReport)
	}
	if config.Purpose == engineBenchmarkPurposeDecision {
		report.OverallSelection = combineEngineBenchmarkSelections(report.Scenarios)
	}
	if err := validateEngineBenchmarkReport(report); err != nil {
		t.Fatalf("validate benchmark report: %v", err)
	}
	if err := writeEngineBenchmarkReport(config.Output, report); err != nil {
		t.Fatalf("write benchmark report: %v", err)
	}
	written, err := readEngineBenchmarkReportStrict(config.Output)
	if err != nil {
		t.Fatalf("re-open benchmark report: %v", err)
	}
	if err := validateEngineBenchmarkReport(written); err != nil {
		t.Fatalf("validate re-opened benchmark report: %v", err)
	}
	if err := validateEngineBenchmarkCurrentProvenance(written); err != nil {
		t.Fatalf("validate re-opened report provenance: %v", err)
	}
	t.Logf("Middle-End engine benchmark report: %s; overall selection: %s", config.Output, report.OverallSelection)
}

func parseEngineBenchmarkRunConfig() (engineBenchmarkRunConfig, error) {
	if engineBenchmarkCLI.output == "" || strings.TrimSpace(engineBenchmarkCLI.cpuPolicy) == "" ||
		(engineBenchmarkCLI.purpose != engineBenchmarkPurposeSmoke && engineBenchmarkCLI.purpose != engineBenchmarkPurposeDecision) ||
		engineBenchmarkCLI.trials < minimumPairedTrials || engineBenchmarkCLI.gomaxprocs <= 0 ||
		engineBenchmarkCLI.eventLoops <= 0 || engineBenchmarkCLI.eventLoops > MaxGnetClientEventLoops ||
		engineBenchmarkCLI.warmup <= 0 || engineBenchmarkCLI.duration <= 0 ||
		engineBenchmarkCLI.resourceCycles <= 0 || engineBenchmarkCLI.multiLinks <= 1 || engineBenchmarkCLI.multiLinks > 4 || engineBenchmarkCLI.slowReadChunk <= 0 ||
		engineBenchmarkCLI.slowReadDelay <= 0 || engineBenchmarkCLI.warmupCycles <= 0 || engineBenchmarkCLI.heapSampleInterval <= 0 ||
		engineBenchmarkCLI.socketBuffer <= 0 || strings.TrimSpace(engineBenchmarkCLI.workerCPUSet) == "" ||
		strings.TrimSpace(engineBenchmarkCLI.peerCPUSet) == "" ||
		engineBenchmarkCLI.baselineIterations <= 0 || engineBenchmarkCLI.baselineIterations > MaxLinkQueueItems ||
		engineBenchmarkCLI.warmup > time.Duration(^uint64(0)>>1)-engineBenchmarkCLI.duration ||
		engineBenchmarkCLI.observationTimeout <= engineBenchmarkCLI.warmup+engineBenchmarkCLI.duration {
		return engineBenchmarkRunConfig{}, errors.New("benchmark requires every policy, topology, timing, affinity, and socket control; no defaults exist")
	}
	if err := validateEngineBenchmarkScale(engineBenchmarkCLI.trials, engineBenchmarkCLI.resourceCycles, len(benchmarkPacketSizes())*4); err != nil {
		return engineBenchmarkRunConfig{}, err
	}
	workerCPUs, err := parseCPUSet(engineBenchmarkCLI.workerCPUSet)
	if err != nil {
		return engineBenchmarkRunConfig{}, fmt.Errorf("worker CPU set: %w", err)
	}
	peerCPUs, err := parseCPUSet(engineBenchmarkCLI.peerCPUSet)
	if err != nil {
		return engineBenchmarkRunConfig{}, fmt.Errorf("peer CPU set: %w", err)
	}
	for cpu := range workerCPUs {
		if _, overlaps := peerCPUs[cpu]; overlaps {
			return engineBenchmarkRunConfig{}, fmt.Errorf("worker and peer CPU sets overlap at CPU %d", cpu)
		}
	}
	availableCPUs, err := inspectCurrentProcessCPUSet()
	if err != nil {
		return engineBenchmarkRunConfig{}, fmt.Errorf("available CPU set: %w", err)
	}
	for label, requested := range map[string]map[int]struct{}{"worker": workerCPUs, "peer": peerCPUs} {
		for cpu := range requested {
			if _, available := availableCPUs[cpu]; !available {
				return engineBenchmarkRunConfig{}, fmt.Errorf("%s CPU %d is outside controller affinity %q", label, cpu, canonicalCPUSet(availableCPUs))
			}
		}
	}
	if engineBenchmarkCLI.gomaxprocs > len(workerCPUs) {
		return engineBenchmarkRunConfig{}, fmt.Errorf("GOMAXPROCS %d exceeds worker affinity size %d", engineBenchmarkCLI.gomaxprocs, len(workerCPUs))
	}
	if err := validateEngineBenchmarkFixedJSONEnvelope(canonicalCPUSet(workerCPUs), canonicalCPUSet(peerCPUs)); err != nil {
		return engineBenchmarkRunConfig{}, err
	}
	minimumImprovement, err := parseDecisionThresholds(engineBenchmarkCLI.minimumImprovement)
	if err != nil {
		return engineBenchmarkRunConfig{}, fmt.Errorf("minimum improvement policy: %w", err)
	}
	maximumRegression, err := parseDecisionThresholds(engineBenchmarkCLI.maximumRegression)
	if err != nil {
		return engineBenchmarkRunConfig{}, fmt.Errorf("maximum regression policy: %w", err)
	}
	for _, metric := range append([]decisionMetric{metricSustainableRate}, resourceDecisionMetrics[:]...) {
		value, ok := minimumImprovement[metric]
		if !ok || !validImprovementThreshold(value) {
			return engineBenchmarkRunConfig{}, fmt.Errorf("minimum improvement policy requires positive %s", metric)
		}
	}
	if len(minimumImprovement) != len(resourceDecisionMetrics)+1 {
		return engineBenchmarkRunConfig{}, errors.New("minimum improvement policy contains an ineligible or duplicate metric")
	}
	for _, metric := range eligibleDecisionMetrics {
		value, ok := maximumRegression[metric]
		if !ok || !validRegressionThreshold(value) {
			return engineBenchmarkRunConfig{}, fmt.Errorf("maximum regression policy requires %s in [0,1]", metric)
		}
	}
	if len(maximumRegression) != len(eligibleDecisionMetrics) {
		return engineBenchmarkRunConfig{}, errors.New("maximum regression policy contains an ineligible or duplicate metric")
	}
	return engineBenchmarkRunConfig{
		Purpose:   engineBenchmarkCLI.purpose,
		Output:    engineBenchmarkCLI.output,
		CPUPolicy: strings.TrimSpace(engineBenchmarkCLI.cpuPolicy),
		Policy: engineDecisionPolicy{
			TrialCount: engineBenchmarkCLI.trials, ConfidenceLevel: 0.95,
			IntervalMethod:     conservativePairedT95Method,
			MinimumImprovement: minimumImprovement, MaximumRegression: maximumRegression,
		},
		GOMAXPROCS:          engineBenchmarkCLI.gomaxprocs,
		EventLoops:          engineBenchmarkCLI.eventLoops,
		Warmup:              engineBenchmarkCLI.warmup,
		MeasurementDuration: engineBenchmarkCLI.duration,
		ResourceCycles:      engineBenchmarkCLI.resourceCycles,
		MultiLinks:          engineBenchmarkCLI.multiLinks,
		SlowReadChunk:       engineBenchmarkCLI.slowReadChunk,
		SlowReadDelay:       engineBenchmarkCLI.slowReadDelay,
		WarmupCycles:        engineBenchmarkCLI.warmupCycles,
		HeapSampleInterval:  engineBenchmarkCLI.heapSampleInterval,
		SocketBuffer:        engineBenchmarkCLI.socketBuffer,
		WorkerCPUSet:        canonicalCPUSet(workerCPUs),
		PeerCPUSet:          canonicalCPUSet(peerCPUs),
		ObservationTimeout:  engineBenchmarkCLI.observationTimeout,
		BaselineIterations:  engineBenchmarkCLI.baselineIterations,
	}, nil
}

func validateEngineBenchmarkFixedJSONEnvelope(workerCPUSet string, peerCPUSet string) error {
	size, err := engineBenchmarkFixedJSONEnvelopeSize(workerCPUSet, peerCPUSet)
	if err != nil {
		return err
	}
	if size > engineBenchmarkFixedJSONBytesPerChild {
		return fmt.Errorf("fixed worker-result JSON envelope %d exceeds per-child ceiling %d", size, engineBenchmarkFixedJSONBytesPerChild)
	}
	return nil
}

func engineBenchmarkFixedJSONEnvelopeSize(workerCPUSet string, peerCPUSet string) (int, error) {
	var result engineBenchmarkWorkerResult
	fillMaximumJSONScalars(reflect.ValueOf(&result).Elem())
	result.Metrics.LatencySamples = nil
	result.Raw.EffectiveWorkerCPUSet = workerCPUSet
	result.Raw.EffectivePeerCPUSet = peerCPUSet
	encoded, err := json.Marshal(result, jsonv1.DefaultOptionsV1())
	if err != nil {
		return 0, fmt.Errorf("marshal maximum fixed worker-result envelope: %w", err)
	}
	return len(encoded), nil
}

func fillMaximumJSONScalars(value reflect.Value) {
	for _, field := range value.Fields() {
		switch field.Kind() {
		case reflect.Struct:
			fillMaximumJSONScalars(field)
		case reflect.Bool:
			field.SetBool(true)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			bits := field.Type().Bits()
			maximum := int64(^uint64(0) >> 1)
			if bits < 64 {
				maximum = 1<<(bits-1) - 1
			}
			field.SetInt(maximum)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			bits := field.Type().Bits()
			maximum := ^uint64(0)
			if bits < 64 {
				maximum = 1<<bits - 1
			}
			field.SetUint(maximum)
		case reflect.Float32, reflect.Float64:
			maximum := math.MaxFloat64
			if field.Kind() == reflect.Float32 {
				maximum = math.MaxFloat32
			}
			field.SetFloat(maximum)
		}
	}
}

func validateEngineBenchmarkScale(trials int, resourceCycles int, requestsPerCycle int) error {
	if trials < minimumPairedTrials || resourceCycles <= 0 || requestsPerCycle <= 0 {
		return errors.New("benchmark scale requires minimum paired trials and positive resource cardinalities")
	}
	observations, ok := checkedMulInt(4, 2, 2, trials)
	if !ok || observations > MaxLinkQueueItems {
		return fmt.Errorf("benchmark child observations exceed local safety ceiling %d", MaxLinkQueueItems)
	}
	latencySamplesPerObservation, ok := checkedMulInt(resourceCycles, requestsPerCycle)
	if !ok {
		return errors.New("retained latency sample count per resource observation overflows int")
	}
	if latencySamplesPerObservation > engineBenchmarkMaxLatencySamplesPerResourceObservation {
		return fmt.Errorf("retained latency samples per resource observation %d exceed local ceiling %d",
			latencySamplesPerObservation, engineBenchmarkMaxLatencySamplesPerResourceObservation)
	}
	return nil
}

func checkedMulInt(values ...int) (int, bool) {
	result := 1
	for _, value := range values {
		if value < 0 || value != 0 && result > int(^uint(0)>>1)/value {
			return 0, false
		}
		result *= value
	}
	return result, true
}

func checkedMulUint64(left uint64, right uint64) (uint64, bool) {
	if right != 0 && left > ^uint64(0)/right {
		return 0, false
	}
	return left * right, true
}

func parseDecisionThresholds(value string) (map[decisionMetric]float64, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("value is required; no policy defaults exist")
	}
	thresholds := make(map[decisionMetric]float64)
	for entry := range strings.SplitSeq(value, ",") {
		name, raw, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok || name == "" || raw == "" {
			return nil, fmt.Errorf("invalid entry %q; want metric=fraction", entry)
		}
		metric := decisionMetric(name)
		if _, exists := thresholds[metric]; exists {
			return nil, fmt.Errorf("duplicate metric %s", metric)
		}
		threshold, err := strconv.ParseFloat(raw, 64)
		if err != nil || !isFinite(threshold) {
			return nil, fmt.Errorf("invalid fraction for %s", metric)
		}
		thresholds[metric] = threshold
	}
	return thresholds, nil
}

func runBlockingBenchmarkCorrectness(t *testing.T) bool {
	return t.Run("benchmark-correctness/blocking", func(t *testing.T) {
		runClientLinkConformance(t, newBlockingEngineForTest)
	})
}

func runGnetBenchmarkCorrectness(t *testing.T, eventLoops int) bool {
	return t.Run("benchmark-correctness/gnet", func(t *testing.T) {
		gnetRuntime, err := NewGnetClientRuntime(GnetClientRuntimeConfig{EventLoops: eventLoops})
		if err != nil {
			t.Fatal(err)
		}
		factory := func(conn net.Conn, bootstrap *ClientBootstrap, limits LinkLimits) (ClientLink, error) {
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				return nil, fmt.Errorf("gnet benchmark conformance connection type %T", conn)
			}
			return gnetRuntime.NewClientLink(tcpConn, bootstrap, limits)
		}
		runClientLinkConformance(t, factory)
		stopContext, cancel := context.WithTimeout(t.Context(), benchmarkStopTimeout)
		defer cancel()
		if err := gnetRuntime.Stop(stopContext); err != nil {
			t.Fatalf("stop correctness gnet runtime: %v", err)
		}
	})
}

func runEngineBenchmarkScenario(
	t *testing.T,
	config engineBenchmarkRunConfig,
	source engineBenchmarkSource,
	machine string,
	workload linkWorkload,
	limits LinkLimits,
	scenario engineBenchmarkScenario,
	expectedRead uint64,
	expectedWritten uint64,
	blockingCorrect bool,
	gnetCorrect bool,
) engineBenchmarkScenarioReport {
	t.Helper()
	workloadEvidence := canonicalEngineBenchmarkWorkload(t, workload)
	measurement := engineMeasurement{
		Controls: engineBenchmarkControls{
			Purpose: config.Purpose, Commit: source.Commit, SourceFingerprint: source.Fingerprint,
			GoVersion: runtime.Version(), Machine: machine,
			CPUPolicy:  config.CPUPolicy,
			Workload:   workloadEvidence,
			EventLoops: config.EventLoops, GOMAXPROCS: config.GOMAXPROCS, Limits: limits,
			MultiLinkCount: config.MultiLinks,
			Warmup:         config.Warmup, WarmupCycles: config.WarmupCycles,
			MeasurementDuration: config.MeasurementDuration,
			RequestsPerCycle:    len(workload.items), ResourceCycles: config.ResourceCycles,
			MaxInFlightPerConnection: 1,
			SlowReadChunk:            scenario.SlowReadChunk, SlowReadDelay: scenario.SlowReadDelay,
			HeapSampleInterval: config.HeapSampleInterval, RequestedSocketBuffer: config.SocketBuffer,
			ObservationTimeout: config.ObservationTimeout,
			WorkerCPUSet:       config.WorkerCPUSet, PeerCPUSet: config.PeerCPUSet,
			ResourceAttribution: benchmarkResourceAttribution,
			ExpectedBytesRead:   expectedRead, ExpectedBytesWritten: expectedWritten,
		},
		Policy:       cloneEngineDecisionPolicy(config.Policy),
		PairedTrials: make([]pairedEngineTrial, 0, config.Policy.TrialCount),
	}
	if blockingCorrect {
		measurement.BlockingCorrectness = completeEngineCorrectness()
	}
	if gnetCorrect {
		measurement.GnetCorrectness = completeEngineCorrectness()
	}
	rawTrials := make([]engineBenchmarkRawPair, 0, config.Policy.TrialCount)
	for pairIndex := range config.Policy.TrialCount {
		firstEngine := "blocking"
		if pairIndex%2 == 1 {
			firstEngine = "gnet"
		}
		var blockingMetrics, gnetMetrics engineTrialMetrics
		var blockingRaw, gnetRaw engineBenchmarkRawObservation
		if firstEngine == "blocking" {
			blockingMetrics, blockingRaw = runIsolatedEngineObservation(t, "blocking", config, scenario)
			gnetMetrics, gnetRaw = runIsolatedEngineObservation(t, "gnet", config, scenario)
		} else {
			gnetMetrics, gnetRaw = runIsolatedEngineObservation(t, "gnet", config, scenario)
			blockingMetrics, blockingRaw = runIsolatedEngineObservation(t, "blocking", config, scenario)
		}
		applyOrValidateObservationControls(t, &measurement.Controls, blockingMetrics, blockingRaw)
		applyOrValidateObservationControls(t, &measurement.Controls, gnetMetrics, gnetRaw)
		measurement.PairedTrials = append(measurement.PairedTrials, pairedEngineTrial{
			PairIndex: pairIndex + 1, FirstEngine: firstEngine,
			Blocking: blockingMetrics, Gnet: gnetMetrics,
		})
		rawTrials = append(rawTrials, engineBenchmarkRawPair{
			PairIndex: pairIndex + 1, FirstEngine: firstEngine,
			Blocking: blockingRaw, Gnet: gnetRaw,
		})
	}
	intervals, err := computeEffectIntervals(measurement.PairedTrials, measurement.Policy.IntervalMethod)
	if err != nil {
		t.Fatalf("%s compute effect intervals: %v", scenario.Name, err)
	}
	measurement.EffectIntervals = intervals
	selection := engineSelectionNone
	if config.Purpose == engineBenchmarkPurposeDecision {
		selection, err = selectLinkEngine(measurement)
		if err != nil {
			t.Fatalf("%s select engine: %v", scenario.Name, err)
		}
	}
	return engineBenchmarkScenarioReport{
		Scenario: scenario, Measurement: measurement, RawTrials: rawTrials, Selection: selection,
	}
}

func canonicalEngineBenchmarkWorkload(t testing.TB, workload linkWorkload) engineBenchmarkWorkloadEvidence {
	t.Helper()
	evidence, err := calculateCanonicalEngineBenchmarkWorkload(workload)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func calculateCanonicalEngineBenchmarkWorkload(workload linkWorkload) (engineBenchmarkWorkloadEvidence, error) {
	packetSizeSet := make(map[int]struct{})
	connectionIDSet := make(map[int64]struct{})
	for _, item := range workload.items {
		packetSizeSet[len(item.wantPacket)] = struct{}{}
		connectionIDSet[item.submission.ConnectionID] = struct{}{}
	}
	packetSizes := slices.Sorted(maps.Keys(packetSizeSet))
	connectionIDs := slices.Sorted(maps.Keys(connectionIDSet))
	if len(packetSizes) != 4 || len(connectionIDs) != 4 {
		return engineBenchmarkWorkloadEvidence{}, fmt.Errorf("canonical benchmark workload has %d packet sizes and %d connection IDs", len(packetSizes), len(connectionIDs))
	}
	return engineBenchmarkWorkloadEvidence{
		Name: workload.name, SessionCount: len(connectionIDs), RequestsPerCycle: len(workload.items),
		PacketSizes: [4]int(packetSizes), ConnectionIDs: [4]int64(connectionIDs),
		MaxInFlightPerConnection: 1, WholeCycles: true, QueueHighWaterScope: "maximum-per-link",
	}, nil
}

func cloneEngineDecisionPolicy(policy engineDecisionPolicy) engineDecisionPolicy {
	policy.MinimumImprovement = maps.Clone(policy.MinimumImprovement)
	policy.MaximumRegression = maps.Clone(policy.MaximumRegression)
	return policy
}

func expectedBenchmarkCycleBytes(t testing.TB, workload linkWorkload) (read uint64, written uint64) {
	t.Helper()
	read, written, err := calculateExpectedBenchmarkCycleBytes(workload)
	if err != nil {
		t.Fatalf("calculate expected benchmark bytes: %v", err)
	}
	return read, written
}

func calculateExpectedBenchmarkCycleBytes(workload linkWorkload) (read uint64, written uint64, err error) {
	for _, item := range workload.items {
		written += uint64(encryptedFrameSize(len(item.submission.Payload)))
		answer, err := (ProxyAnswer{ConnectionID: item.submission.ConnectionID, Packet: item.wantPacket}).MarshalBinary()
		if err != nil {
			return 0, 0, fmt.Errorf("marshal expected benchmark answer: %w", err)
		}
		read += uint64(encryptedFrameSize(len(answer)))
		read += uint64(encryptedFrameSize(SimpleAckPayloadSize))
	}
	return read, written, nil
}

func encryptedFrameSize(payloadSize int) int {
	plaintextSize := payloadSize + FullFrameOverhead
	return (plaintextSize + 15) / 16 * 16
}

func combineEngineBenchmarkSelections(scenarios []engineBenchmarkScenarioReport) engineSelection {
	if len(scenarios) == 0 {
		return engineSelectionNone
	}
	selection := scenarios[0].Selection
	for _, scenario := range scenarios[1:] {
		if scenario.Selection != selection {
			return engineSelectionBlocking
		}
	}
	return selection
}

func applyOrValidateObservationControls(
	t testing.TB,
	controls *engineBenchmarkControls,
	metrics engineTrialMetrics,
	raw engineBenchmarkRawObservation,
) {
	t.Helper()
	if err := validateEngineBenchmarkObservationDiagnostics(*controls, metrics, raw); err != nil {
		t.Fatal(err)
	}
	if raw.EffectiveWorkerSendBuffer <= 0 || raw.EffectiveWorkerReadBuffer <= 0 ||
		raw.EffectivePeerSendBuffer <= 0 || raw.EffectivePeerReadBuffer <= 0 || raw.PeerGOMAXPROCS <= 0 ||
		!raw.EffectiveWorkerNoDelay || !raw.EffectivePeerNoDelay ||
		raw.EffectiveWorkerCPUSet != controls.WorkerCPUSet || raw.EffectivePeerCPUSet != controls.PeerCPUSet {
		t.Fatalf("observation did not enforce controls: worker buffers=%d/%d peer buffers=%d/%d worker CPUs=%q peer CPUs=%q",
			raw.EffectiveWorkerSendBuffer, raw.EffectiveWorkerReadBuffer,
			raw.EffectivePeerSendBuffer, raw.EffectivePeerReadBuffer,
			raw.EffectiveWorkerCPUSet, raw.EffectivePeerCPUSet)
	}
	if controls.EffectiveWorkerSendBuffer == 0 {
		controls.EffectiveWorkerSendBuffer = raw.EffectiveWorkerSendBuffer
		controls.EffectiveWorkerReadBuffer = raw.EffectiveWorkerReadBuffer
		controls.EffectivePeerSendBuffer = raw.EffectivePeerSendBuffer
		controls.EffectivePeerReadBuffer = raw.EffectivePeerReadBuffer
		controls.EffectiveWorkerNoDelay = raw.EffectiveWorkerNoDelay
		controls.EffectivePeerNoDelay = raw.EffectivePeerNoDelay
		controls.PeerGOMAXPROCS = raw.PeerGOMAXPROCS
		return
	}
	if controls.EffectiveWorkerSendBuffer != raw.EffectiveWorkerSendBuffer ||
		controls.EffectiveWorkerReadBuffer != raw.EffectiveWorkerReadBuffer ||
		controls.EffectivePeerSendBuffer != raw.EffectivePeerSendBuffer ||
		controls.EffectivePeerReadBuffer != raw.EffectivePeerReadBuffer ||
		controls.EffectiveWorkerNoDelay != raw.EffectiveWorkerNoDelay || controls.EffectivePeerNoDelay != raw.EffectivePeerNoDelay ||
		controls.PeerGOMAXPROCS != raw.PeerGOMAXPROCS {
		t.Fatal("effective socket or peer scheduling controls changed between observations")
	}
}

func validateEngineBenchmarkObservationDiagnostics(
	controls engineBenchmarkControls,
	metrics engineTrialMetrics,
	raw engineBenchmarkRawObservation,
) error {
	if raw.ThroughputWarmupCycles < controls.WarmupCycles || raw.ResourceWarmupCycles < controls.WarmupCycles {
		return errors.New("observation did not complete the required warmup")
	}
	if raw.ThroughputAnswers != metrics.CompletedRequests || raw.ThroughputAcknowledgements != metrics.CompletedRequests ||
		raw.ResourceAnswers != metrics.ResourceRequests || raw.ResourceAcknowledgements != metrics.ResourceRequests ||
		raw.ThroughputPeerRecords != uint64(metrics.CompletedRequests) || raw.ResourcePeerRecords != uint64(metrics.ResourceRequests) {
		return errors.New("observation answer or acknowledgement totals do not match selector-validated request totals")
	}
	if raw.GoroutineBaseline != metrics.GoroutineBaseline || raw.GoroutineHighWater != metrics.GoroutinePeak ||
		raw.GoroutineAfterCleanup != raw.GoroutineBaseline {
		return fmt.Errorf("goroutine evidence raw baseline/high/after=%d/%d/%d metrics baseline/peak=%d/%d",
			raw.GoroutineBaseline, raw.GoroutineHighWater, raw.GoroutineAfterCleanup, metrics.GoroutineBaseline, metrics.GoroutinePeak)
	}
	if raw.HeapBytesWorkerBaseline != metrics.HeapBytesWorkerBaseline ||
		raw.HeapBytesAllocationBaseline != metrics.HeapBytesAllocationBaseline {
		return fmt.Errorf("heap evidence raw worker/allocation=%d/%d metrics worker/allocation/peak=%d/%d/%d",
			raw.HeapBytesWorkerBaseline, raw.HeapBytesAllocationBaseline,
			metrics.HeapBytesWorkerBaseline, metrics.HeapBytesAllocationBaseline, metrics.HeapBytesPeak)
	}
	if metrics.SubmissionHighWater > controls.Limits.MaxPendingSubmissions ||
		metrics.SubmissionBytesHighWater > controls.Limits.MaxPendingSubmissionBytes ||
		metrics.EventHighWater > controls.Limits.MaxPendingEvents || metrics.EventBytesHighWater > controls.Limits.MaxPendingEventBytes {
		return errors.New("observation queue high-water exceeds configured limits")
	}
	return nil
}

func validateEngineBenchmarkObservationControls(
	controls engineBenchmarkControls,
	metrics engineTrialMetrics,
	raw engineBenchmarkRawObservation,
) error {
	if err := validateEngineBenchmarkObservationDiagnostics(controls, metrics, raw); err != nil {
		return err
	}
	if raw.EffectiveWorkerSendBuffer != controls.EffectiveWorkerSendBuffer ||
		raw.EffectiveWorkerReadBuffer != controls.EffectiveWorkerReadBuffer ||
		raw.EffectivePeerSendBuffer != controls.EffectivePeerSendBuffer ||
		raw.EffectivePeerReadBuffer != controls.EffectivePeerReadBuffer ||
		raw.EffectiveWorkerNoDelay != controls.EffectiveWorkerNoDelay || raw.EffectivePeerNoDelay != controls.EffectivePeerNoDelay ||
		raw.EffectiveWorkerCPUSet != controls.WorkerCPUSet || raw.EffectivePeerCPUSet != controls.PeerCPUSet ||
		raw.PeerGOMAXPROCS != controls.PeerGOMAXPROCS {
		return errors.New("observation raw controls do not match measurement controls")
	}
	return nil
}

func parseCPUSet(value string) (map[int]struct{}, error) {
	capacity := int(unsafe.Sizeof(unix.CPUSet{})) * 8
	result := make(map[int]struct{})
	for component := range strings.SplitSeq(strings.TrimSpace(value), ",") {
		component = strings.TrimSpace(component)
		if component == "" {
			return nil, errors.New("empty CPU component")
		}
		firstText, lastText, ranged := strings.Cut(component, "-")
		first, err := strconv.Atoi(firstText)
		if err != nil || first < 0 {
			return nil, fmt.Errorf("invalid CPU %q", firstText)
		}
		last := first
		if ranged {
			last, err = strconv.Atoi(lastText)
			if err != nil || last < first {
				return nil, fmt.Errorf("invalid CPU range %q", component)
			}
		}
		if first >= capacity || last >= capacity {
			return nil, fmt.Errorf("CPU component %q exceeds unix.CPUSet capacity %d", component, capacity)
		}
		if last-first+1 > capacity-len(result) {
			return nil, fmt.Errorf("CPU component %q exceeds unix.CPUSet cardinality %d", component, capacity)
		}
		for cpu := first; ; cpu++ {
			result[cpu] = struct{}{}
			if cpu == last {
				break
			}
		}
	}
	if len(result) == 0 {
		return nil, errors.New("CPU set is empty")
	}
	return result, nil
}

func canonicalCPUSet(cpus map[int]struct{}) string {
	ordered := slices.Sorted(maps.Keys(cpus))
	parts := make([]string, 0, len(ordered))
	for _, cpu := range ordered {
		parts = append(parts, strconv.Itoa(cpu))
	}
	return strings.Join(parts, ",")
}

func inspectCurrentProcessCPUSet() (map[int]struct{}, error) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil, err
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok && name == "Cpus_allowed_list" {
			return parseCPUSet(strings.TrimSpace(value))
		}
	}
	return nil, errors.New("process status has no Cpus_allowed_list")
}

func inspectEngineBenchmarkSource() (engineBenchmarkSource, error) {
	rootOutput, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return engineBenchmarkSource{}, fmt.Errorf("git rev-parse --show-toplevel: %w", err)
	}
	repositoryRoot := strings.TrimSpace(string(rootOutput))
	commitOutput, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return engineBenchmarkSource{}, fmt.Errorf("git rev-parse HEAD: %w", err)
	}
	statusOutput, err := exec.Command("git", "status", "--porcelain=v1", "--untracked-files=all").Output()
	if err != nil {
		return engineBenchmarkSource{}, fmt.Errorf("git status: %w", err)
	}
	fingerprint, err := fingerprintEngineBenchmarkSource(repositoryRoot)
	if err != nil {
		return engineBenchmarkSource{}, err
	}
	return engineBenchmarkSource{
		Commit:      strings.TrimSpace(string(commitOutput)),
		Dirty:       len(bytes.TrimSpace(statusOutput)) != 0,
		Fingerprint: fingerprint,
	}, nil
}

func fingerprintEngineBenchmarkSource(repositoryRoot string) (string, error) {
	paths := engineBenchmarkFixedSourcePaths(repositoryRoot)
	err := filepath.WalkDir(filepath.Join(repositoryRoot, "pkg/transport/middleend"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && (strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".md")) {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("walk benchmark source: %w", err)
	}
	slices.Sort(paths)
	digest := sha256.New()
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read benchmark source %s: %w", path, err)
		}
		relativePath, err := filepath.Rel(repositoryRoot, path)
		if err != nil {
			return "", fmt.Errorf("relativize benchmark source %s: %w", path, err)
		}
		_, _ = io.WriteString(digest, relativePath)
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write(contents)
		_, _ = digest.Write([]byte{0})
	}
	return fmt.Sprintf("sha256:%x", digest.Sum(nil)), nil
}

func engineBenchmarkFixedSourcePaths(repositoryRoot string) []string {
	return []string{
		filepath.Join(repositoryRoot, "go.mod"),
		filepath.Join(repositoryRoot, "go.sum"),
	}
}

func inspectEngineBenchmarkMachine() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("hostname: %w", err)
	}
	cpuModel := ""
	if runtime.GOOS == "linux" {
		cpuInfo, err := os.ReadFile("/proc/cpuinfo")
		if err != nil {
			return "", fmt.Errorf("read /proc/cpuinfo: %w", err)
		}
		for line := range strings.SplitSeq(string(cpuInfo), "\n") {
			name, value, ok := strings.Cut(line, ":")
			if ok && strings.TrimSpace(name) == "model name" {
				cpuModel = strings.TrimSpace(value)
				break
			}
		}
		if cpuModel == "" {
			return "", errors.New("/proc/cpuinfo has no model name")
		}
	}
	return fmt.Sprintf("hostname=%s;os=%s;arch=%s;cpu=%s", hostname, runtime.GOOS, runtime.GOARCH, cpuModel), nil
}

func inspectEngineBenchmarkBinary() (string, []string, string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", nil, "", fmt.Errorf("resolve benchmark binary: %w", err)
	}
	executable = filepath.Clean(executable)
	contents, err := os.ReadFile(executable)
	if err != nil {
		return "", nil, "", fmt.Errorf("read benchmark binary: %w", err)
	}
	hash := sha256.Sum256(contents)
	buildSettings := make([]string, 0)
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			buildSettings = append(buildSettings, setting.Key+"="+setting.Value)
		}
		slices.Sort(buildSettings)
	}
	kernelContents, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "", nil, "", fmt.Errorf("read kernel release: %w", err)
	}
	return fmt.Sprintf("sha256:%x", hash[:]), buildSettings, strings.TrimSpace(string(kernelContents)), nil
}

func inspectEngineBenchmarkTaskset() (string, string, error) {
	path, err := exec.LookPath("taskset")
	if err != nil {
		return "", "", fmt.Errorf("find taskset: %w", err)
	}
	version, err := exec.Command(path, "--version").Output()
	if err != nil {
		return "", "", fmt.Errorf("taskset --version: %w", err)
	}
	return path, strings.TrimSpace(string(version)), nil
}

func runEngineSharedProtocolBaselines(
	t *testing.T,
	config engineBenchmarkRunConfig,
	source engineBenchmarkSource,
	binaryHash string,
) engineSharedProtocolBaselineReport {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve shared-protocol baseline binary: %v", err)
	}
	benchmarkArguments := []string{
		"-test.run=^$",
		"-test.bench=" + sharedProtocolBenchmarkExpression,
		fmt.Sprintf("-test.benchtime=%dx", config.BaselineIterations),
		"-test.benchmem=true",
		"-test.count=1",
		fmt.Sprintf("-test.cpu=%d", config.GOMAXPROCS),
		"-test.v=true",
	}
	commandArguments := append([]string{"--cpu-list", config.WorkerCPUSet, executable}, benchmarkArguments...)
	baselineContext, cancelBaseline := context.WithTimeout(t.Context(), config.ObservationTimeout)
	defer cancelBaseline()
	command := exec.CommandContext(baselineContext, config.TasksetPath, commandArguments...)
	command.Env = engineBenchmarkEnvironmentWithOverrides(os.Environ(), map[string]string{
		"GOMAXPROCS":                        strconv.Itoa(config.GOMAXPROCS),
		readyBenchmarkCPUSetEnvironment:     config.WorkerCPUSet,
		readyBenchmarkGOMAXPROCSEnvironment: strconv.Itoa(config.GOMAXPROCS),
	})
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("shared-protocol baseline worker failed: %v\n%s", err, output)
	}
	results, err := parseEngineSharedProtocolBaselines(string(output), config.GOMAXPROCS)
	if err != nil {
		t.Fatalf("parse shared-protocol baselines: %v\n%s", err, output)
	}
	report := engineSharedProtocolBaselineReport{
		Commit: source.Commit, SourceFingerprint: source.Fingerprint, BinaryHash: binaryHash,
		GoVersion: runtime.Version(), TestBinaryPath: executable, TasksetPath: config.TasksetPath,
		BenchmarkExpression:   sharedProtocolBenchmarkExpression,
		Iterations:            config.BaselineIterations,
		GOMAXPROCS:            config.GOMAXPROCS,
		WorkerCPUSet:          config.WorkerCPUSet,
		EffectiveWorkerCPUSet: config.WorkerCPUSet,
		AffinityAttestation:   sharedProtocolAffinityAttestation,
		Command:               append([]string{config.TasksetPath}, commandArguments...),
		RawOutput:             string(output),
		Results:               results,
	}
	if err := validateEngineSharedProtocolBaselines(report); err != nil {
		t.Fatalf("validate shared-protocol baselines: %v", err)
	}
	return report
}

func engineBenchmarkEnvironmentWithOverrides(environ []string, overrides map[string]string) []string {
	result := make([]string, 0, len(environ)+len(overrides))
	for _, entry := range environ {
		name, _, ok := strings.Cut(entry, "=")
		if _, replace := overrides[name]; ok && replace {
			continue
		}
		result = append(result, entry)
	}
	for _, name := range slices.Sorted(maps.Keys(overrides)) {
		result = append(result, name+"="+overrides[name])
	}
	return result
}

func parseEngineSharedProtocolBaselines(output string, gomaxprocs int) ([]engineSharedProtocolBaseline, error) {
	results := make([]engineSharedProtocolBaseline, 0, 2*len(benchmarkPacketSizes()))
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "BenchmarkClientBootstrapReady") {
			continue
		}
		operation, payloadSize, benchmarkGOMAXPROCS, err := parseEngineSharedProtocolBenchmarkName(fields[0])
		if err != nil {
			return nil, err
		}
		if benchmarkGOMAXPROCS != gomaxprocs {
			return nil, fmt.Errorf("%s used GOMAXPROCS %d, want %d", fields[0], benchmarkGOMAXPROCS, gomaxprocs)
		}
		iterations, err := strconv.Atoi(fields[1])
		if err != nil || iterations <= 0 {
			return nil, fmt.Errorf("%s has invalid iteration count %q", fields[0], fields[1])
		}
		result := engineSharedProtocolBaseline{
			Operation: operation, PayloadSize: payloadSize, GOMAXPROCS: benchmarkGOMAXPROCS, Iterations: iterations,
		}
		var foundNanoseconds, foundBytes, foundAllocations bool
		for index := 2; index+1 < len(fields); index++ {
			value, unit := fields[index], fields[index+1]
			switch unit {
			case "ns/op":
				result.NanosecondsPerOp, err = strconv.ParseFloat(value, 64)
				foundNanoseconds = err == nil
			case "B/op":
				result.AllocatedBytesPerOp, err = strconv.ParseUint(value, 10, 64)
				foundBytes = err == nil
			case "allocs/op":
				result.AllocationsPerOp, err = strconv.ParseUint(value, 10, 64)
				foundAllocations = err == nil
			default:
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("%s has invalid %s value %q", fields[0], unit, value)
			}
		}
		if !foundNanoseconds || !foundBytes || !foundAllocations {
			return nil, fmt.Errorf("%s is missing ns/op, B/op, or allocs/op", fields[0])
		}
		results = append(results, result)
	}
	return results, nil
}

func parseEngineSharedProtocolBenchmarkName(name string) (operation string, payloadSize int, gomaxprocs int, err error) {
	for _, candidate := range []string{"BenchmarkClientBootstrapReadyEncode", "BenchmarkClientBootstrapReadyFeed"} {
		remainder, ok := strings.CutPrefix(name, candidate+"/")
		if !ok {
			continue
		}
		payloadText, gomaxprocsText, ok := strings.Cut(remainder, "-")
		if strings.Contains(gomaxprocsText, "-") {
			return "", 0, 0, fmt.Errorf("invalid shared-protocol benchmark name %q", name)
		}
		payloadSize, payloadErr := strconv.Atoi(payloadText)
		gomaxprocs := 1
		var gomaxprocsErr error
		if ok {
			gomaxprocs, gomaxprocsErr = strconv.Atoi(gomaxprocsText)
		}
		if payloadErr != nil || payloadSize <= 0 || gomaxprocsErr != nil || gomaxprocs <= 0 {
			return "", 0, 0, fmt.Errorf("invalid shared-protocol benchmark name %q", name)
		}
		return candidate, payloadSize, gomaxprocs, nil
	}
	return "", 0, 0, fmt.Errorf("unknown shared-protocol benchmark %q", name)
}

func validateEngineSharedProtocolBaselines(report engineSharedProtocolBaselineReport) error {
	if report.Commit == "" || report.SourceFingerprint == "" || report.BinaryHash == "" || report.GoVersion == "" ||
		report.TestBinaryPath == "" || report.TasksetPath == "" ||
		report.BenchmarkExpression != sharedProtocolBenchmarkExpression || report.Iterations <= 0 ||
		report.GOMAXPROCS <= 0 || report.WorkerCPUSet == "" || report.EffectiveWorkerCPUSet != report.WorkerCPUSet ||
		report.AffinityAttestation != sharedProtocolAffinityAttestation || len(report.Command) == 0 || report.RawOutput == "" {
		return errors.New("shared-protocol baseline controls or raw output are incomplete")
	}
	if want := canonicalEngineSharedProtocolCommand(report); !slices.Equal(report.Command, want) {
		return fmt.Errorf("shared-protocol command differs from canonical command: got %q want %q", report.Command, want)
	}
	parsedResults, err := parseEngineSharedProtocolBaselines(report.RawOutput, report.GOMAXPROCS)
	if err != nil {
		return fmt.Errorf("parse stored shared-protocol raw output: %w", err)
	}
	if !slices.Equal(parsedResults, report.Results) {
		return errors.New("shared-protocol results do not match the stored raw output")
	}
	affinityEvidence := fmt.Sprintf("shared-protocol baseline affinity attested: CPUs=%s GOMAXPROCS=%d", report.WorkerCPUSet, report.GOMAXPROCS)
	if count := strings.Count(report.RawOutput, affinityEvidence); count != 4 {
		return fmt.Errorf("shared-protocol affinity attestation count = %d, want 4", count)
	}
	operations := []string{"BenchmarkClientBootstrapReadyEncode", "BenchmarkClientBootstrapReadyFeed"}
	expected := make(map[string]struct{}, len(operations)*len(benchmarkPacketSizes()))
	for _, operation := range operations {
		for _, payloadSize := range benchmarkPacketSizes() {
			expected[fmt.Sprintf("%s/%d", operation, payloadSize)] = struct{}{}
		}
	}
	if len(report.Results) != len(expected) {
		return fmt.Errorf("shared-protocol baseline result count = %d, want %d", len(report.Results), len(expected))
	}
	seen := make(map[string]struct{}, len(report.Results))
	for _, result := range report.Results {
		key := fmt.Sprintf("%s/%d", result.Operation, result.PayloadSize)
		if _, ok := expected[key]; !ok {
			return fmt.Errorf("unexpected shared-protocol baseline %s", key)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate shared-protocol baseline %s", key)
		}
		seen[key] = struct{}{}
		if result.GOMAXPROCS != report.GOMAXPROCS || result.Iterations != report.Iterations ||
			!isFinite(result.NanosecondsPerOp) || result.NanosecondsPerOp <= 0 {
			return fmt.Errorf("shared-protocol baseline %s has invalid controls or timing", key)
		}
	}
	return nil
}

func canonicalEngineSharedProtocolCommand(report engineSharedProtocolBaselineReport) []string {
	return []string{
		report.TasksetPath, "--cpu-list", report.WorkerCPUSet, report.TestBinaryPath,
		"-test.run=^$", "-test.bench=" + sharedProtocolBenchmarkExpression,
		fmt.Sprintf("-test.benchtime=%dx", report.Iterations), "-test.benchmem=true", "-test.count=1",
		fmt.Sprintf("-test.cpu=%d", report.GOMAXPROCS), "-test.v=true",
	}
}

func validateEngineBenchmarkReport(report engineBenchmarkReport) error {
	if report.SchemaVersion != engineBenchmarkReportVersion || report.CreatedAt.IsZero() ||
		(report.Purpose != engineBenchmarkPurposeSmoke && report.Purpose != engineBenchmarkPurposeDecision) ||
		report.ConfiguredMultiLinks <= 1 || report.ConfiguredSlowReadChunk <= 0 || report.ConfiguredSlowReadDelay <= 0 ||
		report.Source.Commit == "" || report.Source.Fingerprint == "" || report.Environment.ExecutablePath == "" || report.Environment.GoVersion == "" ||
		report.Environment.GOOS != "linux" || report.Environment.GOARCH == "" || report.Environment.BinaryHash == "" ||
		report.Environment.Machine == "" || report.Environment.Kernel == "" || report.Environment.TasksetPath == "" ||
		report.Environment.TasksetVersion == "" || report.Environment.BaselineIterations <= 0 {
		return errors.New("benchmark report provenance is incomplete")
	}
	if err := validateEngineSharedProtocolBaselines(report.SharedProtocolBaselines); err != nil {
		return err
	}
	if report.SharedProtocolBaselines.Iterations != report.Environment.BaselineIterations {
		return errors.New("shared-protocol baseline iteration control changed")
	}
	baseline := report.SharedProtocolBaselines
	if baseline.GOMAXPROCS != report.Environment.GOMAXPROCS || baseline.WorkerCPUSet != report.Environment.WorkerCPUSet ||
		baseline.EffectiveWorkerCPUSet != report.Environment.WorkerCPUSet || len(baseline.Command) == 0 ||
		baseline.Command[0] != report.Environment.TasksetPath || baseline.Commit != report.Source.Commit ||
		baseline.SourceFingerprint != report.Source.Fingerprint || baseline.BinaryHash != report.Environment.BinaryHash ||
		baseline.GoVersion != report.Environment.GoVersion || baseline.TestBinaryPath != report.Environment.ExecutablePath {
		return errors.New("shared-protocol controls differ from report environment")
	}
	gate := report.Correctness
	if !gate.Passed || !gate.BlockingPassed || !gate.GnetPassed || gate.TestBinaryHash != report.Environment.BinaryHash ||
		gate.TestBinaryPath != report.Environment.ExecutablePath ||
		gate.SourceFingerprint != report.Source.Fingerprint ||
		gate.Tests != [2]string{"benchmark-correctness/blocking", "benchmark-correctness/gnet"} {
		return errors.New("stored correctness gate is incomplete or differs from report provenance")
	}
	if len(report.Scenarios) != 4 {
		return fmt.Errorf("benchmark scenario count = %d, want 4", len(report.Scenarios))
	}
	if err := validateEngineBenchmarkReportExecutionConstraints(report); err != nil {
		return err
	}
	expectedNames := [4]string{"single-link-normal", "multi-link-normal", "single-link-slow-reader", "multi-link-slow-reader"}
	seen := make(map[string]struct{}, 4)
	var reference *engineBenchmarkControls
	for index, scenario := range report.Scenarios {
		if scenario.Scenario.Name != expectedNames[index] {
			return fmt.Errorf("benchmark scenario %d name = %q, want %q", index+1, scenario.Scenario.Name, expectedNames[index])
		}
		if _, duplicate := seen[scenario.Scenario.Name]; duplicate {
			return fmt.Errorf("duplicate benchmark scenario %q", scenario.Scenario.Name)
		}
		seen[scenario.Scenario.Name] = struct{}{}
		if err := validateEngineBenchmarkScenarioReport(scenario); err != nil {
			return fmt.Errorf("scenario %s: %w", scenario.Scenario.Name, err)
		}
		controls := scenario.Measurement.Controls
		if controls.MultiLinkCount != report.ConfiguredMultiLinks {
			return fmt.Errorf("scenario %s multi-link control differs from top-level configuration", scenario.Scenario.Name)
		}
		if strings.Contains(scenario.Scenario.Name, "slow-reader") &&
			(controls.SlowReadChunk != report.ConfiguredSlowReadChunk || controls.SlowReadDelay != report.ConfiguredSlowReadDelay) {
			return fmt.Errorf("scenario %s slow-read controls differ from top-level configuration", scenario.Scenario.Name)
		}
		if controls.Purpose != report.Purpose || controls.Commit != report.Source.Commit ||
			controls.SourceFingerprint != report.Source.Fingerprint || controls.GoVersion != report.Environment.GoVersion ||
			controls.Machine != report.Environment.Machine || controls.CPUPolicy != report.Environment.CPUPolicy ||
			controls.EventLoops != report.Environment.EventLoops || controls.GOMAXPROCS != report.Environment.GOMAXPROCS ||
			controls.WorkerCPUSet != report.Environment.WorkerCPUSet || controls.PeerCPUSet != report.Environment.PeerCPUSet {
			return fmt.Errorf("scenario %s controls differ from top-level source or environment", scenario.Scenario.Name)
		}
		normalized := controls
		normalized.SlowReadChunk = 0
		normalized.SlowReadDelay = 0
		if reference == nil {
			reference = new(normalized)
		} else if *reference != normalized {
			return fmt.Errorf("scenario %s global controls, policy limits, or workload differ", scenario.Scenario.Name)
		}
		if !equalEngineDecisionPolicy(report.Scenarios[0].Measurement.Policy, scenario.Measurement.Policy) {
			return fmt.Errorf("scenario %s decision policy differs", scenario.Scenario.Name)
		}
	}
	if report.Purpose == engineBenchmarkPurposeSmoke {
		if report.OverallSelection != engineSelectionNone {
			return errors.New("smoke report emitted a winner")
		}
		for _, scenario := range report.Scenarios {
			if scenario.Selection != engineSelectionNone {
				return fmt.Errorf("smoke scenario %s emitted a winner", scenario.Scenario.Name)
			}
		}
		return nil
	}
	if want := combineEngineBenchmarkSelections(report.Scenarios); report.OverallSelection != want {
		return fmt.Errorf("overall selection = %s, recomputed %s", report.OverallSelection, want)
	}
	return nil
}

func validateEngineBenchmarkReportExecutionConstraints(report engineBenchmarkReport) error {
	if report.ConfiguredMultiLinks < 2 || report.ConfiguredMultiLinks > 4 ||
		report.Environment.EventLoops <= 0 || report.Environment.EventLoops > MaxGnetClientEventLoops ||
		report.Environment.GOMAXPROCS <= 0 || report.Environment.BaselineIterations <= 0 ||
		report.Environment.BaselineIterations > MaxLinkQueueItems {
		return errors.New("report execution topology exceeds generator constraints")
	}
	workerCPUs, err := parseCPUSet(report.Environment.WorkerCPUSet)
	if err != nil {
		return fmt.Errorf("report worker CPU set: %w", err)
	}
	peerCPUs, err := parseCPUSet(report.Environment.PeerCPUSet)
	if err != nil {
		return fmt.Errorf("report peer CPU set: %w", err)
	}
	for cpu := range workerCPUs {
		if _, overlap := peerCPUs[cpu]; overlap {
			return fmt.Errorf("report worker and peer CPU sets overlap at CPU %d", cpu)
		}
	}
	if report.Environment.GOMAXPROCS > len(workerCPUs) {
		return fmt.Errorf("report GOMAXPROCS %d exceeds worker CPU count %d", report.Environment.GOMAXPROCS, len(workerCPUs))
	}
	if err := validateEngineBenchmarkFixedJSONEnvelope(report.Environment.WorkerCPUSet, report.Environment.PeerCPUSet); err != nil {
		return err
	}
	if len(report.Scenarios) == 0 {
		return errors.New("report has no scenario controls")
	}
	controls := report.Scenarios[0].Measurement.Controls
	if controls.Warmup <= 0 || controls.WarmupCycles <= 0 || controls.WarmupCycles > MaxLinkQueueItems ||
		controls.MeasurementDuration <= 0 || controls.ResourceCycles <= 0 || controls.RequestsPerCycle <= 0 ||
		controls.HeapSampleInterval <= 0 || controls.RequestedSocketBuffer <= 0 || controls.ObservationTimeout <= 0 ||
		controls.ObservationTimeout <= controls.Warmup || controls.MeasurementDuration > controls.ObservationTimeout-controls.Warmup ||
		controls.PeerGOMAXPROCS != len(peerCPUs) {
		return errors.New("report timing, socket, or peer scheduling controls exceed worker constraints")
	}
	if err := validateEngineBenchmarkScale(report.Scenarios[0].Measurement.Policy.TrialCount, controls.ResourceCycles, controls.RequestsPerCycle); err != nil {
		return err
	}
	if err := validateEngineBenchmarkWorkerScale(controls.ResourceCycles, controls.RequestsPerCycle); err != nil {
		return err
	}
	return nil
}

func equalEngineDecisionPolicy(left engineDecisionPolicy, right engineDecisionPolicy) bool {
	return left.TrialCount == right.TrialCount && left.ConfidenceLevel == right.ConfidenceLevel &&
		left.IntervalMethod == right.IntervalMethod && maps.Equal(left.MinimumImprovement, right.MinimumImprovement) &&
		maps.Equal(left.MaximumRegression, right.MaximumRegression)
}

func validateEngineBenchmarkScenarioReport(report engineBenchmarkScenarioReport) error {
	if err := validateEngineMeasurementSchema(report.Measurement); err != nil {
		return err
	}
	controls := report.Measurement.Controls
	if !report.Measurement.BlockingCorrectness.passed() || !report.Measurement.GnetCorrectness.passed() {
		return errors.New("scenario correctness gate did not pass")
	}
	if err := validateEngineBenchmarkScenarioMatrix(report.Scenario, controls); err != nil {
		return err
	}
	if err := validateCanonicalEngineBenchmarkWorkload(controls.Workload, controls); err != nil {
		return err
	}
	if controls.ResourceAttribution != benchmarkResourceAttribution {
		return errors.New("scenario resource attribution control changed")
	}
	if len(report.RawTrials) != len(report.Measurement.PairedTrials) {
		return errors.New("raw and selector trial counts differ")
	}
	for index, trial := range report.Measurement.PairedTrials {
		raw := report.RawTrials[index]
		if raw.PairIndex != trial.PairIndex || raw.FirstEngine != trial.FirstEngine {
			return fmt.Errorf("raw trial %d identity differs from selector trial", index+1)
		}
		if err := validateEngineBenchmarkObservationControls(report.Measurement.Controls, trial.Blocking, raw.Blocking); err != nil {
			return fmt.Errorf("trial %d blocking: %w", index+1, err)
		}
		if err := validateEngineBenchmarkObservationControls(report.Measurement.Controls, trial.Gnet, raw.Gnet); err != nil {
			return fmt.Errorf("trial %d gnet: %w", index+1, err)
		}
	}
	if controls.Purpose == engineBenchmarkPurposeSmoke {
		if report.Selection != engineSelectionNone {
			return errors.New("smoke scenario emitted a winner")
		}
		return nil
	}
	selection, err := selectLinkEngine(report.Measurement)
	if err != nil {
		return err
	}
	if selection != report.Selection {
		return fmt.Errorf("selection = %s, recomputed %s", report.Selection, selection)
	}
	return nil
}

func validateEngineBenchmarkScenarioMatrix(scenario engineBenchmarkScenario, controls engineBenchmarkControls) error {
	wantLinks, wantChunk, wantDelay := 0, 0, time.Duration(0)
	switch scenario.Name {
	case "single-link-normal":
		wantLinks = 1
	case "multi-link-normal":
		wantLinks = controls.MultiLinkCount
	case "single-link-slow-reader":
		wantLinks, wantChunk, wantDelay = 1, controls.SlowReadChunk, controls.SlowReadDelay
		if wantChunk <= 0 || wantDelay <= 0 {
			return errors.New("slow-reader scenario has no positive slow-read controls")
		}
	case "multi-link-slow-reader":
		wantLinks, wantChunk, wantDelay = controls.MultiLinkCount, controls.SlowReadChunk, controls.SlowReadDelay
		if wantChunk <= 0 || wantDelay <= 0 {
			return errors.New("slow-reader scenario has no positive slow-read controls")
		}
	default:
		return fmt.Errorf("unknown benchmark scenario %q", scenario.Name)
	}
	if scenario.Links != wantLinks || scenario.SlowReadChunk != wantChunk || scenario.SlowReadDelay != wantDelay ||
		controls.SlowReadChunk != wantChunk || controls.SlowReadDelay != wantDelay {
		return errors.New("scenario metadata and structured controls differ")
	}
	return nil
}

func validateCanonicalEngineBenchmarkWorkload(workload engineBenchmarkWorkloadEvidence, controls engineBenchmarkControls) error {
	canonicalWorkload, err := buildDeterministicLinkWorkload()
	if err != nil {
		return fmt.Errorf("rebuild canonical benchmark workload: %w", err)
	}
	want, err := calculateCanonicalEngineBenchmarkWorkload(canonicalWorkload)
	if err != nil {
		return err
	}
	if workload != want || workload.RequestsPerCycle != controls.RequestsPerCycle ||
		workload.MaxInFlightPerConnection != controls.MaxInFlightPerConnection {
		return errors.New("structured workload is not the canonical benchmark workload")
	}
	wantLimits := limitsForWorkload(canonicalWorkload)
	if controls.Limits != wantLimits {
		return fmt.Errorf("link limits %+v differ from source-derived limits %+v", controls.Limits, wantLimits)
	}
	wantRead, wantWritten, err := calculateExpectedBenchmarkCycleBytes(canonicalWorkload)
	if err != nil {
		return err
	}
	if controls.ExpectedBytesRead != wantRead || controls.ExpectedBytesWritten != wantWritten {
		return fmt.Errorf("expected cycle bytes read/written=%d/%d, source-derived=%d/%d",
			controls.ExpectedBytesRead, controls.ExpectedBytesWritten, wantRead, wantWritten)
	}
	return nil
}

func writeEngineBenchmarkReport(path string, report engineBenchmarkReport) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".mebench-*.json")
	if err != nil {
		return fmt.Errorf("create temporary report: %w", err)
	}
	temporaryPath := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	// DefaultOptionsV1 gives time.Duration its numeric representation. The v2
	// encoder still supplies deterministic object ordering and strict output.
	if err := json.MarshalWrite(temporary, report, jsonv1.DefaultOptionsV1(), json.Deterministic(true), jsontext.Multiline(true), jsontext.WithIndent("  ")); err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if _, err := temporary.WriteString("\n"); err != nil {
		return fmt.Errorf("terminate report: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync report: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close report: %w", err)
	}
	closed = true
	serialized, err := readEngineBenchmarkReportStrict(temporaryPath)
	if err != nil {
		return fmt.Errorf("strictly validate temporary report: %w", err)
	}
	if err := validateEngineBenchmarkReport(serialized); err != nil {
		return fmt.Errorf("validate temporary report: %w", err)
	}
	if !reflect.DeepEqual(serialized, report) {
		return errors.New("temporary report differs after serialization")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install report: %w", err)
	}
	return nil
}

func readEngineBenchmarkReportStrict(path string) (engineBenchmarkReport, error) {
	var report engineBenchmarkReport
	if err := readBenchmarkJSON(path, &report); err != nil {
		return engineBenchmarkReport{}, fmt.Errorf("strictly decode benchmark report: %w", err)
	}
	return report, nil
}

func validateEngineBenchmarkCurrentProvenance(report engineBenchmarkReport) error {
	if err := validateEngineBenchmarkReportExecutionConstraints(report); err != nil {
		return err
	}
	source, err := inspectEngineBenchmarkSource()
	if err != nil {
		return err
	}
	if source != report.Source {
		return errors.New("report source provenance differs from current source tree")
	}
	machine, err := inspectEngineBenchmarkMachine()
	if err != nil {
		return err
	}
	binaryHash, buildSettings, kernel, err := inspectEngineBenchmarkBinary()
	if err != nil {
		return err
	}
	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current verifier executable: %w", err)
	}
	executablePath = filepath.Clean(executablePath)
	tasksetPath, tasksetVersion, err := inspectEngineBenchmarkTaskset()
	if err != nil {
		return err
	}
	environment := report.Environment
	if environment.ExecutablePath != executablePath || environment.GoVersion != runtime.Version() ||
		environment.GOOS != runtime.GOOS || environment.GOARCH != runtime.GOARCH ||
		environment.Machine != machine || environment.BinaryHash != binaryHash || !slices.Equal(environment.BuildSettings, buildSettings) ||
		environment.Kernel != kernel || environment.GOGC != os.Getenv("GOGC") || environment.GOMEMLIMIT != os.Getenv("GOMEMLIMIT") ||
		environment.GODEBUG != os.Getenv("GODEBUG") || environment.TasksetPath != tasksetPath || environment.TasksetVersion != tasksetVersion {
		return errors.New("report environment provenance differs from current verifier process")
	}
	availableCPUs, err := inspectCurrentProcessCPUSet()
	if err != nil {
		return fmt.Errorf("current verifier CPU set: %w", err)
	}
	for label, value := range map[string]string{"worker": environment.WorkerCPUSet, "peer": environment.PeerCPUSet} {
		requested, err := parseCPUSet(value)
		if err != nil {
			return fmt.Errorf("%s CPU set: %w", label, err)
		}
		for cpu := range requested {
			if _, available := availableCPUs[cpu]; !available {
				return fmt.Errorf("%s CPU %d is outside current verifier affinity %q", label, cpu, canonicalCPUSet(availableCPUs))
			}
		}
	}
	return nil
}

func TestEngineBenchmarkControlParsers(t *testing.T) {
	cpus, err := parseCPUSet("3,1-2,2")
	if err != nil {
		t.Fatal(err)
	}
	if got := canonicalCPUSet(cpus); got != "1,2,3" {
		t.Fatalf("canonical CPU set = %q", got)
	}
	capacity := int(unsafe.Sizeof(unix.CPUSet{})) * 8
	for _, value := range []string{"", "1-", "2-1", "-1", "1,,2", strconv.Itoa(capacity), fmt.Sprintf("0-%d", capacity), "0-9223372036854775806"} {
		if _, err := parseCPUSet(value); err == nil {
			t.Fatalf("invalid CPU set %q was accepted", value)
		}
	}
	if _, err := parseDecisionThresholds(""); err == nil {
		t.Fatal("empty decision threshold policy was accepted")
	}
	if _, err := parseDecisionThresholds("p50_latency=0.1,p50_latency=0.2"); err == nil {
		t.Fatal("duplicate decision threshold was accepted")
	}
	if err := validateEngineBenchmarkScale(MaxLinkQueueItems/16, 1, 16); err != nil {
		t.Fatalf("maximum child observation scale rejected: %v", err)
	}
	if err := validateEngineBenchmarkScale(MaxLinkQueueItems/16+1, 1, 16); err == nil {
		t.Fatal("child observation scale above the local ceiling was accepted")
	}
	if err := validateEngineBenchmarkScale(minimumPairedTrials, int(^uint(0)>>1), 16); err == nil {
		t.Fatal("overflowing retained latency evidence was accepted")
	}
	if err := validateEngineBenchmarkWorkerScale(int(^uint(0)>>1), 16); err == nil {
		t.Fatal("overflowing worker latency evidence was accepted")
	}
	if engineBenchmarkMaxLatencySamplesPerResourceObservation != 195 {
		t.Fatalf("latency samples per resource observation ceiling = %d, want 195", engineBenchmarkMaxLatencySamplesPerResourceObservation)
	}
	if err := validateEngineBenchmarkScale(minimumPairedTrials, 12, 16); err != nil {
		t.Fatalf("12 resource cycles were rejected: %v", err)
	}
	if err := validateEngineBenchmarkScale(minimumPairedTrials, 13, 16); err == nil {
		t.Fatal("13 resource cycles exceeded the serialized latency evidence ceiling but were accepted")
	}
	if err := validateEngineBenchmarkWorkerScale(12, 16); err != nil {
		t.Fatalf("worker rejected 12 resource cycles: %v", err)
	}
	if err := validateEngineBenchmarkWorkerScale(13, 16); err == nil {
		t.Fatal("worker accepted 13 resource cycles")
	}
	size, err := engineBenchmarkFixedJSONEnvelopeSize("0", "1")
	if err != nil {
		t.Fatal(err)
	}
	if size > engineBenchmarkFixedJSONBytesPerChild {
		t.Fatalf("maximum fixed worker-result envelope = %d bytes, ceiling %d", size, engineBenchmarkFixedJSONBytesPerChild)
	}
	paths := engineBenchmarkFixedSourcePaths("/repo")
	wantPaths := []string{filepath.Join("/repo", "go.mod"), filepath.Join("/repo", "go.sum")}
	if !slices.Equal(paths, wantPaths) {
		t.Fatalf("source fingerprint paths = %v, want %v", paths, wantPaths)
	}
}

func TestReadBenchmarkJSONRejectsDuplicateAndUnknownMembers(t *testing.T) {
	for name, contents := range map[string]string{
		"duplicate": `{"Purpose":"smoke","Purpose":"decision"}`,
		"unknown":   `{"Unknown":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readEngineBenchmarkReportStrict(path); err == nil {
				t.Fatal("non-strict JSON was accepted")
			}
		})
	}
	t.Run("oversize", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "report.json")
		file, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(int64(engineBenchmarkMaxJSONBytes) + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := readEngineBenchmarkReportStrict(path); err == nil {
			t.Fatal("oversized JSON was accepted")
		}
	})
}

type engineBenchmarkWhitespaceReader struct{}

func (engineBenchmarkWhitespaceReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = ' '
	}
	return len(buffer), nil
}

func TestReadBenchmarkJSONNonRegularStreamBoundary(t *testing.T) {
	tests := []struct {
		name       string
		spaces     int64
		suffix     string
		wantSize   bool
		wantDecode bool
	}{
		{name: "exact ceiling", spaces: int64(engineBenchmarkMaxJSONBytes) - 2},
		{name: "ceiling plus one", spaces: int64(engineBenchmarkMaxJSONBytes) - 1, wantSize: true},
		{name: "trailing non-whitespace", spaces: int64(engineBenchmarkMaxJSONBytes) - 3, suffix: "x", wantDecode: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			writeResult := make(chan error, 1)
			go func() {
				_, writeErr := io.WriteString(writer, "{}")
				if writeErr == nil && test.spaces > 0 {
					_, writeErr = io.CopyN(writer, engineBenchmarkWhitespaceReader{}, test.spaces)
				}
				if writeErr == nil && test.suffix != "" {
					_, writeErr = io.WriteString(writer, test.suffix)
				}
				writeResult <- errors.Join(writeErr, writer.Close())
			}()
			var decoded struct{}
			decodeErr := readBenchmarkJSONFile(reader, &decoded)
			closeErr := reader.Close()
			writeErr := <-writeResult
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			if writeErr != nil {
				t.Fatal(writeErr)
			}
			if test.wantSize {
				if decodeErr == nil || !strings.Contains(decodeErr.Error(), "exceeds schema-derived safety ceiling") {
					t.Fatalf("size boundary error = %v", decodeErr)
				}
				return
			}
			if test.wantDecode {
				if decodeErr == nil || strings.Contains(decodeErr.Error(), "exceeds schema-derived safety ceiling") {
					t.Fatalf("trailing-data error = %v", decodeErr)
				}
				return
			}
			if decodeErr != nil {
				t.Fatalf("exact-ceiling stream rejected: %v", decodeErr)
			}
		})
	}
}

func TestWriteEngineBenchmarkReportPreservesExistingFileOnInvalidTemporary(t *testing.T) {
	const existing = "existing report"
	for _, test := range []struct {
		name   string
		mutate func(*engineBenchmarkReport)
	}{
		{name: "invalid", mutate: func(report *engineBenchmarkReport) { report.Purpose = "invalid" }},
		{name: "oversize", mutate: func(report *engineBenchmarkReport) {
			report.SharedProtocolBaselines.RawOutput = strings.Repeat("x", engineBenchmarkMaxJSONBytes)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
				t.Fatal(err)
			}
			report := syntheticEngineBenchmarkReport(t)
			test.mutate(&report)
			if err := writeEngineBenchmarkReport(path, report); err == nil {
				t.Fatal("invalid temporary report was installed")
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(contents) != existing {
				t.Fatalf("existing report changed to %q", contents)
			}
		})
	}
}

func TestValidateEngineBenchmarkCurrentProvenanceRejectsStaleSource(t *testing.T) {
	source, err := inspectEngineBenchmarkSource()
	if err != nil {
		t.Fatal(err)
	}
	machine, err := inspectEngineBenchmarkMachine()
	if err != nil {
		t.Fatal(err)
	}
	binaryHash, buildSettings, kernel, err := inspectEngineBenchmarkBinary()
	if err != nil {
		t.Fatal(err)
	}
	tasksetPath, tasksetVersion, err := inspectEngineBenchmarkTaskset()
	if err != nil {
		t.Fatal(err)
	}
	report := syntheticEngineBenchmarkReport(t)
	report.Source = source
	report.Environment.GoVersion, report.Environment.GOOS, report.Environment.GOARCH = runtime.Version(), runtime.GOOS, runtime.GOARCH
	report.Environment.Machine, report.Environment.BinaryHash = machine, binaryHash
	currentExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	report.Environment.ExecutablePath = filepath.Clean(currentExecutable)
	report.Environment.BuildSettings, report.Environment.Kernel = buildSettings, kernel
	report.Environment.GOGC, report.Environment.GOMEMLIMIT, report.Environment.GODEBUG = os.Getenv("GOGC"), os.Getenv("GOMEMLIMIT"), os.Getenv("GODEBUG")
	report.Environment.TasksetPath, report.Environment.TasksetVersion = tasksetPath, tasksetVersion
	if err := validateEngineBenchmarkCurrentProvenance(report); err != nil {
		t.Fatalf("current provenance rejected: %v", err)
	}
	available, err := inspectCurrentProcessCPUSet()
	if err != nil {
		t.Fatal(err)
	}
	capacity := int(unsafe.Sizeof(unix.CPUSet{})) * 8
	missingCPU := -1
	for cpu := range capacity {
		if _, ok := available[cpu]; !ok {
			missingCPU = cpu
			break
		}
	}
	if missingCPU >= 0 {
		unavailable := cloneSyntheticEngineBenchmarkReport(t, report)
		unavailable.Environment.WorkerCPUSet = strconv.Itoa(missingCPU)
		if unavailable.Environment.PeerCPUSet == unavailable.Environment.WorkerCPUSet {
			unavailable.Environment.PeerCPUSet = canonicalCPUSet(available)
		}
		if err := validateEngineBenchmarkCurrentProvenance(unavailable); err == nil {
			t.Fatal("CPU outside current verifier affinity was accepted")
		}
	}
	report.Source.Fingerprint = "stale"
	if err := validateEngineBenchmarkCurrentProvenance(report); err == nil {
		t.Fatal("stale source provenance was accepted")
	}
}

func TestEngineSharedProtocolBaselineParserAndValidation(t *testing.T) {
	const (
		gomaxprocs = 2
		iterations = 17
	)
	var output strings.Builder
	for range 4 {
		fmt.Fprintf(&output, "benchmark_test.go:1: shared-protocol baseline affinity attested: CPUs=0,1 GOMAXPROCS=%d\n", gomaxprocs)
	}
	for _, operation := range []string{"BenchmarkClientBootstrapReadyEncode", "BenchmarkClientBootstrapReadyFeed"} {
		for _, payloadSize := range benchmarkPacketSizes() {
			fmt.Fprintf(&output, "%s/%d-%d\t%d\t123.5 ns/op\t456 B/op\t7 allocs/op\n",
				operation, payloadSize, gomaxprocs, iterations)
		}
	}
	results, err := parseEngineSharedProtocolBaselines(output.String(), gomaxprocs)
	if err != nil {
		t.Fatal(err)
	}
	report := engineSharedProtocolBaselineReport{
		Commit: "commit", SourceFingerprint: "fingerprint", BinaryHash: "binary", GoVersion: "go1.27",
		TestBinaryPath: "/tmp/test", TasksetPath: "taskset",
		BenchmarkExpression:   sharedProtocolBenchmarkExpression,
		Iterations:            iterations,
		GOMAXPROCS:            gomaxprocs,
		WorkerCPUSet:          "0,1",
		EffectiveWorkerCPUSet: "0,1",
		AffinityAttestation:   sharedProtocolAffinityAttestation,
		RawOutput:             output.String(),
		Results:               results,
	}
	report.Command = canonicalEngineSharedProtocolCommand(report)
	if err := validateEngineSharedProtocolBaselines(report); err != nil {
		t.Fatal(err)
	}
	tamperedIterations := report
	tamperedIterations.Results = slices.Clone(report.Results)
	tamperedIterations.Results[0].Iterations++
	if err := validateEngineSharedProtocolBaselines(tamperedIterations); err == nil {
		t.Fatal("tampered shared-protocol iteration count was accepted")
	}
	tamperedDuplicate := report
	tamperedDuplicate.Results = slices.Clone(report.Results)
	tamperedDuplicate.Results[1] = tamperedDuplicate.Results[0]
	if err := validateEngineSharedProtocolBaselines(tamperedDuplicate); err == nil {
		t.Fatal("duplicate shared-protocol result was accepted")
	}
	tamperedRawOutput := report
	tamperedRawOutput.RawOutput = strings.Replace(report.RawOutput, "123.5 ns/op", "124.5 ns/op", 1)
	if err := validateEngineSharedProtocolBaselines(tamperedRawOutput); err == nil {
		t.Fatal("tampered shared-protocol raw output was accepted")
	}
	if _, err := parseEngineSharedProtocolBaselines(strings.Replace(output.String(), "123.5 ns/op", "invalid ns/op", 1), gomaxprocs); err == nil {
		t.Fatal("invalid shared-protocol timing was accepted")
	}
}

func TestEngineBenchmarkObservationRawEvidenceValidation(t *testing.T) {
	controls := engineBenchmarkControls{
		WarmupCycles:              2,
		EffectiveWorkerSendBuffer: 10,
		EffectiveWorkerReadBuffer: 11,
		EffectivePeerSendBuffer:   12,
		EffectivePeerReadBuffer:   13,
		EffectiveWorkerNoDelay:    true,
		EffectivePeerNoDelay:      true,
		WorkerCPUSet:              "0,1",
		PeerCPUSet:                "2,3",
		PeerGOMAXPROCS:            2,
		Limits: LinkLimits{
			MaxPendingSubmissions: 1, MaxPendingSubmissionBytes: 1,
			MaxPendingEvents: 1, MaxPendingEventBytes: 1,
		},
	}
	metrics := engineTrialMetrics{
		CompletedRequests:           8,
		ResourceRequests:            8,
		GoroutineBaseline:           4,
		GoroutinePeak:               6,
		HeapBytesWorkerBaseline:     100,
		HeapBytesAllocationBaseline: 150,
		HeapBytesPeak:               200,
	}
	raw := engineBenchmarkRawObservation{
		ThroughputWarmupCycles:      2,
		ResourceWarmupCycles:        2,
		ThroughputAnswers:           8,
		ThroughputAcknowledgements:  8,
		ResourceAnswers:             8,
		ResourceAcknowledgements:    8,
		ThroughputPeerRecords:       8,
		ResourcePeerRecords:         8,
		GoroutineBaseline:           4,
		GoroutineHighWater:          6,
		GoroutineAfterCleanup:       4,
		HeapBytesWorkerBaseline:     100,
		HeapBytesAllocationBaseline: 150,
		EffectiveWorkerSendBuffer:   10,
		EffectiveWorkerReadBuffer:   11,
		EffectivePeerSendBuffer:     12,
		EffectivePeerReadBuffer:     13,
		EffectiveWorkerNoDelay:      true,
		EffectivePeerNoDelay:        true,
		EffectiveWorkerCPUSet:       "0,1",
		EffectivePeerCPUSet:         "2,3",
		PeerGOMAXPROCS:              2,
	}
	if err := validateEngineBenchmarkObservationControls(controls, metrics, raw); err != nil {
		t.Fatal(err)
	}
	tamperedResource := raw
	tamperedResource.HeapBytesAllocationBaseline++
	if err := validateEngineBenchmarkObservationControls(controls, metrics, tamperedResource); err == nil {
		t.Fatal("tampered raw resource baseline was accepted")
	}
	tamperedControl := raw
	tamperedControl.EffectivePeerReadBuffer++
	if err := validateEngineBenchmarkObservationControls(controls, metrics, tamperedControl); err == nil {
		t.Fatal("tampered raw socket control was accepted")
	}
}

func TestEngineBenchmarkReportTamperValidation(t *testing.T) {
	report := syntheticEngineBenchmarkReport(t)
	if err := validateEngineBenchmarkReport(report); err != nil {
		t.Fatalf("synthetic report: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*engineBenchmarkReport)
	}{
		{name: "duplicate scenario", mutate: func(r *engineBenchmarkReport) { r.Scenarios[1] = r.Scenarios[0] }},
		{name: "renamed scenario", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].Scenario.Name = "renamed" }},
		{name: "scenario links", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].Scenario.Links++ }},
		{name: "scenario controls", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].Measurement.Controls.SlowReadChunk = 1 }},
		{name: "workload", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].Measurement.Controls.Workload.ConnectionIDs[0]++ }},
		{name: "source-derived limits", mutate: func(r *engineBenchmarkReport) {
			for index := range r.Scenarios {
				r.Scenarios[index].Measurement.Controls.Limits.MaxPendingEvents++
			}
		}},
		{name: "source-derived bytes", mutate: func(r *engineBenchmarkReport) {
			for index := range r.Scenarios {
				r.Scenarios[index].Measurement.Controls.ExpectedBytesRead++
			}
		}},
		{name: "source provenance", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].Measurement.Controls.SourceFingerprint = "changed" }},
		{name: "environment", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].Measurement.Controls.GoVersion = "changed" }},
		{name: "environment executable", mutate: func(r *engineBenchmarkReport) { r.Environment.ExecutablePath = "/tmp/changed" }},
		{name: "policy", mutate: func(r *engineBenchmarkReport) { r.Scenarios[1].Measurement.Policy.ConfidenceLevel = 0.9 }},
		{name: "unknown policy key", mutate: func(r *engineBenchmarkReport) {
			r.Scenarios[0].Measurement.Policy.MaximumRegression[decisionMetric("unknown")] = 0.1
		}},
		{name: "baseline command", mutate: func(r *engineBenchmarkReport) {
			r.SharedProtocolBaselines.Command = append(r.SharedProtocolBaselines.Command, "extra")
		}},
		{name: "baseline source", mutate: func(r *engineBenchmarkReport) { r.SharedProtocolBaselines.SourceFingerprint = "changed" }},
		{name: "baseline binary", mutate: func(r *engineBenchmarkReport) { r.SharedProtocolBaselines.BinaryHash = "changed" }},
		{name: "baseline executable", mutate: func(r *engineBenchmarkReport) {
			r.SharedProtocolBaselines.TestBinaryPath = "/tmp/changed"
			r.SharedProtocolBaselines.Command = canonicalEngineSharedProtocolCommand(r.SharedProtocolBaselines)
		}},
		{name: "global control", mutate: func(r *engineBenchmarkReport) { r.Scenarios[1].Measurement.Controls.RequestedSocketBuffer++ }},
		{name: "peer records", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].RawTrials[0].Blocking.ResourcePeerRecords++ }},
		{name: "TCP_NODELAY", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].RawTrials[0].Blocking.EffectivePeerNoDelay = false }},
		{name: "queue over limit", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].Measurement.PairedTrials[0].Blocking.EventHighWater = 2 }},
		{name: "correctness", mutate: func(r *engineBenchmarkReport) { r.Correctness.GnetPassed = false }},
		{name: "correctness executable", mutate: func(r *engineBenchmarkReport) { r.Correctness.TestBinaryPath = "/tmp/changed" }},
		{name: "purpose", mutate: func(r *engineBenchmarkReport) {
			r.Scenarios[0].Measurement.Controls.Purpose = engineBenchmarkPurposeDecision
		}},
		{name: "smoke selection", mutate: func(r *engineBenchmarkReport) { r.OverallSelection = engineSelectionGnet }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tampered := cloneSyntheticEngineBenchmarkReport(t, report)
			test.mutate(&tampered)
			if err := validateEngineBenchmarkReport(tampered); err == nil {
				t.Fatal("tampered report was accepted")
			}
		})
	}
}

func TestEngineBenchmarkScenarioReportTamperValidation(t *testing.T) {
	report := syntheticEngineBenchmarkReport(t)
	base := report.Scenarios[2]
	if err := validateEngineBenchmarkScenarioReport(base); err != nil {
		t.Fatalf("synthetic scenario: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*engineBenchmarkScenarioReport)
	}{
		{name: "malformed scenario", mutate: func(r *engineBenchmarkScenarioReport) { r.Scenario.Name = "other" }},
		{name: "control mismatch", mutate: func(r *engineBenchmarkScenarioReport) { r.Scenario.SlowReadDelay++ }},
		{name: "workload mismatch", mutate: func(r *engineBenchmarkScenarioReport) { r.Measurement.Controls.Workload.RequestsPerCycle++ }},
		{name: "record mismatch", mutate: func(r *engineBenchmarkScenarioReport) { r.RawTrials[0].Gnet.ThroughputPeerRecords++ }},
		{name: "TCP_NODELAY mismatch", mutate: func(r *engineBenchmarkScenarioReport) { r.RawTrials[0].Gnet.EffectiveWorkerNoDelay = false }},
		{name: "correctness failure", mutate: func(r *engineBenchmarkScenarioReport) { r.Measurement.GnetCorrectness.ProtocolBytes = false }},
		{name: "purpose selection mismatch", mutate: func(r *engineBenchmarkScenarioReport) { r.Selection = engineSelectionBlocking }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone := cloneSyntheticEngineBenchmarkReport(t, report).Scenarios[2]
			test.mutate(&clone)
			if err := validateEngineBenchmarkScenarioReport(clone); err == nil {
				t.Fatal("tampered scenario was accepted")
			}
		})
	}
}

func TestEngineBenchmarkExecutionConstraintTamperValidation(t *testing.T) {
	base := syntheticEngineBenchmarkReport(t)
	if err := validateEngineBenchmarkReportExecutionConstraints(base); err != nil {
		t.Fatalf("synthetic execution controls: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*engineBenchmarkReport)
	}{
		{name: "event-loop clamp", mutate: func(r *engineBenchmarkReport) { r.Environment.EventLoops = MaxGnetClientEventLoops + 1 }},
		{name: "multi-links", mutate: func(r *engineBenchmarkReport) { r.ConfiguredMultiLinks = 5 }},
		{name: "warmup cycles", mutate: func(r *engineBenchmarkReport) {
			r.Scenarios[0].Measurement.Controls.WarmupCycles = MaxLinkQueueItems + 1
		}},
		{name: "baseline iterations", mutate: func(r *engineBenchmarkReport) { r.Environment.BaselineIterations = MaxLinkQueueItems + 1 }},
		{name: "overlapping CPUs", mutate: func(r *engineBenchmarkReport) { r.Environment.PeerCPUSet = r.Environment.WorkerCPUSet }},
		{name: "GOMAXPROCS above worker CPUs", mutate: func(r *engineBenchmarkReport) { r.Environment.GOMAXPROCS = 2 }},
		{name: "peer GOMAXPROCS mismatch", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].Measurement.Controls.PeerGOMAXPROCS = 2 }},
		{name: "observation timeout", mutate: func(r *engineBenchmarkReport) {
			r.Scenarios[0].Measurement.Controls.ObservationTimeout = time.Nanosecond
		}},
		{name: "resource evidence cardinality", mutate: func(r *engineBenchmarkReport) { r.Scenarios[0].Measurement.Controls.ResourceCycles = 13 }},
		{name: "child observation cardinality", mutate: func(r *engineBenchmarkReport) {
			r.Scenarios[0].Measurement.Policy.TrialCount = MaxLinkQueueItems/16 + 1
		}},
		{name: "invalid worker CPUs", mutate: func(r *engineBenchmarkReport) { r.Environment.WorkerCPUSet = "0-9223372036854775806" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tampered := cloneSyntheticEngineBenchmarkReport(t, base)
			test.mutate(&tampered)
			if err := validateEngineBenchmarkReportExecutionConstraints(tampered); err == nil {
				t.Fatal("execution controls outside generator constraints were accepted")
			}
		})
	}
}

func syntheticEngineBenchmarkReport(t testing.TB) engineBenchmarkReport {
	t.Helper()
	const gomaxprocs = 1
	var baselineOutput strings.Builder
	for range 4 {
		fmt.Fprintf(&baselineOutput, "benchmark_test.go:1: shared-protocol baseline affinity attested: CPUs=0 GOMAXPROCS=%d\n", gomaxprocs)
	}
	for _, operation := range []string{"BenchmarkClientBootstrapReadyEncode", "BenchmarkClientBootstrapReadyFeed"} {
		for _, payloadSize := range benchmarkPacketSizes() {
			fmt.Fprintf(&baselineOutput, "%s/%d-%d\t1\t1 ns/op\t1 B/op\t1 allocs/op\n", operation, payloadSize, gomaxprocs)
		}
	}
	baselineResults, err := parseEngineSharedProtocolBaselines(baselineOutput.String(), gomaxprocs)
	if err != nil {
		t.Fatal(err)
	}
	baseline := engineSharedProtocolBaselineReport{
		Commit: "commit", SourceFingerprint: "fingerprint", BinaryHash: "binary", GoVersion: "go1.27",
		TestBinaryPath: "/tmp/test", TasksetPath: "/usr/bin/taskset",
		BenchmarkExpression: sharedProtocolBenchmarkExpression, Iterations: 1, GOMAXPROCS: gomaxprocs,
		WorkerCPUSet: "0", EffectiveWorkerCPUSet: "0", AffinityAttestation: sharedProtocolAffinityAttestation,
		RawOutput: baselineOutput.String(), Results: baselineResults,
	}
	baseline.Command = canonicalEngineSharedProtocolCommand(baseline)
	names := [4]string{"single-link-normal", "multi-link-normal", "single-link-slow-reader", "multi-link-slow-reader"}
	canonicalWorkload, err := buildDeterministicLinkWorkload()
	if err != nil {
		t.Fatal(err)
	}
	canonicalLimits := limitsForWorkload(canonicalWorkload)
	expectedRead, expectedWritten, err := calculateExpectedBenchmarkCycleBytes(canonicalWorkload)
	if err != nil {
		t.Fatal(err)
	}
	scenarios := make([]engineBenchmarkScenarioReport, 0, 4)
	for index, name := range names {
		measurement := completeEngineMeasurementSchema()
		measurement.Controls.Purpose = engineBenchmarkPurposeSmoke
		measurement.Controls.Commit = "commit"
		measurement.Controls.SourceFingerprint = "fingerprint"
		measurement.Controls.GoVersion = "go1.27"
		measurement.Controls.Machine = "machine"
		measurement.Controls.CPUPolicy = "policy"
		measurement.Controls.EventLoops = 1
		measurement.Controls.GOMAXPROCS = 1
		measurement.Controls.MultiLinkCount = 2
		measurement.Controls.WorkerCPUSet = "0"
		measurement.Controls.PeerCPUSet = "1"
		measurement.Controls.Workload = engineBenchmarkWorkloadEvidence{
			Name: "four-sessions-payload-matrix", SessionCount: 4, PacketSizes: [4]int(benchmarkPacketSizes()),
			ConnectionIDs: [4]int64{1000, 1001, 1002, 1003}, RequestsPerCycle: 16,
			MaxInFlightPerConnection: 1, WholeCycles: true, QueueHighWaterScope: "maximum-per-link",
		}
		measurement.Controls.RequestsPerCycle = 16
		measurement.Controls.Limits = canonicalLimits
		measurement.Controls.ExpectedBytesRead = expectedRead
		measurement.Controls.ExpectedBytesWritten = expectedWritten
		measurement.Controls.EffectiveWorkerNoDelay = true
		measurement.Controls.EffectivePeerNoDelay = true
		measurement.Controls.ResourceAttribution = benchmarkResourceAttribution
		scenario := engineBenchmarkScenario{Name: name, Links: 1}
		if index%2 == 1 {
			scenario.Links = 2
		}
		if index >= 2 {
			scenario.SlowReadChunk, scenario.SlowReadDelay = 1, time.Nanosecond
			measurement.Controls.SlowReadChunk, measurement.Controls.SlowReadDelay = 1, time.Nanosecond
		} else {
			measurement.Controls.SlowReadChunk, measurement.Controls.SlowReadDelay = 0, 0
		}
		rawTrials := make([]engineBenchmarkRawPair, len(measurement.PairedTrials))
		for trialIndex := range measurement.PairedTrials {
			trial := &measurement.PairedTrials[trialIndex]
			for _, metrics := range []*engineTrialMetrics{&trial.Blocking, &trial.Gnet} {
				metrics.CompletedRequests = 16
				metrics.SustainableRequestsPerSec = 16 / metrics.Duration.Seconds()
				metrics.ResourceRequests = 16
				metrics.LatencySamples = make([]time.Duration, 16)
				metrics.BytesRead = expectedRead
				metrics.BytesWritten = expectedWritten
				metrics.RawBytesRead = expectedRead
				metrics.RawBytesWritten = expectedWritten
				metrics.ResourceRawBytesRead = expectedRead
				metrics.ResourceRawBytesWritten = expectedWritten
				metrics.HeapBytesWorkerBaseline = 1
				metrics.HeapBytesAllocationBaseline = 1
				metrics.HeapBytesPeak = 2
				metrics.HeapBytesHighWater = 1
			}
			raw := func(metrics engineTrialMetrics) engineBenchmarkRawObservation {
				return engineBenchmarkRawObservation{
					ThroughputWarmupCycles: measurement.Controls.WarmupCycles, ResourceWarmupCycles: measurement.Controls.WarmupCycles,
					ThroughputAnswers: metrics.CompletedRequests, ThroughputAcknowledgements: metrics.CompletedRequests,
					ResourceAnswers: metrics.ResourceRequests, ResourceAcknowledgements: metrics.ResourceRequests,
					ThroughputPeerRecords: uint64(metrics.CompletedRequests), ResourcePeerRecords: uint64(metrics.ResourceRequests),
					GoroutineBaseline: metrics.GoroutineBaseline, GoroutineHighWater: metrics.GoroutinePeak,
					GoroutineAfterCleanup: metrics.GoroutineBaseline, HeapBytesWorkerBaseline: 1,
					HeapBytesAllocationBaseline: 1,
					EffectiveWorkerSendBuffer:   1, EffectiveWorkerReadBuffer: 1,
					EffectivePeerSendBuffer: 1, EffectivePeerReadBuffer: 1,
					EffectiveWorkerNoDelay: true, EffectivePeerNoDelay: true,
					EffectiveWorkerCPUSet: "0", EffectivePeerCPUSet: "1", PeerGOMAXPROCS: 1,
				}
			}
			rawTrials[trialIndex] = engineBenchmarkRawPair{PairIndex: trial.PairIndex, FirstEngine: trial.FirstEngine}
			rawTrials[trialIndex].Blocking = raw(trial.Blocking)
			rawTrials[trialIndex].Gnet = raw(trial.Gnet)
		}
		recomputeEffectIntervals(t, &measurement)
		scenarios = append(scenarios, engineBenchmarkScenarioReport{
			Scenario: scenario, Measurement: measurement, RawTrials: rawTrials, Selection: engineSelectionNone,
		})
	}
	return engineBenchmarkReport{
		SchemaVersion: engineBenchmarkReportVersion, Purpose: engineBenchmarkPurposeSmoke, CreatedAt: time.Unix(1, 0),
		Source: engineBenchmarkSource{Commit: "commit", Fingerprint: "fingerprint"},
		Environment: engineBenchmarkEnvironment{
			ExecutablePath: "/tmp/test", GoVersion: "go1.27", GOOS: "linux", GOARCH: "amd64", Machine: "machine", CPUPolicy: "policy",
			GOMAXPROCS: 1, EventLoops: 1, BinaryHash: "binary", Kernel: "kernel", WorkerCPUSet: "0", PeerCPUSet: "1",
			TasksetPath: "/usr/bin/taskset", TasksetVersion: "taskset", BaselineIterations: 1,
		},
		SharedProtocolBaselines: baseline,
		Correctness: engineBenchmarkCorrectnessGate{
			Passed: true, BlockingPassed: true, GnetPassed: true, TestBinaryHash: "binary", TestBinaryPath: "/tmp/test", SourceFingerprint: "fingerprint",
			Tests: [2]string{"benchmark-correctness/blocking", "benchmark-correctness/gnet"},
		},
		ConfiguredMultiLinks: 2, ConfiguredSlowReadChunk: 1, ConfiguredSlowReadDelay: time.Nanosecond,
		Scenarios: scenarios, OverallSelection: engineSelectionNone,
	}
}

func cloneSyntheticEngineBenchmarkReport(t testing.TB, report engineBenchmarkReport) engineBenchmarkReport {
	t.Helper()
	contents, err := json.Marshal(report, jsonv1.DefaultOptionsV1())
	if err != nil {
		t.Fatal(err)
	}
	var clone engineBenchmarkReport
	if err := json.Unmarshal(contents, &clone, jsonv1.DefaultOptionsV1()); err != nil {
		t.Fatal(err)
	}
	return clone
}
