//go:build linux

package middleend

import (
	"os"
	"runtime"
	"strconv"
	"testing"
)

const (
	readyBenchmarkCPUSetEnvironment     = "TELEGO_MEBENCH_WORKER_CPUS"
	readyBenchmarkGOMAXPROCSEnvironment = "TELEGO_MEBENCH_GOMAXPROCS"
)

func verifyReadyBenchmarkAffinity(b *testing.B) {
	b.Helper()
	cpuSet := os.Getenv(readyBenchmarkCPUSetEnvironment)
	if cpuSet == "" {
		return
	}
	wantGOMAXPROCS, err := strconv.Atoi(os.Getenv(readyBenchmarkGOMAXPROCSEnvironment))
	if err != nil || wantGOMAXPROCS <= 0 {
		b.Fatalf("invalid %s", readyBenchmarkGOMAXPROCSEnvironment)
	}
	if got := runtime.GOMAXPROCS(0); got != wantGOMAXPROCS {
		b.Fatalf("shared-protocol baseline GOMAXPROCS = %d, want %d", got, wantGOMAXPROCS)
	}
	effectiveCPUSet := verifyProcessThreadCPUSet(b, cpuSet)
	b.Logf("shared-protocol baseline affinity attested: CPUs=%s GOMAXPROCS=%d", effectiveCPUSet, wantGOMAXPROCS)
}
