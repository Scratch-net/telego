//go:build !linux

package middleend

import (
	"os"
	"testing"
)

func verifyReadyBenchmarkAffinity(b *testing.B) {
	b.Helper()
	if os.Getenv("TELEGO_MEBENCH_WORKER_CPUS") != "" {
		b.Fatal("pinned shared-protocol baselines require Linux")
	}
}
