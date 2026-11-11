package config

import "math"

// fileDescriptorSoftLimit is replaced by tests.
var fileDescriptorSoftLimit = currentFileDescriptorSoftLimit

// maxConnectionsFDReserve keeps descriptors for listeners, event loops,
// Middle-End links, mask-host fetches, and metrics. It is at most half of a
// small limit.
const maxConnectionsFDReserve = 256

// generalMaxConnections returns the global client cap. A positive value is
// used as configured. Zero derives the cap from the process RLIMIT_NOFILE
// soft limit: each direct client holds two descriptors (client and DC), so
// the cap is half of the limit after a reserve. An unknown limit gives 0
// (unlimited).
func generalMaxConnections(configured int) int {
	if configured > 0 {
		return configured
	}
	soft, ok := fileDescriptorSoftLimit()
	if !ok || soft == 0 {
		return 0
	}
	soft = min(soft, math.MaxInt32)
	reserve := min(uint64(maxConnectionsFDReserve), soft/2)
	return int((soft - reserve) / 2)
}
