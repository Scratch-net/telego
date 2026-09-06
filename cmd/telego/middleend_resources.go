package main

import (
	"errors"

	"github.com/scratch-net/telego/pkg/log"
	"github.com/scratch-net/telego/pkg/transport/middleend"
)

var errFileDescriptorLimitUnavailable = errors.New("file-descriptor limit is unavailable on this platform")

type fileDescriptorLimit struct {
	soft uint64
	hard uint64
}

func middleEndDirectFallbackFDMinimum(maxConnections int) uint64 {
	if maxConnections <= 0 {
		return 0
	}
	return 2 * uint64(maxConnections)
}

// middleEndLinkCapacity includes reserved refresh candidates in the logical
// link allowance. It is not a process descriptor limit: bootstrap sockets,
// close completion, listeners, and runtime descriptors have separate lifetimes.
// After logical closure, each ME owner loop can still hold one enrolled socket
// until gnet finishes that OnClose call and physically closes the descriptor.
func middleEndLinkCapacity(snapshot middleend.ServiceSnapshot) (live, rotation int) {
	generationCapacity := func(manager *middleend.FixedBindingManagerSnapshot) int {
		if manager == nil {
			return 0
		}
		return len(manager.Slots) + snapshot.Capacity.MaxRefreshCandidatesPerManager
	}
	active := generationCapacity(snapshot.Supervisor.Active)
	retiring := generationCapacity(snapshot.Supervisor.Retiring)
	return active + retiring, 2 * max(active, retiring)
}

func logMiddleEndFileDescriptorCapacity(maxConnections int) {
	limit, err := currentFileDescriptorLimit()
	if errors.Is(err, errFileDescriptorLimitUnavailable) {
		return
	}
	minimum := middleEndDirectFallbackFDMinimum(maxConnections)
	if err != nil {
		log.Warn().Err(err).Msg("Middle-End could not read the process file-descriptor limit")
		return
	}
	if limit.soft <= minimum {
		log.Warn().
			Uint64("soft_limit", limit.soft).
			Uint64("hard_limit", limit.hard).
			Uint64("direct_fallback_fd_minimum", minimum).
			Msg("Middle-End direct-fallback capacity exceeds the process file-descriptor limit; increase the limit or reduce middle-end.max-connections")
		return
	}
	log.Info().
		Uint64("soft_limit", limit.soft).
		Uint64("hard_limit", limit.hard).
		Uint64("direct_fallback_fd_minimum", minimum).
		Msg("Middle-End file-descriptor capacity checked; optional listeners and runtime descriptors are additional")
}
