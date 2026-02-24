package dc

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// ProbeResult holds the result of probing a single address.
type ProbeResult struct {
	Addr    Addr
	RTT     time.Duration
	Success bool
	Error   string
}

// DCProbeResult holds all probe results for a single DC.
type DCProbeResult struct {
	DCID    int
	Results []ProbeResult
}

// ProbeTimeout is the timeout for each probe attempt.
const ProbeTimeout = 5 * time.Second

// probed holds the sorted addresses after probing (read-only after Init).
var (
	probedDCs   map[int][]Addr
	probedMu    sync.RWMutex
	probeOnce   sync.Once
	probeLogger func(format string, args ...any)
)

// SetProbeLogger sets the logger for probe output.
func SetProbeLogger(logger func(format string, args ...any)) {
	probeLogger = logger
}

func logProbe(format string, args ...any) {
	if probeLogger != nil {
		probeLogger(format, args...)
	} else {
		fmt.Printf(format+"\n", args...)
	}
}

// Init probes all DC addresses and sorts them by RTT.
// Should be called once at startup. Blocks until complete.
func Init() {
	probeOnce.Do(func() {
		results := probeAllDCs()
		printProbeResults(results)
		storeSortedAddresses(results)
	})
}

// probeAllDCs probes all known DC addresses concurrently.
func probeAllDCs() []DCProbeResult {
	// Collect all DCs to probe
	allDCs := make(map[int][]Addr)
	for id, addrs := range DefaultDCs {
		allDCs[id] = addrs
	}
	for id, addrs := range CDNDCs {
		allDCs[id] = addrs
	}

	var wg sync.WaitGroup
	results := make([]DCProbeResult, 0, len(allDCs))
	var mu sync.Mutex

	for dcID, addrs := range allDCs {
		dcID := dcID
		addrs := addrs
		wg.Add(1)
		go func() {
			defer wg.Done()
			dcResult := probeDC(dcID, addrs)
			mu.Lock()
			results = append(results, dcResult)
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Sort by DC ID for consistent output
	sort.Slice(results, func(i, j int) bool {
		return results[i].DCID < results[j].DCID
	})

	return results
}

// probeDC probes all addresses for a single DC.
func probeDC(dcID int, addrs []Addr) DCProbeResult {
	result := DCProbeResult{DCID: dcID}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, addr := range addrs {
		addr := addr
		wg.Add(1)
		go func() {
			defer wg.Done()
			pr := probeAddr(addr)
			mu.Lock()
			result.Results = append(result.Results, pr)
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Sort by RTT (successful first, then by RTT; failed last)
	sort.Slice(result.Results, func(i, j int) bool {
		if result.Results[i].Success != result.Results[j].Success {
			return result.Results[i].Success
		}
		return result.Results[i].RTT < result.Results[j].RTT
	})

	return result
}

// probeAddr probes a single address and returns the result.
func probeAddr(addr Addr) ProbeResult {
	start := time.Now()

	conn, err := net.DialTimeout(addr.Network, addr.Address, ProbeTimeout)
	if err != nil {
		return ProbeResult{
			Addr:    addr,
			Success: false,
			Error:   err.Error(),
		}
	}
	conn.Close()

	return ProbeResult{
		Addr:    addr,
		RTT:     time.Since(start),
		Success: true,
	}
}

// printProbeResults prints probe results in telemt style.
func printProbeResults(results []DCProbeResult) {
	logProbe("================== Telegram DC Connectivity ==================")

	// Count successes
	var totalV4, totalV6, successV4, successV6 int
	for _, dc := range results {
		for _, r := range dc.Results {
			if r.Addr.IsIPv6() {
				totalV6++
				if r.Success {
					successV6++
				}
			} else {
				totalV4++
				if r.Success {
					successV4++
				}
			}
		}
	}

	if successV4 > 0 && successV6 > 0 {
		logProbe("  IPv4: %d/%d | IPv6: %d/%d", successV4, totalV4, successV6, totalV6)
	} else if successV4 > 0 {
		logProbe("  IPv4: %d/%d | IPv6: unavailable", successV4, totalV4)
	} else if successV6 > 0 {
		logProbe("  IPv4: unavailable | IPv6: %d/%d", successV6, totalV6)
	} else {
		logProbe("  No DC connectivity!")
	}

	logProbe("===============================================================")

	// Print IPv4 results
	for _, dc := range results {
		for _, r := range dc.Results {
			if r.Addr.IsIPv6() {
				continue
			}
			if r.Success {
				logProbe("  DC%d [IPv4] %-21s %6.0f ms", dc.DCID, r.Addr.Address, float64(r.RTT.Microseconds())/1000)
			} else {
				logProbe("  DC%d [IPv4] %-21s   FAIL", dc.DCID, r.Addr.Address)
			}
		}
	}

	// Print IPv6 results if any succeeded
	if successV6 > 0 {
		logProbe("---------------------------------------------------------------")
		for _, dc := range results {
			for _, r := range dc.Results {
				if !r.Addr.IsIPv6() {
					continue
				}
				if r.Success {
					logProbe("  DC%d [IPv6] %-40s %6.0f ms", dc.DCID, r.Addr.Address, float64(r.RTT.Microseconds())/1000)
				} else {
					logProbe("  DC%d [IPv6] %-40s   FAIL", dc.DCID, r.Addr.Address)
				}
			}
		}
	}

	logProbe("===============================================================")
}

// storeSortedAddresses stores the sorted addresses for later use.
func storeSortedAddresses(results []DCProbeResult) {
	probedMu.Lock()
	defer probedMu.Unlock()

	probedDCs = make(map[int][]Addr)
	for _, dc := range results {
		addrs := make([]Addr, 0, len(dc.Results))
		for _, r := range dc.Results {
			addrs = append(addrs, r.Addr)
		}
		probedDCs[dc.DCID] = addrs
	}
}

// GetProbedAddresses returns addresses sorted by RTT for a DC.
// Falls back to default addresses if probing hasn't been done.
func GetProbedAddresses(dc int) ([]Addr, bool) {
	probedMu.RLock()
	defer probedMu.RUnlock()

	if probedDCs == nil {
		return DCAddresses(dc)
	}

	// Check probed results first
	if addrs, ok := probedDCs[dc]; ok {
		return addrs, true
	}

	// Handle negative DC (media-only)
	absDC := dc
	if absDC < 0 {
		absDC = -absDC
	}
	if addrs, ok := probedDCs[absDC]; ok {
		return addrs, true
	}

	// Fallback to default
	return DCAddresses(dc)
}
