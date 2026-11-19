package dc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
	"golang.org/x/net/proxy"
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
	probeSocks5 string // SOCKS5 proxy address for probing
	probeDialer proxy.Dialer
)

// SetProbeLogger sets the logger for probe output.
func SetProbeLogger(logger func(format string, args ...any)) {
	probeLogger = logger
}

// SetProbeSocks5 sets the SOCKS5 proxy for DC probing.
func SetProbeSocks5(addr string) error {
	if addr == "" {
		probeSocks5 = ""
		probeDialer = nil
		return nil
	}
	dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		return err
	}
	probeSocks5 = addr
	probeDialer = dialer
	return nil
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

// Check probes every known DC address with the MTProto check and returns the
// results without changing the stored address order. telego doctor uses it.
func Check() []DCProbeResult {
	return probeAllDCs()
}

// probeAllDCs probes all known DC addresses concurrently.
func probeAllDCs() []DCProbeResult {
	// Collect all DCs to probe
	allDCs := make(map[int][]Addr)
	maps.Copy(allDCs, DefaultDCs)
	maps.Copy(allDCs, CDNDCs)

	var wg sync.WaitGroup
	results := make([]DCProbeResult, 0, len(allDCs))
	var mu sync.Mutex

	for dcID, addrs := range allDCs {
		wg.Go(func() {
			dcResult := probeDC(dcID, addrs)
			mu.Lock()
			results = append(results, dcResult)
			mu.Unlock()
		})
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
		wg.Go(func() {
			pr := probeAddr(dcID, addr)
			mu.Lock()
			result.Results = append(result.Results, pr)
			mu.Unlock()
		})
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
// When using SOCKS5, we measure actual round-trip by sending data and waiting
// for response, since TCP handshake alone is handled locally by the proxy.
func probeAddr(dcID int, addr Addr) ProbeResult {
	// Skip IPv6 probing via SOCKS5 - many proxies don't support it properly
	// and may return false positives (accept connection but can't route).
	if probeDialer != nil && addr.IsIPv6() {
		return ProbeResult{
			Addr:    addr,
			Success: false,
			Error:   "skipped (IPv6 via SOCKS5 unreliable)",
		}
	}

	var conn net.Conn
	var err error

	if probeDialer != nil {
		// Use SOCKS5 proxy for probing with timeout
		ctx, cancel := context.WithTimeout(context.Background(), ProbeTimeout)
		defer cancel()

		if ctxDialer, ok := probeDialer.(proxy.ContextDialer); ok {
			conn, err = ctxDialer.DialContext(ctx, addr.Network, addr.Address)
		} else {
			// Fallback without context (rare)
			conn, err = probeDialer.Dial(addr.Network, addr.Address)
		}
	} else {
		// Direct connection
		conn, err = net.DialTimeout(addr.Network, addr.Address, ProbeTimeout)
	}

	if err != nil {
		return ProbeResult{
			Addr:    addr,
			Success: false,
			Error:   err.Error(),
		}
	}
	defer conn.Close()
	rtt, err := probeConnection(conn, dcID, ProbeTimeout)
	if err != nil {
		return ProbeResult{Addr: addr, Error: err.Error()}
	}
	return ProbeResult{Addr: addr, RTT: rtt, Success: true}
}

// MTProto constants for the unauthenticated first handshake step
// (https://core.telegram.org/schema/mtproto):
//
//	req_pq_multi#be7e8ef1 nonce:int128 = ResPQ;
//	resPQ#05162463 nonce:int128 server_nonce:int128 pq:string
//	    server_public_key_fingerprints:Vector<long> = ResPQ;
const (
	ctorReqPQMulti uint32 = 0xbe7e8ef1
	ctorResPQ      uint32 = 0x05162463
	// An unencrypted message envelope is auth_key_id(8), message_id(8) and
	// message_data_length(4).
	probeEnvelopeSize = 20
	// The smallest resPQ holds the envelope, the constructor and the nonce.
	minResPQFrame = probeEnvelopeSize + 4 + 16
	// A real resPQ is about 84 bytes plus up to 15 bytes of padding.
	maxResPQFrame = 256
)

// errNotTelegram means the peer completed TCP but did not answer
// req_pq_multi with a resPQ that echoes the nonce.
var errNotTelegram = errors.New("peer did not answer with a matching resPQ")

// probeConnection proves that the peer is a Telegram DC and measures one
// MTProto round trip. It sends an obfuscated2 handshake for dc with
// padded-intermediate framing, then req_pq_multi in an unencrypted message.
// The peer must answer with resPQ and echo the random nonce, which a
// middlebox that only resets or closes connections cannot do.
// The same check is used by mtg (github.com/9seconds/mtg, mtglib/dcprobe).
func probeConnection(conn net.Conn, dc int, timeout time.Duration) (time.Duration, error) {
	frame, encryptor, decryptor, err := obfuscated2.GenerateServerFrameWithType(dc, obfuscated2.ConnectionTypePaddedIntermediate)
	if err != nil {
		return 0, fmt.Errorf("obfuscated2 frame: %w", err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, fmt.Errorf("nonce: %w", err)
	}
	const messageSize = probeEnvelopeSize + 4 + 16
	request := make([]byte, len(frame)+4+messageSize)
	copy(request, frame)
	body := request[len(frame):]
	binary.LittleEndian.PutUint32(body[0:4], messageSize)
	// auth_key_id stays zero for an unencrypted message.
	binary.LittleEndian.PutUint64(body[12:20], probeMessageID(time.Now()))
	binary.LittleEndian.PutUint32(body[20:24], 4+16)
	binary.LittleEndian.PutUint32(body[24:28], ctorReqPQMulti)
	copy(body[28:44], nonce[:])
	encryptor.XORKeyStream(body, body)

	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return 0, fmt.Errorf("set write deadline: %w", err)
	}
	rttStart := time.Now()
	if n, err := conn.Write(request); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	} else if n != len(request) {
		return 0, fmt.Errorf("write: %w", io.ErrShortWrite)
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return 0, fmt.Errorf("set read deadline: %w", err)
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, fmt.Errorf("read resPQ length: %w", err)
	}
	decryptor.XORKeyStream(header[:], header[:])
	size := binary.LittleEndian.Uint32(header[:])
	if size < minResPQFrame || size > maxResPQFrame {
		return 0, fmt.Errorf("%w: frame length %d", errNotTelegram, size)
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(conn, response); err != nil {
		return 0, fmt.Errorf("read resPQ: %w", err)
	}
	rtt := time.Since(rttStart)
	decryptor.XORKeyStream(response, response)
	payload := response[probeEnvelopeSize:]
	if ctor := binary.LittleEndian.Uint32(payload[0:4]); ctor != ctorResPQ {
		return 0, fmt.Errorf("%w: constructor 0x%08x", errNotTelegram, ctor)
	}
	if !bytes.Equal(payload[4:20], nonce[:]) {
		return 0, fmt.Errorf("%w: nonce mismatch", errNotTelegram)
	}
	return rtt, nil
}

// probeMessageID returns a client message_id for now: Unix seconds in the
// high 32 bits, the fraction of a second in the low bits, and the two
// lowest bits cleared.
func probeMessageID(now time.Time) uint64 {
	fraction := uint64(now.Nanosecond()) << 32 / uint64(time.Second)
	return (uint64(now.Unix())<<32 | fraction) &^ 3
}

// printProbeResults prints probe results in telemt style.
func printProbeResults(results []DCProbeResult) {
	if probeSocks5 != "" {
		logProbe("============== Telegram DC Connectivity (via SOCKS5) ============")
	} else {
		logProbe("================== Telegram DC Connectivity ==================")
	}

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
