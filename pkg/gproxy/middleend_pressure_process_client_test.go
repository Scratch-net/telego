//go:build linux && me_pressure_investigation

package gproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
	"github.com/scratch-net/telego/pkg/webproxy"
	"golang.org/x/sys/unix"
)

type pressureDriverResult struct {
	Scenario                                                                                     string
	Clients, CommandBatch, PacketBytes, Waves, WarmedLinks, CompletedResponses, ExplicitClosures int
	PauseNanoseconds                                                                             int64
	Server                                                                                       pressureServerReady
	Snapshots                                                                                    []pressureNamedSnapshot
	Errors                                                                                       []string
	ElapsedNanoseconds                                                                           int64
	AllRetainedOrdinaryBytes                                                                     int
	FastLatency, PausedLatency                                                                   pressureLatency
	AllPaused                                                                                    bool
	RequestedReceiveBuffer, EffectiveReceiveBuffer                                               int
	RotationBacklogResponses                                                                     int
}

type pressureLatency struct {
	Count                                                          int
	P50Nanoseconds, P95Nanoseconds, P99Nanoseconds, MaxNanoseconds int64
	// At most 64 evenly spaced observations, in arrival-index order.
	SamplesNanoseconds []int64
}

func pressureLatencySummary(values []int64) pressureLatency {
	x := pressureLatency{Count: len(values)}
	if len(values) == 0 {
		return x
	}
	for i := range min(64, len(values)) {
		x.SamplesNanoseconds = append(x.SamplesNanoseconds, values[i*len(values)/min(64, len(values))])
	}
	slices.Sort(values)
	x.P50Nanoseconds, x.P95Nanoseconds, x.P99Nanoseconds, x.MaxNanoseconds = values[(len(values)-1)*50/100], values[(len(values)-1)*95/100], values[(len(values)-1)*99/100], values[len(values)-1]
	return x
}

type pressureNamedSnapshot struct {
	Name     string
	Snapshot pressureProcessSnapshot
}

type pressureWireClient struct {
	reader                        io.Reader
	write                         func([]byte) error
	close                         func() error
	requestCipher, responseCipher cipher.Stream
	decoder                       *middleend.ClientPacketDecoder
	encoder                       *middleend.ClientPacketEncoder
	tls                           bool
	readBuffer                    [64 << 10]byte
	pending                       []byte
	effectiveReceiveBuffer        int
}

var pressureClientSerial atomic.Uint64

func pressureNewWireClient(t *testing.T, dc int) (*pressureWireClient, []byte, error) {
	return pressureNewWireClientWithSecret(t, dc, pressureProcessKey)
}

func pressureNewWireClientWithSecret(t *testing.T, dc int, secret []byte) (*pressureWireClient, []byte, error) {
	frame := buildDeterministicO2ClientFrame(t, secret, dc, obfuscated2.ConnectionTypeIntermediate)
	// Replay identity lives outside the key/IV and encrypted DC/type fields.
	binary.LittleEndian.PutUint64(frame[:8], pressureClientSerial.Add(1)<<8|0xa5)
	_, _, responseCipher, requestCipher, err := obfuscated2.ParseClientFrameWithType(secret, frame)
	if err != nil {
		return nil, nil, err
	}
	decoder, err := middleend.NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, middleend.MaxClientPacketSize)
	if err != nil {
		return nil, nil, err
	}
	encoder, err := middleend.NewClientPacketEncoder(obfuscated2.ConnectionTypeIntermediate, middleend.MaxClientPacketSize)
	if err != nil {
		return nil, nil, err
	}
	return &pressureWireClient{requestCipher: requestCipher, responseCipher: responseCipher, decoder: decoder, encoder: encoder}, frame, nil
}

func pressureDialNative(t *testing.T, ctx context.Context, address string, dc int, tls bool) (*pressureWireClient, error) {
	return pressureDialNativeOptions(t, ctx, address, dc, tls, pressureProcessKey, "example.com", *pressureProcessReceiveBuffer)
}

func pressureDialNativeWithSecret(t *testing.T, ctx context.Context, address string, dc int, tls bool, secret []byte, hostname string) (*pressureWireClient, error) {
	return pressureDialNativeOptions(t, ctx, address, dc, tls, secret, hostname, 64<<10)
}

func pressureDialNativeOptions(t *testing.T, ctx context.Context, address string, dc int, tls bool, secret []byte, hostname string, receiveBuffer int) (*pressureWireClient, error) {
	client, frame, err := pressureNewWireClientWithSecret(t, dc, secret)
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tcp := conn.(*net.TCPConn)
	if err := tcp.SetReadBuffer(receiveBuffer); err != nil {
		_ = conn.Close()
		return nil, err
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		client.effectiveReceiveBuffer, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if socketErr != nil {
		_ = conn.Close()
		return nil, socketErr
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	client.reader, client.close = conn, conn.Close
	client.write = func(data []byte) error { return pressureWriteAll(conn, data) }
	client.tls = tls
	if tls {
		sessionID := make([]byte, 32)
		binary.LittleEndian.PutUint64(sessionID, pressureClientSerial.Load())
		hello := buildTLSRecord(faketls.RecordTypeHandshake, buildValidClientHello(secret, hostname, sessionID))
		if err := client.write(hello); err != nil {
			_ = conn.Close()
			return nil, err
		}
		for _, kind := range []byte{faketls.RecordTypeHandshake, faketls.RecordTypeChangeCipherSpec, faketls.RecordTypeApplicationData} {
			var header [5]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				_ = conn.Close()
				return nil, err
			}
			if header[0] != kind {
				_ = conn.Close()
				return nil, fmt.Errorf("TLS handshake record %x, want %x", header[0], kind)
			}
			if _, err := io.CopyN(io.Discard, conn, int64(binary.BigEndian.Uint16(header[3:]))); err != nil {
				_ = conn.Close()
				return nil, err
			}
		}
		frame = buildTLSRecord(faketls.RecordTypeApplicationData, frame)
	}
	if err := client.write(frame); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return client, nil
}

func pressureWriteAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		data = data[n:]
	}
	return nil
}

func (c *pressureWireClient) send(size, count int, sequence uint32) error {
	// The encrypted MTProto envelope minimum is 56 bytes. Only this compact
	// request enters the server; the separate peer generates response payloads.
	command := make([]byte, middleend.EncryptedMessageHeaderSize)
	copy(command, "MPR1")
	binary.LittleEndian.PutUint32(command[4:], uint32(size))
	binary.LittleEndian.PutUint32(command[8:], uint32(count))
	binary.LittleEndian.PutUint32(command[12:], sequence)
	return c.sendPacket(command)
}

func (c *pressureWireClient) sendPacket(packet []byte) error {
	wire, err := c.encoder.Encode(packet)
	if err != nil {
		return err
	}
	c.requestCipher.XORKeyStream(wire, wire)
	if c.tls {
		wire = buildTLSRecord(faketls.RecordTypeApplicationData, wire)
	}
	return c.write(wire)
}

func (c *pressureWireClient) receive(size int, sequence uint32) error {
	packet, err := c.readPacket()
	if err != nil {
		return err
	}
	if len(packet) != size {
		return fmt.Errorf("sequence %d: packet bytes=%d, want %d", sequence, len(packet), size)
	}
	if got := binary.LittleEndian.Uint32(packet); got != sequence {
		return fmt.Errorf("response sequence=%d, want %d", got, sequence)
	}
	for offset := 4; offset < len(packet); offset++ {
		if packet[offset] != byte(sequence+uint32(offset)) {
			return fmt.Errorf("sequence %d: changed byte at %d", sequence, offset)
		}
	}
	return nil
}

func (c *pressureWireClient) readPacket() ([]byte, error) {
	for {
		decoded, ok, err := c.decoder.Next()
		if err != nil {
			return nil, err
		}
		if ok {
			return decoded.Payload, nil
		}
		if len(c.pending) != 0 {
			n, err := c.decoder.Feed(c.pending)
			if err != nil {
				return nil, err
			}
			if n == 0 {
				return nil, io.ErrNoProgress
			}
			c.pending = c.pending[n:]
			continue
		}
		var n int
		if c.tls {
			var header [5]byte
			if _, err := io.ReadFull(c.reader, header[:]); err != nil {
				return nil, err
			}
			if header[0] != faketls.RecordTypeApplicationData {
				return nil, fmt.Errorf("response TLS record=%x", header[0])
			}
			n = int(binary.BigEndian.Uint16(header[3:]))
			if _, err := io.ReadFull(c.reader, c.readBuffer[:n]); err != nil {
				return nil, err
			}
		} else {
			n, err = c.reader.Read(c.readBuffer[:])
			if err != nil && n == 0 {
				return nil, err
			}
			if n == 0 {
				return nil, io.ErrNoProgress
			}
		}
		c.responseCipher.XORKeyStream(c.readBuffer[:n], c.readBuffer[:n])
		c.pending = c.readBuffer[:n]
	}
}

func runPressureProcessDriver(t *testing.T) (resultErr error) {
	started := time.Now()
	result := pressureDriverResult{Scenario: *pressureProcessScenario, Clients: *pressureProcessClients,
		CommandBatch: *pressureProcessBatch, PacketBytes: *pressureProcessSize, Waves: *pressureProcessWaves, PauseNanoseconds: int64(*pressureProcessPause),
		AllPaused: *pressureProcessAllPaused, RequestedReceiveBuffer: *pressureProcessReceiveBuffer}
	var fastLatencies, pausedLatencies []int64
	defer func() {
		result.ElapsedNanoseconds = int64(time.Since(started))
		result.FastLatency, result.PausedLatency = pressureLatencySummary(fastLatencies), pressureLatencySummary(pausedLatencies)
		if resultErr != nil {
			result.Errors = append(result.Errors, resultErr.Error())
		}
		resultErr = errors.Join(resultErr, pressureWriteJSON(*pressureProcessResult, result))
	}()
	if result.Clients < 1 || result.Clients > 1000 || result.CommandBatch < 0 || result.Waves < 1 || result.Waves > 10 ||
		result.PacketBytes < 4 || result.PacketBytes > middleend.MaxClientPacketSize || result.PacketBytes%4 != 0 ||
		result.RequestedReceiveBuffer < 4096 || result.RequestedReceiveBuffer > 65536 {
		return errors.New("invalid client/count/batch/packet parameters")
	}
	if err := pressureReadJSON(*pressureProcessReady, &result.Server); err != nil {
		return err
	}
	maximum, _ := middleend.ClientResponseOutputBound(middleend.LinkEventProxyAnswer, middleend.MaxClientPacketSize)
	outputBound, _ := middleend.ClientResponseOutputBound(middleend.LinkEventProxyAnswer, result.PacketBytes)
	result.AllRetainedOrdinaryBytes = result.Clients * (middleend.MinimumResponseOrdinaryBytes() - middleend.ResponseAllocationCharge(maximum+middleend.ResponseOutputMetadataBytes) + middleend.ResponseAllocationCharge(outputBound+middleend.ResponseOutputMetadataBytes))
	ctx, cancel := context.WithTimeout(t.Context(), *pressureProcessTimeout)
	defer cancel()
	snapshot := func(name string) (pressureProcessSnapshot, error) {
		var x pressureProcessSnapshot
		err := pressureControl(ctx, result.Server, "GET", "/snapshot", &x)
		if err == nil {
			result.Snapshots = append(result.Snapshots, pressureNamedSnapshot{Name: name, Snapshot: x})
			if *pressureProcessProgress != "" {
				err = pressureWriteJSON(*pressureProcessProgress, pressureNamedSnapshot{Name: name, Snapshot: x})
			}
		}
		return x, err
	}
	if _, err := snapshot("startup"); err != nil {
		return err
	}
	if err := pressureWarmLinks(t, ctx, result.Server); err != nil {
		return fmt.Errorf("warm physical links: %w", err)
	}
	result.WarmedLinks = result.Server.LinksPerGeneration
	if _, err := snapshot("warmed"); err != nil {
		return err
	}
	var clients []*pressureWireClient
	var sessions []*pressureWEBSession
	defer func() {
		for _, client := range clients {
			_ = client.close()
		}
		for _, session := range sessions {
			session.stop()
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		var drained pressureProcessSnapshot
		if err := pressureAwait(cleanupCtx, func() (bool, error) {
			if err := pressureControl(cleanupCtx, result.Server, "GET", "/snapshot", &drained); err != nil {
				return false, err
			}
			return drained.Pool.UsedBytes == 0 && drained.Frontend.MiddleEndBindingsActive == 0, nil
		}); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("driver cleanup: %w (pool=%d bindings=%d)", err, drained.Pool.UsedBytes, drained.Frontend.MiddleEndBindingsActive))
		}
		result.Snapshots = append(result.Snapshots, pressureNamedSnapshot{Name: "closed", Snapshot: drained})
		if *pressureProcessProgress != "" {
			resultErr = errors.Join(resultErr, pressureWriteJSON(*pressureProcessProgress, result.Snapshots[len(result.Snapshots)-1]))
		}
	}()
	switch result.Scenario {
	case "native", "rotation", "exhaustion", "rotation_exhaustion":
		for i := range result.Clients {
			if (result.Scenario == "rotation" || result.Scenario == "rotation_exhaustion") && i == result.Clients/2 {
				if len(clients) < 2 {
					return errors.New("rotation requires at least four clients for old/new healthy neighbors")
				}
				// Retain more than the native writer can accept on an existing
				// old-generation binding. A snapshot barrier proves backlog
				// exists before replacement and still exists after publication.
				const backlogCount, backlogSequence = 8, uint32(800000)
				if err := clients[0].send(middleend.MaxClientPacketSize, backlogCount, backlogSequence); err != nil {
					return err
				}
				var before pressureProcessSnapshot
				if err := pressureAwait(ctx, func() (bool, error) {
					if err := pressureControl(ctx, result.Server, "GET", "/snapshot", &before); err != nil {
						return false, err
					}
					return before.QueuedBytes >= middleend.MaxClientPacketSize && before.Frontend.OutputBytes > 0, nil
				}); err != nil {
					return fmt.Errorf("rotation backlog barrier: %w", err)
				}
				if _, err := snapshot("rotation_backlog_before"); err != nil {
					return err
				}
				if err := pressureControl(ctx, result.Server, "POST", "/rotate", nil); err != nil {
					return err
				}
				after, err := snapshot("rotation_backlog_after")
				if err != nil {
					return err
				}
				if after.RetiringSlots != result.Server.LinksPerGeneration || after.QueuedBytes < middleend.MaxClientPacketSize || after.Frontend.OutputBytes == 0 {
					return errors.New("rotation did not overlap retained old-generation response backlog")
				}
				if pressureEvictions(after) != pressureEvictions(before) || after.SlotFailures != before.SlotFailures {
					return errors.New("rotation lost an old-generation binding or link")
				}
				if err := pressureWarmLinks(t, ctx, result.Server); err != nil {
					return err
				}
				if result.Scenario == "rotation" {
					for j := range backlogCount {
						if err := clients[0].receive(middleend.MaxClientPacketSize, backlogSequence+uint32(j)); err != nil {
							return fmt.Errorf("old generation backlog recovery: %w", err)
						}
						result.RotationBacklogResponses++
					}
				}
				result.WarmedLinks += result.Server.LinksPerGeneration
				if _, err := snapshot("rotated"); err != nil {
					return err
				}
			}
			client, err := pressureDialNative(t, ctx, result.Server.NativeAddress, 2, i%2 != 0)
			if err != nil {
				return fmt.Errorf("connect client %d: %w", i, err)
			}
			clients = append(clients, client)
			result.EffectiveReceiveBuffer = client.effectiveReceiveBuffer
			// Verify admission before rotation; an O2 handshake alone does not
			// commit the ME route until the first complete client request.
			if err := client.send(64, 1, uint32(i+10000)); err != nil {
				return err
			}
			if err := client.receive(64, uint32(i+10000)); err != nil {
				return fmt.Errorf("admit client %d: %w", i, err)
			}
		}
	case "http", "ws":
		for i := 0; i < result.Clients; {
			session, err := pressureNewWEBSession(ctx, result.Server, result.Scenario == "ws")
			if err != nil {
				return err
			}
			sessions = append(sessions, session)
			for range min(125, result.Clients-i) {
				client, err := session.openClient(t, uint32(i%125+1))
				if err != nil {
					return err
				}
				clients = append(clients, client)
				i++
			}
		}
	default:
		return fmt.Errorf("unknown scenario %q", result.Scenario)
	}
	connected, err := snapshot("connected")
	if err != nil {
		return err
	}
	if result.Scenario == "exhaustion" || result.Scenario == "rotation_exhaustion" {
		if len(clients) < 2 {
			return errors.New("exhaustion requires an aggressor and healthy neighbor")
		}
		count := min(4096, result.Server.ResponseBudgetBytes/middleend.MaxClientPacketSize*3+8)
		sequence, aggressor := uint32(500000), 0
		if result.Scenario == "rotation_exhaustion" {
			aggressor = result.Clients / 2
			if connected.ActiveSlots != result.Server.LinksPerGeneration || connected.RetiringSlots != result.Server.LinksPerGeneration || connected.QueuedBytes < middleend.MaxClientPacketSize {
				return errors.New("combined exhaustion lacks overlapping active/retiring generations with retained old backlog")
			}
		}
		// The old stream is already response-blocked, so frontend admission
		// intentionally pauses its further requests. A new active-generation
		// stream supplies this independent burst while old output stays held.
		if err := clients[aggressor].send(middleend.MaxClientPacketSize, count, sequence); err != nil {
			return err
		}
		var exhausted pressureProcessSnapshot
		if err := pressureAwait(ctx, func() (bool, error) {
			if err := pressureControl(ctx, result.Server, "GET", "/snapshot", &exhausted); err != nil {
				return false, err
			}
			return pressureEvictions(exhausted) > pressureEvictions(connected), nil
		}); err != nil {
			return fmt.Errorf("actual exhaustion barrier: %w", err)
		}
		peak, err := snapshot("exhausted")
		if err != nil {
			return err
		}
		for i := range count {
			err := clients[aggressor].receive(middleend.MaxClientPacketSize, sequence+uint32(i))
			if err == nil {
				result.CompletedResponses++
				continue
			}
			if !pressureExplicitClose(err) {
				return fmt.Errorf("exhaustion stream failed without explicit closure: %w", err)
			}
			result.ExplicitClosures++
			break
		}
		if result.ExplicitClosures != 1 || pressureEvictions(peak) <= pressureEvictions(connected) {
			return fmt.Errorf("exhaustion did not prove pressure closure: closures=%d eviction delta=%d", result.ExplicitClosures, pressureEvictions(peak)-pressureEvictions(connected))
		}
		if peak.Pool.HighWaterBytes > peak.Pool.LimitBytes {
			return errors.New("pool high water exceeded limit")
		}
		if peak.Pool.HighWaterBytes < peak.Pool.OrdinaryLimitBytes-2*middleend.MaxClientPacketSize {
			return errors.New("pressure closure lacked near-capacity pool accounting evidence")
		}
		if result.Scenario == "rotation_exhaustion" && (peak.ActiveSlots != result.Server.LinksPerGeneration || peak.RetiringSlots != result.Server.LinksPerGeneration) {
			return errors.New("generation overlap disappeared before global exhaustion")
		}
		oldClosed := false
		if result.Scenario == "rotation_exhaustion" {
			for i := range 8 {
				if err := clients[0].receive(middleend.MaxClientPacketSize, 800000+uint32(i)); err != nil {
					if !pressureExplicitClose(err) {
						return fmt.Errorf("old backlog recovery after global pressure: %w", err)
					}
					oldClosed = true
					result.ExplicitClosures++
					break
				}
				result.RotationBacklogResponses++
			}
		}
		for i, client := range clients {
			if i == aggressor || i == 0 && oldClosed {
				continue
			}
			if err := client.send(64, 1, uint32(i+900000)); err != nil {
				return fmt.Errorf("healthy neighbor send: %w", err)
			}
			if err := client.receive(64, uint32(i+900000)); err != nil {
				return fmt.Errorf("healthy neighbor response: %w", err)
			}
			result.CompletedResponses++
		}
		final, err := snapshot("recovered")
		if err != nil {
			return err
		}
		if final.SlotFailures != connected.SlotFailures {
			return errors.New("pressure closed a physical ME link")
		}
		if pressureEvictions(final)-pressureEvictions(connected) != uint64(result.ExplicitClosures) {
			return errors.New("explicit closures do not match pressure-selected victims")
		}
		return nil
	}
	for wave := range result.Waves {
		var completed atomic.Int64
		var closed atomic.Int64
		sentAt := make([]atomic.Int64, len(clients))
		latencies := make([]int64, len(clients))
		waveErrors := make(chan error, len(clients)*3)
		resume := make(chan struct{})
		var readers sync.WaitGroup
		for i, client := range clients {
			readers.Go(func() {
				if result.AllPaused || i%2 == 0 || len(sessions) != 0 {
					select {
					case <-resume:
					case <-ctx.Done():
						waveErrors <- ctx.Err()
						return
					}
				}
				if err := client.receive(result.PacketBytes, uint32(wave*10000+i+1)); err != nil {
					if pressureExplicitClose(err) {
						closed.Add(1)
					}
					waveErrors <- fmt.Errorf("wave %d client %d: %w", wave, i, err)
					return
				}
				completed.Add(1)
				latencies[i] = time.Now().UnixNano() - sentAt[i].Load()
			})
		}
		batch := result.CommandBatch
		if batch == 0 {
			batch = len(clients)
		}
		for start := 0; start < len(clients); start += batch {
			gate := make(chan struct{})
			var writers sync.WaitGroup
			for i := start; i < min(start+batch, len(clients)); i++ {
				writers.Go(func() {
					<-gate
					sentAt[i].Store(time.Now().UnixNano())
					if err := clients[i].send(result.PacketBytes, 1, uint32(wave*10000+i+1)); err != nil {
						waveErrors <- fmt.Errorf("wave %d command %d: %w", wave, i, err)
					}
				})
			}
			close(gate)
			writers.Wait()
			if result.CommandBatch != 0 {
				if err := pressurePause(ctx, 10*time.Millisecond); err != nil {
					close(resume)
					return err
				}
			}
		}
		if err := pressurePause(ctx, time.Duration(result.PauseNanoseconds)); err != nil {
			close(resume)
			return err
		}
		paused, err := snapshot(fmt.Sprintf("wave_%d_paused", wave))
		if err != nil {
			close(resume)
			return err
		}
		if result.AllPaused && len(sessions) == 0 && result.PacketBytes > result.EffectiveReceiveBuffer && paused.QueuedBytes == 0 && paused.Frontend.OutputBytes == 0 {
			close(resume)
			return errors.New("all-paused profile retained no server queue/output at pause boundary")
		}
		if len(sessions) != 0 && paused.HTTP.PendingBytes == 0 && paused.WS.PendingBytes == 0 && paused.QueuedBytes == 0 && paused.Frontend.OutputBytes == 0 {
			close(resume)
			return errors.New("paused WEB profile retained no carrier/queue/output storage")
		}
		carrierDone := make([]<-chan error, 0, len(sessions))
		for _, session := range sessions {
			carrierDone = append(carrierDone, session.startWave(result.PacketBytes))
		}
		close(resume)
		readers.Wait()
		for _, done := range carrierDone {
			if err := <-done; err != nil {
				waveErrors <- err
			}
		}
		close(waveErrors)
		result.CompletedResponses += int(completed.Load())
		result.ExplicitClosures += int(closed.Load())
		for i, latency := range latencies {
			if latency == 0 {
				continue
			}
			if result.AllPaused || i%2 == 0 || len(sessions) != 0 {
				pausedLatencies = append(pausedLatencies, latency)
			} else {
				fastLatencies = append(fastLatencies, latency)
			}
		}
		for err := range waveErrors {
			result.Errors = append(result.Errors, err.Error())
		}
		if len(result.Errors) != 0 {
			return errors.New("finite wave lost a response; see result Errors")
		}
		var drained pressureProcessSnapshot
		if err := pressureAwait(ctx, func() (bool, error) {
			if err := pressureControl(ctx, result.Server, "GET", "/snapshot", &drained); err != nil {
				return false, err
			}
			return drained.QueuedBytes == 0 && drained.Frontend.OutputBytes == 0 && drained.Pool.StageBytes[middleend.ResponseMemoryInflight] == 0, nil
		}); err != nil {
			return fmt.Errorf("wave %d drain: %w", wave, err)
		}
		result.Snapshots = append(result.Snapshots, pressureNamedSnapshot{Name: fmt.Sprintf("wave_%d_drained", wave), Snapshot: drained})
		if *pressureProcessProgress != "" {
			if err := pressureWriteJSON(*pressureProcessProgress, result.Snapshots[len(result.Snapshots)-1]); err != nil {
				return err
			}
		}
		if pressureEvictions(drained) != pressureEvictions(connected) || drained.SlotFailures != connected.SlotFailures || drained.Frontend.ResponseStallClosures != connected.Frontend.ResponseStallClosures {
			return errors.New("finite profile evicted a binding or closed a physical link")
		}
	}
	return nil
}

func pressureExplicitClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}

func pressureEvictions(x pressureProcessSnapshot) uint64 {
	var total uint64
	for _, value := range x.Evictions {
		total += value
	}
	return total
}

func pressurePause(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func pressureAwait(ctx context.Context, condition func() (bool, error)) error {
	for {
		ok, err := condition()
		if err != nil || ok {
			return err
		}
		if err := pressurePause(ctx, 10*time.Millisecond); err != nil {
			return err
		}
	}
}

func pressureWarmLinks(t *testing.T, ctx context.Context, ready pressureServerReady) error {
	var baseline pressureProcessSnapshot
	if err := pressureControl(ctx, ready, "GET", "/snapshot", &baseline); err != nil {
		return err
	}
	clients := make([]*pressureWireClient, 0, ready.LinksPerGeneration)
	defer func() {
		for _, client := range clients {
			_ = client.close()
		}
	}()
	// Keep all warmup bindings resident until every slot is exercised; least
	// resident routing then visits each of the four slots in every signed DC.
	for i := range ready.LinksPerGeneration {
		dc := 2
		if ready.LinksPerGeneration == 48 {
			dc = i/4 + 1
			if dc > 6 {
				dc = -(dc - 6)
			}
		}
		client, err := pressureDialNativeWithSecret(t, ctx, ready.NativeAddress, dc, false, pressureProcessKey, "example.com")
		if err != nil {
			return err
		}
		clients = append(clients, client)
		sequence := uint32(1000000 + i)
		if err := client.send(middleend.MaxClientPacketSize, 1, sequence); err != nil {
			return err
		}
		if err := client.receive(middleend.MaxClientPacketSize, sequence); err != nil {
			return fmt.Errorf("slot %d DC%d: %w", i, dc, err)
		}
	}
	var warmed pressureProcessSnapshot
	if err := pressureControl(ctx, ready, "GET", "/snapshot", &warmed); err != nil {
		return err
	}
	if warmed.ActiveWarmedSlots != ready.LinksPerGeneration {
		return fmt.Errorf("maximum-response warmup reached %d/%d active physical slots", warmed.ActiveWarmedSlots, ready.LinksPerGeneration)
	}
	for _, client := range clients {
		_ = client.close()
	}
	clients = nil
	return pressureAwait(ctx, func() (bool, error) {
		if err := pressureControl(ctx, ready, "GET", "/snapshot", &warmed); err != nil {
			return false, err
		}
		return warmed.ResidentBindings == baseline.ResidentBindings, nil
	})
}

type pressureWEBSession struct {
	ctx                    context.Context
	cancel                 context.CancelFunc
	address, token, cursor string
	http                   *http.Client
	websocket              net.Conn
	wsReader               io.Reader
	writeMu                sync.Mutex
	sequence               uint64
	streams                map[uint32]*pressureWEBReader
	done                   chan struct{}
}

type pressureWEBReader struct {
	ctx    context.Context
	chunks chan []byte
	buffer []byte
	err    error
	closed bool
}

func (r *pressureWEBReader) Read(dst []byte) (int, error) {
	for len(r.buffer) == 0 {
		select {
		case chunk, ok := <-r.chunks:
			if !ok {
				return 0, r.err
			}
			r.buffer = chunk
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		}
	}
	n := copy(dst, r.buffer)
	r.buffer = r.buffer[n:]
	return n, nil
}

func pressureNewWEBSession(ctx context.Context, ready pressureServerReady, websocket bool) (*pressureWEBSession, error) {
	ctx, cancel := context.WithCancel(ctx)
	s := &pressureWEBSession{ctx: ctx, cancel: cancel, address: ready.HTTPAddress, cursor: "0", http: &http.Client{}, streams: make(map[uint32]*pressureWEBReader)}
	carrier := "http"
	if websocket {
		carrier, s.address = "ws", ready.WSAddress
	}
	var bootstrap struct{ Token string }
	if err := pressureControl(ctx, ready, "POST", "/bootstrap?carrier="+carrier, &bootstrap); err != nil {
		cancel()
		return nil, err
	}
	hello, err := webproxy.EncodeFrame(webproxy.Frame{Type: webproxy.FrameHello, Payload: []byte{1}})
	if err != nil {
		cancel()
		return nil, err
	}
	response, _, err := s.request("/api/v1/session", hello, map[string]string{"Authorization": "Bearer " + bootstrap.Token})
	if err != nil {
		cancel()
		return nil, err
	}
	if response.StatusCode != 200 {
		cancel()
		return nil, fmt.Errorf("WEB create status %d", response.StatusCode)
	}
	s.token = response.Header.Get("X-Session-Token")
	if websocket {
		conn, reader, _, err := (ws.Dialer{Host: "proxy.example.com", Protocols: []string{"tproxy-v1." + s.token}}).Dial(ctx, "ws://"+s.address+"/api/v1/ws")
		if err != nil {
			cancel()
			return nil, err
		}
		s.websocket, s.wsReader = conn, conn
		if reader != nil {
			s.wsReader = reader
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetReadBuffer(64 << 10)
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
	}
	return s, nil
}

func (s *pressureWEBSession) request(path string, body []byte, headers map[string]string) (*http.Response, []byte, error) {
	request, err := http.NewRequestWithContext(s.ctx, "POST", "http://"+s.address+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	request.Host = "proxy.example.com"
	if path != "/api/v1/down" {
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	request.Header.Set("Authorization", "Bearer "+s.token)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := s.http.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if len(data) > 2<<20 {
		return nil, nil, errors.New("WEB response exceeded default carrier batch")
	}
	return response, data, err
}

func (s *pressureWEBSession) upload(frames []webproxy.Frame) error {
	var data []byte
	for _, frame := range frames {
		var err error
		data, err = webproxy.AppendFrame(data, frame)
		if err != nil {
			return err
		}
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.websocket != nil {
		return wsutil.WriteClientBinary(s.websocket, data)
	}
	s.sequence++
	response, _, err := s.request("/api/v1/up", data, map[string]string{"X-Up-Seq": strconv.FormatUint(s.sequence, 10)})
	if err != nil {
		return err
	}
	if response.StatusCode != 204 {
		return fmt.Errorf("WEB upload status %d", response.StatusCode)
	}
	return nil
}

func (s *pressureWEBSession) openClient(t *testing.T, id uint32) (*pressureWireClient, error) {
	client, frame, err := pressureNewWireClient(t, 2)
	if err != nil {
		return nil, err
	}
	reader := &pressureWEBReader{ctx: s.ctx, chunks: make(chan []byte, 8)}
	s.streams[id] = reader
	client.reader = reader
	client.write = func(data []byte) error {
		return s.upload([]webproxy.Frame{{Type: webproxy.FrameData, StreamID: id, Payload: data}})
	}
	client.close = func() error { return s.upload([]webproxy.Frame{{Type: webproxy.FrameClose, StreamID: id}}) }
	if err := s.upload([]webproxy.Frame{{Type: webproxy.FrameOpen, StreamID: id}, {Type: webproxy.FrameData, StreamID: id, Payload: frame}}); err != nil {
		return nil, err
	}
	return client, nil
}

// A reader exists only while draining one finite wave. Joining it before the
// next command ensures every paused wave pauses the actual carrier. No timeout
// interrupts a partially decoded WebSocket frame.
func (s *pressureWEBSession) startWave(packetBytes int) <-chan error {
	result := make(chan error, 1)
	done := make(chan struct{})
	s.done = done
	go func() {
		defer close(done)
		err := s.readWave((packetBytes + 4) * len(s.streams))
		if err != nil {
			s.failReaders(err)
		}
		result <- err
	}()
	return result
}

func (s *pressureWEBSession) failReaders(err error) {
	for _, reader := range s.streams {
		if !reader.closed {
			reader.err, reader.closed = err, true
			close(reader.chunks)
		}
	}
}

func (s *pressureWEBSession) readBatch() ([]webproxy.Frame, error) {
	var data []byte
	if s.websocket != nil {
		var err error
		data, _, err = wsutil.ReadServerData(struct {
			io.Reader
			io.Writer
		}{s.wsReader, &pressureWSWriter{s: s}})
		if err != nil {
			return nil, fmt.Errorf("WEB websocket read: %w", err)
		}
	} else {
		response, body, err := s.request("/api/v1/down", nil, map[string]string{"X-Down-Cursor": s.cursor})
		if err != nil {
			return nil, fmt.Errorf("WEB download: %w", err)
		}
		if response.StatusCode != 200 && response.StatusCode != 204 {
			return nil, fmt.Errorf("WEB download status %d: %s", response.StatusCode, body)
		}
		s.cursor, data = response.Header.Get("X-Down-Cursor"), body
	}
	if len(data) == 0 {
		return nil, nil
	}
	frames, err := webproxy.ParseBatch(data)
	if err != nil {
		return nil, fmt.Errorf("WEB parse batch: %w", err)
	}
	return frames, nil
}

func (s *pressureWEBSession) consumeFrames(frames []webproxy.Frame) (int, error) {
	count := 0
	for _, frame := range frames {
		if frame.Type == webproxy.FramePing {
			if err := s.upload([]webproxy.Frame{{Type: webproxy.FramePong, Payload: frame.Payload}}); err != nil {
				return count, err
			}
			continue
		}
		reader := s.streams[frame.StreamID]
		if reader == nil {
			continue
		}
		switch frame.Type {
		case webproxy.FrameData:
			if reader.closed {
				return count, errors.New("WEB data after stream close")
			}
			select {
			case reader.chunks <- frame.Payload:
			case <-s.ctx.Done():
				return count, s.ctx.Err()
			}
			count += len(frame.Payload)
		case webproxy.FrameClose:
			return count, fmt.Errorf("WEB stream %d: %w", frame.StreamID, io.EOF)
		}
	}
	return count, nil
}

func (s *pressureWEBSession) readWave(expected int) error {
	for received := 0; received < expected; {
		frames, err := s.readBatch()
		if err != nil {
			return err
		}
		n, err := s.consumeFrames(frames)
		if err != nil {
			return err
		}
		received += n
		if received > expected {
			return fmt.Errorf("WEB wave bytes=%d, want %d", received, expected)
		}
	}
	// Replenish stream credit only after the complete wave is consumed.
	// This keeps maximum-packet scenarios valid beyond the initial4MiB grant.
	credit, err := webproxy.WindowPayload(uint32(expected / len(s.streams)))
	if err != nil {
		return err
	}
	frames := make([]webproxy.Frame, 0, len(s.streams))
	for id := range s.streams {
		frames = append(frames, webproxy.Frame{Type: webproxy.FrameWindow, StreamID: id, Payload: credit})
	}
	if err := s.upload(frames); err != nil {
		return err
	}
	if s.websocket == nil {
		// A final down request acknowledges the last batch. No next-wave
		// command exists yet; this bounded long poll must contain no data.
		frames, err := s.readBatch()
		if err != nil {
			return err
		}
		n, err := s.consumeFrames(frames)
		if err != nil {
			return err
		}
		if n != 0 {
			return fmt.Errorf("WEB extra bytes after complete wave: %d", n)
		}
	}
	return nil
}

type pressureWSWriter struct{ s *pressureWEBSession }

func (w *pressureWSWriter) Write(data []byte) (int, error) {
	w.s.writeMu.Lock()
	defer w.s.writeMu.Unlock()
	return w.s.websocket.Write(data)
}

func (s *pressureWEBSession) stop() {
	s.cancel()
	if s.websocket != nil {
		_ = s.websocket.Close()
	}
	if s.done != nil {
		<-s.done
	}
	s.failReaders(context.Canceled)
	s.http.CloseIdleConnections()
}
