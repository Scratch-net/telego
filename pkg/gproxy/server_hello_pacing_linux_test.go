//go:build linux

package gproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
	"golang.org/x/sys/unix"
)

type helloPacingTestHandler struct {
	*ProxyHandler
	response []byte
	opened   chan gnet.Conn
	closed   chan struct{}
}

func (h *helloPacingTestHandler) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	ctx := c.Context().(*ConnContext)
	h.activeConns.Add(1)
	action := h.startServerHelloPacing(c, ctx, h.response)
	h.opened <- c
	return nil, action
}

func (h *helloPacingTestHandler) OnClose(c gnet.Conn, err error) gnet.Action {
	action := h.ProxyHandler.OnClose(c, err)
	close(h.closed)
	return action
}

func pacingTCPInfo(t *testing.T, conn *net.TCPConn) *unix.TCPInfo {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var info *unix.TCPInfo
	if err := raw.Control(func(fd uintptr) { info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) }); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func pacingEnrolledInfo(t *testing.T, conn gnet.Conn) *unix.TCPInfo {
	t.Helper()
	type result struct {
		info *unix.TCPInfo
		err  error
	}
	done := make(chan result, 1)
	if err := conn.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		info, err := unix.GetsockoptTCPInfo(conn.Fd(), unix.IPPROTO_TCP, unix.TCP_INFO)
		done <- result{info, err}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.info
	case <-time.After(time.Second):
		t.Fatal("socket owner did not report TCP_INFO")
		return nil
	}
}

func startPacingTest(t *testing.T, response []byte, smallWindow ...bool) (*helloPacingTestHandler, *net.TCPConn, *net.TCPConn, *ConnContext, chan gnet.Conn) {
	t.Helper()
	peer, socket := directTCPPair(t)
	if len(smallWindow) > 0 && smallWindow[0] {
		_ = peer.Close()
		_ = socket.Close()
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			err := raw.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1024) })
			return errors.Join(err, socketErr)
		}}
		client, err := dialer.DialContext(t.Context(), "tcp4", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		peer = client.(*net.TCPConn)
		socket, err = listener.AcceptTCP()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close(); _ = socket.Close() })
	}
	h := &helloPacingTestHandler{ProxyHandler: NewProxyHandler(&Config{ServerHelloSegmentSize: 92}, &testLogger{}), response: response, opened: make(chan gnet.Conn, 1), closed: make(chan struct{})}
	engine, err := gnet.NewClient(h)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	ctx := NewConnContext()
	ready := make(chan gnet.Conn, 1)
	// Let the test install an isolated packet capture before enrollment.
	go func() {
		select {
		case <-t.Context().Done():
		case <-ready:
			if _, err := engine.EnrollContext(socket, ctx); err != nil {
				return
			}
		}
	}()
	return h, peer, socket, ctx, ready
}

func TestServerHelloPacingSegmentsAndBulk(t *testing.T) {
	response := bytes.Repeat([]byte{0x5a}, 4096)
	h, peer, socket, ctx, start := startPacingTest(t, response)
	stopCapture := capturePacedSocket(t, socket, peer)
	before := pacingTCPInfo(t, socket)
	start <- nil
	conn := <-h.opened
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(response))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Fatal("paced response changed")
	}
	deadline := time.Now().Add(time.Second)
	for ctx.State() != StateReadO2Frame {
		if time.Now().After(deadline) {
			t.Fatal("paced response did not resume O2")
		}
		time.Sleep(time.Millisecond)
	}
	after := pacingEnrolledInfo(t, conn)
	segments := after.Data_segs_out - before.Data_segs_out
	if segments < uint32((len(response)+91)/92) {
		t.Fatalf("only %d data segments for %d bytes", segments, len(response))
	}
	bulk := bytes.Repeat([]byte{0x7b}, 64*1024)
	if err := conn.AsyncWrite(bulk, nil); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(bulk))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bulk) {
		t.Fatal("bulk response changed")
	}
	last := pacingEnrolledInfo(t, conn)
	bulkSegments := last.Data_segs_out - after.Data_segs_out
	if last.Snd_mss < 1000 || last.Snd_mss < before.Snd_mss || bulkSegments >= uint32(len(bulk)/500) {
		t.Fatalf("bulk MSS or segmentation regressed: before=%d after=%d segments=%d", before.Snd_mss, last.Snd_mss, bulkSegments)
	}
	t.Logf("paced %d bytes in %d data segments; bulk %d bytes in %d data segments; MSS %d -> %d", len(response), segments, len(bulk), bulkSegments, before.Snd_mss, last.Snd_mss)
	stopCapture(len(response), 92)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.closed:
	case <-time.After(time.Second):
		t.Fatal("paced connection did not close")
	}
}

func TestServerHelloPacingCloseReleasesResponse(t *testing.T) {
	h, _, _, ctx, start := startPacingTest(t, make([]byte, maxPacedServerHello))
	start <- nil
	conn := <-h.opened
	pacer := ctx.helloPacer.Load()
	if pacer == nil {
		t.Fatal("no paced response")
	}
	_ = conn.Close()
	select {
	case <-h.closed:
	case <-time.After(time.Second):
		t.Fatal("close did not complete")
	}
	pacer.mu.Lock()
	retained, closed := len(pacer.data), pacer.closed
	pacer.mu.Unlock()
	if retained != 0 || !closed || ctx.helloPacer.Load() != nil {
		t.Fatal("close retained paced response")
	}
}

func TestServerHelloPacingResumesCoalescedO2(t *testing.T) {
	key := []byte("0123456789abcdef")
	h := NewProxyHandler(&Config{
		Secrets:           []Secret{{Name: "test", Key: key, Host: "example.com"}},
		TimeSkewTolerance: time.Minute, ServerHelloSegmentSize: 92,
	}, &testLogger{})
	captured := captureOutboundHandshake(h)
	peer, socket := directTCPPair(t)
	engine, err := gnet.NewClient(h)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	hello := fragmentedHello(buildValidClientHello(key, "example.com", bytes.Repeat([]byte{0x73}, 32)), 1, 3, 40)
	o2 := buildTLSRecord(faketls.RecordTypeApplicationData, buildDeterministicO2ClientFrame(t, key, -3, obfuscated2.ConnectionTypePaddedIntermediate))
	if _, err = peer.Write(append(hello, o2...)); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.EnrollContext(socket, nil); err != nil {
		t.Fatal(err)
	}
	got := waitForOutboundHandshake(t, captured)
	if got.err != nil || got.dcID != -3 || got.connectionType != obfuscated2.ConnectionTypePaddedIntermediate {
		t.Fatalf("paced O2 route changed: %+v", got)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	response, err := io.ReadAll(peer)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) < 5 || response[0] != faketls.RecordTypeHandshake {
		t.Fatal("paced native handshake omitted its ServerHello")
	}
}

func TestServerHelloPacingWindowAndDeadline(t *testing.T) {
	h, peer, _, ctx, start := startPacingTest(t, make([]byte, maxPacedServerHello), true)
	start <- nil
	conn := <-h.opened
	deadline := time.Now().Add(time.Second)
	for {
		info := pacingEnrolledInfo(t, conn)
		if info.Notsent_bytes != 0 {
			if info.Notsent_bytes > 92 {
				t.Fatalf("queued %d bytes beyond one paced chunk", info.Notsent_bytes)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("small receive window did not stall the paced response")
		}
		time.Sleep(time.Millisecond)
	}
	if err := conn.EventLoop().Execute(t.Context(), gnet.RunnableFunc(func(context.Context) error {
		pacer := ctx.helloPacer.Load()
		if pacer != nil {
			pacer.mu.Lock()
			pacer.deadline = time.Now().Add(-time.Second)
			pacer.mu.Unlock()
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.closed:
	case <-time.After(time.Second):
		t.Fatal("paced deadline did not close the connection")
	}
	if ctx.helloPacer.Load() != nil {
		t.Fatal("deadline retained paced state")
	}
	_ = peer.Close()
}

type helloRejectedOwner struct{ gnet.EventLoop }

func (helloRejectedOwner) Execute(context.Context, gnet.Runnable) error {
	return errors.New("owner stopped")
}

type helloRejectedConn struct{ gnet.Conn }

func (helloRejectedConn) EventLoop() gnet.EventLoop { return helloRejectedOwner{} }

func TestServerHelloPacingRejectedOwner(t *testing.T) {
	conn := helloRejectedConn{newTestMockGnetConn()}
	ctx := NewConnContext()
	ctx.SetState(StateWriteServerHello)
	pacer := &serverHelloPacer{conn: conn, ctx: ctx, data: make([]byte, 1024)}
	ctx.helloPacer.Store(pacer)
	pacer.enqueue()
	if !pacer.closed || pacer.data != nil || ctx.helloPacer.Load() != nil {
		t.Fatal("rejected owner retained paced output")
	}
}

// Capture is optional in the normal suite. A release investigation can set
// TELEGO_TEST_PCAP to a private artifact path and grant capture permission.
func capturePacedSocket(t *testing.T, server, client *net.TCPConn) func(int, int) {
	t.Helper()
	path := os.Getenv("TELEGO_TEST_PCAP")
	if path == "" {
		return func(int, int) {}
	}
	port := server.LocalAddr().(*net.TCPAddr).Port
	clientPort := client.LocalAddr().(*net.TCPAddr).Port
	command := exec.CommandContext(t.Context(), "tcpdump", "-U", "--immediate-mode", "-i", "lo", "-nn", "-s", "0", "-w", path, "tcp", "and", "src", "port", strconv.Itoa(port), "and", "dst", "port", strconv.Itoa(clientPort))
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	listening := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		var diagnostics strings.Builder
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "listening on") {
				listening <- ""
				return
			}
			diagnostics.WriteString(scanner.Text())
			diagnostics.WriteByte('\n')
		}
		listening <- diagnostics.String()
	}()
	select {
	case message := <-listening:
		if message != "" {
			_ = command.Wait()
			t.Fatalf("isolated tcpdump failed: %s", message)
		}
	case <-time.After(time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("isolated tcpdump did not start")
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			_ = command.Process.Signal(syscall.SIGINT)
			_ = command.Wait()
		}
	}
	t.Cleanup(stop)
	return func(helloBytes, segmentSize int) {
		time.Sleep(50 * time.Millisecond)
		stop()
		output, err := exec.CommandContext(t.Context(), "tcpdump", "-nn", "-r", path).Output()
		if err != nil {
			t.Fatal(err)
		}
		total, helloPackets, bulkPackets := 0, 0, 0
		for line := range strings.SplitSeq(string(output), "\n") {
			_, size, ok := strings.Cut(line, ", length ")
			if !ok {
				continue
			}
			n, err := strconv.Atoi(strings.TrimSpace(size))
			if err != nil || n == 0 {
				continue
			}
			if total < helloBytes {
				if n > segmentSize {
					t.Fatalf("captured handshake payload %d exceeds %d bytes", n, segmentSize)
				}
				helloPackets++
			} else if n > segmentSize {
				bulkPackets++
			}
			total += n
		}
		if total < helloBytes || helloPackets == 0 || bulkPackets == 0 {
			t.Fatalf("incomplete packet evidence: total=%d helloPackets=%d bulkPackets=%d", total, helloPackets, bulkPackets)
		}
		t.Logf("isolated packet capture: %d handshake packets <= %d payload bytes; %d larger bulk packets", helloPackets, segmentSize, bulkPackets)
	}
}

func TestServerHelloPacingFirstRecordOnly(t *testing.T) {
	record := append([]byte{faketls.RecordTypeHandshake, 3, 3, 0, 122}, bytes.Repeat([]byte{0x5a}, 122)...)
	response := append(record, bytes.Repeat([]byte{0x6b}, 3969)...)
	h, peer, socket, ctx, start := startPacingTest(t, response)
	h.config.ServerHelloPaceFirstRecord = true
	before := pacingTCPInfo(t, socket)
	start <- nil
	conn := <-h.opened
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(response))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Fatal("paced response changed")
	}
	deadline := time.Now().Add(time.Second)
	for ctx.State() != StateReadO2Frame {
		if time.Now().After(deadline) {
			t.Fatal("paced response did not resume O2")
		}
		time.Sleep(time.Millisecond)
	}
	after := pacingEnrolledInfo(t, conn)
	segments := after.Data_segs_out - before.Data_segs_out
	// 127 bytes in 92-byte chunks is 2 segments; the 3969-byte rest needs
	// at most a few more at the loopback MSS.
	if segments < 3 || segments > 8 {
		t.Fatalf("%d data segments for a first-record-only paced response", segments)
	}
	t.Logf("first-record pacing sent %d bytes in %d data segments", len(response), segments)
}

func TestPacedPrefix(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response []byte
		want     int
	}{
		{"short header", []byte{0x16, 3, 3}, 3},
		{"first record", append([]byte{0x16, 3, 3, 0, 10}, make([]byte, 100)...), 15},
		{"truncated record", append([]byte{0x16, 3, 3, 0, 200}, make([]byte, 100)...), 105},
		{"capped record", append([]byte{0x16, 3, 3, 0x10, 0}, make([]byte, 5000)...), maxPacedFirstRecord},
	} {
		if got := pacedPrefix(tc.response); got != tc.want {
			t.Errorf("%s: pacedPrefix = %d, want %d", tc.name, got, tc.want)
		}
	}
}
