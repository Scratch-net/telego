package webproxy

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"golang.org/x/sys/unix"
)

// throttledReader delivers at most rate bytes per second. It models a client
// whose link is slower than the response, but that never stops reading. If
// slowBytes is set, only the first slowBytes are throttled.
type throttledReader struct {
	reader    io.Reader
	rate      int
	slowBytes int
	started   time.Time
	read      int
}

func (r *throttledReader) Read(data []byte) (int, error) {
	if r.started.IsZero() {
		r.started = time.Now()
	}
	data = data[:min(len(data), 4096)]
	if r.slowBytes != 0 && r.read >= r.slowBytes {
		return r.reader.Read(data)
	}
	if due := r.started.Add(time.Duration(r.read) * time.Second / time.Duration(r.rate)); time.Until(due) > 0 {
		time.Sleep(time.Until(due))
	}
	n, err := r.reader.Read(data)
	r.read += n
	return n, err
}

func queueSlowReaderBatch(t *testing.T, session *Session, fill byte) int {
	t.Helper()
	payloadSize := MaxFramePayload - FrameHeaderSize
	session.mu.Lock()
	queued := session.queueFrameLocked(FrameData, 1, bytes.Repeat([]byte{fill}, payloadSize)) &&
		session.queueFrameLocked(FrameData, 2, bytes.Repeat([]byte{fill + 1}, payloadSize))
	session.mu.Unlock()
	if !queued {
		t.Fatal("failed to queue slow-reader downlink")
	}
	return 2 * (FrameHeaderSize + payloadSize)
}

// dialPathMSSTest is dialHTTPTest with an Ethernet-sized MSS advertised by the
// client, as on a real path. Loopback otherwise uses a 64 KiB MSS. With a small
// receive buffer, Linux 7.0 drops those segments and delivers at about 40 KB/s
// with acknowledgements seconds apart, independent of the server.
func dialPathMSSTest(t *testing.T, address string) net.Conn {
	t.Helper()
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, 1400)
		}); err != nil {
			return err
		}
		return socketErr
	}}
	connection, err := dialer.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.(*net.TCPConn).SetNoDelay(true); err != nil {
		connection.Close()
		t.Fatal(err)
	}
	return connection
}

// slowReaderRate and slowReaderBytes model a client on a slow link. With the
// default kernel send buffer, the userspace output buffer of the server can
// stay unchanged for longer than WriteTimeout while the kernel still sends.
// On Linux 6.x loopback this happens, and the slow-reader tests fail without
// the acknowledged-bytes check. Linux 7.0 refills from the userspace buffer
// often enough that the tests pass without it, so they guard it on 6.x only.
const (
	slowReaderRate  = 128 << 10
	slowReaderBytes = 512 << 10
)

// A slow but progressing client must receive a batch whose transfer takes
// longer than WriteTimeout. A fixed per-response deadline would truncate the
// batch on every poll, and the next poll would replay the same batch.
func TestHTTPServerSlowReaderCompletesDownlinkBeyondWriteTimeout(t *testing.T) {
	const writeTimeout = 300 * time.Millisecond
	application := newHTTPTestApplicationWithConfig(t, time.Second, nil, func(config *HTTPServerConfig) {
		config.WriteTimeout = writeTimeout
	})
	created := createTestSession(t, application.manager, application.profiles[0])
	want := queueSlowReaderBatch(t, created.Session, 0x41)

	// Default socket buffers, as in the WebSocket test below. A tiny receive
	// buffer makes Linux 7.0 drop the 64 KiB loopback segments.
	connection := dialHTTPTest(t, application.address)
	defer connection.Close()
	request := "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + created.Token + "\r\nX-Down-Cursor: 0\r\nContent-Length: 0\r\n\r\n"
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	reader := bufio.NewReader(&throttledReader{reader: connection, rate: slowReaderRate, slowBytes: slowReaderBytes})
	response, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("downlink X-Accel-Buffering = %q", response.Header.Get("X-Accel-Buffering"))
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	elapsed := time.Since(started)
	if err != nil || len(body) != want {
		t.Fatalf("slow reader got %d of %d bytes after %v: %v", len(body), want, elapsed, err)
	}
	if elapsed < 2*writeTimeout {
		t.Fatalf("transfer took %v; the test requires a transfer longer than WriteTimeout", elapsed)
	}
	if frames, err := ParseBatch(body); err != nil || len(frames) != 2 {
		t.Fatalf("slow reader frames = %d, %v", len(frames), err)
	}
}

func TestHTTPServerWebSocketSlowReaderCompletesMessageBeyondWriteTimeout(t *testing.T) {
	const writeTimeout = 300 * time.Millisecond
	application := newHTTPTestApplicationWithConfig(t, 30*time.Second, func(config *ManagerConfig) {
		config.Carrier = CarrierWebSocket
	}, func(config *HTTPServerConfig) {
		config.WriteTimeout = writeTimeout
	})
	created := createTestSession(t, application.manager, application.profiles[0])
	want := queueSlowReaderBatch(t, created.Session, 0x61)

	client, response := dialWebSocketTest(t, application.address, webSocketProtocolPrefix+created.Token, "", nil)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade = %d", response.StatusCode)
	}
	defer client.close()
	// Default socket buffers: a tiny receive window adds TCP zero-window
	// persist gaps that exceed the short test WriteTimeout under load.
	client.reader = bufio.NewReader(&throttledReader{reader: client.reader, rate: slowReaderRate, slowBytes: slowReaderBytes})
	started := time.Now()
	opcode, payload, err := client.readResult(30 * time.Second)
	elapsed := time.Since(started)
	if err != nil || opcode != ws.OpBinary || len(payload) != want {
		t.Fatalf("slow WebSocket reader got opcode %v, %d of %d bytes after %v: %v", opcode, len(payload), want, elapsed, err)
	}
	if elapsed < 2*writeTimeout {
		t.Fatalf("transfer took %v; the test requires a transfer longer than WriteTimeout", elapsed)
	}
	if frames, err := ParseBatch(payload); err != nil || len(frames) != 2 {
		t.Fatalf("slow WebSocket frames = %d, %v", len(frames), err)
	}
}

// A client that stops reading must still hit WriteTimeout with the default
// kernel send buffer. Kernel-side progress stops when the peer window fills.
func TestHTTPServerStalledReaderClosesWithDefaultSendBuffer(t *testing.T) {
	const writeTimeout = 300 * time.Millisecond
	application := newHTTPTestApplicationWithConfig(t, time.Second, nil, func(config *HTTPServerConfig) {
		config.WriteTimeout = writeTimeout
		config.IdleTimeout = 10 * time.Second
	})
	created := createTestSession(t, application.manager, application.profiles[0])
	want := queueSlowReaderBatch(t, created.Session, 0x51)

	connection := dialPathMSSTest(t, application.address)
	defer connection.Close()
	if tcp, ok := connection.(*net.TCPConn); ok {
		if err := tcp.SetReadBuffer(4096); err != nil {
			t.Fatal(err)
		}
	}
	request := "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer " + created.Token + "\r\nX-Down-Cursor: 0\r\nContent-Length: 0\r\n\r\n"
	started := time.Now()
	if _, err := io.WriteString(connection, request); err != nil {
		t.Fatal(err)
	}
	waitForDownPoll(t, created.Session, true)
	time.Sleep(4 * writeTimeout)
	waitForDownPoll(t, created.Session, false)
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(connection)
	if err != nil {
		t.Fatalf("reading timed-out response: %v", err)
	}
	if len(received) >= want {
		t.Fatalf("write timeout did not truncate the unread response: got %d bytes", len(received))
	}
	if elapsed := time.Since(started); elapsed >= application.server.config.IdleTimeout {
		t.Fatalf("connection closed at idle timeout after %v, not write timeout", elapsed)
	}
}
