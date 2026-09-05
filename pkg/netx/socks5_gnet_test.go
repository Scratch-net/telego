package netx

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

type socksEnrollmentHandler struct {
	gnet.BuiltinEventEngine
	payload  []byte
	received []byte
	opened   chan any
	echoed   chan string
}

func (h *socksEnrollmentHandler) OnOpen(c gnet.Conn) ([]byte, gnet.Action) {
	h.opened <- c.Context()
	return h.payload, gnet.None
}

func (h *socksEnrollmentHandler) OnTraffic(c gnet.Conn) gnet.Action {
	data, err := c.Next(c.InboundBuffered())
	if err != nil {
		return gnet.Close
	}
	h.received = append(h.received, data...)
	if len(h.received) >= len(h.payload) {
		h.echoed <- string(h.received)
		return gnet.Close
	}
	return gnet.None
}

func TestSocks5DialContextEnrollsRawSocket(t *testing.T) {
	proxyAddr, targetAddr, cleanup := startMockSocks5Server(t)
	t.Cleanup(cleanup)
	dialer, err := NewSocks5Dialer(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, ok := conn.(*net.TCPConn); !ok {
		t.Fatalf("dial returned %T, want raw *net.TCPConn", conn)
	}
	// Cancellation governs setup only; it must not poison the enrolled socket.
	cancel()
	handler := &socksEnrollmentHandler{
		payload: []byte("enrolled SOCKS payload"), opened: make(chan any, 1), echoed: make(chan string, 1),
	}
	engine, err := gnet.NewClient(handler)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop() })
	const enrollmentContext = "SOCKS enrollment"
	if _, err := engine.EnrollContext(conn, enrollmentContext); err != nil {
		t.Fatalf("gnet enrollment failed: %v", err)
	}
	select {
	case got := <-handler.opened:
		if got != enrollmentContext {
			t.Fatalf("OnOpen context = %v, want %q", got, enrollmentContext)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gnet did not open SOCKS socket")
	}
	select {
	case got := <-handler.echoed:
		if got != string(handler.payload) {
			t.Fatalf("gnet echo = %q, want %q", got, handler.payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gnet did not relay SOCKS payload")
	}
}

func TestSocks5DialContextCancelsStalledHandshake(t *testing.T) {
	for _, stage := range []string{"greeting", "connect"} {
		for _, deadline := range []bool{false, true} {
			name := stage + "/cancel"
			if deadline {
				name = stage + "/deadline"
			}
			t.Run(name, func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				ready := make(chan error, 1)
				peerClosed := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						ready <- err
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					var greeting [3]byte
					if _, err := io.ReadFull(conn, greeting[:]); err != nil {
						ready <- err
						return
					}
					if stage == "connect" {
						if _, err := conn.Write([]byte{5, 0}); err != nil {
							ready <- err
							return
						}
						var request [10]byte
						if _, err := io.ReadFull(conn, request[:]); err != nil {
							ready <- err
							return
						}
					}
					ready <- nil
					var trailing [1]byte
					_, err = conn.Read(trailing[:])
					peerClosed <- err
				}()
				dialer, err := NewSocks5Dialer(listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				wantErr := context.Canceled
				if deadline {
					var expire context.CancelFunc
					ctx, expire = context.WithTimeout(ctx, 200*time.Millisecond)
					defer expire()
					wantErr = context.DeadlineExceeded
				}
				done := make(chan error, 1)
				go func() {
					conn, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:443")
					if conn != nil {
						_ = conn.Close()
					}
					done <- err
				}()
				select {
				case err := <-ready:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("SOCKS handshake did not reach stalled stage")
				}
				if !deadline {
					cancel()
				}
				select {
				case err := <-done:
					if !errors.Is(err, wantErr) {
						t.Fatalf("dial error = %v, want %v", err, wantErr)
					}
				case <-time.After(time.Second):
					t.Fatal("cancellation did not interrupt SOCKS handshake")
				}
				select {
				case err := <-peerClosed:
					if !errors.Is(err, io.EOF) {
						t.Fatalf("canceled setup retained socket: peer read = %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("canceled setup did not close its socket")
				}
			})
		}
	}
}
