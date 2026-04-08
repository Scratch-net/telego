package gproxy

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

func TestHandshakeTimeout_SilentConnection(t *testing.T) {
	port := fmt.Sprintf("%d", 30000+rand.Intn(10000))
	cfg := &Config{
		BindAddr:         "127.0.0.1:" + port,
		HandshakeTimeout: 2 * time.Second,
		Secrets: []Secret{
			{Name: "test", Key: []byte("0123456789abcdef"), Host: "example.com"},
		},
	}

	logger := &testLogger{}
	handler := NewProxyHandler(cfg, logger)

	var engPtr atomic.Pointer[gnet.Engine]
	ready := make(chan struct{})
	wrapper := &engineCaptureHandler{
		ProxyHandler: handler,
		engPtr:       &engPtr,
		ready:        ready,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- gnet.Run(wrapper, "tcp://127.0.0.1:"+port,
			gnet.WithNumEventLoop(1),
		)
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to start")
	}

	defer func() {
		if eng := engPtr.Load(); eng != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			(*eng).Stop(ctx)
		}
	}()

	// Open a silent connection (no data sent)
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Give gnet event loop time to process
	time.Sleep(100 * time.Millisecond)

	active := atomic.LoadInt64(&handler.activeConns)
	if active != 1 {
		t.Fatalf("expected 1 active conn, got %d", active)
	}

	// Wait for handshake timeout (2s + 1s buffer)
	time.Sleep(3 * time.Second)

	active = atomic.LoadInt64(&handler.activeConns)
	if active != 0 {
		t.Fatalf("expected 0 active conns after timeout, got %d (leak!)", active)
	}

	t.Logf("handshake timeout worked: silent connection closed after ~2s")
}
