package middleend

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

type observedSTUNConn struct {
	net.Conn
	reads  atomic.Int32
	closes atomic.Int32
}

func (c *observedSTUNConn) Read(data []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(data)
}

func (c *observedSTUNConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

type retransmittingSTUNConn struct {
	*observedSTUNConn
	writes chan struct{}
}

func (c *retransmittingSTUNConn) Write(data []byte) (int, error) {
	c.writes <- struct{}{}
	return c.Conn.Write(data)
}

func TestSTUNProbeCancellationInterruptsBlockedRetransmission(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	connection := &retransmittingSTUNConn{
		observedSTUNConn: &observedSTUNConn{Conn: client},
		writes:           make(chan struct{}, 2),
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := probeSTUNConnection(ctx, AddressFamilyIPv4, "pipe", connection)
		done <- err
	}()
	if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var request [20]byte
	if _, err := io.ReadFull(peer, request[:]); err != nil {
		t.Fatal(err)
	}
	<-connection.writes
	select {
	case <-connection.writes:
	case <-ctx.Done():
		t.Fatal("STUN client did not retransmit")
	}
	// Leave the retry write blocked, then cancel the connection owner.
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked retransmission error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		_ = peer.Close()
		<-done
		t.Fatal("canceled probe remained blocked in its retransmission")
	}
	if connection.closes.Load() != 1 || connection.reads.Load() != 1 {
		t.Fatal("probe retried failed reads or did not close its owned connection exactly once")
	}
}

func TestSTUNProbeCancellationClosesOwnedConnection(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	connection := &observedSTUNConn{Conn: client}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := probeSTUNConnection(ctx, AddressFamilyIPv4, "pipe", connection)
		done <- err
	}()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var request [20]byte
	if _, err := io.ReadFull(peer, request[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled probe error = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("probe remained blocked after cancellation")
	}
	if reads := connection.reads.Load(); reads > 1 {
		t.Fatalf("reader retried failed reads %d times", reads)
	}
	if connection.closes.Load() != 1 {
		t.Fatal("probe did not close its owned connection exactly once")
	}
}

func TestSTUNProbeCancellationInterruptsInitialWrite(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	connection := &observedSTUNConn{Conn: client}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := probeSTUNConnection(ctx, AddressFamilyIPv4, "pipe", connection)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked initial write error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("blocked initial write took %v", elapsed)
	}
	if connection.closes.Load() != 1 || connection.reads.Load() > 1 {
		t.Fatal("initial-write cancellation leaked ownership or retried failed reads")
	}
}

// Models the interval where the socket deadline has expired but the context
// timer has not yet published cancellation.
type pendingDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c pendingDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestSTUNProbeExpiredSocketDeadlinePreservesContextError(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	ctx := pendingDeadlineContext{Context: t.Context(), deadline: time.Now().Add(20 * time.Millisecond)}
	_, err := probeSTUNConnection(ctx, AddressFamilyIPv4, "pipe", client)
	if !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatalf("socket/context deadline race: probe=%v context=%v", err, ctx.Err())
	}
}

type failedSTUNReadConn struct {
	*observedSTUNConn
	err error
}

func (c *failedSTUNReadConn) Write(data []byte) (int, error) { return len(data), nil }
func (c *failedSTUNReadConn) Read([]byte) (int, error) {
	c.reads.Add(1)
	return 0, c.err
}

func TestSTUNProbePermanentReadErrorDoesNotRetry(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	readErr := errors.New("permanent read failure")
	connection := &failedSTUNReadConn{observedSTUNConn: &observedSTUNConn{Conn: client}, err: readErr}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	_, err := probeSTUNConnection(ctx, AddressFamilyIPv4, "pipe", connection)
	if !errors.Is(err, readErr) || connection.reads.Load() != 1 || connection.closes.Load() != 1 {
		t.Fatalf("permanent failure retried or lost ownership: err=%v reads=%d closes=%d", err, connection.reads.Load(), connection.closes.Load())
	}
}

func TestSTUNProbeRetriesAndIgnoresUnrelatedDatagrams(t *testing.T) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	client, err := net.Dial("udp4", peer.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	connection := &observedSTUNConn{Conn: client}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() {
		if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		var first, second [1024]byte
		n, _, err := peer.ReadFrom(first[:])
		if err != nil {
			serverDone <- err
			return
		}
		// Drop the first request. A retry must reuse its transaction ID.
		m, address, err := peer.ReadFrom(second[:])
		if err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(first[:n], second[:m]) {
			serverDone <- errors.New("STUN retry changed its request")
			return
		}
		request := &stun.Message{Raw: second[:m]}
		if err := request.Decode(); err != nil {
			serverDone <- err
			return
		}
		foreign, err := stun.Build(stun.TransactionID, stun.BindingSuccess,
			&stun.XORMappedAddress{IP: net.IPv4(1, 1, 1, 1), Port: 12345})
		if err != nil {
			serverDone <- err
			return
		}
		response, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess,
			&stun.XORMappedAddress{IP: net.IPv4(8, 8, 8, 8), Port: 12345})
		if err != nil {
			serverDone <- err
			return
		}
		for _, packet := range [][]byte{[]byte("malformed"), foreign.Raw, response.Raw} {
			if _, err := peer.WriteTo(packet, address); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()
	address, err := probeSTUNConnection(ctx, AddressFamilyIPv4, "udp", connection)
	if serverErr := <-serverDone; serverErr != nil {
		t.Fatal(serverErr)
	}
	if err != nil || address != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("retried probe = %s, %v", address, err)
	}
	if connection.closes.Load() != 1 {
		t.Fatal("probe did not close its owned connection exactly once")
	}
}

func TestSTUNProbeResponseCancellationRace(t *testing.T) {
	for iteration := range 60 {
		client, peer := net.Pipe()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		var server sync.WaitGroup
		server.Go(func() {
			defer peer.Close()
			defer cancel()
			var request [20]byte
			if _, err := io.ReadFull(peer, request[:]); err != nil {
				return
			}
			message := &stun.Message{Raw: request[:]}
			if err := message.Decode(); err != nil {
				t.Error(err)
				return
			}
			response, err := stun.Build(stun.NewTransactionIDSetter(message.TransactionID), stun.BindingSuccess,
				&stun.XORMappedAddress{IP: net.IPv4(8, 8, 8, 8), Port: 12345})
			if err != nil {
				t.Error(err)
				return
			}
			switch iteration % 3 {
			case 0:
				cancel()
			case 1:
				server.Go(cancel)
			}
			_, _ = peer.Write(response.Raw)
		})
		address, err := probeSTUNConnection(ctx, AddressFamilyIPv4, "pipe", client)
		cancel()
		server.Wait()
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("iteration %d: response/cancel error = %v", iteration, err)
		}
		if err == nil && address != netip.MustParseAddr("8.8.8.8") {
			t.Fatalf("iteration %d: address = %s", iteration, address)
		}
	}
}
