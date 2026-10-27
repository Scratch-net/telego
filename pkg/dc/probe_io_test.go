package dc

import (
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

type probeResultConn struct {
	net.Conn
	readN            int
	readErr          error
	writeN           *int
	writeErr         error
	readDeadlineErr  error
	writeDeadlineErr error
}

func (c *probeResultConn) Read(data []byte) (int, error) {
	if c.readN != 0 {
		data[0] = 1
	}
	return c.readN, c.readErr
}

func (c *probeResultConn) Write(data []byte) (int, error) {
	if c.writeN != nil {
		return *c.writeN, c.writeErr
	}
	return len(data), c.writeErr
}

func (c *probeResultConn) SetReadDeadline(time.Time) error  { return c.readDeadlineErr }
func (c *probeResultConn) SetWriteDeadline(time.Time) error { return c.writeDeadlineErr }

func TestProbeConnectionClassifiesPeerResponse(t *testing.T) {
	otherError := errors.New("unrelated I/O failure")
	for _, test := range []struct {
		name string
		conn probeResultConn
		want error
	}{
		{name: "data", conn: probeResultConn{readN: 1}},
		{name: "data before EOF", conn: probeResultConn{readN: 1, readErr: io.EOF}},
		{name: "data before timeout", conn: probeResultConn{readN: 1, readErr: os.ErrDeadlineExceeded}},
		{name: "peer EOF", conn: probeResultConn{readErr: io.EOF}},
		{name: "peer reset", conn: probeResultConn{readErr: &net.OpError{Op: "read", Err: syscall.ECONNRESET}}},
		{name: "timeout", conn: probeResultConn{readErr: &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}}, want: os.ErrDeadlineExceeded},
		{name: "local close", conn: probeResultConn{readErr: net.ErrClosed}, want: net.ErrClosed},
		{name: "other read error", conn: probeResultConn{readErr: otherError}, want: otherError},
		{name: "empty read", conn: probeResultConn{}, want: io.ErrNoProgress},
		{name: "write error", conn: probeResultConn{writeErr: otherError}, want: otherError},
		{name: "short write", conn: probeResultConn{writeN: new(63)}, want: io.ErrShortWrite},
		{name: "empty write", conn: probeResultConn{writeN: new(0)}, want: io.ErrShortWrite},
		{name: "write deadline", conn: probeResultConn{writeDeadlineErr: otherError}, want: otherError},
		{name: "read deadline", conn: probeResultConn{readDeadlineErr: otherError}, want: otherError},
	} {
		t.Run(test.name, func(t *testing.T) {
			rtt, err := probeConnection(&test.conn, time.Second)
			if !errors.Is(err, test.want) {
				t.Fatalf("probe error = %v, want %v", err, test.want)
			}
			if err == nil && rtt <= 0 {
				t.Fatal("peer response did not record RTT")
			}
			if err != nil && rtt != 0 {
				t.Fatal("failed probe returned a successful RTT")
			}
		})
	}
}

func TestProbeConnectionSilentPeerTimesOut(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	readDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, peer)
		close(readDone)
	}()
	rtt, err := probeConnection(client, 20*time.Millisecond)
	_ = client.Close()
	<-readDone
	if !errors.Is(err, os.ErrDeadlineExceeded) || rtt != 0 {
		t.Fatalf("silent peer probe = %s, %v; want failure", rtt, err)
	}
}
