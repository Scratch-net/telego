//go:build linux

package middleend

import (
	"net"
	"os"
	"testing"

	"github.com/panjf2000/gnet/v2"
	"golang.org/x/sys/unix"
)

type diagnosticFDConn struct {
	gnet.Conn
	fd int
}

func (c diagnosticFDConn) Fd() int { return c.fd }

func TestLinuxSocketDiagnosticsRealLoopback(t *testing.T) {
	runtime := newTestGnetRuntime(t)
	client, peer := dialFakeMiddleEnd(t, fakePeerConfig{})
	link, err := runtime.NewClientLink(client.(*net.TCPConn), newTestBootstrap(t), LinkLimits{
		MaxPendingSubmissions: 2, MaxPendingSubmissionBytes: KeepalivePayloadSize * 2,
		MaxPendingEvents: 2, MaxPendingEventBytes: KeepalivePayloadSize * 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := link.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := link.TrySubmit(LinkSubmission{SubmissionID: 1, Payload: (Ping{ID: 7}).MarshalBinary()}); err != nil {
		t.Fatal(err)
	}
	if event := receiveLinkEvent(t, link); event.Kind != LinkEventPong {
		t.Fatalf("event = %+v", event)
	}
	before := link.Snapshot().Transport
	if !before.IO.Available || before.IO.ReadBytes == 0 || before.IO.WriteAttemptBytes == 0 || before.IO.LastReadAt.IsZero() ||
		before.Socket.Status != LinkSocketNotCaptured || !before.Socket.At.IsZero() {
		t.Fatalf("running evidence = %+v", before)
	}
	if err := peer.conn.Close(); err != nil {
		t.Fatal(err)
	}
	waitLinkDone(t, link)
	closed := link.Snapshot().Transport
	if closed.Socket.Status != LinkSocketAvailable || closed.Socket.At.IsZero() || closed.Socket.State == 0 || closed.Socket.SendCongestionWindow == 0 ||
		closed.IO.ReadBytes < before.IO.ReadBytes || !closed.IO.OutboundObserved || closed.IO.OutboundProgressBytes == 0 || closed.IO.WriteInFlight || closed.IO.OutboundProgressIncomplete {
		t.Fatalf("close evidence = %+v", closed)
	}
	if err := waitFakePeer(t, peer); err != nil {
		t.Fatal(err)
	}
	if err := link.Close(); err != nil {
		t.Fatal(err)
	}
	if after := link.Snapshot().Transport; after != closed {
		t.Fatal("closed evidence changed")
	}
}

func TestLinuxSocketDiagnosticsUnavailableAndSyscallFailure(t *testing.T) {
	if snapshot := captureOwnerSocket(nil); snapshot.Status != LinkSocketUnavailable || snapshot.At.IsZero() {
		t.Fatalf("missing owner = %+v", snapshot)
	}
	if snapshot := captureOwnerSocket(diagnosticFDConn{fd: -1}); snapshot.Status != LinkSocketUnavailable {
		t.Fatalf("invalid descriptor = %+v", snapshot)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	raw, err := reader.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot LinkSocketSnapshot
	if err := raw.Control(func(fd uintptr) { snapshot = captureOwnerSocket(diagnosticFDConn{fd: int(fd)}) }); err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != LinkSocketError || snapshot.Errno != uint64(unix.ENOTSOCK) || snapshot.State != 0 {
		t.Fatalf("failed syscall masquerades as available: %+v", snapshot)
	}
}
