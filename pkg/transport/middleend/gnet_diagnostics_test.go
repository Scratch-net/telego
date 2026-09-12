package middleend

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/panjf2000/gnet/v2"
)

type reentrantDiagnosticConn struct {
	gnet.Conn
	link     *GnetClientLink
	fdCalls  int
	buffered int
}

func (c *reentrantDiagnosticConn) Fd() int               { c.fdCalls++; return -1 }
func (c *reentrantDiagnosticConn) OutboundBuffered() int { return c.buffered }
func (c *reentrantDiagnosticConn) Writev([][]byte) (int, error) {
	c.link.onClose(c, io.ErrClosedPipe)
	return 0, io.ErrClosedPipe
}

func TestGnetDiagnosticsReentrantCloseFreezesBeforeWriteReturns(t *testing.T) {
	link := &GnetClientLink{
		runtime: &GnetClientRuntime{}, bootstrap: newTestBootstrap(t), state: LinkStateReady,
		events: make(chan LinkEvent, 1), done: make(chan struct{}), startDone: make(chan struct{}),
		transport: LinkTransportSnapshot{IO: LinkIOSnapshot{Available: true}},
	}
	conn := &reentrantDiagnosticConn{link: link}
	link.observeReadBytes(17)
	if err := link.writeOwnerBatch(conn, [][]byte{{1, 2, 3, 4}}, []gnetWireCharge{{submissionBytes: 4}}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write result = %v", err)
	}
	if !channelClosed(link.Done()) {
		t.Fatal("reentrant close did not complete")
	}
	frozen := link.Snapshot().Transport
	if frozen.IO.ReadBytes != 17 || frozen.IO.ReadEvents != 1 || frozen.IO.WriteAttemptBytes != 4 || frozen.IO.WriteAttempts != 1 ||
		frozen.Socket.At.IsZero() || frozen.IO.LastWriteAttemptAt.After(frozen.Socket.At) || !frozen.IO.WriteInFlight || !frozen.IO.OutboundProgressIncomplete {
		t.Fatalf("close evidence missed the in-flight attempt: %+v", frozen)
	}
	fdCalls := conn.fdCalls
	link.observeReadBytes(100)
	link.observeWriteAttempt(100)
	link.observeOutboundProgress(100, 100)
	link.onClose(conn, errors.New("later error"))
	for range 10 {
		if snapshot := link.Snapshot(); snapshot.Transport != frozen || snapshot.PendingSubmissions != 0 || snapshot.PendingEvents != 0 {
			t.Fatalf("terminal snapshot changed: %+v", snapshot)
		}
	}
	if conn.fdCalls != fdCalls {
		t.Fatal("a frozen close or Snapshot read the old descriptor")
	}
}

func TestGnetDiagnosticsPartialWriteCloseRetainsExactProgress(t *testing.T) {
	for _, buffered := range []int{0, 2} {
		link := &GnetClientLink{
			runtime: &GnetClientRuntime{}, bootstrap: newTestBootstrap(t), state: LinkStateReady,
			events: make(chan LinkEvent, 1), done: make(chan struct{}), startDone: make(chan struct{}),
			transport: LinkTransportSnapshot{IO: LinkIOSnapshot{Available: true}}, ownerWireTotal: 100,
		}
		link.observeOutboundProgress(30, 70)
		before := link.Snapshot().Transport.IO
		conn := &reentrantDiagnosticConn{link: link, buffered: buffered}
		if err := link.writeOwnerBatch(conn, [][]byte{{1, 2, 3, 4}}, []gnetWireCharge{{submissionBytes: 4}}); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
		closed := link.Snapshot().Transport
		if closed.IO.OutboundBufferedBytes != buffered || !closed.IO.OutboundProgressIncomplete || !closed.IO.WriteInFlight ||
			closed.IO.OutboundProgressBytes != before.OutboundProgressBytes || closed.IO.LastOutboundProgressAt != before.LastOutboundProgressAt {
			t.Fatalf("buffered=%d: reentrant partial error invented progress: before=%+v after=%+v", buffered, before, closed)
		}
		link.endOwnerWrite()
		if after := link.Snapshot().Transport; after != closed {
			t.Fatal("write return rewrote terminal partial-progress evidence")
		}
	}
}

func TestLinkDiagnosticsCountersAreMonotonic(t *testing.T) {
	now := time.Now()
	observed := LinkIOSnapshot{Available: true, ReadBytes: ^uint64(0) - 2, WriteAttemptBytes: ^uint64(0) - 2}
	observed.read(8, now)
	observed.writeAttempt(8, now)
	observed.read(0, now.Add(time.Hour))
	observed.writeAttempt(-1, now.Add(time.Hour))
	if observed.ReadBytes != ^uint64(0) || observed.WriteAttemptBytes != ^uint64(0) || observed.LastReadAt != now || observed.LastWriteAttemptAt != now {
		t.Fatalf("counter wrapped or an empty attempt changed time: %+v", observed)
	}
}

func TestBlockingDiagnosticsAreExplicitlyUnsupported(t *testing.T) {
	link := &BlockingClientLinkEngine{state: LinkStateClosed}
	snapshot := link.Snapshot().Transport
	if snapshot.IO.Available || snapshot.Socket.Status != LinkSocketUnsupported {
		t.Fatalf("reference engine claims unsupported evidence: %+v", snapshot)
	}
}
