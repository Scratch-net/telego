package webproxy

import (
	"io"
	"testing"

	"github.com/panjf2000/gnet/v2"
	"github.com/panjf2000/gnet/v2/pkg/buffer/elastic"
)

type capacityRingConn struct {
	gnet.Conn
	input  elastic.RingBuffer
	output elastic.Buffer
}

func (c *capacityRingConn) InboundBuffered() int       { return c.input.Buffered() }
func (c *capacityRingConn) OutboundBuffered() int      { return c.output.Buffered() }
func (c *capacityRingConn) Read(p []byte) (int, error) { return c.input.Read(p) }
func (c *capacityRingConn) WriteOwned(p []byte, release func(error)) (int, error) {
	c.output.AppendOwned(p, release)
	return len(p), nil
}

func TestSocketBackendPartialReadRetainsCapacityCharge(t *testing.T) {
	conn := &capacityRingConn{}
	t.Cleanup(conn.input.Done)
	_, _ = conn.input.Write(make([]byte, RelayDataChunk))
	charged := 0
	backend := &socketBackend{conn: conn, options: BackendOpenOptions{
		MaxOutputBytes: 2 * RelayDataChunk, MaxOutputItems: 2,
		OutputBudget: BackendBudget{
			Reserve: func(n, _ int) bool { charged += n; return true },
			Release: func(n, _ int) { charged -= n },
		},
	}}
	if backend.onTraffic(conn) != gnet.None {
		t.Fatal("initial traffic rejected")
	}
	if conn.input.Cap() != 0 {
		t.Fatal("OnTraffic retained gnet input ring")
	}
	if n, err := backend.TryRead(make([]byte, RelayDataChunk-1)); n != RelayDataChunk-1 || err != nil {
		t.Fatalf("partial read = %d, %v", n, err)
	}
	if charged < RelayDataChunk {
		t.Fatalf("one unread byte retains the original allocation: charged=%d, original=%d", charged, RelayDataChunk)
	}
	if n, err := backend.TryRead(make([]byte, 1)); n != 1 || err != nil {
		t.Fatalf("final read = %d, %v", n, err)
	}
	if charged != 0 {
		t.Fatalf("completed allocation still charged: %d", charged)
	}
}

func TestSocketBackendInputChargeSurvivesPartialWriteAndClose(t *testing.T) {
	conn := &capacityRingConn{}
	charged, items, closed := 0, 0, 0
	backend := &socketBackend{conn: conn, setupComplete: true, options: BackendOpenOptions{
		MaxInputBytes: 33, MaxInputItems: 1,
		InputBudget: BackendBudget{
			Reserve: func(n, count int) bool { charged += n; items += count; return true },
			Release: func(n, count int) { charged -= n; items -= count },
		},
		OnClosed: func(error) {
			closed++
			if charged != 0 || items != 0 {
				t.Error("OnClosed preceded disposal")
			}
		},
	}}
	if n, err := backend.TryWrite(make([]byte, 33)); n != 33 || err != nil {
		t.Fatalf("write=%d,%v", n, err)
	}
	_, _ = conn.output.Discard(32)
	if charged != 33 || items != 1 || backend.inputBytes != 33 {
		t.Fatal("partial socket write released whole allocation")
	}
	if n, err := backend.TryWrite([]byte{1}); n != 0 || err != nil {
		t.Fatal("partial drain granted extra retained capacity")
	}
	backend.closed = true // gnet OnClose precedes outbound Release.
	if charged != 33 {
		t.Fatal("OnClose released borrowed bytes too early")
	}
	conn.output.Release()
	backend.requestDisposal(io.EOF) // The following owner task is the disposal barrier.
	backend.OwnerStopped()
	if charged != 0 || items != 0 || closed != 1 || backend.inputBytes != 0 {
		t.Fatal("close did not dispose exactly once")
	}
}

func TestSocketBackendOutputChunksKeepExactCapacityAcrossGrowth(t *testing.T) {
	conn := &capacityRingConn{}
	t.Cleanup(conn.input.Done)
	charged, items := 0, 0
	backend := &socketBackend{conn: conn, setupComplete: true, options: BackendOpenOptions{
		MaxOutputBytes: 100, MaxOutputItems: 3,
		OutputBudget: BackendBudget{
			Reserve: func(n, count int) bool { charged += n; items += count; return true },
			Release: func(n, count int) { charged -= n; items -= count },
		},
	}}
	for _, size := range []int{17, 33, 49} {
		_, _ = conn.input.Write(make([]byte, size))
		if backend.onTraffic(conn) != gnet.None {
			t.Fatal("bounded chunk rejected")
		}
		if cap(backend.outputTail.data) != size || conn.input.Cap() != 0 {
			t.Fatal("rounded or external retained allocation")
		}
	}
	if charged != 99 || items != 3 {
		t.Fatal("growth accounting mismatch")
	}
	if n, err := backend.TryRead(make([]byte, 49)); n != 49 || err != nil {
		t.Fatalf("read=%d,%v", n, err)
	}
	if charged != 82 || items != 2 || backend.outputBytes != 50 {
		t.Fatal("partial second chunk released its prefix")
	}
	backend.OwnerStopped()
	if charged != 0 || items != 0 || backend.outputHead != nil || backend.outputTail != nil {
		t.Fatal("retirement retained output chunks")
	}
}

func TestSocketBackendReservesBeforeRetainingInput(t *testing.T) {
	conn := &capacityRingConn{}
	t.Cleanup(conn.input.Done)
	backend := &socketBackend{conn: conn, options: BackendOpenOptions{
		MaxInputBytes: 100, MaxOutputBytes: 100,
		InputBudget:  BackendBudget{Reserve: func(int, int) bool { return false }},
		OutputBudget: BackendBudget{Reserve: func(int, int) bool { return false }},
	}}
	if n, err := backend.TryWrite(make([]byte, 17)); n != 0 || err != nil {
		t.Fatal("rejected input budget was ignored")
	}
	if conn.output.Buffered() != 0 || backend.inputBytes != 0 {
		t.Fatal("rejected write retained output")
	}
	_, _ = conn.input.Write(make([]byte, 33))
	if backend.onTraffic(conn) != gnet.Close {
		t.Fatal("rejected output budget did not close")
	}
	if backend.outputHead != nil || backend.outputCost != 0 {
		t.Fatal("rejected input copied into retained queue")
	}
}
