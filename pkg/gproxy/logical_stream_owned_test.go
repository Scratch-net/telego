package gproxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/middleend"
)

func TestLogicalStreamOwnedOutputRetainsAllocationUntilDrained(t *testing.T) {
	stream, _, budget, _ := newQueuedLogicalOutput(t)
	stream.options.MaxOutputBytes = 128
	// These tests drive the owner synchronously and do not enter protocol work.
	stream.scheduled.Store(true)
	defer stream.OwnerStopped()
	if logicalOwnedOutputMetadataBytes > int64(middleend.ResponseOutputNodeBytes) {
		t.Fatal("logical output metadata exceeds the ME response envelope")
	}
	data := make([]byte, 8, 64)
	copy(data, "response")
	cancel, ok := prepareClientOutput(stream, 128)
	if !ok {
		t.Fatal("output preparation failed")
	}
	defer cancel()
	releases := 0
	if n, err := stream.writeMiddleEndOwned(data, func(err error) {
		releases++
		if err != nil {
			t.Errorf("drained output release = %v", err)
		}
		clear(data)
	}); n != len(data) || err != nil {
		t.Fatalf("owned write = %d, %v", n, err)
	}
	entry := stream.output
	if entry == nil || &entry.data[0] != &data[0] {
		t.Fatal("owned output copied the ciphertext")
	}
	if stream.preparedOutput != 0 || stream.reservedBytes != 0 || stream.reservedItems != 0 {
		t.Fatal("prepared output credit was not consumed")
	}
	assertLogicalOutputBudget(t, budget, cap(data), 1)
	first := make([]byte, 3)
	if n, err := stream.TryRead(first); n != len(first) || err != nil || string(first) != "res" {
		t.Fatalf("partial read = %d, %v, %q", n, err, first)
	}
	if releases != 0 || stream.OutboundBuffered() != 5 || stream.outputCapacity != cap(data) {
		t.Fatalf("partial drain released allocation: calls=%d, unread=%d, capacity=%d", releases, stream.OutboundBuffered(), stream.outputCapacity)
	}
	if stream.reserveOutput(65, 65) != 0 {
		t.Fatal("partial drain exposed retained allocation capacity")
	}
	assertLogicalOutputBudget(t, budget, cap(data), 1)
	last := make([]byte, 5)
	if n, err := stream.TryRead(last); n != len(last) || err != nil || string(last) != "ponse" {
		t.Fatalf("final read = %d, %v, %q", n, err, last)
	}
	if releases != 1 || stream.output != nil || stream.outputLast != nil || stream.OutboundBuffered() != 0 {
		t.Fatal("drained output retained its node or release callback")
	}
	if entry.data != nil || entry.next != nil || entry.release != nil || !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("drained entry retained the owned allocation")
	}
	cancel()
	stream.OwnerStopped()
	if releases != 1 {
		t.Fatalf("shutdown released drained output %d times", releases)
	}
	budget.assertEmpty(t)
}

func TestLogicalStreamOwnedOutputPreservesOrdinaryWritesAndItemLimit(t *testing.T) {
	stream, _, budget, _ := newQueuedLogicalOutput(t)
	stream.options.MaxOutputItems = 2
	stream.scheduled.Store(true)
	defer stream.OwnerStopped()
	ordinary := []byte("copied")
	if n, err := stream.Write(ordinary); n != len(ordinary) || err != nil {
		t.Fatalf("ordinary write = %d, %v", n, err)
	}
	clear(ordinary)
	releases := 0
	if _, err := stream.writeMiddleEndOwned([]byte("owned"), func(err error) {
		releases++
		if err != nil {
			t.Errorf("owned output release = %v", err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	rejections := 0
	if n, err := stream.writeMiddleEndOwned([]byte("extra"), func(err error) {
		rejections++
		if !errors.Is(err, io.ErrShortBuffer) {
			t.Errorf("item limit release = %v", err)
		}
	}); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("item limit admission = %d, %v", n, err)
	}
	if rejections != 1 {
		t.Fatalf("rejected output release calls = %d", rejections)
	}
	first := make([]byte, len(ordinary))
	if n, err := stream.TryRead(first); n != len(first) || err != nil || string(first) != "copied" {
		t.Fatalf("ordinary copy read = %d, %v, %q", n, err, first)
	}
	last := make([]byte, len("owned"))
	if n, err := stream.TryRead(last); n != len(last) || err != nil || string(last) != "owned" {
		t.Fatalf("owned FIFO read = %d, %v, %q", n, err, last)
	}
	if releases != 1 {
		t.Fatalf("owned output release calls = %d", releases)
	}
	budget.assertEmpty(t)
}

func TestLogicalStreamOwnedOutputRejectsCapacityBeyondPreparedCredit(t *testing.T) {
	stream, _, budget, _ := newQueuedLogicalOutput(t)
	stream.scheduled.Store(true)
	defer stream.OwnerStopped()
	cancel, ok := prepareClientOutput(stream, 8)
	if !ok {
		t.Fatal("output preparation failed")
	}
	releases := 0
	if n, err := stream.writeMiddleEndOwned(make([]byte, 4, 16), func(err error) {
		releases++
		if !errors.Is(err, io.ErrShortBuffer) {
			t.Errorf("capacity rejection = %v", err)
		}
	}); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("oversized capacity admission = %d, %v", n, err)
	}
	if releases != 1 || stream.output != nil {
		t.Fatal("rejected output retained ownership")
	}
	assertLogicalOutputBudget(t, budget, 8, 1)
	cancel()
	cancel()
	budget.assertEmpty(t)
}

func TestLogicalStreamOwnedOutputShutdownReleasesPartialAndPreparedOutput(t *testing.T) {
	for _, stopOwner := range []bool{false, true} {
		name := "close"
		if stopOwner {
			name = "owner_stopped"
		}
		t.Run(name, func(t *testing.T) {
			stream, owner, budget, closed := newQueuedLogicalOutput(t)
			stream.scheduled.Store(true)
			defer stream.OwnerStopped()
			releases := 0
			for range 2 {
				data := make([]byte, 8, 16)
				if _, err := stream.writeMiddleEndOwned(data, func(err error) {
					releases++
					if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
						t.Errorf("shutdown release = %v", err)
					}
					clear(data)
				}); err != nil {
					t.Fatal(err)
				}
			}
			first, second := stream.output, stream.output.next
			if n, err := stream.TryRead(make([]byte, 4)); n != 4 || err != nil {
				t.Fatalf("partial read before stop = %d, %v", n, err)
			}
			cancel, ok := prepareClientOutput(stream, 64)
			if !ok {
				t.Fatal("output preparation failed")
			}
			if stopOwner {
				stream.OwnerStopped()
			} else {
				if err := stream.Close(); err != nil {
					t.Fatal(err)
				}
				runQueuedLogicalOutput(t, owner)
			}
			cancel()
			stream.OwnerStopped()
			runQueuedLogicalOutput(t, owner)
			select {
			case <-closed:
			default:
				t.Fatal("shutdown retained logical work")
			}
			if releases != 2 || stream.output != nil || stream.outputLast != nil || stream.outputOffset != 0 {
				t.Fatal("shutdown retained output or released it twice")
			}
			for _, entry := range []*logicalOutputEntry{first, second} {
				if entry.data != nil || entry.next != nil || entry.release != nil {
					t.Fatal("shutdown retained detached output entry")
				}
			}
			if n, err := stream.writeMiddleEndOwned([]byte("late"), func(err error) {
				releases++
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("late output release = %v", err)
				}
			}); n != 0 || !errors.Is(err, net.ErrClosed) || releases != 3 {
				t.Fatalf("late output = %d, %v, release calls=%d", n, err, releases)
			}
			budget.assertEmpty(t)
		})
	}
}

func TestLogicalStreamOwnedOutputCloseDuringReservationReleasesAdmission(t *testing.T) {
	stream, owner, budget, closed := newQueuedLogicalOutput(t)
	stream.scheduled.Store(true)
	defer stream.OwnerStopped()
	entered, resume := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	defer unblock()
	reserve := stream.options.OutputBudget.Reserve
	stream.options.OutputBudget.Reserve = func(bytes, items int) bool {
		close(entered)
		<-resume
		return reserve(bytes, items)
	}
	done := make(chan struct{})
	releases := 0
	go func() {
		defer close(done)
		stream.ownerMu.Lock()
		defer stream.ownerMu.Unlock()
		if n, err := stream.writeMiddleEndOwned(make([]byte, 8, 64), func(err error) {
			releases++
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("racing close release = %v", err)
			}
		}); n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Errorf("racing close write = %d, %v", n, err)
		}
	}()
	<-entered
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	unblock()
	<-done
	runQueuedLogicalOutput(t, owner)
	select {
	case <-closed:
	default:
		t.Fatal("racing close retained output admission")
	}
	if releases != 1 || stream.output != nil || stream.outputLast != nil {
		t.Fatal("racing close retained or released output twice")
	}
	budget.assertEmpty(t)
}

func assertLogicalOutputBudget(t *testing.T, budget *logicalTestBudget, wantBytes, wantItems int) {
	t.Helper()
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if budget.bytes != wantBytes || budget.items != wantItems {
		t.Fatalf("logical output budget = %d bytes, %d items; want %d bytes, %d items", budget.bytes, budget.items, wantBytes, wantItems)
	}
}
