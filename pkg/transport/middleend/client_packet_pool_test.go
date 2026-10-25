package middleend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

func TestClientPacketBufferPoolBoundAndExclusiveOwnership(t *testing.T) {
	pool := new(clientPacketBufferPool)
	retained := 0
	for _, size := range clientPacketBufferSizes {
		first := pool.get(size, size)
		second := pool.get(size, size)
		excess := pool.get(size, size)
		if first == second || first == excess || second == excess {
			t.Fatal("live borrowers share storage")
		}
		pool.put(first)
		pool.put(second)
		pool.put(excess)
		retained += 2 * size
	}
	if retained >= 4<<20 {
		t.Fatalf("idle buffer capacity %d exceeds the 4 MiB bound", retained)
	}
	for class, size := range clientPacketBufferSizes {
		first := pool.get(size, size)
		second := pool.get(size, size)
		third := pool.get(size, size)
		if first == second || first == third || second == third {
			t.Fatal("cache returned a buffer still owned by another borrower")
		}
		for i := range pool.slots[class] {
			if pool.slots[class][i].Load() != nil {
				t.Fatal("empty cache still owns a borrowed buffer")
			}
		}
	}
	for _, limit := range []int{1, 65535, 65537, 131073, MaxClientPacketSize} {
		if buffer := pool.get(limit, limit); buffer != nil {
			t.Fatalf("rounded buffer capacity %d exceeds exact limit %d", cap(buffer.data), limit)
		}
	}
}

func TestClientPacketDecoderPoolPreservesOutputAndClearsScratch(t *testing.T) {
	pool := new(clientPacketBufferPool)
	decoder := pooledTestDecoder(t, pool)
	payload := bytes.Repeat([]byte{0x93}, 128*1024-4)
	wire := encodeClientInputFixture(t, obfuscated2.ConnectionTypeIntermediate, payload, false, nil)
	// Exercise both growth and completion returns, including used prefixes.
	for offset := 0; offset < len(wire); offset += 64 * 1024 {
		end := min(offset+64*1024, len(wire))
		if n, err := decoder.Feed(wire[offset:end]); err != nil || n != end-offset {
			t.Fatalf("Feed = %d, %v", n, err)
		}
	}
	packet, ok, err := decoder.Next()
	if err != nil || !ok || !bytes.Equal(packet.Payload, payload) {
		t.Fatalf("Next = %t, %v", ok, err)
	}
	if decoder.RetainedCapacityBytes() != 0 || decoder.pooledBuffer != nil {
		t.Fatal("drained decoder retains large scratch storage")
	}
	for _, size := range []int{64 * 1024, 128 * 1024} {
		buffer := pool.get(size, size)
		if !bytes.Equal(buffer.data, make([]byte, size)) {
			t.Fatalf("reclaimed %d-byte buffer contains plaintext", size)
		}
		// Reuse belongs exclusively to this borrower. A previously returned
		// packet must remain intact while its old scratch buffer changes.
		for i := range buffer.data {
			buffer.data[i] = 0x57
		}
	}
	if !bytes.Equal(packet.Payload, payload) || cap(packet.Payload) != len(payload) {
		t.Fatal("scratch reuse changed the independently owned packet")
	}
}

func TestClientPacketDecoderPoolTerminalCleanup(t *testing.T) {
	for _, terminal := range []string{"close", "truncated", "invalid"} {
		t.Run(terminal, func(t *testing.T) {
			pool := new(clientPacketBufferPool)
			decoder := pooledTestDecoder(t, pool)
			wire := bytes.Repeat([]byte{0xac}, 65536)
			length := uint32(128 * 1024)
			if terminal == "invalid" {
				length = uint32(MaxClientPacketSize + 4)
			}
			binary.LittleEndian.PutUint32(wire, length)
			if n, err := decoder.Feed(wire); err != nil || n != len(wire) {
				t.Fatalf("Feed = %d, %v", n, err)
			}
			scratch := decoder.pooledBuffer
			switch terminal {
			case "truncated":
				if !errors.Is(decoder.Finish(), ErrIncompleteClientPacket) {
					t.Fatal("truncated packet was accepted")
				}
			case "invalid":
				if _, ok, err := decoder.Next(); ok || err == nil {
					t.Fatal("oversized packet was accepted")
				}
			}
			_ = decoder.Close()
			_ = decoder.Close()
			if decoder.pooledBuffer != nil || decoder.RetainedCapacityBytes() != 0 {
				t.Fatal("terminal decoder retained scratch")
			}
			first := pool.get(len(wire), len(wire))
			second := pool.get(len(wire), len(wire))
			if first != scratch || first == second {
				t.Fatal("terminal cleanup lost or returned scratch more than once")
			}
			if !bytes.Equal(first.data, make([]byte, len(wire))) {
				t.Fatal("terminal cleanup left plaintext in returned scratch")
			}
		})
	}
}

func TestClientPacketDecoderPoolConcurrentReuse(t *testing.T) {
	pool := new(clientPacketBufferPool)
	var workers sync.WaitGroup
	for worker := range 8 {
		decoder := pooledTestDecoder(t, pool)
		workers.Go(func() {
			defer decoder.Close()
			wire := bytes.Repeat([]byte{byte(worker + 1)}, 128*1024)
			binary.LittleEndian.PutUint32(wire, uint32(len(wire)-4))
			for range 100 {
				if n, err := decoder.Feed(wire); err != nil || n != len(wire) {
					t.Errorf("Feed = %d, %v", n, err)
					return
				}
				packet, ok, err := decoder.Next()
				if err != nil || !ok || !bytes.Equal(packet.Payload, wire[4:]) {
					t.Errorf("cross-decoder corruption: Next = %t, %v", ok, err)
					return
				}
			}
		})
	}
	workers.Wait()
}

func pooledTestDecoder(t *testing.T, pool *clientPacketBufferPool) *ClientPacketDecoder {
	t.Helper()
	decoder, err := NewClientPacketDecoder(obfuscated2.ConnectionTypeIntermediate, MaxClientPacketSize)
	if err != nil {
		t.Fatal(err)
	}
	decoder.bufferPool = pool
	t.Cleanup(func() { _ = decoder.Close() })
	return decoder
}
