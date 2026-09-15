package gproxy

import (
	"bytes"
	"testing"

	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

func TestMiddleEndSmallAckFitsCarrierHeadroom(t *testing.T) {
	handler, link, _, _, frame, decryptor := newMiddleEndTestHandler(t, 2, obfuscated2.ConnectionTypeIntermediate, nil)
	x := newLogicalTestStream(t, handler, func(options *LogicalStreamOptions) {
		reserve := options.OutputBudget.Reserve
		options.OutputBudget.Reserve = func(bytes, items int) bool {
			return bytes <= 4 && reserve(bytes, items)
		}
	})
	x.write(t, frame)
	var id int64
	awaitSpliceCondition(t, "logical ACK binding committed", func() bool {
		runLogicalOwner(t, x.owner, func() {
			if client := x.stream.ctx.middleEnd; client != nil {
				id = client.binding.ConnectionID()
			}
		})
		return id != 0
	})
	link.emit(middleend.LinkEvent{Kind: middleend.LinkEventSimpleAck, ConnectionID: id, ConfirmKey: 42})
	wire := x.read(t, 4)
	decryptor.XORKeyStream(wire, wire)
	if !bytes.Equal(wire, []byte{42, 0, 0, 0}) || handler.middleEnd.stats().OutputEvictions != 0 {
		t.Fatalf("four-byte carrier headroom blocked or corrupted ACK: %x", wire)
	}
}
