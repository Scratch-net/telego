package middleend

import (
	"fmt"
	"unsafe"

	"github.com/scratch-net/telego/pkg/transport/faketls"
)

// ResponseOutputNodeBytes covers one native or logical linked output record.
const ResponseOutputNodeBytes = int(unsafe.Sizeof(struct {
	data    []byte
	next    *byte
	release func(error)
}{}))

// ResponseOutputOwnerBytes covers the explicit frontend allocation owner.
const ResponseOutputOwnerBytes = int(unsafe.Sizeof(struct {
	data       []byte
	allocation *ResponseAllocation
}{}))

// ResponseOutputCallbackBytes covers the Go compiler closure layout: code
// pointer then its single immutable owner pointer. This capture was verified
// with Go 1.27 compiler escape analysis. Allocator rounding is runtime overhead.
const ResponseOutputCallbackBytes = int(unsafe.Sizeof(struct {
	entry uintptr
	owner *byte
}{}))

// ResponseOutputMetadataBytes includes the retained output node, explicit
// allocation owner, and callback environment. Concrete layouts are checked in
// the frontend. Runtime allocator rounding remains outside the response pool.
const ResponseOutputMetadataBytes = ResponseOutputNodeBytes + ResponseOutputOwnerBytes + ResponseOutputCallbackBytes

// ClientResponseOutputBound bounds every supported frontend's encoded response
// for this event size. It includes framing, padding, and FakeTLS records, but
// excludes allocation handles and output metadata. No codec state is changed.
func ClientResponseOutputBound(kind LinkEventKind, packetBytes int) (int, error) {
	wire := 0
	switch kind {
	case LinkEventProxyAnswer:
		if packetBytes < 0 || packetBytes > MaxClientPacketSize {
			return 0, fmt.Errorf("%w: response packet length %d", ErrInvalidClientPacket, packetBytes)
		}
		wire = packetBytes + 7
	case LinkEventSimpleAck:
		wire = 4
	case LinkEventCloseExternal:
		return 0, nil
	default:
		return 0, fmt.Errorf("%w: response event kind %d", ErrInvalidClientPacket, kind)
	}
	// A split consumes one byte. Counting a complete probe window after it
	// overestimates the actual DRS window, which counts the split as a record.
	remaining := wire - 1
	probes := min(faketls.DRSRampRecords, (remaining+faketls.DRSProbeSize-1)/faketls.DRSProbeSize)
	remaining = max(0, remaining-probes*faketls.DRSProbeSize)
	records := 1 + probes + (remaining+faketls.MaxRecordPayload-1)/faketls.MaxRecordPayload
	return wire + records*faketls.RecordHeaderSize, nil
}

func responseEventAllocationCapacity(event LinkEvent) (int, error) {
	output, err := ClientResponseOutputBound(event.Kind, len(event.Packet))
	if err != nil || output == 0 {
		return cap(event.Packet), err
	}
	// Extra capacity is reserved promotion headroom, not retained packet bytes.
	// It guarantees promotion even when ordinary capacity is completely full.
	return max(cap(event.Packet), output+ResponseOutputMetadataBytes), nil
}
