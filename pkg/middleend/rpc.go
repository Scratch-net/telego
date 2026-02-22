package middleend

// RPC type constants for ME protocol.
const (
	// Client -> ME
	RPCTypePing    uint32 = 0x7abe77ed // Keepalive ping
	RPCTypeData    uint32 = 0x02014b50 // Forward data
	RPCTypeConnect uint32 = 0x02034b50 // Connection request

	// ME -> Client
	RPCTypePong     uint32 = 0x347773ed // Keepalive pong
	RPCTypeResponse uint32 = 0x02024b50 // Data response
	RPCTypeError    uint32 = 0x02044b50 // Error response
)

// RPCFrame represents an ME protocol frame.
type RPCFrame struct {
	Length  uint32
	Type    uint32
	Payload []byte
}
