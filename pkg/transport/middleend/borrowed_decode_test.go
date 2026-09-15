package middleend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestFrameDecoderBorrowedPayloadAndMaximumCapacity(t *testing.T) {
	payload := bytes.Repeat([]byte{0x37}, MaxMEFrameSize-FullFrameOverhead)
	wire, err := EncodeFrame(0, payload, ChecksumCRC32)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewFrameDecoder(0, MaxMEFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < len(wire); {
		end := min(offset+997, len(wire))
		previousCapacity := cap(decoder.buffer)
		consumed, err := decoder.Feed(wire[offset:end])
		if err != nil || consumed != end-offset {
			t.Fatalf("fragment Feed = %d, %v", consumed, err)
		}
		if cap(decoder.buffer) > MaxMEFrameSize || previousCapacity+cap(decoder.buffer) > 2*MaxMEFrameSize {
			t.Fatalf("decoder capacity escaped bound: old=%d new=%d", previousCapacity, cap(decoder.buffer))
		}
		offset = end
	}
	if cap(decoder.buffer) != MaxMEFrameSize {
		t.Fatalf("maximum frame retained capacity=%d, want %d", cap(decoder.buffer), MaxMEFrameSize)
	}
	backing := decoder.buffer[:cap(decoder.buffer)]
	frame, ok, err := decoder.nextBorrowed()
	if err != nil || !ok || !bytes.Equal(frame.Payload, payload) {
		t.Fatalf("borrowed Next = %t, %v", ok, err)
	}
	if &frame.Payload[0] != &backing[8] || cap(frame.Payload) != len(frame.Payload) {
		t.Fatal("borrowed frame copied payload or exposed later decoder storage")
	}
	decoder.retire()
	if decoder.buffer != nil || !allZero(backing) {
		t.Fatal("retired decoder retained its borrowed storage")
	}
}

func TestFrameDecoderOwningPayloadSurvivesReuse(t *testing.T) {
	decoder, err := NewFrameDecoder(0, 64)
	if err != nil {
		t.Fatal(err)
	}
	var first Frame
	for sequence := range 2 {
		payload := bytes.Repeat([]byte{byte(sequence + 1)}, 52)
		wire, err := EncodeFrame(int32(sequence), payload, ChecksumCRC32)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decoder.Feed(wire); err != nil {
			t.Fatal(err)
		}
		frame, ok, err := decoder.Next()
		if err != nil || !ok {
			t.Fatalf("owning Next = %t, %v", ok, err)
		}
		if sequence == 0 {
			first = frame
		}
	}
	decoder.retire()
	if !bytes.Equal(first.Payload, bytes.Repeat([]byte{1}, 52)) {
		t.Fatal("public Next payload changed during decoder reuse or retirement")
	}
}

func TestClientBootstrapBorrowedFramesFragmentedAndCoalesced(t *testing.T) {
	for _, mode := range []ChecksumMode{ChecksumCRC32, ChecksumCRC32C} {
		for _, fragment := range []int{1, 3, maxBootstrapBorrowedFeedSize * 2} {
			t.Run(fmt.Sprintf("crc%d_fragment%d", mode, fragment), func(t *testing.T) {
				client, server := borrowedTestHandshake(t)
				defer client.retire()
				handshake := borrowedTestPeerHandshake(mode)
				var wire []byte
				if mode == ChecksumCRC32C {
					wire = server.encodeHandshake(t, handshake)
				} else {
					// A peer that does not advertise CRC32C keeps its encoder
					// in the initial CRC32 mode for sequence zero and later.
					wire = server.encodePayload(t, mustMarshalHandshake(t, handshake))
				}
				packetSize := 64
				if fragment > maxBootstrapBorrowedFeedSize {
					packetSize = MaxClientPacketSize
				}
				packets := [][]byte{{1, 2, 3, 4}, bytes.Repeat([]byte{0x53}, packetSize), {5, 6, 7, 8}}
				for index, packet := range packets {
					payload, err := (ProxyAnswer{ConnectionID: int64(index + 1), Packet: packet}).MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
					wire = append(wire, server.encodePayload(t, payload)...)
				}
				readyCalls, frames, readyUpdates := 0, 0, 0
				var lastBorrowed []byte
				for _, part := range fragmentBytes(wire, fragment) {
					for len(part) != 0 {
						n, update, err := client.feedFrames(part, func() error {
							readyCalls++
							if !client.Ready() || client.decoder.ChecksumMode() != mode || client.encoder.ChecksumMode() != mode {
								t.Fatal("ready callback preceded handshake validation or checksum negotiation")
							}
							return nil
						}, func(frame Frame) error {
							if readyCalls != 1 || frame.Sequence != int32(frames) {
								t.Fatalf("frame %d preceded readiness or changed order", frame.Sequence)
							}
							answer, err := parseProxyAnswer(frame.Payload, false)
							if err != nil {
								return err
							}
							if answer.ConnectionID != int64(frames+1) || !bytes.Equal(answer.Packet, packets[frames]) {
								t.Fatal("borrowed response changed its routing or payload")
							}
							if cap(frame.Payload) != len(frame.Payload) || cap(answer.Packet) != len(answer.Packet) ||
								&answer.Packet[0] != &frame.Payload[ProxyAnswerHeaderSize] {
								t.Fatal("borrowed response copied or exposed storage outside its packet")
							}
							lastBorrowed = answer.Packet
							frames++
							return nil
						})
						if err != nil || n == 0 || n > maxBootstrapBorrowedFeedSize {
							t.Fatalf("borrowed feed consumed=%d, err=%v", n, err)
						}
						if len(update.Frames) != 0 || cap(client.decoder.buffer) > MaxMEFrameSize || cap(client.decrypter.pending) >= 32 {
							t.Fatal("borrowed feed retained a frame batch or exceeded decoder bounds")
						}
						if update.BecameReady {
							readyUpdates++
						}
						part = part[n:]
					}
				}
				if frames != len(packets) || readyCalls != 1 || readyUpdates != 1 {
					t.Fatalf("frames=%d ready calls=%d ready updates=%d", frames, readyCalls, readyUpdates)
				}
				if err := client.Finish(); err != nil {
					t.Fatal(err)
				}
				client.retire()
				if !allZero(lastBorrowed) || client.decoder != nil || client.decrypter != nil {
					t.Fatal("bootstrap retirement retained borrowed payload or decoder storage")
				}
			})
		}
	}
}

func TestClientBootstrapBorrowedCallbacksFailPermanently(t *testing.T) {
	for _, failReady := range []bool{false, true} {
		t.Run(fmt.Sprintf("ready=%t", failReady), func(t *testing.T) {
			client, server := borrowedTestHandshake(t)
			wire := server.encodeHandshake(t, borrowedTestPeerHandshake(ChecksumCRC32C))
			for id := range 2 {
				wire = append(wire, server.encodePayload(t, (Pong{ID: uint64(id)}).MarshalBinary())...)
			}
			failure := errors.New("event handoff failed")
			ready, frames := 0, 0
			_, update, err := client.feedFrames(wire, func() error {
				ready++
				if failReady {
					return failure
				}
				return nil
			}, func(Frame) error {
				frames++
				return failure
			})
			if !errors.Is(err, failure) || update.BecameReady || len(update.Frames) != 0 || client.Ready() {
				t.Fatalf("callback failure returned update=%+v err=%v ready=%t", update, err, client.Ready())
			}
			wantFrames := 1
			if failReady {
				wantFrames = 0
			}
			if ready != 1 || frames != wantFrames || client.decoder != nil || client.decrypter != nil {
				t.Fatal("callback failure delivered later frames or retained protocol state")
			}
			if _, _, err := client.Feed(nil); !errors.Is(err, failure) {
				t.Fatalf("callback failure was not permanent: %v", err)
			}
		})
	}
}

func TestClientBootstrapPublicFeedRetainsIndependentPayloads(t *testing.T) {
	client, server := borrowedTestHandshake(t)
	wire := server.encodeHandshake(t, borrowedTestPeerHandshake(ChecksumCRC32C))
	first := (Pong{ID: 12}).MarshalBinary()
	wire = append(wire, server.encodePayload(t, first)...)
	_, update, err := client.Feed(wire)
	if err != nil || len(update.Frames) != 1 {
		t.Fatalf("public feed frames=%d, err=%v", len(update.Frames), err)
	}
	if _, _, err := client.Feed(server.encodePayload(t, (Pong{ID: 13}).MarshalBinary())); err != nil {
		t.Fatal(err)
	}
	client.retire()
	if !bytes.Equal(update.Frames[0].Payload, first) {
		t.Fatal("public feed payload changed after decoder reuse or retirement")
	}
}

func TestClientBootstrapBorrowedCallbackEncode(t *testing.T) {
	for _, invalidOutbound := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalid_outbound=%t", invalidOutbound), func(t *testing.T) {
			client, server := borrowedTestHandshake(t)
			defer client.retire()
			wire := server.encodeHandshake(t, borrowedTestPeerHandshake(ChecksumCRC32C))
			for id := range 2 {
				wire = append(wire, server.encodePayload(t, (Ping{ID: uint64(id + 17)}).MarshalBinary())...)
			}
			frames := 0
			var borrowed []byte
			_, update, err := client.feedFrames(wire, nil, func(frame Frame) error {
				frames++
				borrowed = frame.Payload
				ping, err := ParsePing(frame.Payload)
				if err != nil {
					return err
				}
				payload := Pong(ping).MarshalBinary()
				if invalidOutbound {
					payload = []byte{1}
				}
				reply, err := client.Encode(payload)
				if err != nil {
					return err
				}
				if !bytes.Equal(frame.Payload, ping.MarshalBinary()) {
					t.Fatal("successful Encode changed the borrowed inbound payload")
				}
				consumed, plaintext := server.decrypter.Feed(reply)
				if consumed != len(reply) {
					t.Fatal("server did not consume the complete automatic reply")
				}
				if _, err := server.decoder.Feed(plaintext); err != nil {
					return err
				}
				response, ok, err := server.decoder.Next()
				if err != nil || !ok {
					t.Fatalf("automatic reply decode = %t, %v", ok, err)
				}
				pong, err := ParsePong(response.Payload)
				if err != nil || pong.ID != ping.ID {
					t.Fatalf("automatic pong = %+v, %v", pong, err)
				}
				return nil
			})
			if invalidOutbound {
				if !errors.Is(err, ErrInvalidFrameSize) || frames != 1 || client.Ready() || update.BecameReady {
					t.Fatalf("Encode failure: err=%v frames=%d ready=%t", err, frames, client.Ready())
				}
				if client.decoder != nil || client.decrypter != nil || !allZero(borrowed) {
					t.Fatal("Encode failure retained borrowed payload or decoder state")
				}
				if _, _, nextErr := client.Feed(nil); !errors.Is(nextErr, ErrInvalidFrameSize) {
					t.Fatalf("Encode failure was not permanent: %v", nextErr)
				}
				return
			}
			if err != nil || frames != 2 || !client.Ready() || !update.BecameReady || len(update.Frames) != 0 {
				t.Fatalf("automatic replies: err=%v frames=%d ready=%t", err, frames, client.Ready())
			}
		})
	}
}

func TestProxyAnswerBorrowedParserPreservesValidation(t *testing.T) {
	wire, err := (ProxyAnswer{ConnectionID: 19, Packet: []byte{1, 2, 3, 4}}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	borrowed, err := parseProxyAnswer(wire, false)
	if err != nil || &borrowed.Packet[0] != &wire[ProxyAnswerHeaderSize] || cap(borrowed.Packet) != len(borrowed.Packet) {
		t.Fatalf("borrowed proxy answer = %+v, %v", borrowed, err)
	}
	owned, err := ParseProxyAnswer(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire[ProxyAnswerHeaderSize]++
	if borrowed.Packet[0] != 2 || owned.Packet[0] != 1 {
		t.Fatal("proxy answer parser ownership changed")
	}
	tests := []struct {
		name string
		wire []byte
		want error
	}{
		{"short", wire[:15], ErrInvalidRPCPayload},
		{"unaligned", wire[:len(wire)-1], ErrInvalidRPCPayload},
		{"operation", slices.Clone(wire), ErrInvalidRPCPayload},
		{"flags", slices.Clone(wire), ErrInvalidRPCFlags},
		{"maximum", make([]byte, ProxyAnswerHeaderSize+MaxClientPacketSize+4), ErrClientPacketTooLarge},
	}
	binary.LittleEndian.PutUint32(tests[2].wire[:4], OperationProxyRequest)
	binary.LittleEndian.PutUint32(tests[3].wire[4:8], 0x20)
	binary.LittleEndian.PutUint32(tests[4].wire[:4], OperationProxyAnswer)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if answer, err := parseProxyAnswer(test.wire, false); !errors.Is(err, test.want) || answer.Packet != nil {
				t.Fatalf("borrowed parser error=%v packet length=%d", err, len(answer.Packet))
			}
		})
	}
}

func borrowedTestHandshake(t *testing.T) (*ClientBootstrap, *testServerState) {
	t.Helper()
	client, initial := newStartedTestBootstrap(t)
	server := newTestServerState(t, initial)
	_, update, err := client.feedFrames(server.nonceWire, nil, func(Frame) error {
		t.Fatal("nonce stage delivered an RPC frame")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	server.acceptClientHandshake(t, update.Outbound)
	return client, server
}

func borrowedTestPeerHandshake(mode ChecksumMode) HandshakePacket {
	var flags uint32
	if mode == ChecksumCRC32C {
		flags = HandshakeFlagCRC32C
	}
	return HandshakePacket{
		Flags: flags, Sender: ProcessID{IP: 0x08080808, Port: 443, PID: 71, Uptime: 12345}, Peer: testLocalProcessID(),
	}
}
