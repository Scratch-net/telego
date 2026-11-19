package dc

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

// fakeDCReply changes the resPQ that serveFakeDC sends. It gets the request
// nonce and returns the decrypted frame body, without the length prefix.
type fakeDCReply func(nonce []byte) []byte

func validResPQ(nonce []byte) []byte {
	body := make([]byte, probeEnvelopeSize+4+16+16+12)
	binary.LittleEndian.PutUint32(body[16:20], uint32(len(body)-probeEnvelopeSize))
	binary.LittleEndian.PutUint32(body[20:24], ctorResPQ)
	copy(body[24:40], nonce)
	_, _ = rand.Read(body[40:56])
	return body
}

// serveFakeDC answers one probe like a Telegram DC. It returns the DC ID
// from the obfuscated2 frame, or an error when the request is malformed.
func serveFakeDC(conn net.Conn, reply fakeDCReply) (int, error) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	frame := make([]byte, obfuscated2.FrameSize)
	if _, err := io.ReadFull(conn, frame); err != nil {
		return 0, err
	}
	reader, err := obfuscated2.NewAESCTR(frame[8:40], frame[40:56])
	if err != nil {
		return 0, err
	}
	var reversed [48]byte
	for i := range 48 {
		reversed[47-i] = frame[8+i]
	}
	writer, err := obfuscated2.NewAESCTR(reversed[:32], reversed[32:])
	if err != nil {
		return 0, err
	}
	header := make([]byte, obfuscated2.FrameSize)
	reader.XORKeyStream(header, frame)
	if got := obfuscated2.ConnectionType(binary.LittleEndian.Uint32(header[56:60])); got != obfuscated2.ConnectionTypePaddedIntermediate {
		return 0, errors.New("probe did not use padded-intermediate framing")
	}
	dc := int(int16(binary.LittleEndian.Uint16(header[60:62])))
	request := make([]byte, 4+probeEnvelopeSize+4+16)
	if _, err := io.ReadFull(conn, request); err != nil {
		return dc, err
	}
	reader.XORKeyStream(request, request)
	body := request[4:]
	if binary.LittleEndian.Uint32(request[0:4]) != uint32(len(body)) ||
		binary.LittleEndian.Uint64(body[0:8]) != 0 ||
		binary.LittleEndian.Uint64(body[8:16])&3 != 0 ||
		binary.LittleEndian.Uint32(body[16:20]) != 20 ||
		binary.LittleEndian.Uint32(body[20:24]) != ctorReqPQMulti {
		return dc, errors.New("malformed req_pq_multi")
	}
	response := reply(body[24:40])
	out := make([]byte, 4+len(response))
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(response)))
	copy(out[4:], response)
	writer.XORKeyStream(out, out)
	_, err = conn.Write(out)
	return dc, err
}

func TestProbeConnectionRequiresResPQ(t *testing.T) {
	for _, test := range []struct {
		name  string
		reply fakeDCReply
		want  error
	}{
		{name: "valid resPQ", reply: validResPQ},
		{name: "padded resPQ", reply: func(nonce []byte) []byte { return append(validResPQ(nonce), make([]byte, 15)...) }},
		{name: "nonce mismatch", reply: func(nonce []byte) []byte {
			body := validResPQ(nonce)
			body[24] ^= 1
			return body
		}, want: errNotTelegram},
		{name: "wrong constructor", reply: func(nonce []byte) []byte {
			body := validResPQ(nonce)
			binary.LittleEndian.PutUint32(body[20:24], 0x12345678)
			return body
		}, want: errNotTelegram},
		{name: "short frame", reply: func([]byte) []byte { return make([]byte, minResPQFrame-1) }, want: errNotTelegram},
		{name: "large frame", reply: func([]byte) []byte { return make([]byte, maxResPQFrame+4) }, want: errNotTelegram},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			served := make(chan error, 1)
			go func() {
				dc, err := serveFakeDC(server, test.reply)
				if err == nil && dc != -4 {
					err = errors.New("probe sent the wrong DC")
				}
				served <- err
			}()
			rtt, err := probeConnection(client, -4, time.Second)
			if !errors.Is(err, test.want) {
				t.Fatalf("probe error = %v, want %v", err, test.want)
			}
			if (err == nil) != (rtt > 0) {
				t.Fatalf("rtt %s with error %v", rtt, err)
			}
			_ = client.Close()
			if serveErr := <-served; serveErr != nil && test.want == nil {
				t.Fatal(serveErr)
			}
		})
	}
}

type probeResultConn struct {
	net.Conn
	readErr          error
	writeN           *int
	writeErr         error
	readDeadlineErr  error
	writeDeadlineErr error
}

func (c *probeResultConn) Read([]byte) (int, error) { return 0, c.readErr }

func (c *probeResultConn) Write(data []byte) (int, error) {
	if c.writeN != nil {
		return *c.writeN, c.writeErr
	}
	return len(data), c.writeErr
}

func (c *probeResultConn) SetReadDeadline(time.Time) error  { return c.readDeadlineErr }
func (c *probeResultConn) SetWriteDeadline(time.Time) error { return c.writeDeadlineErr }

// A reset or close used to count as a healthy DC. A middlebox that kills
// connections to Telegram addresses must now fail the probe.
func TestProbeConnectionRejectsCloseResetAndErrors(t *testing.T) {
	otherError := errors.New("unrelated I/O failure")
	for _, test := range []struct {
		name string
		conn probeResultConn
		want error
	}{
		{name: "peer EOF", conn: probeResultConn{readErr: io.EOF}, want: io.EOF},
		{name: "peer reset", conn: probeResultConn{readErr: &net.OpError{Op: "read", Err: syscall.ECONNRESET}}, want: syscall.ECONNRESET},
		{name: "timeout", conn: probeResultConn{readErr: &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}}, want: os.ErrDeadlineExceeded},
		{name: "local close", conn: probeResultConn{readErr: net.ErrClosed}, want: net.ErrClosed},
		{name: "write error", conn: probeResultConn{writeErr: otherError}, want: otherError},
		{name: "short write", conn: probeResultConn{writeN: new(63)}, want: io.ErrShortWrite},
		{name: "write deadline", conn: probeResultConn{writeDeadlineErr: otherError}, want: otherError},
		{name: "read deadline", conn: probeResultConn{readDeadlineErr: otherError}, want: otherError},
	} {
		t.Run(test.name, func(t *testing.T) {
			rtt, err := probeConnection(&test.conn, 2, time.Second)
			if !errors.Is(err, test.want) || rtt != 0 {
				t.Fatalf("probe = %s, %v; want failure %v", rtt, err, test.want)
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
	rtt, err := probeConnection(client, 2, 20*time.Millisecond)
	_ = client.Close()
	<-readDone
	if !errors.Is(err, os.ErrDeadlineExceeded) || rtt != 0 {
		t.Fatalf("silent peer probe = %s, %v; want failure", rtt, err)
	}
}

func TestProbeMessageID(t *testing.T) {
	now := time.Unix(1_700_000_000, 500_000_000)
	id := probeMessageID(now)
	if id>>32 != 1_700_000_000 || uint32(id) != 1<<31 {
		t.Fatalf("message id %#x", id)
	}
}
