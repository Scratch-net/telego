package gproxy

import (
	"context"
	"net"

	"github.com/panjf2000/gnet/v2"
)

// clientEndpoint is the owner-only byte interface shared by sockets and WEB
// streams. Socket descriptors and gnet connection contexts stay in adapters.
type clientEndpoint interface {
	Peek(int) ([]byte, error)
	Discard(int) (int, error)
	InboundBuffered() int
	Write([]byte) (int, error)
	OutboundBuffered() int
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	Close() error
}

func clientOwner(c clientEndpoint) gnet.EventLoop {
	if stream, ok := c.(*LogicalStream); ok {
		return stream.options.Owner
	}
	return c.(gnet.Conn).EventLoop()
}

func executeClient(c clientEndpoint, run gnet.Runnable) error {
	if stream, ok := c.(*LogicalStream); ok {
		return stream.execute(run)
	}
	return clientOwner(c).Execute(context.Background(), run)
}

func wakeClient(c clientEndpoint) error {
	if stream, ok := c.(*LogicalStream); ok {
		return stream.schedule()
	}
	return c.(gnet.Conn).Wake(nil)
}

func asyncWriteClient(c clientEndpoint, data []byte, callback func(error) error) error {
	if stream, ok := c.(*LogicalStream); ok {
		err := stream.execute(gnet.RunnableFunc(func(context.Context) error {
			err := stream.writeReserved(data)
			return callback(err)
		}))
		if err != nil {
			stream.releaseOutput(len(data), 1)
		}
		return err
	}
	return c.(gnet.Conn).AsyncWrite(data, func(_ gnet.Conn, err error) error {
		return callback(err)
	})
}

func reserveClientOutput(c clientEndpoint, want, minimum int) int {
	if stream, ok := c.(*LogicalStream); ok {
		return stream.reserveOutput(want, minimum)
	}
	return want
}

func releaseClientOutput(c clientEndpoint, bytes, items int) {
	if stream, ok := c.(*LogicalStream); ok {
		stream.releaseOutput(bytes, items)
	}
}

// prepareClientOutput reserves a complete ME response before taking its
// readiness event or advancing its cipher. The release closes unused credit.
func prepareClientOutput(c clientEndpoint, maximum int) (func(), bool) {
	stream, ok := c.(*LogicalStream)
	if !ok {
		return func() {}, true
	}
	if stream.reserveOutput(maximum, maximum) == 0 {
		return nil, false
	}
	stream.preparedOutput = maximum
	return func() {
		if stream.preparedOutput != 0 {
			stream.releaseOutput(stream.preparedOutput, 1)
			stream.preparedOutput = 0
		}
	}, true
}

// gnet invokes OnClose before freeing its outbound buffer. The next upstream
// owner task is the release barrier for logical input charges and OnClosed.
func (h *ProxyHandler) completeUpstreamClose(conn gnet.Conn, client clientEndpoint, output *relayOutput, done func()) {
	complete := func() {
		output.destinationClosed()
		if done != nil {
			done()
		}
	}
	if _, logical := client.(*LogicalStream); !logical {
		complete()
		return
	}
	barrier := h.upstreamCloses.add(complete)
	_ = conn.EventLoop().Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		barrier.finish()
		return nil
	}))
	// Execute can succeed after the poller exits. Stop retires any remaining
	// barrier after all owners release their buffers, including rejected tasks.
}
