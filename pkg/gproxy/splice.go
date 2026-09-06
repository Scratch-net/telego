package gproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/netx"
)

const spliceDrainCheckInterval = 5 * time.Millisecond

// spliceConnContext carries raw TLS bytes between the client and Nginx.
// Nginx retains TLS termination; neither relay owner interprets these bytes.
type spliceConnContext struct {
	proxy      *ProxyHandler
	client     clientEndpoint
	clientCtx  *ConnContext
	cancelDial context.CancelFunc
	toClient   *relayOutput
	upstream   atomic.Pointer[spliceUpstream]
	active     atomic.Bool
	closed     atomic.Bool
	onClosed   func()
}

type spliceUpstream struct {
	conn   gnet.Conn
	output *relayOutput
}

func dialSpliceTarget(ctx context.Context, address string) (net.Conn, error) {
	return netx.NewDialer().DialContext(ctx, "tcp", address)
}

func (h *ProxyHandler) spliceIdleTimeout() time.Duration {
	if h.config.SpliceIdleTimeout > 0 {
		return h.config.SpliceIdleTimeout
	}
	return 30 * time.Second
}

func (h *ProxyHandler) startSplice(client clientEndpoint, ctx *ConnContext) gnet.Action {
	if h.config.SpliceHost == "" {
		h.logger.Debug("[#%d] no splice host configured, closing", ctx.id)
		return h.failHandshake(ctx, handshakeStageForState(ctx.State()))
	}
	ctx.stopHandshakeTimer()
	ctx.SetState(StateSplicing)
	dialContext, cancelDial := context.WithCancel(h.upstreamContext)
	splice := &spliceConnContext{proxy: h, client: client, clientCtx: ctx, cancelDial: cancelDial}
	splice.toClient = newRelayOutput(client, nil, ctx, h.maxWriteBuffer)
	splice.toClient.buffered = client.OutboundBuffered()
	ctx.splice.Store(splice)
	ctx.startConnectionIdle(client, h.spliceIdleTimeout())

	address := net.JoinHostPort(h.config.SpliceHost, fmt.Sprint(h.config.SplicePort))
	if override := ctx.consumeSpliceOverride(); override != "" {
		address = override
	}
	// Capture client metadata on its owner before dialing. The public client
	// may close and release gnet's address storage while the dial is running.
	var header []byte
	if h.config.SpliceProxyProtocol > 0 {
		header = buildProxyProtocolHeader(h.config.SpliceProxyProtocol,
			ctx.RealClientAddr(client.RemoteAddr()), client.LocalAddr())
	}
	h.logger.Debug("[#%d] splicing to %s", ctx.id, address)
	done := retainLogicalWork(client)
	go func() { defer done(); h.dialSplice(dialContext, splice, address, header) }()
	return gnet.None
}

// Only connection establishment runs outside gnet. All buffered input, output,
// activation, and close processing run on their respective owners.
func (h *ProxyHandler) dialSplice(dialContext context.Context, splice *spliceConnContext, address string, header []byte) {
	defer splice.cancelDial()
	if h.dcClient == nil || splice.clientCtx.State() == StateClosed {
		_ = splice.client.Close()
		return
	}
	conn, err := h.spliceDial(dialContext, address)
	if err != nil {
		h.logger.Debug("failed to dial splice target %s: %v", address, err)
		_ = splice.client.Close()
		return
	}
	// Enrollment duplicates the descriptor; the original belongs to this dial.
	defer conn.Close()
	if splice.clientCtx.State() == StateClosed || dialContext.Err() != nil {
		_ = splice.client.Close()
		return
	}
	splice.onClosed = retainLogicalWork(splice.client)
	upstream, err := h.dcClient.EnrollContext(conn, splice)
	if err != nil {
		splice.onClosed()
		h.logger.Debug("failed to enroll splice target %s: %v", address, err)
		_ = splice.client.Close()
		return
	}
	if err := executeClient(splice.client, gnet.RunnableFunc(func(context.Context) error {
		if splice.clientCtx.State() == StateClosed {
			return upstream.Close()
		}
		if splice.closed.Load() {
			// An early EOF has already handed its retained input to this owner.
			return nil
		}
		target := splice.upstream.Load()
		if target == nil {
			_ = upstream.Close()
			return splice.client.Close()
		}
		if len(header) > 0 {
			if target.output.reserve(len(header), len(header)) != len(header) {
				return splice.client.Close()
			}
			if err := target.output.write(header, nil); err != nil {
				return err
			}
		}
		// Header submission precedes all client bytes on the same output queue.
		splice.active.Store(true)
		if action := h.handleSplice(splice.client, splice.clientCtx); action == gnet.Close {
			return splice.client.Close()
		}
		return upstream.Wake(nil)
	})); err != nil {
		_ = upstream.Close()
		_ = splice.client.Close()
	}
}

func (splice *spliceConnContext) onOpen(conn gnet.Conn) gnet.Action {
	if splice.clientCtx.State() == StateClosed {
		return gnet.Close
	}
	output := newRelayOutput(conn, splice.client, splice.clientCtx, splice.proxy.maxWriteBuffer)
	output.buffered = conn.OutboundBuffered()
	splice.toClient.mu.Lock()
	splice.toClient.source = conn
	splice.toClient.mu.Unlock()
	splice.upstream.Store(&spliceUpstream{conn: conn, output: output})
	return gnet.None
}

func (splice *spliceConnContext) onTraffic(conn gnet.Conn) gnet.Action {
	if splice.clientCtx.State() == StateClosed {
		return gnet.Close
	}
	if conn.InboundBuffered() > max(splice.proxy.maxWriteBuffer, relayBatchSize) {
		return gnet.Close
	}
	if !splice.active.Load() {
		return gnet.None
	}
	return relaySpliceBytes(conn, splice.toClient, splice.clientCtx)
}

func (h *ProxyHandler) handleSplice(client clientEndpoint, ctx *ConnContext) gnet.Action {
	if ctx.spliceDrainRequested.Load() {
		return h.handleSpliceDrain(client, ctx)
	}
	if client.InboundBuffered() > max(h.maxWriteBuffer, relayBatchSize) {
		return gnet.Close
	}
	splice := ctx.splice.Load()
	if splice == nil || !splice.active.Load() {
		return gnet.None
	}
	if splice.closed.Load() {
		return gnet.None
	}
	target := splice.upstream.Load()
	if target == nil {
		return gnet.Close
	}
	return relaySpliceBytes(client, target.output, ctx)
}

func relaySpliceBytes(source clientEndpoint, output *relayOutput, ctx *ConnContext) gnet.Action {
	data, err := source.Peek(-1)
	if err != nil || len(data) == 0 {
		return gnet.None
	}
	n := output.reserve(min(len(data), relayBatchSize), 1)
	if n == 0 {
		return gnet.None
	}
	buffer := make([]byte, n)
	copy(buffer, data[:n])
	if discarded, err := source.Discard(n); err != nil || discarded != n {
		output.cancelReservation(n)
		return gnet.Close
	}
	if err := output.write(buffer, nil); err != nil {
		return gnet.Close
	}
	ctx.refreshAuthenticatedIdle()
	if source.InboundBuffered() > 0 {
		if err := wakeClient(source); err != nil {
			return gnet.Close
		}
	}
	return gnet.None
}

func (splice *spliceConnContext) onClose(conn gnet.Conn, err error) gnet.Action {
	var output *relayOutput
	splice.closed.Store(true)
	if target := splice.upstream.Load(); target != nil {
		output = target.output
		output.close()
	}
	defer splice.proxy.completeUpstreamClose(conn, splice.client, output, splice.onClosed)
	splice.toClient.close()
	if splice.clientCtx.State() == StateClosed {
		return gnet.None
	}
	if !errors.Is(err, io.EOF) {
		_ = splice.client.Close()
		return gnet.None
	}
	// gnet releases unconsumed inbound bytes immediately after OnClose, even
	// when backpressure left a tail. Retain that bounded tail before release.
	data, _ := conn.Peek(-1)
	if len(data) > max(splice.proxy.maxWriteBuffer, relayBatchSize) {
		_ = splice.client.Close()
		return gnet.None
	}
	var release func()
	if stream, ok := splice.client.(*LogicalStream); ok && len(data) > 0 {
		size := len(data)
		if !stream.reserveAuxInput(size, 1) {
			_ = stream.Close()
			return gnet.None
		}
		release = func() { stream.releaseAuxInput(size, 1) }
	}
	tail := make([]byte, len(data))
	copy(tail, data)
	splice.proxy.beginSpliceClientDrain(splice.client, splice.clientCtx, tail, release)
	return gnet.None
}

func (ctx *ConnContext) closeSplice() {
	if splice := ctx.splice.Swap(nil); splice != nil {
		if splice.cancelDial != nil {
			splice.cancelDial()
		}
		splice.toClient.close()
		if target := splice.upstream.Load(); target != nil {
			target.output.close()
			_ = target.conn.Close()
		}
	}
}

// The output barrier follows every earlier write before it starts draining
// the retained EOF tail, including logical writes on gnet's two task queues.
func (h *ProxyHandler) beginSpliceClientDrain(client clientEndpoint, ctx *ConnContext, tail []byte, releases ...func()) {
	var release func()
	if len(releases) > 0 {
		release = releases[0]
	}
	ctx.spliceDrainRequested.Store(true)
	err := executeAfterClientOutput(client, gnet.RunnableFunc(func(context.Context) error {
		if ctx.State() == StateClosed {
			clear(tail)
			if release != nil {
				release()
			}
			return nil
		}
		ctx.stopConnectionTimers()
		ctx.beginSpliceDrain(client, h.spliceIdleTimeout(), tail, release)
		if h.handleSpliceDrain(client, ctx) == gnet.Close {
			return client.Close()
		}
		return nil
	}))
	if err != nil {
		clear(tail)
		if release != nil {
			release()
		}
		_ = client.Close()
	}
}

func (h *ProxyHandler) handleSpliceDrain(client clientEndpoint, ctx *ConnContext) gnet.Action {
	if buffered := client.InboundBuffered(); buffered > 0 {
		_, _ = client.Discard(buffered)
	}
	if !ctx.isSpliceDraining() {
		return gnet.None
	}
	if len(ctx.spliceDrainTail) > 0 {
		capacity := max(0, h.maxWriteBuffer-client.OutboundBuffered())
		n := min(capacity, len(ctx.spliceDrainTail), relayBatchSize)
		if n > 0 {
			if stream, ok := client.(*LogicalStream); ok {
				n = stream.reserveOutput(n, 1)
				if n == 0 {
					ctx.armSpliceDrainWake(client)
					return gnet.None
				}
				stream.preparedOutput = n
			}
			written, err := client.Write(ctx.spliceDrainTail[:n])
			if err != nil || written != n {
				return gnet.Close
			}
			clear(ctx.spliceDrainTail[:n])
			ctx.spliceDrainTail = ctx.spliceDrainTail[n:]
		}
	}
	if len(ctx.spliceDrainTail) > 0 || client.OutboundBuffered() != 0 {
		ctx.armSpliceDrainWake(client)
		return gnet.None
	}
	ctx.finishSpliceDrain()
	return gnet.Close
}

func (ctx *ConnContext) beginSpliceDrain(client clientEndpoint, timeout time.Duration, tail []byte, releases ...func()) {
	var release func()
	if len(releases) > 0 {
		release = releases[0]
	}
	ctx.spliceDrainMu.Lock()
	defer ctx.spliceDrainMu.Unlock()
	if ctx.spliceDraining {
		clear(tail)
		if release != nil {
			release()
		}
		return
	}
	ctx.spliceDraining = true
	ctx.spliceDrainTail = tail
	ctx.spliceDrainRelease = release
	ctx.spliceDrainID++
	id := ctx.spliceDrainID
	ctx.spliceDrainDeadline = time.AfterFunc(timeout, func() {
		err := executeClient(client, gnet.RunnableFunc(func(context.Context) error {
			ctx.spliceDrainMu.Lock()
			if !ctx.spliceDraining || ctx.spliceDrainID != id {
				ctx.spliceDrainMu.Unlock()
				return nil
			}
			ctx.finishSpliceDrainLocked()
			ctx.spliceDrainMu.Unlock()
			return client.Close()
		}))
		if err != nil && ctx.State() != StateClosed {
			_ = client.Close()
		}
	})
}

func (ctx *ConnContext) isSpliceDraining() bool {
	ctx.spliceDrainMu.Lock()
	defer ctx.spliceDrainMu.Unlock()
	return ctx.spliceDraining
}

func (ctx *ConnContext) armSpliceDrainWake(client clientEndpoint) {
	ctx.spliceDrainMu.Lock()
	if !ctx.spliceDraining || ctx.spliceDrainWake != nil {
		ctx.spliceDrainMu.Unlock()
		return
	}
	id := ctx.spliceDrainID
	ctx.spliceDrainWake = time.AfterFunc(spliceDrainCheckInterval, func() {
		ctx.spliceDrainMu.Lock()
		if !ctx.spliceDraining || ctx.spliceDrainID != id {
			ctx.spliceDrainMu.Unlock()
			return
		}
		ctx.spliceDrainWake = nil
		ctx.spliceDrainMu.Unlock()
		_ = wakeClient(client)
	})
	ctx.spliceDrainMu.Unlock()
}

func (ctx *ConnContext) finishSpliceDrain() {
	ctx.spliceDrainMu.Lock()
	ctx.finishSpliceDrainLocked()
	ctx.spliceDrainMu.Unlock()
}

func (ctx *ConnContext) finishSpliceDrainLocked() {
	ctx.spliceDraining = false
	ctx.spliceDrainRequested.Store(false)
	ctx.spliceDrainID++
	clear(ctx.spliceDrainTail)
	ctx.spliceDrainTail = nil
	if ctx.spliceDrainRelease != nil {
		ctx.spliceDrainRelease()
		ctx.spliceDrainRelease = nil
	}
	if ctx.spliceDrainDeadline != nil {
		ctx.spliceDrainDeadline.Stop()
		ctx.spliceDrainDeadline = nil
	}
	if ctx.spliceDrainWake != nil {
		ctx.spliceDrainWake.Stop()
		ctx.spliceDrainWake = nil
	}
}

func (ctx *ConnContext) cancelSpliceDrain() {
	ctx.finishSpliceDrain()
}
