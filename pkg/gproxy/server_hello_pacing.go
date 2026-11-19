package gproxy

import (
	"context"
	"sync"
	"time"

	"github.com/panjf2000/gnet/v2"
)

const (
	maxPacedServerHello    = 64 * 1024
	serverHelloPaceDelay   = time.Millisecond
	serverHelloPaceTimeout = 3 * time.Second
)

// serverHelloPacer owns one response and one timer. Socket access and writes
// run only on the connection owner. The mutex also protects shutdown cleanup.
type serverHelloPacer struct {
	mu       sync.Mutex
	timer    *time.Timer
	closed   bool
	data     []byte
	offset   int
	size     int
	deadline time.Time
	conn     gnet.Conn
	ctx      *ConnContext
	handler  *ProxyHandler
}

func (h *ProxyHandler) startServerHelloPacing(conn gnet.Conn, ctx *ConnContext, response []byte) gnet.Action {
	size := h.config.ServerHelloSegmentSize
	if size < 64 || size > 1460 || len(response) > maxPacedServerHello || conn.SetNoDelay(true) != nil {
		return h.failHandshake(ctx, handshakeFailureTLSServerHello)
	}
	p := &serverHelloPacer{data: response, size: size, deadline: time.Now().Add(serverHelloPaceTimeout), conn: conn, ctx: ctx, handler: h}
	ctx.helloPacer.Store(p)
	ctx.SetState(StateWriteServerHello)
	p.step()
	return gnet.None
}

func (p *serverHelloPacer) stop() {
	p.mu.Lock()
	p.closed = true
	p.data = nil
	if p.timer != nil {
		p.timer.Stop()
	}
	p.mu.Unlock()
}

func (p *serverHelloPacer) enqueue() {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return
	}
	if err := p.conn.EventLoop().Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
		p.step()
		return nil
	})); err != nil {
		p.stop()
		p.ctx.helloPacer.CompareAndSwap(p, nil)
		_ = p.conn.Close()
	}
}

func (p *serverHelloPacer) step() {
	p.mu.Lock()
	if p.closed || p.ctx.State() != StateWriteServerHello {
		p.mu.Unlock()
		p.stop()
		return
	}
	if time.Now().After(p.deadline) {
		p.mu.Unlock()
		p.fail()
		return
	}
	busy, err := serverHelloSocketBusy(p.conn)
	if err != nil {
		p.mu.Unlock()
		p.fail()
		return
	}
	if !busy && p.offset == len(p.data) {
		p.closed = true
		p.data = nil
		p.mu.Unlock()
		p.ctx.helloPacer.CompareAndSwap(p, nil)
		p.ctx.SetState(StateReadO2Frame)
		if p.handler.handleO2Frame(p.conn, p.ctx) == gnet.Close {
			_ = p.conn.Close()
		}
		return
	}
	if !busy {
		end := min(p.offset+p.size, len(p.data))
		n, writeErr := writeServerHelloChunk(p.conn, p.data[p.offset:end])
		if writeErr != nil {
			p.mu.Unlock()
			p.fail()
			return
		}
		p.offset += n
	}
	if p.timer == nil {
		p.timer = time.AfterFunc(serverHelloPaceDelay, p.enqueue)
	} else {
		p.timer.Reset(serverHelloPaceDelay)
	}
	p.mu.Unlock()
}

func (p *serverHelloPacer) fail() {
	p.stop()
	p.ctx.helloPacer.CompareAndSwap(p, nil)
	p.handler.recordHandshakeFailure(p.ctx, handshakeFailureTLSServerHello)
	_ = p.conn.Close()
}
