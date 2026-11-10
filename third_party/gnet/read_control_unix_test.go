// Copyright (c) 2026 Telego contributors.
// Licensed under the Apache License, Version 2.0. See LICENSE.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package gnet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type readControlResult struct {
	data []byte
	err  error
}
type readControlEvents struct {
	BuiltinEventEngine
	blocked  bool // owner-only
	received bytes.Buffer
	closed   chan readControlResult
}

func (h *readControlEvents) OnOpen(c Conn) ([]byte, Action) {
	if err := c.(ReadController).PauseRead(); err != nil {
		return nil, Close
	}
	return nil, None
}
func (h *readControlEvents) OnTraffic(c Conn) Action {
	if h.blocked {
		if err := c.(ReadController).PauseRead(); err != nil {
			return Close
		}
		return None
	}
	data, _ := c.Peek(-1)
	_, _ = h.received.Write(data)
	_, _ = c.Discard(len(data))
	return None
}
func (h *readControlEvents) OnClose(_ Conn, err error) Action {
	h.closed <- readControlResult{bytes.Clone(h.received.Bytes()), err}
	return None
}
func readControlOwner(t *testing.T, c Conn, run func() error) {
	t.Helper()
	done := make(chan error, 1)
	if err := c.EventLoop().Execute(t.Context(), RunnableFunc(func(context.Context) error {
		done <- run()
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read control owner stalled")
	}
}

func TestTelegoReadPausePreservesWritesAndEOF(t *testing.T) {
	for _, edge := range []bool{false, true} {
		for _, finish := range []string{"half_close", "full_close", "stop", "close_before_resume"} {
			t.Run(fmt.Sprintf("edge=%v/%s", edge, finish), func(t *testing.T) {
				h := &readControlEvents{blocked: true, closed: make(chan readControlResult, 1)}
				client, err := NewClient(h, WithNumEventLoop(1), WithEdgeTriggeredIO(edge), WithSocketSendBuffer(4096))
				if err != nil {
					t.Fatal(err)
				}
				if err = client.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Stop() })
				socket, peer := lifecyclePair(t)
				c, err := client.Enroll(socket)
				if err != nil {
					t.Fatal(err)
				}
				if err = peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				payload := bytes.Repeat([]byte{42}, 65553)
				if _, err = peer.Write(payload); err != nil {
					t.Fatal(err)
				}
				if err = peer.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				response := bytes.Repeat([]byte{43}, 512<<10)
				readControlOwner(t, c, func() error {
					_, err := c.Write(response)
					return err
				})
				got := make([]byte, len(response))
				if _, err = io.ReadFull(peer, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, response) {
					t.Fatal("paused reads changed write payload")
				}
				if finish == "full_close" {
					_ = peer.Close()
				}
				// A write-ready event or a peer half/full close must not bypass the pause.
				time.Sleep(30 * time.Millisecond)
				readControlOwner(t, c, func() error {
					native := c.(*conn)
					if !native.opened || !native.readPaused || c.InboundBuffered() != 0 || h.received.Len() != 0 {
						return fmt.Errorf("read pause lost: open=%v pause=%v input=%d delivered=%d", native.opened, native.readPaused, c.InboundBuffered(), h.received.Len())
					}
					return c.(ReadController).ResumeRead()
				})
				// Resume retries the blocked consumer before reading another socket byte.
				readControlOwner(t, c, func() error {
					if !c.(*conn).readPaused || c.InboundBuffered() != 0 {
						return fmt.Errorf("resume bypassed blocked consumer")
					}
					if finish == "close_before_resume" {
						if err := c.(ReadController).ResumeRead(); err != nil {
							return err
						}
						return c.EventLoop().Close(c)
					}
					if finish != "stop" {
						h.blocked = false
						return c.(ReadController).ResumeRead()
					}
					return nil
				})
				if finish == "stop" {
					if err = client.Stop(); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case result := <-h.closed:
					if finish == "stop" || finish == "close_before_resume" {
						if len(result.data) != 0 {
							t.Fatalf("shutdown read paused payload: %d", len(result.data))
						}
					} else if !bytes.Equal(result.data, payload) || !errors.Is(result.err, io.EOF) {
						t.Fatalf("resumed payload=%d/%d close=%v", len(result.data), len(payload), result.err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("paused connection did not complete")
				}
			})
		}
	}
}
