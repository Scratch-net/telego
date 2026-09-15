package middleend

import "errors"

var errLinkResponseSink = errors.New("Middle-End response sink cannot be installed")

// A response sink is an internal opt-in for manager-owned physical links.
// Installation never invokes the sink. Delivery consumes every event on all
// returns, runs outside the link lock, and must not wait for client or link I/O.
// Ping/Pong remain on Events so request dispatch and probe completion retain
// their single-consumer ordering. Events also remains the terminal signal.
type linkResponseSink interface {
	installResponseSink(func(LinkEvent) error) error
}

func responseSinkEvent(kind LinkEventKind) bool {
	return kind == LinkEventProxyAnswer || kind == LinkEventSimpleAck || kind == LinkEventCloseExternal
}

// Install once before Start, or after an unpublished replacement's probe.
// An empty channel is mandatory: the same lock chooses channel or sink at
// delivery, so an event cannot cross this boundary through the old channel.
func (l *GnetClientLink) installResponseSink(sink func(LinkEvent) error) error {
	if l == nil || sink == nil {
		return errLinkResponseSink
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.responseSink != nil || l.terminalClaimed || l.finalized ||
		l.state != LinkStateCreated && l.state != LinkStateReady {
		return errLinkResponseSink
	}
	l.reconcileEventsLocked()
	if l.pendingEvents != 0 || len(l.events) != 0 {
		return errLinkResponseSink
	}
	l.responseSink = sink
	return nil
}

// Caller holds manager.mu through installation and slot publication. A gnet
// owner may begin delivery immediately but cannot route until publication ends.
func (m *fixedBindingManager) installResponseSinkLocked(slot *fixedBindingSlot, link ClientLink, events <-chan LinkEvent) error {
	installer, ok := link.(linkResponseSink)
	if !ok {
		return nil
	}
	return installer.installResponseSink(func(event LinkEvent) error {
		return m.routeEventIncarnation(slot, events, event)
	})
}
