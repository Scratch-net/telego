package middleend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixedBindingFakeLink struct {
	mu sync.Mutex

	events    chan LinkEvent
	ready     chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	startGate <-chan struct{}
	tryGate   <-chan struct{}
	startErr  error
	tryErr    error
	closeErr  error
	terminal  error
	closed    bool
	secret    string

	startCalls  int
	eventsCalls int
	closeCalls  int
	tryCalls    int
	submissions []LinkSubmission
	attempted   []LinkSubmission
	rejected    [][]byte

	onStart  func()
	onTry    func()
	afterTry func(bool)
	onClose  func()
}

func newFixedBindingFakeLink() *fixedBindingFakeLink {
	return &fixedBindingFakeLink{
		events: make(chan LinkEvent, 64),
		ready:  make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
}

func (l *fixedBindingFakeLink) Start(ctx context.Context) error {
	l.mu.Lock()
	l.startCalls++
	hook := l.onStart
	gate := l.startGate
	startErr := l.startErr
	l.mu.Unlock()
	if hook != nil {
		hook()
	}
	if gate != nil {
		select {
		case <-gate:
		case <-l.done:
			return ErrLinkClosed
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	return startErr
}

func (l *fixedBindingFakeLink) TrySubmit(submission LinkSubmission) error {
	l.mu.Lock()
	l.tryCalls++
	hook := l.onTry
	after := l.afterTry
	tryGate := l.tryGate
	l.mu.Unlock()
	if hook != nil {
		hook()
	}
	if tryGate != nil {
		select {
		case <-tryGate:
		case <-l.done:
			l.mu.Lock()
			l.rejected = append(l.rejected, submission.Payload)
			l.mu.Unlock()
			if after != nil {
				after(false)
			}
			return ErrLinkClosed
		}
	}
	l.mu.Lock()
	tryErr := l.tryErr
	if l.closed {
		tryErr = ErrLinkClosed
	}
	l.attempted = append(l.attempted, submission)
	if tryErr != nil {
		l.rejected = append(l.rejected, submission.Payload)
	} else {
		copyOfSubmission := submission
		copyOfSubmission.Payload = bytes.Clone(submission.Payload)
		l.submissions = append(l.submissions, copyOfSubmission)
	}
	l.mu.Unlock()
	if after != nil {
		after(tryErr == nil)
	}
	return tryErr
}

func (l *fixedBindingFakeLink) attemptedSubmissions() []LinkSubmission {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.attempted)
}

func (l *fixedBindingFakeLink) Events() <-chan LinkEvent {
	l.mu.Lock()
	l.eventsCalls++
	l.mu.Unlock()
	return l.events
}

func (l *fixedBindingFakeLink) SubmissionReady() <-chan struct{} {
	return l.ready
}

func (l *fixedBindingFakeLink) Snapshot() LinkSnapshot {
	select {
	case <-l.done:
		return LinkSnapshot{State: LinkStateClosed}
	default:
		return LinkSnapshot{State: LinkStateReady}
	}
}

func (l *fixedBindingFakeLink) Done() <-chan struct{} {
	return l.done
}

func (l *fixedBindingFakeLink) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.terminal
}

func (l *fixedBindingFakeLink) Close() error {
	l.mu.Lock()
	l.closeCalls++
	hook := l.onClose
	l.mu.Unlock()
	if hook != nil {
		hook()
	}
	l.peerClose(nil)
	return l.closeErr
}

func (l *fixedBindingFakeLink) emit(event LinkEvent) {
	l.events <- event
}

func (l *fixedBindingFakeLink) peerClose(err error) {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.terminal = err
		l.closed = true
		l.mu.Unlock()
		close(l.events)
		close(l.done)
	})
}

func (l *fixedBindingFakeLink) setTryError(err error) {
	l.mu.Lock()
	l.tryErr = err
	l.mu.Unlock()
}

func (l *fixedBindingFakeLink) stats() (starts, events, closes int, submissions []LinkSubmission, rejected [][]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.startCalls, l.eventsCalls, l.closeCalls, slices.Clone(l.submissions), slices.Clone(l.rejected)
}

type nonComparableClientLink []*fixedBindingFakeLink

func (l nonComparableClientLink) Start(ctx context.Context) error  { return l[0].Start(ctx) }
func (l nonComparableClientLink) TrySubmit(s LinkSubmission) error { return l[0].TrySubmit(s) }
func (l nonComparableClientLink) SubmissionReady() <-chan struct{} { return l[0].SubmissionReady() }
func (l nonComparableClientLink) Events() <-chan LinkEvent         { return l[0].Events() }
func (l nonComparableClientLink) Snapshot() LinkSnapshot           { return l[0].Snapshot() }
func (l nonComparableClientLink) Done() <-chan struct{}            { return l[0].Done() }
func (l nonComparableClientLink) Err() error                       { return l[0].Err() }
func (l nonComparableClientLink) Close() error                     { return l[0].Close() }

type dynamicNonComparableClientLink struct {
	link   *fixedBindingFakeLink
	marker any
}

func (l dynamicNonComparableClientLink) Start(ctx context.Context) error {
	return l.link.Start(ctx)
}
func (l dynamicNonComparableClientLink) TrySubmit(s LinkSubmission) error {
	return l.link.TrySubmit(s)
}
func (l dynamicNonComparableClientLink) SubmissionReady() <-chan struct{} {
	return l.link.SubmissionReady()
}
func (l dynamicNonComparableClientLink) Events() <-chan LinkEvent { return l.link.Events() }
func (l dynamicNonComparableClientLink) Snapshot() LinkSnapshot   { return l.link.Snapshot() }
func (l dynamicNonComparableClientLink) Done() <-chan struct{}    { return l.link.Done() }
func (l dynamicNonComparableClientLink) Err() error               { return l.link.Err() }
func (l dynamicNonComparableClientLink) Close() error             { return l.link.Close() }

func fixedBindingTestLimits() FixedBindingLimits {
	return FixedBindingLimits{
		MaxResidentBindings:               64,
		MaxResidentBindingsPerSlot:        32,
		MaxPendingRequestItemsPerBinding:  1,
		MaxPendingRequestBytesPerBinding:  1 << 20,
		MaxPendingRequestItemsPerSlot:     32,
		MaxPendingRequestBytesPerSlot:     4 << 20,
		MaxPendingRequestItems:            64,
		MaxPendingRequestBytes:            8 << 20,
		MaxPendingControlItemsPerSlot:     32,
		MaxPendingControlBytesPerSlot:     1 << 20,
		MaxPendingControlItems:            64,
		MaxPendingControlBytes:            2 << 20,
		MaxPendingResponseItemsPerBinding: 8,
		MaxPendingResponseBytesPerBinding: 1 << 20,
		MaxPendingResponseItemsPerSlot:    32,
		MaxPendingResponseBytesPerSlot:    4 << 20,
		MaxPendingResponseItems:           64,
		MaxPendingResponseBytes:           8 << 20,
	}
}

func newStartedFixedBindingManager(t *testing.T, slots ...FixedBindingSlot) *FixedBindingManager {
	t.Helper()
	manager, err := NewFixedBindingManager(slots, fixedBindingTestLimits())
	if err != nil {
		t.Fatalf("NewFixedBindingManager: %v", err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return manager
}

func fixedBindingProxyRequest() ProxyRequest {
	packet := make([]byte, EncryptedMessageHeaderSize)
	packet[0] = 1
	return ProxyRequest{
		Flags:      ProxyRequestFlagMagic | ProxyRequestFlagExternalMode2 | ProxyRequestFlagIntermediate,
		RemoteAddr: netip.MustParseAddrPort("198.51.100.10:443"),
		ProxyAddr:  netip.MustParseAddrPort("203.0.113.20:8443"),
		Packet:     packet,
	}
}

func fixedBindingMaxProxyRequest() ProxyRequest {
	request := fixedBindingProxyRequest()
	request.Packet = make([]byte, MaxClientPacketSize)
	request.Packet[0] = 1
	return request
}

func nextFixedBindingEvent(t *testing.T, binding *ClientBinding) LinkEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	event, err := binding.NextEvent(ctx)
	if err != nil {
		t.Fatalf("NextEvent: %v", err)
	}
	return event
}

func waitFixedBindingCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for fixed-binding condition")
		}
		runtime.Gosched()
	}
}

func waitFixedBindingSubmissions(t *testing.T, link *fixedBindingFakeLink, count int) []LinkSubmission {
	t.Helper()
	var submissions []LinkSubmission
	waitFixedBindingCondition(t, func() bool {
		_, _, _, submissions, _ = link.stats()
		return len(submissions) >= count
	})
	return submissions
}

func fixedBindingProbePing(t *testing.T, submission LinkSubmission) Ping {
	t.Helper()
	ping, err := ParsePing(submission.Payload)
	if err != nil {
		t.Fatalf("ParsePing: %v", err)
	}
	if submission.ConnectionID != 0 || submission.SubmissionID == 0 {
		t.Fatalf("probe submission identities = connection %d submission %d", submission.ConnectionID, submission.SubmissionID)
	}
	return ping
}

func nextFixedBindingReadyToken(t *testing.T, manager *FixedBindingManager) *ClientReadyToken {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if token := manager.TryNextReady(); token != nil {
			return token
		}
		select {
		case <-manager.Ready():
		case <-manager.Done():
			if token := manager.TryNextReady(); token != nil {
				return token
			}
			t.Fatalf("manager terminated before readiness: %v", manager.Err())
		case <-deadline.C:
			t.Fatal("timed out waiting for fixed-binding readiness")
		}
	}
}

func TestFixedBindingManagerRoutesExactSignedDCIDs(t *testing.T) {
	negative := newFixedBindingFakeLink()
	positive := newFixedBindingFakeLink()
	zero := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t,
		FixedBindingSlot{DCID: -2, Link: negative},
		FixedBindingSlot{DCID: 2, Link: positive},
		FixedBindingSlot{DCID: 0, Link: zero},
	)

	bindings := make(map[DCID]*ClientBinding)
	for _, dcID := range []DCID{-2, 2, 0} {
		binding, err := manager.Bind(dcID)
		if err != nil {
			t.Fatalf("Bind(%d): %v", dcID, err)
		}
		bindings[dcID] = binding
	}
	if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingUnknownDC) {
		t.Fatalf("Bind unknown error = %v", err)
	}

	links := map[DCID]*fixedBindingFakeLink{-2: negative, 2: positive, 0: zero}
	for _, dcID := range []DCID{-2, 2, 0} {
		packet := []byte{byte(dcID), 2, 3, 4}
		wantPacket := bytes.Clone(packet)
		links[dcID].emit(LinkEvent{
			Kind:         LinkEventProxyAnswer,
			ConnectionID: bindings[dcID].ConnectionID(),
			AnswerFlags:  ProxyAnswerFlagFlush,
			Packet:       packet,
		})
		event := nextFixedBindingEvent(t, bindings[dcID])
		if event.ConnectionID != bindings[dcID].ConnectionID() || event.AnswerFlags != ProxyAnswerFlagFlush || !bytes.Equal(event.Packet, wantPacket) {
			t.Fatalf("DC %d event = %+v", dcID, event)
		}
		if !allZero(packet) {
			t.Fatalf("DC %d transferred packet not cleared: %x", dcID, packet)
		}
	}
}

func TestFixedBindingManagerDCIDsAreSortedAndDefensive(t *testing.T) {
	manager, err := NewFixedBindingManager([]FixedBindingSlot{
		{DCID: 4, Link: newFixedBindingFakeLink()},
		{DCID: -2, Link: newFixedBindingFakeLink()},
		{DCID: 0, Link: newFixedBindingFakeLink()},
	}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	dcIDs := manager.DCIDs()
	if want := []DCID{-2, 0, 4}; !slices.Equal(dcIDs, want) {
		t.Fatalf("DCIDs = %v, want %v", dcIDs, want)
	}
	dcIDs[0] = 99
	if got := manager.DCIDs(); !slices.Equal(got, []DCID{-2, 0, 4}) {
		t.Fatalf("mutating returned DCIDs changed manager state: %v", got)
	}

	var nilManager *FixedBindingManager
	if got := nilManager.DCIDs(); got != nil {
		t.Fatalf("nil manager DCIDs = %v", got)
	}
}

func TestFixedBindingManagerQuiesceDrainsExistingBindings(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}

	drained := manager.Quiesce()
	if repeated := manager.Quiesce(); repeated != drained {
		t.Fatal("Quiesce did not return its stable drain channel")
	}
	select {
	case <-drained:
		t.Fatal("manager drained while an existing binding was resident")
	default:
	}
	if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingManagerQuiesced) {
		t.Fatalf("Bind after Quiesce = %v", err)
	}

	link.emit(LinkEvent{
		Kind:         LinkEventProxyAnswer,
		ConnectionID: binding.ConnectionID(),
		Packet:       []byte{1, 2, 3, 4},
	})
	if event := nextFixedBindingEvent(t, binding); event.Kind != LinkEventProxyAnswer {
		t.Fatalf("existing binding event after Quiesce = %+v", event)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("manager did not publish drained after its last binding left")
	}
}

func TestFixedBindingManagerQuiesceBeforeStart(t *testing.T) {
	manager, err := NewFixedBindingManager(
		[]FixedBindingSlot{{DCID: 1, Link: newFixedBindingFakeLink()}},
		fixedBindingTestLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	drained := manager.Quiesce()
	select {
	case <-drained:
	default:
		t.Fatal("empty manager did not drain synchronously")
	}
	if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingManagerNotStarted) {
		t.Fatalf("Bind before Start = %v", err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingManagerQuiesced) {
		t.Fatalf("Bind after Start = %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingManagerClosed) {
		t.Fatalf("Bind after Close = %v", err)
	}
}

func TestFixedBindingManagerQuiesceLinearizesWithBind(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	const binders = 32
	start := make(chan struct{})
	results := make(chan struct {
		binding *ClientBinding
		err     error
	}, binders)
	var wait sync.WaitGroup
	for range binders {
		wait.Go(func() {
			<-start
			binding, err := manager.Bind(1)
			results <- struct {
				binding *ClientBinding
				err     error
			}{binding: binding, err: err}
		})
	}
	close(start)
	drained := manager.Quiesce()
	wait.Wait()
	close(results)

	bindings := make([]*ClientBinding, 0, binders)
	for result := range results {
		if result.err == nil {
			bindings = append(bindings, result.binding)
			continue
		}
		if !errors.Is(result.err, ErrFixedBindingManagerQuiesced) {
			t.Fatalf("concurrent Bind = %v", result.err)
		}
	}
	if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingManagerQuiesced) {
		t.Fatalf("Bind after Quiesce returned = %v", err)
	}
	for _, binding := range bindings {
		if err := binding.Close(); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatalf("manager did not drain %d successful concurrent bindings", len(bindings))
	}
}

func TestNewFixedBindingManagerRejectsInvalidConstruction(t *testing.T) {
	validLink := newFixedBindingFakeLink()
	nilEvents := newFixedBindingFakeLink()
	nilEvents.events = nil
	validLimits := fixedBindingTestLimits()
	var typedNil *fixedBindingFakeLink
	var typedNilSlice nonComparableClientLink
	tests := []struct {
		name   string
		slots  []FixedBindingSlot
		limits FixedBindingLimits
	}{
		{name: "empty", limits: validLimits},
		{name: "too many", slots: make([]FixedBindingSlot, MaxProxyTargets+1), limits: validLimits},
		{name: "nil link", slots: []FixedBindingSlot{{DCID: 1}}, limits: validLimits},
		{name: "typed nil", slots: []FixedBindingSlot{{DCID: 1, Link: typedNil}}, limits: validLimits},
		{name: "typed nil slice", slots: []FixedBindingSlot{{DCID: 1, Link: typedNilSlice}}, limits: validLimits},
		{name: "nil Events", slots: []FixedBindingSlot{{DCID: 1, Link: nilEvents}}, limits: validLimits},
		{name: "duplicate link", slots: []FixedBindingSlot{{DCID: -2, Link: validLink}, {DCID: 2, Link: validLink}}, limits: validLimits},
		{name: "zero limits", slots: []FixedBindingSlot{{DCID: 1, Link: validLink}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewFixedBindingManager(test.slots, test.limits); !errors.Is(err, ErrInvalidFixedBindingManager) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	_, _, closes, _, _ := validLink.stats()
	if closes != 0 {
		t.Fatalf("validation closed caller-owned link %d times", closes)
	}
}

func TestNewFixedBindingManagerAcceptsNonComparableLinks(t *testing.T) {
	for _, test := range []struct {
		name string
		link func(*fixedBindingFakeLink) ClientLink
	}{
		{
			name: "named slice",
			link: func(link *fixedBindingFakeLink) ClientLink {
				return nonComparableClientLink{link}
			},
		},
		{
			name: "interface field with dynamic slice",
			link: func(link *fixedBindingFakeLink) ClientLink {
				return dynamicNonComparableClientLink{link: link, marker: []byte{1}}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			link := newFixedBindingFakeLink()
			manager, err := NewFixedBindingManager(
				[]FixedBindingSlot{{DCID: 1, Link: test.link(link)}},
				fixedBindingTestLimits(),
			)
			if err != nil {
				t.Fatalf("NewFixedBindingManager: %v", err)
			}
			if err := manager.Start(t.Context()); err != nil {
				t.Fatalf("Start: %v", err)
			}
			if err := manager.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		})
	}
}

func TestNewFixedBindingManagerRejectsDuplicateEventsChannelWithoutOwnership(t *testing.T) {
	first := newFixedBindingFakeLink()
	second := newFixedBindingFakeLink()
	second.events = first.events
	if _, err := NewFixedBindingManager([]FixedBindingSlot{
		{DCID: -2, Link: first},
		{DCID: 2, Link: second},
	}, fixedBindingTestLimits()); !errors.Is(err, ErrInvalidFixedBindingManager) {
		t.Fatalf("error = %v", err)
	}
	for index, link := range []*fixedBindingFakeLink{first, second} {
		_, events, closes, _, _ := link.stats()
		if events != 1 || closes != 0 {
			t.Fatalf("link %d Events/Close calls = %d/%d", index, events, closes)
		}
	}
	first.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 1})
	if len(first.events) != 1 {
		t.Fatalf("validation started an Events consumer; buffered events = %d", len(first.events))
	}
	<-first.events
}

func TestFixedBindingOpaqueWrappersRedactCopiesPointersAndEnclosingStructs(t *testing.T) {
	const linkMarker = "fixed-binding-link-secret-marker"
	packet := []byte{211, 212, 213, 214}
	const packetMarker = "[211 212 213 214]"
	link := newFixedBindingFakeLink()
	link.secret = linkMarker
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet})
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return binding.state.items == 1
	})

	managerValue := *manager
	bindingValue := *binding
	if managerValue.Err() != nil || bindingValue.ConnectionID() != binding.ConnectionID() {
		t.Fatal("copied wrappers do not share their pointer-backed state")
	}
	enclosing := struct {
		Manager FixedBindingManager
		Binding ClientBinding
	}{Manager: managerValue, Binding: bindingValue}
	var nilManager *FixedBindingManager
	var nilBinding *ClientBinding
	for _, value := range []any{
		manager,
		managerValue,
		binding,
		bindingValue,
		enclosing,
		nilManager,
		nilBinding,
	} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, linkMarker) || strings.Contains(formatted, packetMarker) ||
				strings.Contains(formatted, "%!v(PANIC") {
				t.Fatalf("format %q exposed state: %s", format, formatted)
			}
		}
	}
}

func TestFixedBindingLimitsRejectNestedAndCeilingViolations(t *testing.T) {
	tests := []FixedBindingLimits{
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxResidentBindingsPerSlot = l.MaxResidentBindings + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxResidentBindings = MaxFixedBindingResidents + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxPendingRequestItemsPerSlot = l.MaxPendingRequestItems + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxPendingRequestBytesPerSlot = l.MaxPendingRequestBytes + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxPendingRequestItems = MaxLinkQueueItems + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxPendingRequestBytes = MaxLinkQueueBytes + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxPendingResponseItemsPerBinding = l.MaxPendingResponseItemsPerSlot + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxPendingResponseItemsPerSlot = l.MaxPendingResponseItems + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxPendingResponseBytesPerBinding = l.MaxPendingResponseBytesPerSlot + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxPendingResponseBytesPerSlot = l.MaxPendingResponseBytes + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxPendingResponseItems = MaxLinkQueueItems + 1
			return l
		}(),
		func() FixedBindingLimits {
			l := fixedBindingTestLimits()
			l.MaxPendingResponseBytes = MaxLinkQueueBytes + 1
			return l
		}(),
	}
	for index, limits := range tests {
		if err := limits.Validate(); !errors.Is(err, ErrInvalidFixedBindingManager) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

func TestFixedBindingLimitsAdmitTelemtConnectionDefault(t *testing.T) {
	limits := fixedBindingTestLimits()
	limits.MaxResidentBindings = 10_000
	limits.MaxResidentBindingsPerSlot = 2_500
	if err := limits.Validate(); err != nil {
		t.Fatalf("10,000-resident policy = %v", err)
	}
}

func TestFixedBindingManagerConcurrentStartExactlyOnce(t *testing.T) {
	gate := make(chan struct{})
	link := newFixedBindingFakeLink()
	link.startGate = gate
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	const callers = 64
	results := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Go(func() { results <- manager.Start(t.Context()) })
	}
	waitFixedBindingCondition(t, func() bool {
		starts, events, _, _, _ := link.stats()
		return starts == 1 && events == 1
	})
	close(gate)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("Start = %v", err)
		}
	}
	starts, events, _, _, _ := link.stats()
	if starts != 1 || events != 1 {
		t.Fatalf("starts/events = %d/%d", starts, events)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFixedBindingManagerPartialStartFailureCleansAllLinks(t *testing.T) {
	first := newFixedBindingFakeLink()
	second := newFixedBindingFakeLink()
	second.startErr = errors.New("bootstrap failed")
	third := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{
		{DCID: -1, Link: first},
		{DCID: 0, Link: second},
		{DCID: 1, Link: third},
	}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); !errors.Is(err, ErrFixedBindingInitialFailure) {
		t.Fatalf("Start = %v", err)
	}
	select {
	case <-manager.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("manager did not finish initial failure cleanup")
	}
	for index, link := range []*fixedBindingFakeLink{first, second, third} {
		_, events, closes, _, _ := link.stats()
		if events != 1 || closes != 1 {
			t.Fatalf("link %d events/closes = %d/%d", index, events, closes)
		}
	}
	if !errors.Is(manager.Err(), ErrFixedBindingInitialFailure) {
		t.Fatalf("Err = %v", manager.Err())
	}
	if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingInitialFailure) {
		t.Fatalf("Bind after failure = %v", err)
	}
}

func TestFixedBindingManagerStartsAllSlotsConcurrently(t *testing.T) {
	release := make(chan struct{})
	started := make(chan DCID, 3)
	links := []*fixedBindingFakeLink{
		newFixedBindingFakeLink(),
		newFixedBindingFakeLink(),
		newFixedBindingFakeLink(),
	}
	slots := make([]FixedBindingSlot, len(links))
	for index, link := range links {
		dcID := DCID(index + 1)
		link.startGate = release
		link.onStart = func() { started <- dcID }
		slots[index] = FixedBindingSlot{DCID: dcID, Link: link}
	}
	manager, err := NewFixedBindingManager(slots, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- manager.Start(t.Context()) }()

	seen := make(map[DCID]bool, len(links))
	for range links {
		select {
		case dcID := <-started:
			seen[dcID] = true
		case <-time.After(time.Second):
			t.Fatalf("only %d of %d fixed links started before release", len(seen), len(links))
		}
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("Start: %v", err)
	}
	if len(seen) != len(links) {
		t.Fatalf("started DCs = %v", seen)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFixedBindingManagerConcurrentStartFailureIsDeterministic(t *testing.T) {
	firstErr := errors.New("first failed")
	secondErr := errors.New("second failed")
	first := newFixedBindingFakeLink()
	first.startErr = firstErr
	second := newFixedBindingFakeLink()
	second.startErr = secondErr
	manager, err := NewFixedBindingManager([]FixedBindingSlot{
		{DCID: -1, Link: first},
		{DCID: 1, Link: second},
	}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	startErr := manager.Start(t.Context())
	if !errors.Is(startErr, firstErr) || errors.Is(startErr, secondErr) {
		t.Fatalf("Start error = %v", startErr)
	}
}

func TestFixedBindingManagerSuccessfulStartDetachesContext(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := manager.Bind(1); err != nil {
		t.Fatalf("Bind after Start context cancellation: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFixedBindingManagerEnforcesActiveBindingLimits(t *testing.T) {
	t.Run("per slot", func(t *testing.T) {
		limits := fixedBindingTestLimits()
		limits.MaxResidentBindings = 2
		limits.MaxResidentBindingsPerSlot = 1
		manager, err := NewFixedBindingManager([]FixedBindingSlot{
			{DCID: -2, Link: newFixedBindingFakeLink()},
			{DCID: 2, Link: newFixedBindingFakeLink()},
		}, limits)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Bind(-2); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Bind(-2); !errors.Is(err, ErrFixedBindingLimit) {
			t.Fatalf("second per-slot Bind = %v", err)
		}
		if _, err := manager.Bind(2); err != nil {
			t.Fatalf("other slot Bind = %v", err)
		}
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("global", func(t *testing.T) {
		limits := fixedBindingTestLimits()
		limits.MaxResidentBindings = 1
		limits.MaxResidentBindingsPerSlot = 1
		manager, err := NewFixedBindingManager([]FixedBindingSlot{
			{DCID: -2, Link: newFixedBindingFakeLink()},
			{DCID: 2, Link: newFixedBindingFakeLink()},
		}, limits)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Bind(-2); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Bind(2); !errors.Is(err, ErrFixedBindingLimit) {
			t.Fatalf("global Bind = %v", err)
		}
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFixedBindingManagerCloseWinsStartRace(t *testing.T) {
	gate := make(chan struct{})
	link := newFixedBindingFakeLink()
	link.startGate = gate
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	startResult := make(chan error, 1)
	go func() { startResult <- manager.Start(t.Context()) }()
	waitFixedBindingCondition(t, func() bool {
		starts, _, _, _, _ := link.stats()
		return starts == 1
	})
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-startResult; !errors.Is(err, ErrFixedBindingManagerClosed) {
		t.Fatalf("Start = %v", err)
	}
}

func TestFixedBindingManagerCloseBeforeStartOwnsAndClosesLinks(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	starts, events, closes, _, _ := link.stats()
	if starts != 0 || events != 1 || closes != 1 {
		t.Fatalf("starts/events/closes = %d/%d/%d", starts, events, closes)
	}
	if err := manager.Start(t.Context()); !errors.Is(err, ErrFixedBindingManagerClosed) {
		t.Fatalf("Start after Close = %v", err)
	}
}

func TestFixedBindingManagerAllocatorsAreUniqueAndExhaustWithoutWrap(t *testing.T) {
	restore := setFixedBindingAllocatorStateForTest(0, 0)
	defer restore()
	link := newFixedBindingFakeLink()
	limits := fixedBindingTestLimits()
	limits.MaxResidentBindings = 1024
	limits.MaxResidentBindingsPerSlot = 1024
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	const count = 512
	ids := make(chan int64, count)
	var wait sync.WaitGroup
	for range count {
		wait.Go(func() {
			binding, bindErr := manager.Bind(1)
			if bindErr != nil {
				ids <- 0
				return
			}
			ids <- binding.ConnectionID()
		})
	}
	wait.Wait()
	close(ids)
	seen := make(map[int64]struct{}, count)
	for id := range ids {
		if id <= 0 {
			t.Fatalf("invalid ID %d", id)
		}
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate ID %d", id)
		}
		seen[id] = struct{}{}
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}

	fixedBindingConnectionIDs.Store(math.MaxInt64 - 1)
	if id, err := allocateFixedBindingConnectionID(); err != nil || id != math.MaxInt64 {
		t.Fatalf("last connection ID = %d, %v", id, err)
	}
	if id, err := allocateFixedBindingConnectionID(); id != 0 || !errors.Is(err, ErrFixedBindingConnectionIDExhausted) {
		t.Fatalf("exhausted connection ID = %d, %v", id, err)
	}
	fixedBindingSubmissionIDs.Store(math.MaxUint64 - 1)
	if id, err := allocateFixedBindingSubmissionID(); err != nil || id != math.MaxUint64 {
		t.Fatalf("last submission ID = %d, %v", id, err)
	}
	if id, err := allocateFixedBindingSubmissionID(); id != 0 || !errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
		t.Fatalf("exhausted submission ID = %d, %v", id, err)
	}
}

func TestFixedBindingManagerConnectionIDExhaustionDoesNotStopManager(t *testing.T) {
	restore := setFixedBindingAllocatorStateForTest(math.MaxInt64-1, 0)
	defer restore()
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil || binding.ConnectionID() != math.MaxInt64 {
		t.Fatalf("last Bind = %d, %v", binding.ConnectionID(), err)
	}
	for range 2 {
		if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingConnectionIDExhausted) {
			t.Fatalf("exhausted Bind = %v", err)
		}
	}
	if _, err := binding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil {
		t.Fatalf("existing binding request = %v", err)
	}
	if manager.Err() != nil {
		t.Fatalf("manager Err = %v", manager.Err())
	}
}

func TestFixedBindingManagerSubmissionIDExhaustionIsPermanent(t *testing.T) {
	t.Run("Bind observes exhaustion before connection allocation", func(t *testing.T) {
		restore := setFixedBindingAllocatorStateForTest(41, math.MaxUint64)
		defer restore()
		link := newFixedBindingFakeLink()
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
			t.Fatalf("Bind = %v", err)
		}
		if fixedBindingConnectionIDs.Load() != 41 {
			t.Fatalf("connection allocator advanced to %d", fixedBindingConnectionIDs.Load())
		}
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(manager.Err(), ErrFixedBindingSubmissionIDExhausted) {
			t.Fatalf("Err = %v", manager.Err())
		}
		if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
			t.Fatalf("Bind after terminal = %v", err)
		}
		_, _, closes, submissions, _ := link.stats()
		if closes != 1 || len(submissions) != 0 {
			t.Fatalf("terminal closes/submissions = %d/%d", closes, len(submissions))
		}
	})

	t.Run("request", func(t *testing.T) {
		restore := setFixedBindingAllocatorStateForTest(0, 0)
		defer restore()
		link := newFixedBindingFakeLink()
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		binding, err := manager.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		fixedBindingSubmissionIDs.Store(math.MaxUint64)
		if _, err := binding.PrepareProxyRequest(fixedBindingProxyRequest()); !errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
			t.Fatalf("PrepareProxyRequest = %v", err)
		}
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
			t.Fatalf("Bind after terminal = %v", err)
		}
		if _, err := binding.PrepareProxyRequest(fixedBindingProxyRequest()); !errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
			t.Fatalf("repeated request = %v", err)
		}
		manager.state.mu.Lock()
		slot := manager.state.slots[1]
		if slot.requestItems != 0 || slot.requestBytes != 0 ||
			manager.state.requestItems != 0 || manager.state.requestBytes != 0 ||
			len(manager.state.byID) != 0 || !errors.Is(binding.state.terminalErr, ErrFixedBindingSubmissionIDExhausted) {
			t.Fatalf("terminal request charges = slot %d/%d global %d/%d",
				slot.requestItems, slot.requestBytes, manager.state.requestItems, manager.state.requestBytes)
		}
		manager.state.mu.Unlock()
		_, _, closes, submissions, _ := link.stats()
		if closes != 1 || len(submissions) != 0 {
			t.Fatalf("terminal closes/submissions = %d/%d", closes, len(submissions))
		}
	})

	t.Run("local close", func(t *testing.T) {
		restore := setFixedBindingAllocatorStateForTest(0, 0)
		defer restore()
		link := newFixedBindingFakeLink()
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		binding, err := manager.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		fixedBindingSubmissionIDs.Store(math.MaxUint64)
		for range 2 {
			if err := binding.Close(); !errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
				t.Fatalf("Close = %v", err)
			}
		}
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
			t.Fatalf("Bind after terminal = %v", err)
		}
		_, _, closes, submissions, _ := link.stats()
		if closes != 1 || len(submissions) != 0 {
			t.Fatalf("terminal closes/submissions = %d/%d", closes, len(submissions))
		}
	})

	t.Run("stale close", func(t *testing.T) {
		restore := setFixedBindingAllocatorStateForTest(0, 0)
		defer restore()
		link := newFixedBindingFakeLink()
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		fixedBindingSubmissionIDs.Store(math.MaxUint64)
		link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 987654})
		select {
		case <-manager.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("manager did not stop after stale-close exhaustion")
		}
		if !errors.Is(manager.Err(), ErrFixedBindingSubmissionIDExhausted) {
			t.Fatalf("Err = %v", manager.Err())
		}
		if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
			t.Fatalf("Bind after terminal = %v", err)
		}
		_, _, closes, submissions, _ := link.stats()
		if closes != 1 || len(submissions) != 0 {
			t.Fatalf("terminal closes/submissions = %d/%d", closes, len(submissions))
		}
	})
}

func TestFixedBindingPreparedRequestRetriesStableSubmissionAfterCapacity(t *testing.T) {
	restore := setFixedBindingAllocatorStateForTest(0, 0)
	defer restore()
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	request := fixedBindingProxyRequest()
	request.ConnectionID = -999
	status, err := binding.PrepareProxyRequest(request)
	if err != nil || status != PrepareProxyRequestQueued {
		t.Fatalf("PrepareProxyRequest = %d, %v", status, err)
	}
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	first := link.attemptedSubmissions()[0]
	if len(first.Payload) == 0 {
		t.Fatal("first attempt has empty payload")
	}
	firstPointer := &first.Payload[0]
	wantPayload := bytes.Clone(first.Payload)
	for attempt := range 1000 {
		link.ready <- struct{}{}
		waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == attempt+2 })
	}
	attempts := link.attemptedSubmissions()
	for index, attempt := range attempts {
		if attempt.SubmissionID != first.SubmissionID || attempt.ConnectionID != binding.ConnectionID() ||
			len(attempt.Payload) == 0 || &attempt.Payload[0] != firstPointer || !bytes.Equal(attempt.Payload, wantPayload) {
			t.Fatalf("attempt %d changed stable submission", index)
		}
	}
	link.setTryError(nil)
	link.ready <- struct{}{}
	waitFixedBindingCondition(t, func() bool {
		_, _, _, submissions, _ := link.stats()
		return len(submissions) == 1
	})
	token := nextFixedBindingReadyToken(t, manager)
	result, ok, err := token.TryTakeRequestResult()
	if err != nil || !ok || !result.Accepted || result.Err != nil || result.SubmissionID != first.SubmissionID {
		t.Fatalf("request result = %+v, %v, %v", result, ok, err)
	}
	if err := token.Ack(); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseProxyRequest(wantPayload)
	if err != nil || parsed.ConnectionID != binding.ConnectionID() {
		t.Fatalf("marshaled request connection = %d, %v", parsed.ConnectionID, err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	for index, attempt := range link.attemptedSubmissions() {
		if !bytes.Equal(attempt.Payload, wantPayload) {
			t.Fatalf("manager cleared transferred attempt %d", index)
		}
	}
}

func TestFixedBindingPreparedWaitingReservationAndStrictSlotFIFO(t *testing.T) {
	limits := fixedBindingTestLimits()
	limits.MaxPendingRequestItemsPerSlot = 1
	limits.MaxPendingRequestItems = 1
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	first, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	third, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	request := fixedBindingProxyRequest()
	if status, err := first.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestQueued {
		t.Fatalf("first prepare = %d, %v", status, err)
	}
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	if status, err := second.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestWaiting {
		t.Fatalf("second prepare = %d, %v", status, err)
	}
	link.setTryError(nil)
	link.ready <- struct{}{}

	var reservation *ClientPrepareReservation
	for reservation == nil {
		token := nextFixedBindingReadyToken(t, manager)
		switch token.ConnectionID() {
		case first.ConnectionID():
			result, ok, err := token.TryTakeRequestResult()
			if err != nil || !ok || !result.Accepted {
				t.Fatalf("first result = %+v, %v, %v", result, ok, err)
			}
		case second.ConnectionID():
			var ok bool
			reservation, ok, err = token.TryTakePrepareReservation()
			if err != nil || !ok {
				t.Fatalf("second reservation = %v, %v, %v", reservation, ok, err)
			}
		default:
			t.Fatalf("unexpected ready binding %d", token.ConnectionID())
		}
		if err := token.Ack(); err != nil {
			t.Fatal(err)
		}
	}
	if status, err := third.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestWaiting {
		t.Fatalf("third prepare = %d, %v", status, err)
	}
	if got := len(link.attemptedSubmissions()); got != 2 {
		t.Fatalf("later request bypassed reservation: attempts=%d", got)
	}
	request.ConnectionID = math.MinInt64
	if err := second.PrepareReservedProxyRequest(reservation, request); err != nil {
		t.Fatal(err)
	}
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 3 })
	attempts := link.attemptedSubmissions()
	if attempts[0].ConnectionID != first.ConnectionID() || attempts[1].ConnectionID != first.ConnectionID() ||
		attempts[2].ConnectionID != second.ConnectionID() {
		t.Fatalf("slot FIFO = %d, %d, %d", attempts[0].ConnectionID, attempts[1].ConnectionID, attempts[2].ConnectionID)
	}
	if got := len(attempts); got != 3 {
		t.Fatalf("unmaterialized third request was attempted: %d", got)
	}
}

func TestFixedBindingReservationMismatchReleasesExactCharge(t *testing.T) {
	limits := fixedBindingTestLimits()
	limits.MaxPendingRequestItemsPerSlot = 1
	limits.MaxPendingRequestItems = 1
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	first, _ := manager.Bind(1)
	second, _ := manager.Bind(1)
	request := fixedBindingProxyRequest()
	_, _ = first.PrepareProxyRequest(request)
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	if status, err := second.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestWaiting {
		t.Fatalf("waiting prepare = %d, %v", status, err)
	}
	link.setTryError(nil)
	link.ready <- struct{}{}
	var reservation *ClientPrepareReservation
	for reservation == nil {
		token := nextFixedBindingReadyToken(t, manager)
		if token.ConnectionID() == first.ConnectionID() {
			_, _, _ = token.TryTakeRequestResult()
		} else {
			reservation, _, err = token.TryTakePrepareReservation()
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := token.Ack(); err != nil {
			t.Fatal(err)
		}
	}
	mismatch := request
	mismatch.Packet = bytes.Clone(request.Packet)
	mismatch.Packet[len(mismatch.Packet)-1] ^= 1
	if err := second.PrepareReservedProxyRequest(reservation, mismatch); !errors.Is(err, ErrFixedBindingRequestRejected) {
		t.Fatalf("mismatch = %v", err)
	}
	manager.state.mu.Lock()
	slot := manager.state.slots[1]
	if slot.requestItems != 0 || slot.requestBytes != 0 || manager.state.requestItems != 0 || manager.state.requestBytes != 0 || second.state.request != nil {
		t.Fatalf("request charges after mismatch = slot %d/%d global %d/%d", slot.requestItems, slot.requestBytes, manager.state.requestItems, manager.state.requestBytes)
	}
	manager.state.mu.Unlock()
	if err := second.PrepareReservedProxyRequest(reservation, request); !errors.Is(err, ErrFixedBindingRequestRejected) {
		t.Fatalf("stale reservation = %v", err)
	}
}

func TestFixedBindingForeignReservationCannotStrandOrigin(t *testing.T) {
	limits := fixedBindingTestLimits()
	limits.MaxPendingRequestItemsPerSlot = 1
	limits.MaxPendingRequestItems = 1
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	blocker, _ := manager.Bind(1)
	origin, _ := manager.Bind(1)
	receiver, _ := manager.Bind(1)
	request := fixedBindingProxyRequest()
	_, _ = blocker.PrepareProxyRequest(request)
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	_, _ = origin.PrepareProxyRequest(request)
	link.setTryError(nil)
	link.ready <- struct{}{}
	var reservation *ClientPrepareReservation
	var originToken *ClientReadyToken
	for reservation == nil {
		token := nextFixedBindingReadyToken(t, manager)
		if token.ConnectionID() == blocker.ConnectionID() {
			_, _, _ = token.TryTakeRequestResult()
			_ = token.Ack()
			continue
		}
		if token.ConnectionID() != origin.ConnectionID() {
			t.Fatalf("unexpected ready connection %d", token.ConnectionID())
		}
		reservation, _, err = token.TryTakePrepareReservation()
		if err != nil {
			t.Fatal(err)
		}
		originToken = token
	}
	if err := receiver.PrepareReservedProxyRequest(reservation, request); !errors.Is(err, ErrFixedBindingRequestRejected) {
		t.Fatalf("foreign reservation = %v", err)
	}
	manager.state.mu.Lock()
	if manager.state.requestItems != 0 || manager.state.requestBytes != 0 || origin.state.request != nil || receiver.state.terminal {
		t.Fatalf("foreign reservation state = requests %d/%d origin %v receiver terminal %v",
			manager.state.requestItems, manager.state.requestBytes, origin.state.request, receiver.state.terminal)
	}
	manager.state.mu.Unlock()
	if terminalErr, ok, err := originToken.TryTerminal(); err != nil || !ok || !errors.Is(terminalErr, ErrFixedBindingRequestRejected) {
		t.Fatalf("origin terminal = %v, %v, %v", terminalErr, ok, err)
	}
	if err := originToken.Ack(); err != nil {
		t.Fatal(err)
	}
	manager.state.mu.Lock()
	originResident := origin.state.resident
	manager.state.mu.Unlock()
	if originResident {
		t.Fatal("foreign reservation origin remained resident after observation")
	}
	if status, err := receiver.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestQueued {
		t.Fatalf("healthy receiver prepare = %d, %v", status, err)
	}
}

func TestFixedBindingManagerCloseWaitsForClaimedMaterialization(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	manager.state.materializeHookForTest = sync.OnceFunc(func() {
		close(entered)
		<-release
	})
	prepareDone := make(chan error, 1)
	go func() {
		_, prepareErr := binding.PrepareProxyRequest(fixedBindingProxyRequest())
		prepareDone <- prepareErr
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- manager.Close() }()
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return manager.state.state == fixedBindingManagerClosing
	})
	select {
	case <-manager.Done():
		t.Fatal("manager completed while materialization was active")
	default:
	}
	_, _, closes, _, _ := link.stats()
	if closes != 0 {
		t.Fatalf("link closed before materialization resolved: %d", closes)
	}
	close(release)
	if err := <-prepareDone; !errors.Is(err, ErrFixedBindingManagerClosed) {
		t.Fatalf("PrepareProxyRequest = %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	manager.state.mu.Lock()
	if manager.state.requestItems != 0 || manager.state.requestBytes != 0 || manager.state.residentBindings != 0 {
		t.Fatalf("terminal accounting = requests %d/%d residents %d", manager.state.requestItems, manager.state.requestBytes, manager.state.residentBindings)
	}
	manager.state.mu.Unlock()
}

func TestFixedBindingMaterializationFailureWakesOrderedClose(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	binding, _ := manager.Bind(1)
	request := fixedBindingProxyRequest()
	entered := make(chan struct{})
	release := make(chan struct{})
	manager.state.materializeHookForTest = sync.OnceFunc(func() {
		close(entered)
		<-release
	})
	prepareDone := make(chan error, 1)
	go func() {
		_, prepareErr := binding.PrepareProxyRequest(request)
		prepareDone <- prepareErr
	}()
	<-entered
	closeDone := binding.BeginClose()
	request.Packet[0] = 0
	close(release)
	if err := <-prepareDone; !errors.Is(err, ErrFixedBindingRequestRejected) {
		t.Fatalf("materialization failure = %v", err)
	}
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("ordered close stranded after materialization failure")
	}
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	attempts := link.attemptedSubmissions()
	if len(attempts) != 1 {
		t.Fatalf("attempts = %d, want only CloseConnection", len(attempts))
	}
	if _, err := ParseCloseConnection(attempts[0].Payload); err != nil {
		t.Fatalf("ordered control = %v", err)
	}
	if closeErr, ok := binding.CloseResult(); !ok || !errors.Is(closeErr, ErrInvalidMTProtoEnvelope) {
		t.Fatalf("CloseResult = %v, %v", closeErr, ok)
	}
}

func TestFixedBindingManagerReadyCoalescesEventAndTerminal(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte{1, 2, 3, 4}
	link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet})
	link.emit(LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: binding.ConnectionID()})
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return binding.state.items == 2 && binding.state.terminal
	})
	token := nextFixedBindingReadyToken(t, manager)
	if terminalErr, ok, err := token.TryTerminal(); err != nil || ok || terminalErr != nil {
		t.Fatalf("terminal bypassed queued events = %v, %v, %v", terminalErr, ok, err)
	}
	for _, want := range []LinkEventKind{LinkEventProxyAnswer, LinkEventCloseExternal} {
		event, ok, err := token.TryNextEvent()
		if err != nil || !ok || event.Kind != want {
			t.Fatalf("TryNextEvent = %+v, %v, %v; want %d", event, ok, err, want)
		}
	}
	if terminalErr, ok, err := token.TryTerminal(); err != nil || !ok || terminalErr != nil {
		t.Fatalf("TryTerminal = %v, %v, %v", terminalErr, ok, err)
	}
	if err := token.Ack(); err != nil {
		t.Fatal(err)
	}
	if err := token.Ack(); !errors.Is(err, ErrFixedBindingReadyToken) {
		t.Fatalf("duplicate Ack = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := binding.NextEvent(ctx); !errors.Is(err, ErrFixedBindingConsumerMode) {
		t.Fatalf("mixed NextEvent = %v", err)
	}
	manager.state.mu.Lock()
	residents := manager.state.residentBindings
	manager.state.mu.Unlock()
	if residents != 0 {
		t.Fatalf("resident bindings after terminal Ack = %d", residents)
	}
}

func TestFixedBindingReadyAckBeforeConsumeRequeuesReason(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, _ := manager.Bind(1)
	link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID(), ConfirmKey: 123})
	first := nextFixedBindingReadyToken(t, manager)
	if err := first.Ack(); err != nil {
		t.Fatal(err)
	}
	second := nextFixedBindingReadyToken(t, manager)
	if second.ConnectionID() != binding.ConnectionID() {
		t.Fatalf("requeued connection = %d", second.ConnectionID())
	}
	event, ok, err := second.TryNextEvent()
	if err != nil || !ok || event.Kind != LinkEventSimpleAck || event.ConfirmKey != 123 {
		t.Fatalf("requeued event = %+v, %v, %v", event, ok, err)
	}
	if err := second.Ack(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.TryNextEvent(); !errors.Is(err, ErrFixedBindingReadyToken) {
		t.Fatalf("stale token = %v", err)
	}
}

func TestFixedBindingManagerControlQueueDropsStaleCloseWithoutFailingLink(t *testing.T) {
	limits := fixedBindingTestLimits()
	limits.MaxPendingControlItemsPerSlot = 2
	limits.MaxPendingControlItems = 2
	limits.MaxPendingControlBytesPerSlot = ClosePayloadSize + KeepalivePayloadSize
	limits.MaxPendingControlBytes = ClosePayloadSize + KeepalivePayloadSize
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 101})
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 102})
	waitFixedBindingCondition(t, func() bool {
		return manager.Snapshot().ControlBackpressureEvents == 1
	})
	manager.state.mu.Lock()
	slot := manager.state.slots[1]
	if slot.failed {
		manager.state.mu.Unlock()
		t.Fatal("stale close control saturation failed the shared link")
	}
	if slot.controlItems != 1 || slot.controlBytes != ClosePayloadSize || manager.state.controlItems != 1 || manager.state.controlBytes != ClosePayloadSize {
		t.Fatalf("control charges = slot %d/%d global %d/%d", slot.controlItems, slot.controlBytes, manager.state.controlItems, manager.state.controlBytes)
	}
	manager.state.mu.Unlock()
	_, _, _, _, rejected := link.stats()
	if len(rejected) != 1 {
		t.Fatalf("link attempts after dropped stale close = %d", len(rejected))
	}
}

func TestClientBindingCloseControlBackpressureIsBindingLocal(t *testing.T) {
	limits := fixedBindingTestLimits()
	limits.MaxPendingControlItemsPerSlot = 2
	limits.MaxPendingControlItems = 2
	limits.MaxPendingControlBytesPerSlot = ClosePayloadSize + KeepalivePayloadSize
	limits.MaxPendingControlBytes = ClosePayloadSize + KeepalivePayloadSize
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID() + 1_000_000})
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })

	select {
	case <-binding.BeginClose():
	case <-time.After(time.Second):
		t.Fatal("binding-local close did not complete after bounded control rejection")
	}
	if result, complete := binding.CloseResult(); !complete || result != nil {
		t.Fatalf("binding close result = %v, complete %v", result, complete)
	}
	snapshot := manager.Snapshot()
	if snapshot.ControlBackpressureEvents != 1 || snapshot.ResidentBindings != 0 || snapshot.Slots[0].Failed {
		t.Fatalf("post-close snapshot = %+v", snapshot)
	}
	if _, err := manager.Bind(1); err != nil {
		t.Fatalf("shared link rejected a new binding after local close pressure: %v", err)
	}
}

func TestFixedBindingManagerRequiresLivenessControlReserve(t *testing.T) {
	for name, mutate := range map[string]func(*FixedBindingLimits){
		"slot items": func(limits *FixedBindingLimits) {
			limits.MaxPendingControlItemsPerSlot = 1
		},
		"slot bytes": func(limits *FixedBindingLimits) {
			limits.MaxPendingControlBytesPerSlot = ClosePayloadSize + KeepalivePayloadSize - 1
		},
		"global items": func(limits *FixedBindingLimits) {
			limits.MaxPendingControlItems = 1
		},
		"global bytes": func(limits *FixedBindingLimits) {
			limits.MaxPendingControlBytes = ClosePayloadSize + KeepalivePayloadSize - 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			limits := fixedBindingTestLimits()
			mutate(&limits)
			if _, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: newFixedBindingFakeLink()}}, limits); !errors.Is(err, ErrInvalidFixedBindingManager) {
				t.Fatalf("reserve validation = %v", err)
			}
		})
	}
}

func TestFixedBindingManagerRejectsCapacityIdentityAndUnusableMinima(t *testing.T) {
	nilCapacity := newFixedBindingFakeLink()
	nilCapacity.ready = nil
	if _, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: nilCapacity}}, fixedBindingTestLimits()); !errors.Is(err, ErrInvalidFixedBindingManager) {
		t.Fatalf("nil capacity channel = %v", err)
	}
	first := newFixedBindingFakeLink()
	second := newFixedBindingFakeLink()
	second.ready = first.ready
	if _, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: first}, {DCID: 2, Link: second}}, fixedBindingTestLimits()); !errors.Is(err, ErrInvalidFixedBindingManager) {
		t.Fatalf("duplicate capacity channel = %v", err)
	}
	for _, mutate := range []func(*FixedBindingLimits){
		func(l *FixedBindingLimits) {
			l.MaxPendingRequestBytesPerBinding = ProxyRequestBaseSize + UnencryptedMessageHeaderSize + MinimumUnencryptedBodySize - 1
		},
		func(l *FixedBindingLimits) { l.MaxPendingControlBytesPerSlot = ClosePayloadSize - 1 },
		func(l *FixedBindingLimits) { l.MaxPendingResponseBytes = ClosePayloadSize - 1 },
	} {
		limits := fixedBindingTestLimits()
		mutate(&limits)
		if err := limits.Validate(); !errors.Is(err, ErrInvalidFixedBindingManager) {
			t.Fatalf("unusable minimum = %v", err)
		}
	}
}

func TestFixedBindingGlobalWaitArbitration(t *testing.T) {
	t.Run("oldest global waiter blocks smaller bypass", func(t *testing.T) {
		limits := fixedBindingTestLimits()
		limits.MaxPendingRequestBytesPerBinding = 400
		limits.MaxPendingRequestBytesPerSlot = 400
		limits.MaxPendingRequestBytes = 400
		anchorLink := newFixedBindingFakeLink()
		anchorLink.setTryError(ErrLinkBackpressure)
		oldLink := newFixedBindingFakeLink()
		smallLink := newFixedBindingFakeLink()
		manager, err := NewFixedBindingManager([]FixedBindingSlot{
			{DCID: 1, Link: anchorLink}, {DCID: 2, Link: oldLink}, {DCID: 3, Link: smallLink},
		}, limits)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = manager.Close() })
		anchor, _ := manager.Bind(1)
		oldest, _ := manager.Bind(2)
		smaller, _ := manager.Bind(3)
		anchorRequest := fixedBindingProxyRequest()
		anchorRequest.Packet = make([]byte, 144)
		anchorRequest.Packet[0] = 1
		oldRequest := fixedBindingProxyRequest()
		oldRequest.Packet = make([]byte, 244)
		oldRequest.Packet[0] = 1
		smallRequest := fixedBindingProxyRequest()
		if _, err := anchor.PrepareProxyRequest(anchorRequest); err != nil {
			t.Fatal(err)
		}
		waitFixedBindingCondition(t, func() bool { return len(anchorLink.attemptedSubmissions()) == 1 })
		if status, err := oldest.PrepareProxyRequest(oldRequest); err != nil || status != PrepareProxyRequestWaiting {
			t.Fatalf("oldest = %d, %v", status, err)
		}
		if status, err := smaller.PrepareProxyRequest(smallRequest); err != nil || status != PrepareProxyRequestWaiting {
			t.Fatalf("smaller = %d, %v", status, err)
		}
		manager.state.mu.Lock()
		oldPhase := oldest.state.request.phase
		smallPhase := smaller.state.request.phase
		manager.state.mu.Unlock()
		if oldPhase != preparedRequestWaiting || smallPhase != preparedRequestWaiting {
			t.Fatalf("global bypass phases = old %d small %d", oldPhase, smallPhase)
		}
		anchorLink.setTryError(nil)
		anchorLink.ready <- struct{}{}
		waitFixedBindingCondition(t, func() bool {
			manager.state.mu.Lock()
			defer manager.state.mu.Unlock()
			return oldest.state.request.phase == preparedRequestReserved
		})
		manager.state.mu.Lock()
		smallPhase = smaller.state.request.phase
		manager.state.mu.Unlock()
		if smallPhase != preparedRequestWaiting {
			t.Fatalf("smaller bypassed 300-byte oldest reservation: phase %d", smallPhase)
		}
	})

	t.Run("locally ineligible head does not block unrelated slot", func(t *testing.T) {
		limits := fixedBindingTestLimits()
		limits.MaxPendingRequestItemsPerSlot = 1
		limits.MaxPendingRequestItems = 2
		firstLink := newFixedBindingFakeLink()
		firstLink.setTryError(ErrLinkBackpressure)
		secondLink := newFixedBindingFakeLink()
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: firstLink}, {DCID: 2, Link: secondLink}}, limits)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = manager.Close() })
		anchor, _ := manager.Bind(1)
		blocked, _ := manager.Bind(1)
		unrelated, _ := manager.Bind(2)
		request := fixedBindingProxyRequest()
		_, _ = anchor.PrepareProxyRequest(request)
		waitFixedBindingCondition(t, func() bool { return len(firstLink.attemptedSubmissions()) == 1 })
		_, _ = blocked.PrepareProxyRequest(request)
		if status, err := unrelated.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestWaiting {
			t.Fatalf("unrelated prepare = %d, %v", status, err)
		}
		manager.state.mu.Lock()
		blockedPhase := blocked.state.request.phase
		unrelatedPhase := unrelated.state.request.phase
		manager.state.mu.Unlock()
		if blockedPhase != preparedRequestWaiting || unrelatedPhase != preparedRequestReserved {
			t.Fatalf("local eligibility phases = blocked %d unrelated %d", blockedPhase, unrelatedPhase)
		}
	})
}

func TestFixedBindingTicketAndEpochExhaustionNeverWraps(t *testing.T) {
	t.Run("wait ticket stops manager", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		link.setTryError(ErrLinkBackpressure)
		limits := fixedBindingTestLimits()
		limits.MaxPendingRequestItemsPerSlot = 1
		limits.MaxPendingRequestItems = 1
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		first, _ := manager.Bind(1)
		second, _ := manager.Bind(1)
		_, _ = first.PrepareProxyRequest(fixedBindingProxyRequest())
		waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
		manager.state.mu.Lock()
		manager.state.waitTicket = math.MaxUint64
		manager.state.mu.Unlock()
		if _, err := second.PrepareProxyRequest(fixedBindingProxyRequest()); !errors.Is(err, ErrFixedBindingWaitTicketExhausted) {
			t.Fatalf("wait ticket exhaustion = %v", err)
		}
		<-manager.Done()
		if !errors.Is(manager.Err(), ErrFixedBindingWaitTicketExhausted) {
			t.Fatalf("manager Err = %v", manager.Err())
		}
	})

	t.Run("reservation epoch retires only binding", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		binding, _ := manager.Bind(1)
		binding.state.reservationEpoch = math.MaxUint64
		if _, err := binding.PrepareProxyRequest(fixedBindingProxyRequest()); !errors.Is(err, ErrFixedBindingEpochExhausted) {
			t.Fatalf("reservation epoch = %v", err)
		}
		if manager.Err() != nil {
			t.Fatalf("binding-local epoch stopped manager: %v", manager.Err())
		}
		if _, err := manager.Bind(1); err != nil {
			t.Fatalf("healthy Bind after binding epoch exhaustion = %v", err)
		}
	})

	t.Run("ready epoch stops manager", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		binding, _ := manager.Bind(1)
		packet := []byte{1, 2, 3, 4}
		link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet})
		waitFixedBindingCondition(t, func() bool {
			manager.state.mu.Lock()
			defer manager.state.mu.Unlock()
			return binding.state.readyQueued
		})
		manager.state.mu.Lock()
		binding.state.readyEpoch = math.MaxUint64
		manager.state.mu.Unlock()
		if token := manager.TryNextReady(); token != nil {
			t.Fatalf("ready epoch returned token: %v", token)
		}
		<-manager.Done()
		if !errors.Is(manager.Err(), ErrFixedBindingEpochExhausted) || !allZero(packet) {
			t.Fatalf("ready epoch Err/packet = %v/%x", manager.Err(), packet)
		}
	})
}

func TestFixedBindingEpochRejectedHeadWakesControlFollower(t *testing.T) {
	limits := fixedBindingTestLimits()
	limits.MaxPendingRequestItemsPerSlot = 1
	limits.MaxPendingRequestItems = 1
	anchorLink := newFixedBindingFakeLink()
	anchorLink.setTryError(ErrLinkBackpressure)
	followerLink := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: anchorLink}, {DCID: 2, Link: followerLink}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	anchor, _ := manager.Bind(1)
	candidate, _ := manager.Bind(2)
	_, _ = anchor.PrepareProxyRequest(fixedBindingProxyRequest())
	waitFixedBindingCondition(t, func() bool { return len(anchorLink.attemptedSubmissions()) == 1 })
	candidate.state.reservationEpoch = math.MaxUint64
	if status, err := candidate.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil || status != PrepareProxyRequestWaiting {
		t.Fatalf("candidate prepare = %d, %v", status, err)
	}
	followerLink.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 987654})
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return manager.state.slots[2].controlItems == 1
	})
	if got := len(followerLink.attemptedSubmissions()); got != 0 {
		t.Fatalf("control bypassed waiting head: %d attempts", got)
	}
	anchorLink.setTryError(nil)
	anchorLink.ready <- struct{}{}
	waitFixedBindingCondition(t, func() bool { return len(followerLink.attemptedSubmissions()) == 1 })
	attempt := followerLink.attemptedSubmissions()[0]
	closed, err := ParseCloseConnection(attempt.Payload)
	if err != nil || closed.ConnectionID != 987654 {
		t.Fatalf("control follower = %+v, %v", attempt, err)
	}
	manager.state.mu.Lock()
	anchorSlot := manager.state.slots[1]
	followerSlot := manager.state.slots[2]
	if manager.state.requestItems != 0 || manager.state.requestBytes != 0 ||
		manager.state.controlItems != 0 || manager.state.controlBytes != 0 ||
		anchorSlot.requestItems != 0 || anchorSlot.requestBytes != 0 ||
		followerSlot.requestItems != 0 || followerSlot.requestBytes != 0 ||
		followerSlot.controlItems != 0 || followerSlot.controlBytes != 0 {
		t.Fatalf("head rejection counters = global request %d/%d control %d/%d; anchor request %d/%d; follower request %d/%d control %d/%d",
			manager.state.requestItems, manager.state.requestBytes, manager.state.controlItems, manager.state.controlBytes,
			anchorSlot.requestItems, anchorSlot.requestBytes, followerSlot.requestItems, followerSlot.requestBytes,
			followerSlot.controlItems, followerSlot.controlBytes)
	}
	if !candidate.state.terminal || !errors.Is(candidate.state.terminalErr, ErrFixedBindingEpochExhausted) {
		t.Fatalf("candidate terminal = %v, %v", candidate.state.terminal, candidate.state.terminalErr)
	}
	manager.state.mu.Unlock()
}

func TestFixedBindingPromotedReservationSubmissionIDExhaustionRollsBack(t *testing.T) {
	restore := setFixedBindingAllocatorStateForTest(0, 0)
	defer restore()
	limits := fixedBindingTestLimits()
	limits.MaxPendingRequestItemsPerSlot = 1
	limits.MaxPendingRequestItems = 1
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	first, _ := manager.Bind(1)
	second, _ := manager.Bind(1)
	request := fixedBindingProxyRequest()
	_, _ = first.PrepareProxyRequest(request)
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	_, _ = second.PrepareProxyRequest(request)
	link.setTryError(nil)
	link.ready <- struct{}{}
	var reservation *ClientPrepareReservation
	for reservation == nil {
		token := nextFixedBindingReadyToken(t, manager)
		if token.ConnectionID() == first.ConnectionID() {
			_, _, _ = token.TryTakeRequestResult()
		} else {
			reservation, _, err = token.TryTakePrepareReservation()
			if err != nil {
				t.Fatal(err)
			}
		}
		_ = token.Ack()
	}
	fixedBindingSubmissionIDs.Store(math.MaxUint64)
	if err := second.PrepareReservedProxyRequest(reservation, request); !errors.Is(err, ErrFixedBindingSubmissionIDExhausted) {
		t.Fatalf("materialization exhaustion = %v", err)
	}
	<-manager.Done()
	manager.state.mu.Lock()
	if manager.state.requestItems != 0 || manager.state.requestBytes != 0 || manager.state.residentBindings != 0 {
		t.Fatalf("exhaustion rollback = requests %d/%d residents %d", manager.state.requestItems, manager.state.requestBytes, manager.state.residentBindings)
	}
	manager.state.mu.Unlock()
}

func TestFixedBindingReadyLeaseCoalescesAllReasons(t *testing.T) {
	limits := fixedBindingTestLimits()
	limits.MaxPendingRequestItemsPerSlot = 1
	limits.MaxPendingRequestItems = 1
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	blocker, _ := manager.Bind(1)
	target, _ := manager.Bind(1)
	request := fixedBindingProxyRequest()
	_, _ = blocker.PrepareProxyRequest(request)
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	packet := []byte{4, 3, 2, 1}
	link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: target.ConnectionID(), Packet: packet})
	token := nextFixedBindingReadyToken(t, manager)
	if token.ConnectionID() != target.ConnectionID() {
		t.Fatalf("leased token connection = %d", token.ConnectionID())
	}
	if status, err := target.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestWaiting {
		t.Fatalf("target prepare = %d, %v", status, err)
	}
	link.setTryError(nil)
	link.ready <- struct{}{}
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return target.state.request.phase == preparedRequestReserved
	})
	reservation, ok, err := token.TryTakePrepareReservation()
	if err != nil || !ok {
		t.Fatalf("reservation on existing lease = %v, %v, %v", reservation, ok, err)
	}
	if err := target.PrepareReservedProxyRequest(reservation, request); err != nil {
		t.Fatal(err)
	}
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return target.state.result != nil
	})
	link.emit(LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: target.ConnectionID()})
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return target.state.terminal
	})
	if terminalErr, ok, err := token.TryTerminal(); err != nil || ok || terminalErr != nil {
		t.Fatalf("terminal bypassed result/events = %v, %v, %v", terminalErr, ok, err)
	}
	result, ok, err := token.TryTakeRequestResult()
	if err != nil || !ok || !result.Accepted {
		t.Fatalf("coalesced result = %+v, %v, %v", result, ok, err)
	}
	for _, want := range []LinkEventKind{LinkEventProxyAnswer, LinkEventCloseExternal} {
		event, ok, err := token.TryNextEvent()
		if err != nil || !ok || event.Kind != want {
			t.Fatalf("coalesced event = %+v, %v, %v", event, ok, err)
		}
	}
	if terminalErr, ok, err := token.TryTerminal(); err != nil || !ok || terminalErr != nil {
		t.Fatalf("coalesced terminal = %v, %v, %v", terminalErr, ok, err)
	}
	if err := token.Ack(); err != nil {
		t.Fatal(err)
	}
}

func TestFixedBindingCloseQueuesAfterOwnedRequestAcrossBackpressure(t *testing.T) {
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	binding, _ := manager.Bind(1)
	request := fixedBindingProxyRequest()
	if status, err := binding.PrepareProxyRequest(request); err != nil || status != PrepareProxyRequestQueued {
		t.Fatalf("PrepareProxyRequest = %d, %v", status, err)
	}
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	closeDone := binding.BeginClose()
	manager.state.mu.Lock()
	head := manager.state.slots[1].outHead
	if head == nil || head.kind != outboundRequest || head.next == nil || head.next.kind != outboundControl {
		manager.state.mu.Unlock()
		t.Fatal("local close was not queued behind the manager-owned request")
	}
	manager.state.mu.Unlock()
	first := link.attemptedSubmissions()[0]
	firstPointer := &first.Payload[0]
	wantPayload := bytes.Clone(first.Payload)
	for attempt := range 1000 {
		link.ready <- struct{}{}
		waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == attempt+2 })
		latest := link.attemptedSubmissions()[attempt+1]
		if latest.SubmissionID != first.SubmissionID || latest.ConnectionID != first.ConnectionID ||
			&latest.Payload[0] != firstPointer || !bytes.Equal(latest.Payload, wantPayload) {
			t.Fatalf("request attempt %d changed before close", attempt+1)
		}
	}
	link.setTryError(nil)
	link.ready <- struct{}{}
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("ordered close did not complete")
	}
	attempts := link.attemptedSubmissions()
	if len(attempts) != 1003 {
		t.Fatalf("attempt count = %d", len(attempts))
	}
	requestSubmission := attempts[len(attempts)-2]
	closeSubmission := attempts[len(attempts)-1]
	if requestSubmission.SubmissionID != first.SubmissionID || !bytes.Equal(requestSubmission.Payload, wantPayload) {
		t.Fatal("accepted request changed")
	}
	if _, err := ParseProxyRequest(requestSubmission.Payload); err != nil {
		t.Fatalf("request order = %v", err)
	}
	closed, err := ParseCloseConnection(closeSubmission.Payload)
	if err != nil || closed.ConnectionID != binding.ConnectionID() || closeSubmission.SubmissionID == first.SubmissionID {
		t.Fatalf("close order = %+v, %v", closeSubmission, err)
	}
	if err, ok := binding.CloseResult(); !ok || err != nil {
		t.Fatalf("CloseResult = %v, %v", err, ok)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requestSubmission.Payload, wantPayload) || allZero(closeSubmission.Payload) {
		t.Fatal("manager cleared payload backing transferred to link")
	}
}

func TestFixedBindingRemoteCloseLocalCleanupReleasesResident(t *testing.T) {
	limits := fixedBindingTestLimits()
	limits.MaxResidentBindings = 1
	limits.MaxResidentBindingsPerSlot = 1
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	binding, _ := manager.Bind(1)
	if _, err := binding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil {
		t.Fatal(err)
	}
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return binding.state.result != nil
	})
	packet := []byte{8, 7, 6, 5}
	link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet})
	link.emit(LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: binding.ConnectionID()})
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return binding.state.terminal && binding.state.items == 2
	})
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	if !allZero(packet) {
		t.Fatalf("local cleanup retained remote packet: %x", packet)
	}
	manager.state.mu.Lock()
	residents := manager.state.residentBindings
	pending := manager.state.pending
	result := binding.state.result
	manager.state.mu.Unlock()
	if residents != 0 || pending != 0 || result != nil {
		t.Fatalf("cleanup state = residents %d pending %d result %v", residents, pending, result)
	}
	if _, err := manager.Bind(1); err != nil {
		t.Fatalf("Bind after cleanup = %v", err)
	}
}

func TestFixedBindingManagerClosePreservesStickySlotFailureForBinding(t *testing.T) {
	failure := errors.New("sticky slot failure")
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	binding, _ := manager.Bind(1)
	link.peerClose(failure)
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return manager.state.slots[1].failed
	})
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := binding.Close(); !errors.Is(err, ErrFixedBindingSlotFailed) || !errors.Is(err, failure) {
		t.Fatalf("binding Close after manager Close = %v", err)
	}
	if err, ok := binding.CloseResult(); !ok || !errors.Is(err, ErrFixedBindingSlotFailed) || !errors.Is(err, failure) {
		t.Fatalf("CloseResult = %v, %v", err, ok)
	}
}

func TestFixedBindingBlockingConsumerTerminalChurnReleasesResident(t *testing.T) {
	limits := fixedBindingTestLimits()
	limits.MaxResidentBindings = 1
	limits.MaxResidentBindingsPerSlot = 1
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	for iteration := range 100 {
		binding, err := manager.Bind(1)
		if err != nil {
			t.Fatalf("Bind %d = %v", iteration, err)
		}
		link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID(), ConfirmKey: uint32(iteration + 1)})
		link.emit(LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: binding.ConnectionID()})
		if event := nextFixedBindingEvent(t, binding); event.Kind != LinkEventSimpleAck {
			t.Fatalf("iteration %d first event = %+v", iteration, event)
		}
		if event := nextFixedBindingEvent(t, binding); event.Kind != LinkEventCloseExternal {
			t.Fatalf("iteration %d close event = %+v", iteration, event)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		_, eventErr := binding.NextEvent(ctx)
		cancel()
		if !errors.Is(eventErr, io.EOF) {
			t.Fatalf("iteration %d terminal = %v", iteration, eventErr)
		}
		manager.state.mu.Lock()
		residents := manager.state.residentBindings
		queued := binding.state.readyQueued
		manager.state.mu.Unlock()
		if residents != 0 || queued || manager.TryNextReady() != nil {
			t.Fatalf("iteration %d readiness pinned resident: residents=%d queued=%v", iteration, residents, queued)
		}
	}
}

func TestFixedBindingManagerCloseNeedsNoReadyOrCapacityConsumer(t *testing.T) {
	t.Run("materialized waiting and queued control", func(t *testing.T) {
		limits := fixedBindingTestLimits()
		limits.MaxPendingRequestItemsPerSlot = 1
		limits.MaxPendingRequestItems = 1
		link := newFixedBindingFakeLink()
		link.setTryError(ErrLinkBackpressure)
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		first, _ := manager.Bind(1)
		second, _ := manager.Bind(1)
		_, _ = first.PrepareProxyRequest(fixedBindingProxyRequest())
		waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
		_, _ = second.PrepareProxyRequest(fixedBindingProxyRequest())
		link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 99999})
		waitFixedBindingCondition(t, func() bool {
			manager.state.mu.Lock()
			defer manager.state.mu.Unlock()
			return manager.state.controlItems == 1
		})
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
		manager.state.mu.Lock()
		if manager.state.requestItems != 0 || manager.state.requestBytes != 0 ||
			manager.state.controlItems != 0 || manager.state.controlBytes != 0 || manager.state.residentBindings != 0 {
			t.Fatalf("terminal retained state = requests %d/%d controls %d/%d residents %d",
				manager.state.requestItems, manager.state.requestBytes, manager.state.controlItems,
				manager.state.controlBytes, manager.state.residentBindings)
		}
		manager.state.mu.Unlock()
		for index, attempted := range link.attemptedSubmissions() {
			if !allZero(attempted.Payload) {
				t.Fatalf("manager-owned attempt %d not cleared", index)
			}
		}
	})

	t.Run("reserved and unconsumed result", func(t *testing.T) {
		limits := fixedBindingTestLimits()
		limits.MaxPendingRequestItemsPerSlot = 1
		limits.MaxPendingRequestItems = 1
		link := newFixedBindingFakeLink()
		link.setTryError(ErrLinkBackpressure)
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		first, _ := manager.Bind(1)
		second, _ := manager.Bind(1)
		_, _ = first.PrepareProxyRequest(fixedBindingProxyRequest())
		waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
		_, _ = second.PrepareProxyRequest(fixedBindingProxyRequest())
		link.setTryError(nil)
		link.ready <- struct{}{}
		waitFixedBindingCondition(t, func() bool {
			manager.state.mu.Lock()
			defer manager.state.mu.Unlock()
			return first.state.result != nil && second.state.request.phase == preparedRequestReserved && second.state.readyQueued
		})
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
		manager.state.mu.Lock()
		if manager.state.requestItems != 0 || manager.state.requestBytes != 0 || manager.state.residentBindings != 0 ||
			first.state.result != nil || first.state.readyQueued || second.state.readyQueued {
			t.Fatalf("reserved/result shutdown retained state")
		}
		manager.state.mu.Unlock()
	})

	t.Run("leased result event and terminal", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		binding, _ := manager.Bind(1)
		_, _ = binding.PrepareProxyRequest(fixedBindingProxyRequest())
		packet := []byte{1, 3, 3, 7}
		link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet})
		waitFixedBindingCondition(t, func() bool {
			manager.state.mu.Lock()
			defer manager.state.mu.Unlock()
			return binding.state.result != nil && binding.state.items == 1
		})
		token := nextFixedBindingReadyToken(t, manager)
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
		if err := token.Ack(); !errors.Is(err, ErrFixedBindingReadyToken) {
			t.Fatalf("shutdown token Ack = %v", err)
		}
		if !allZero(packet) {
			t.Fatalf("shutdown retained queued packet: %x", packet)
		}
		manager.state.mu.Lock()
		if manager.state.pending != 0 || manager.state.pendingBytes != 0 || manager.state.residentBindings != 0 {
			t.Fatalf("leased shutdown accounting = %d/%d residents %d", manager.state.pending, manager.state.pendingBytes, manager.state.residentBindings)
		}
		manager.state.mu.Unlock()
	})

	t.Run("local close control", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		link.setTryError(ErrLinkBackpressure)
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		binding, _ := manager.Bind(1)
		bindingDone := binding.BeginClose()
		waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-bindingDone:
		default:
			t.Fatal("manager Close did not cancel local close")
		}
		attempt := link.attemptedSubmissions()[0]
		if !allZero(attempt.Payload) {
			t.Fatalf("canceled local close payload not cleared: %x", attempt.Payload)
		}
	})
}

func TestFixedBindingManagerClosePublishesPayloadFreeReadyTerminal(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	binding, err := manager.BindReady(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot := manager.Snapshot()
	if snapshot.ResidentBindings != 0 || snapshot.RequestBytes != 0 || snapshot.ControlBytes != 0 || snapshot.ResponseBytes != 0 {
		t.Fatalf("closed manager retained resident or payload state: %+v", snapshot)
	}

	token := nextFixedBindingReadyToken(t, manager)
	if token.ConnectionID() != binding.ConnectionID() {
		t.Fatalf("terminal token connection = %d, want %d", token.ConnectionID(), binding.ConnectionID())
	}
	terminalErr, terminal, err := token.TryTerminal()
	if err != nil || !terminal || terminalErr != nil {
		t.Fatalf("terminal token = terminal %v error %v token error %v", terminal, terminalErr, err)
	}
	if err := token.Ack(); err != nil {
		t.Fatalf("terminal token Ack: %v", err)
	}
	if token := manager.TryNextReady(); token != nil {
		t.Fatalf("unexpected readiness after terminal Ack: %v", token)
	}
}

func TestFixedBindingManagerRoutesOrderedResponsesAndReleasesCharges(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	events := []LinkEvent{
		{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), AnswerFlags: ProxyAnswerFlagFlush, Packet: []byte{1, 2, 3, 4}},
		{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID(), ConfirmKey: 0x11223344},
		{Kind: LinkEventCloseExternal, ConnectionID: binding.ConnectionID()},
	}
	wantEvents := make([]LinkEvent, len(events))
	copy(wantEvents, events)
	for index := range wantEvents {
		wantEvents[index].Packet = bytes.Clone(events[index].Packet)
	}
	for _, event := range events {
		link.emit(event)
	}
	wantItems := len(events)
	wantBytes := 0
	for _, event := range events {
		wantBytes += event.ByteSize()
	}
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		slot := manager.state.slots[1]
		return binding.state.items == wantItems && binding.state.bytes == wantBytes &&
			slot.pending == wantItems && slot.bytes == wantBytes &&
			manager.state.pending == wantItems && manager.state.pendingBytes == wantBytes
	})
	remainingBytes := wantBytes
	for index, want := range wantEvents {
		got := nextFixedBindingEvent(t, binding)
		if got.Kind != want.Kind || got.AnswerFlags != want.AnswerFlags || got.ConfirmKey != want.ConfirmKey || !bytes.Equal(got.Packet, want.Packet) {
			t.Fatalf("event %d = %+v, want %+v", index, got, want)
		}
		remainingBytes -= want.ByteSize()
		remainingItems := wantItems - index - 1
		manager.state.mu.Lock()
		slot := manager.state.slots[1]
		if binding.state.items != remainingItems || binding.state.bytes != remainingBytes ||
			slot.pending != remainingItems || slot.bytes != remainingBytes ||
			manager.state.pending != remainingItems || manager.state.pendingBytes != remainingBytes {
			t.Fatalf("charges after %d = binding %d/%d slot %d/%d global %d/%d",
				index, binding.state.items, binding.state.bytes, slot.pending, slot.bytes,
				manager.state.pending, manager.state.pendingBytes)
		}
		manager.state.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := binding.NextEvent(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal NextEvent = %v", err)
	}
	if err := binding.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, _, submissions, _ := link.stats()
	if len(submissions) != 0 {
		t.Fatalf("remote close caused reciprocal submissions: %+v", submissions)
	}
}

func TestClientBindingResponseRingStaysBoundedUnderNeverEmptyChurn(t *testing.T) {
	const (
		limit = 3
		churn = 4096
	)
	limits := fixedBindingTestLimits()
	limits.MaxPendingResponseItemsPerBinding = limit
	limits.MaxPendingResponseItemsPerSlot = limit
	limits.MaxPendingResponseItems = limit
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager(
		[]FixedBindingSlot{{DCID: 1, Link: link}},
		limits,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	for key := uint32(1); key <= limit; key++ {
		link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID(), ConfirmKey: key})
	}
	wantBytes := limit * SimpleAckPayloadSize
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return binding.state.items == limit
	})
	for index := range churn {
		wantKey := uint32(index + 1)
		if event := nextFixedBindingEvent(t, binding); event.ConfirmKey != wantKey {
			t.Fatalf("event %d ConfirmKey = %d, want %d", index, event.ConfirmKey, wantKey)
		}
		link.emit(LinkEvent{
			Kind:         LinkEventSimpleAck,
			ConnectionID: binding.ConnectionID(),
			ConfirmKey:   uint32(index + limit + 1),
		})
		waitFixedBindingCondition(t, func() bool {
			manager.state.mu.Lock()
			defer manager.state.mu.Unlock()
			slot := manager.state.slots[1]
			return binding.state.items == limit && binding.state.bytes == wantBytes &&
				slot.pending == limit && slot.bytes == wantBytes &&
				manager.state.pending == limit && manager.state.pendingBytes == wantBytes
		})
		manager.state.mu.Lock()
		if len(binding.state.queue) > limit || cap(binding.state.queue) > limit {
			t.Fatalf("iteration %d queue len/cap = %d/%d, limit %d", index, len(binding.state.queue), cap(binding.state.queue), limit)
		}
		manager.state.mu.Unlock()
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	manager.state.mu.Lock()
	defer manager.state.mu.Unlock()
	slot := manager.state.slots[1]
	if binding.state.items != 0 || binding.state.bytes != 0 || slot.pending != 0 || slot.bytes != 0 ||
		manager.state.pending != 0 || manager.state.pendingBytes != 0 {
		t.Fatalf("terminal charges = binding %d/%d slot %d/%d global %d/%d",
			binding.state.items, binding.state.bytes, slot.pending, slot.bytes,
			manager.state.pending, manager.state.pendingBytes)
	}
	if len(binding.state.queue) > limit || cap(binding.state.queue) > limit {
		t.Fatalf("terminal queue len/cap = %d/%d, limit %d", len(binding.state.queue), cap(binding.state.queue), limit)
	}
	for index, event := range binding.state.queue {
		if event.Kind != 0 || event.ConnectionID != 0 || event.AnswerFlags != 0 ||
			event.ConfirmKey != 0 || event.KeepaliveID != 0 || event.Packet != nil {
			t.Fatalf("terminal queue entry %d retains state: %+v", index, event)
		}
	}
}

func TestFixedBindingManagerRejectsUnchargedPacketFieldsAtEveryResponseByteScope(t *testing.T) {
	for _, kind := range []LinkEventKind{LinkEventSimpleAck, LinkEventCloseExternal} {
		for _, scope := range []string{"binding", "slot", "global"} {
			t.Run(fmt.Sprintf("kind_%d_%s", kind, scope), func(t *testing.T) {
				limits := fixedBindingTestLimits()
				fixedSize := SimpleAckPayloadSize
				if kind == LinkEventCloseExternal {
					fixedSize = ClosePayloadSize
				}
				switch scope {
				case "binding":
					limits.MaxPendingResponseBytesPerBinding = fixedSize
				case "slot":
					limits.MaxPendingResponseBytesPerBinding = fixedSize
					limits.MaxPendingResponseBytesPerSlot = fixedSize
				case "global":
					limits.MaxPendingResponseBytesPerBinding = fixedSize
					limits.MaxPendingResponseBytesPerSlot = fixedSize
					limits.MaxPendingResponseBytes = fixedSize
				}
				link := newFixedBindingFakeLink()
				manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
				if err != nil {
					t.Fatal(err)
				}
				if err := manager.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = manager.Close() })
				binding, err := manager.Bind(1)
				if err != nil {
					t.Fatal(err)
				}
				packet := make([]byte, 64<<10)
				for index := range packet {
					packet[index] = 0xa5
				}
				link.emit(LinkEvent{Kind: kind, ConnectionID: binding.ConnectionID(), Packet: packet})
				waitFixedBindingCondition(t, func() bool {
					manager.state.mu.Lock()
					defer manager.state.mu.Unlock()
					return manager.state.slots[1].failed
				})
				if !allZero(packet) {
					t.Fatal("invalid packet field was not cleared")
				}
				manager.state.mu.Lock()
				slot := manager.state.slots[1]
				if binding.state.items != 0 || binding.state.bytes != 0 || len(binding.state.queue) != 0 ||
					slot.pending != 0 || slot.bytes != 0 || manager.state.pending != 0 || manager.state.pendingBytes != 0 ||
					binding.state.remoteClosed || !errors.Is(slot.err, ErrFixedBindingProtocol) {
					t.Fatalf("retained state = binding %d/%d queue %d slot %d/%d global %d/%d remote %v err %v",
						binding.state.items, binding.state.bytes, len(binding.state.queue), slot.pending, slot.bytes,
						manager.state.pending, manager.state.pendingBytes, binding.state.remoteClosed, slot.err)
				}
				manager.state.mu.Unlock()
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				if _, err := binding.NextEvent(ctx); !errors.Is(err, ErrFixedBindingProtocol) {
					t.Fatalf("NextEvent = %v", err)
				}
			})
		}
	}
}

func TestFixedBindingManagerRejectsImpossibleLinkEventShapes(t *testing.T) {
	tests := []struct {
		name  string
		event func(int64) LinkEvent
	}{
		{name: "unknown kind", event: func(int64) LinkEvent { return LinkEvent{Kind: LinkEventKind(255)} }},
		{name: "answer flags", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: id, AnswerFlags: ProxyAnswerFlags(1)}
		}},
		{name: "answer confirmation", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: id, ConfirmKey: 1}
		}},
		{name: "answer keepalive", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: id, KeepaliveID: 1}
		}},
		{name: "answer alignment", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: id, Packet: []byte{1, 2, 3}}
		}},
		{name: "answer size", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: id, Packet: make([]byte, MaxClientPacketSize+4)}
		}},
		{name: "ack answer flags", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: id, AnswerFlags: ProxyAnswerFlagFlush}
		}},
		{name: "ack keepalive", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: id, KeepaliveID: 1}
		}},
		{name: "ack nonnil empty packet", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: id, Packet: make([]byte, 0, 4096)}
		}},
		{name: "close answer flags", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: id, AnswerFlags: ProxyAnswerFlagFlush}
		}},
		{name: "close confirmation", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: id, ConfirmKey: 1}
		}},
		{name: "close keepalive", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: id, KeepaliveID: 1}
		}},
		{name: "ping connection", event: func(id int64) LinkEvent {
			return LinkEvent{Kind: LinkEventPing, ConnectionID: id, KeepaliveID: 1}
		}},
		{name: "ping answer flags", event: func(int64) LinkEvent {
			return LinkEvent{Kind: LinkEventPing, AnswerFlags: ProxyAnswerFlagFlush, KeepaliveID: 1}
		}},
		{name: "ping confirmation", event: func(int64) LinkEvent {
			return LinkEvent{Kind: LinkEventPing, ConfirmKey: 1, KeepaliveID: 1}
		}},
		{name: "pong packet", event: func(int64) LinkEvent {
			return LinkEvent{Kind: LinkEventPong, KeepaliveID: 1, Packet: []byte{1, 2, 3, 4}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			link := newFixedBindingFakeLink()
			manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
			binding, err := manager.Bind(1)
			if err != nil {
				t.Fatal(err)
			}
			event := test.event(binding.ConnectionID())
			packet := event.Packet
			link.emit(event)
			waitFixedBindingCondition(t, func() bool {
				manager.state.mu.Lock()
				defer manager.state.mu.Unlock()
				return manager.state.slots[1].failed
			})
			if packet != nil && !allZero(packet) {
				t.Fatalf("invalid packet not cleared: %x", packet)
			}
			manager.state.mu.Lock()
			slotErr := manager.state.slots[1].err
			items := binding.state.items
			manager.state.mu.Unlock()
			if !errors.Is(slotErr, ErrFixedBindingProtocol) || items != 0 {
				t.Fatalf("slot error/items = %v/%d", slotErr, items)
			}
		})
	}
}

func TestFixedBindingManagerClonesProxyAnswerAwayFromOversizedBacking(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	backing := make([]byte, 64<<10)
	copy(backing, []byte{1, 2, 3, 4})
	packet := backing[:4]
	link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet})
	wantBytes := ProxyAnswerHeaderSize + len(packet)
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return binding.state.items == 1
	})
	if !allZero(packet) {
		t.Fatalf("transferred source packet not cleared: %x", packet)
	}
	manager.state.mu.Lock()
	queued := binding.state.queue[binding.state.head].Packet
	slot := manager.state.slots[1]
	if len(queued) != 4 || cap(queued) != 4 || binding.state.bytes != wantBytes ||
		slot.bytes != wantBytes || manager.state.pendingBytes != wantBytes {
		t.Fatalf("queued len/cap and charges = %d/%d binding %d slot %d global %d",
			len(queued), cap(queued), binding.state.bytes, slot.bytes, manager.state.pendingBytes)
	}
	manager.state.mu.Unlock()
	copy(backing, []byte{9, 9, 9, 9})
	event := nextFixedBindingEvent(t, binding)
	if !bytes.Equal(event.Packet, []byte{1, 2, 3, 4}) || cap(event.Packet) != len(event.Packet) {
		t.Fatalf("delivered packet/cap = %x/%d", event.Packet, cap(event.Packet))
	}
}

func TestFixedBindingManagerResponseSaturationFailsOnlyOffendingBinding(t *testing.T) {
	tests := []struct {
		name             string
		limits           func() FixedBindingLimits
		secondSlot       bool
		firstKind        LinkEventKind
		secondKind       LinkEventKind
		sameTarget       bool
		preserveIncoming bool
	}{
		{
			name: "per binding items",
			limits: func() FixedBindingLimits {
				l := fixedBindingTestLimits()
				l.MaxPendingResponseItemsPerBinding = 1
				return l
			},
			firstKind:  LinkEventSimpleAck,
			secondKind: LinkEventSimpleAck,
			sameTarget: true,
		},
		{
			name: "per binding bytes",
			limits: func() FixedBindingLimits {
				l := fixedBindingTestLimits()
				l.MaxPendingResponseBytesPerBinding = ProxyAnswerHeaderSize + 3
				return l
			},
			firstKind: LinkEventProxyAnswer,
		},
		{
			name: "per slot items",
			limits: func() FixedBindingLimits {
				l := fixedBindingTestLimits()
				l.MaxPendingResponseItemsPerBinding = 1
				l.MaxPendingResponseItemsPerSlot = 1
				return l
			},
			firstKind:        LinkEventSimpleAck,
			secondKind:       LinkEventSimpleAck,
			preserveIncoming: true,
		},
		{
			name: "per slot bytes",
			limits: func() FixedBindingLimits {
				l := fixedBindingTestLimits()
				l.MaxPendingResponseBytesPerBinding = SimpleAckPayloadSize
				l.MaxPendingResponseBytesPerSlot = SimpleAckPayloadSize + 1
				return l
			},
			firstKind:        LinkEventSimpleAck,
			secondKind:       LinkEventSimpleAck,
			preserveIncoming: true,
		},
		{
			name: "global items",
			limits: func() FixedBindingLimits {
				l := fixedBindingTestLimits()
				l.MaxPendingResponseItemsPerBinding = 1
				l.MaxPendingResponseItems = 1
				l.MaxPendingResponseItemsPerSlot = 1
				return l
			},
			secondSlot:       true,
			firstKind:        LinkEventSimpleAck,
			secondKind:       LinkEventSimpleAck,
			preserveIncoming: true,
		},
		{
			name: "global bytes",
			limits: func() FixedBindingLimits {
				l := fixedBindingTestLimits()
				l.MaxPendingResponseBytes = SimpleAckPayloadSize + 1
				l.MaxPendingResponseBytesPerSlot = SimpleAckPayloadSize
				l.MaxPendingResponseBytesPerBinding = SimpleAckPayloadSize
				return l
			},
			secondSlot:       true,
			firstKind:        LinkEventSimpleAck,
			secondKind:       LinkEventSimpleAck,
			preserveIncoming: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := newFixedBindingFakeLink()
			second := newFixedBindingFakeLink()
			manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: first}, {DCID: 2, Link: second}}, test.limits())
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			bindingA, err := manager.Bind(1)
			if err != nil {
				t.Fatal(err)
			}
			secondDC := DCID(1)
			if test.secondSlot {
				secondDC = 2
			}
			bindingB, err := manager.Bind(secondDC)
			if err != nil {
				t.Fatal(err)
			}
			firstEvent := LinkEvent{Kind: test.firstKind, ConnectionID: bindingA.ConnectionID()}
			if test.firstKind == LinkEventProxyAnswer {
				firstEvent.Packet = []byte{1, 2, 3, 4}
			}
			first.emit(firstEvent)
			if test.secondKind != 0 {
				waitFixedBindingCondition(t, func() bool {
					manager.state.mu.Lock()
					defer manager.state.mu.Unlock()
					return manager.state.pending == 1
				})
				target := bindingB
				if test.sameTarget {
					target = bindingA
				}
				secondEvent := LinkEvent{Kind: test.secondKind, ConnectionID: target.ConnectionID()}
				if test.secondSlot {
					second.emit(secondEvent)
				} else {
					first.emit(secondEvent)
				}
			}
			offendingBinding := bindingA
			healthyBinding := bindingB
			waitFixedBindingCondition(t, func() bool {
				manager.state.mu.Lock()
				defer manager.state.mu.Unlock()
				return offendingBinding.state.terminal
			})
			if test.firstKind == LinkEventProxyAnswer && !allZero(firstEvent.Packet) {
				t.Fatalf("rejected response packet was not cleared: %x", firstEvent.Packet)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if _, nextErr := offendingBinding.NextEvent(ctx); !errors.Is(nextErr, ErrFixedBindingResponseBackpressure) {
				t.Fatalf("NextEvent = %v", nextErr)
			}
			if test.preserveIncoming {
				event, nextErr := healthyBinding.NextEvent(ctx)
				if nextErr != nil || event.Kind != test.secondKind {
					t.Fatalf("preserved incoming event = %+v, %v", event, nextErr)
				}
			}
			snapshot := manager.Snapshot()
			for _, slot := range snapshot.Slots {
				if slot.Failed {
					t.Fatalf("response saturation failed shared slot: %+v", slot)
				}
			}
			if _, err := healthyBinding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil {
				t.Fatalf("healthy binding unusable: %v", err)
			}
			if _, err := manager.Bind(healthyBinding.DCID()); err != nil {
				t.Fatalf("healthy slot rejected new binding: %v", err)
			}
			if err := manager.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFixedBindingManagerRejectsZeroAndCrossSlotIDs(t *testing.T) {
	for _, test := range []struct {
		name         string
		connectionID int64
	}{
		{name: "zero"},
		{name: "negative one", connectionID: -1},
		{name: "minimum int64", connectionID: math.MinInt64},
	} {
		t.Run(test.name, func(t *testing.T) {
			link := newFixedBindingFakeLink()
			manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
			packet := []byte{5, 4, 3, 2}
			link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: test.connectionID, Packet: packet})
			waitFixedBindingCondition(t, func() bool {
				manager.state.mu.Lock()
				defer manager.state.mu.Unlock()
				return manager.state.slots[1].failed
			})
			if !allZero(packet) {
				t.Fatalf("rejected packet not cleared: %x", packet)
			}
			manager.state.mu.Lock()
			err := manager.state.slots[1].err
			manager.state.mu.Unlock()
			if !errors.Is(err, ErrFixedBindingProtocol) {
				t.Fatalf("slot error = %v", err)
			}
		})
	}

	t.Run("cross slot", func(t *testing.T) {
		first := newFixedBindingFakeLink()
		second := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: -2, Link: first}, FixedBindingSlot{DCID: 2, Link: second})
		binding, err := manager.Bind(2)
		if err != nil {
			t.Fatal(err)
		}
		first.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: binding.ConnectionID()})
		waitFixedBindingCondition(t, func() bool {
			manager.state.mu.Lock()
			defer manager.state.mu.Unlock()
			return manager.state.slots[-2].failed
		})
		if _, err := binding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil {
			t.Fatalf("correct slot binding failed: %v", err)
		}
	})
}

func TestFixedBindingManagerStaleIDBestEffortClose(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 987654})
		waitFixedBindingCondition(t, func() bool {
			_, _, _, submissions, _ := link.stats()
			return len(submissions) == 1
		})
		_, _, _, submissions, _ := link.stats()
		closed, err := ParseCloseConnection(submissions[0].Payload)
		if err != nil || closed.ConnectionID != 987654 || submissions[0].SubmissionID == 0 {
			t.Fatalf("stale close = %+v, %v", submissions[0], err)
		}
		manager.state.mu.Lock()
		failed := manager.state.slots[1].failed
		manager.state.mu.Unlock()
		if failed {
			t.Fatal("accepted best-effort close failed slot")
		}
	})

	t.Run("unknown proxy answer", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		packet := []byte{9, 8, 7, 6}
		link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: 987654, Packet: packet})
		waitFixedBindingCondition(t, func() bool {
			_, _, _, submissions, _ := link.stats()
			return len(submissions) == 1
		})
		if !allZero(packet) {
			t.Fatalf("stale packet not cleared: %x", packet)
		}
		_, _, _, submissions, _ := link.stats()
		closed, err := ParseCloseConnection(submissions[0].Payload)
		if err != nil || closed.ConnectionID != 987654 {
			t.Fatalf("stale close = %+v, %v", submissions[0], err)
		}
		manager.state.mu.Lock()
		failed := manager.state.slots[1].failed
		manager.state.mu.Unlock()
		if failed {
			t.Fatal("accepted proxy-answer close failed slot")
		}
	})

	t.Run("unknown external close ignored", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		manager.state.mu.Lock()
		slot := manager.state.slots[1]
		manager.state.mu.Unlock()
		if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: 987654}); err != nil {
			t.Fatalf("routeEvent = %v", err)
		}
		_, _, _, submissions, _ := link.stats()
		manager.state.mu.Lock()
		failed := manager.state.slots[1].failed
		manager.state.mu.Unlock()
		if len(submissions) != 0 || failed {
			t.Fatalf("unknown external close submissions/failed = %d/%v", len(submissions), failed)
		}
	})

	t.Run("backpressure retries only after capacity", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		link.setTryError(ErrLinkBackpressure)
		_ = newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: 987654})
		waitFixedBindingCondition(t, func() bool {
			link.mu.Lock()
			defer link.mu.Unlock()
			return len(link.rejected) == 1
		})
		_, _, _, _, rejected := link.stats()
		if len(rejected) != 1 || allZero(rejected[0]) {
			t.Fatalf("backpressured stale-close payload was not retained: %x", rejected)
		}
		time.Sleep(10 * time.Millisecond)
		link.mu.Lock()
		tryCalls := link.tryCalls
		link.mu.Unlock()
		if tryCalls != 1 {
			t.Fatalf("TrySubmit calls without capacity = %d", tryCalls)
		}
		link.setTryError(nil)
		link.ready <- struct{}{}
		waitFixedBindingCondition(t, func() bool {
			_, _, _, submissions, _ := link.stats()
			return len(submissions) == 1
		})
		_, _, _, submissions, _ := link.stats()
		if !bytes.Equal(rejected[0], submissions[0].Payload) {
			t.Fatalf("retried stale close changed payload: %x != %x", rejected[0], submissions[0].Payload)
		}
	})
}

func TestClientBindingClosePaths(t *testing.T) {
	t.Run("accepted concurrent idempotent", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		binding, err := manager.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		packet := []byte{7, 7, 7, 7}
		link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet})
		waitFixedBindingCondition(t, func() bool {
			manager.state.mu.Lock()
			defer manager.state.mu.Unlock()
			return manager.state.pending == 1
		})
		const callers = 32
		results := make(chan error, callers)
		var wait sync.WaitGroup
		for range callers {
			wait.Go(func() { results <- binding.Close() })
		}
		wait.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Fatal(err)
			}
		}
		_, _, _, submissions, _ := link.stats()
		if len(submissions) != 1 {
			t.Fatalf("close submissions = %d", len(submissions))
		}
		if !allZero(packet) {
			t.Fatalf("local close retained packet: %x", packet)
		}
		manager.state.mu.Lock()
		if manager.state.pending != 0 || manager.state.pendingBytes != 0 || binding.state.active {
			t.Fatalf("local close accounting = %d/%d active=%v", manager.state.pending, manager.state.pendingBytes, binding.state.active)
		}
		manager.state.mu.Unlock()
		if closeRequest, err := ParseCloseConnection(submissions[0].Payload); err != nil || closeRequest.ConnectionID != binding.ConnectionID() {
			t.Fatalf("close request = %+v, %v", closeRequest, err)
		}
	})

	t.Run("backpressure waits for capacity", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		binding, err := manager.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		link.setTryError(ErrLinkBackpressure)
		done := binding.BeginClose()
		waitFixedBindingCondition(t, func() bool {
			link.mu.Lock()
			defer link.mu.Unlock()
			return link.tryCalls == 1
		})
		select {
		case <-done:
			t.Fatal("Close completed while its control was backpressured")
		default:
		}
		link.setTryError(nil)
		link.ready <- struct{}{}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not retry after capacity")
		}
		if err, ok := binding.CloseResult(); !ok || err != nil {
			t.Fatalf("CloseResult = %v, %v", err, ok)
		}
	})

	t.Run("dead link", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		binding, err := manager.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		link.setTryError(ErrLinkClosed)
		if err := binding.Close(); !errors.Is(err, ErrLinkClosed) || !errors.Is(err, ErrFixedBindingSlotFailed) {
			t.Fatalf("Close = %v", err)
		}
	})

	t.Run("remote close sends none", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		binding, err := manager.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		link.emit(LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: binding.ConnectionID()})
		if event := nextFixedBindingEvent(t, binding); event.Kind != LinkEventCloseExternal {
			t.Fatalf("event = %+v", event)
		}
		if err := binding.Close(); err != nil {
			t.Fatal(err)
		}
		_, _, _, submissions, _ := link.stats()
		if len(submissions) != 0 {
			t.Fatalf("remote close caused %d submissions", len(submissions))
		}
	})

	t.Run("remote close keeps one close result when rejection races", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		link.tryErr = ErrLinkBackpressure
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		binding, err := manager.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		firstClose := binding.BeginClose()
		waitFixedBindingCondition(t, func() bool {
			link.mu.Lock()
			defer link.mu.Unlock()
			return link.tryCalls == 1
		})
		link.emit(LinkEvent{Kind: LinkEventCloseExternal, ConnectionID: binding.ConnectionID()})
		select {
		case <-firstClose:
		case <-time.After(5 * time.Second):
			t.Fatal("remote close did not complete local close")
		}
		if err, ok := binding.CloseResult(); !ok || err != nil {
			t.Fatalf("first Close = %v, %v", err, ok)
		}
		if err := binding.Close(); err != nil {
			t.Fatalf("repeated Close = %v", err)
		}
	})

	t.Run("accepted close wins later slot failure", func(t *testing.T) {
		failure := errors.New("link failed after accepting close")
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		binding, err := manager.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		link.afterTry = func(accepted bool) {
			if accepted {
				link.peerClose(failure)
			}
		}
		const callers = 32
		results := make(chan error, callers)
		var wait sync.WaitGroup
		for range callers {
			wait.Go(func() { results <- binding.Close() })
		}
		wait.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Fatalf("Close = %v", err)
			}
		}
		if err := binding.Close(); err != nil {
			t.Fatalf("repeated Close = %v", err)
		}
		_, _, _, submissions, rejected := link.stats()
		if len(submissions) != 1 || len(rejected) != 0 {
			t.Fatalf("accepted/rejected submissions = %d/%d", len(submissions), len(rejected))
		}
	})
}

func TestFixedBindingManagerCloseJoinsLinkErrorsAndClosesAll(t *testing.T) {
	first := newFixedBindingFakeLink()
	second := newFixedBindingFakeLink()
	closeErr := errors.New("close failed")
	first.closeErr = closeErr
	manager, err := NewFixedBindingManager([]FixedBindingSlot{
		{DCID: -2, Link: first},
		{DCID: 2, Link: second},
	}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close = %v", err)
	}
	for index, link := range []*fixedBindingFakeLink{first, second} {
		_, _, closes, _, _ := link.stats()
		if closes != 1 {
			t.Fatalf("link %d closes = %d", index, closes)
		}
	}
}

func TestFixedBindingManagerCloseClearsBufferedPacketsAndJoinsConsumers(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte{9, 8, 7, 6}
	link.emit(LinkEvent{Kind: LinkEventProxyAnswer, ConnectionID: binding.ConnectionID(), Packet: packet})
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return manager.state.pending == 1
	})
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if !allZero(packet) {
		t.Fatalf("manager-owned packet not cleared: %x", packet)
	}
	manager.state.mu.Lock()
	slot := manager.state.slots[1]
	if binding.state.items != 0 || binding.state.bytes != 0 || slot.pending != 0 || slot.bytes != 0 ||
		manager.state.pending != 0 || manager.state.pendingBytes != 0 || len(manager.state.byID) != 0 {
		t.Fatalf("terminal accounting = binding %d/%d slot %d/%d global %d/%d bindings %d",
			binding.state.items, binding.state.bytes, slot.pending, slot.bytes,
			manager.state.pending, manager.state.pendingBytes, len(manager.state.byID))
	}
	manager.state.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := binding.NextEvent(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("NextEvent = %v", err)
	}
	_, events, _, _, _ := link.stats()
	if events != 1 {
		t.Fatalf("Events consumers = %d", events)
	}
}

func TestFixedBindingManagerOneSlotFailureLeavesOtherUsable(t *testing.T) {
	first := newFixedBindingFakeLink()
	second := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: -2, Link: first}, FixedBindingSlot{DCID: 2, Link: second})
	first.peerClose(errors.New("source failed"))
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return manager.state.slots[-2].failed
	})
	if _, err := manager.Bind(-2); !errors.Is(err, ErrFixedBindingSlotFailed) {
		t.Fatalf("failed slot Bind = %v", err)
	}
	binding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := binding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil {
		t.Fatalf("healthy slot submission: %v", err)
	}
}

func TestFixedBindingManagerBalancesBindingsAcrossSameDCPool(t *testing.T) {
	first := newFixedBindingFakeLink()
	second := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(
		t,
		FixedBindingSlot{DCID: 2, Link: first},
		FixedBindingSlot{DCID: 2, Link: second},
	)
	bindings := make([]*ClientBinding, 0, 6)
	for range 6 {
		binding, err := manager.Bind(2)
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		bindings = append(bindings, binding)
	}
	manager.state.mu.Lock()
	group := manager.state.slotGroups[2]
	residents := []int{group[0].resident, group[1].resident}
	manager.state.mu.Unlock()
	if !slices.Equal(residents, []int{3, 3}) {
		t.Fatalf("resident distribution = %v, want [3 3]", residents)
	}
	if bindings[0].state.slot != group[0] || bindings[1].state.slot != group[1] {
		t.Fatal("equal-load ties did not rotate in configured order")
	}
	for _, binding := range bindings {
		if err := binding.Close(); err != nil {
			t.Fatalf("Close binding: %v", err)
		}
	}
}

func TestFixedBindingManagerSameDCLinkFailureIsolatesBindingsAndAdmission(t *testing.T) {
	failure := errors.New("first pooled link failed")
	first := newFixedBindingFakeLink()
	second := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(
		t,
		FixedBindingSlot{DCID: 2, Link: first},
		FixedBindingSlot{DCID: 2, Link: second},
	)
	firstBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind first: %v", err)
	}
	secondBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind second: %v", err)
	}
	if firstBinding.state.slot == secondBinding.state.slot {
		t.Fatal("test bindings were not distributed across the pool")
	}

	first.peerClose(failure)
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return manager.state.slotGroups[2][0].failed
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := firstBinding.NextEvent(ctx); !errors.Is(err, ErrFixedBindingSlotFailed) || !errors.Is(err, failure) {
		t.Fatalf("failed-link binding result = %v", err)
	}
	if _, err := secondBinding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil {
		t.Fatalf("healthy-link binding request: %v", err)
	}
	thirdBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind after one pooled failure: %v", err)
	}
	if thirdBinding.state.slot != secondBinding.state.slot {
		t.Fatal("new binding selected the failed pooled link")
	}
	if err := firstBinding.Close(); !errors.Is(err, ErrFixedBindingSlotFailed) {
		t.Fatalf("Close failed binding: %v", err)
	}
	if err := secondBinding.Close(); err != nil {
		t.Fatalf("Close healthy binding: %v", err)
	}
	if err := thirdBinding.Close(); err != nil {
		t.Fatalf("Close new binding: %v", err)
	}
}

func TestFixedBindingManagerRepairsFailedSlotWithoutMovingHealthyBindings(t *testing.T) {
	failure := errors.New("replace pooled link")
	failedLink := newFixedBindingFakeLink()
	healthyLink := newFixedBindingFakeLink()
	replacement := newFixedBindingFakeLink()
	manager, err := newFixedBindingManager(
		[]FixedBindingSlot{{DCID: 2, Link: failedLink}, {DCID: 2, Link: healthyLink}},
		fixedBindingTestLimits(),
		func(context.Context, DCID) (ClientLink, error) { return replacement, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	failedBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	healthyBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	failedLink.peerClose(failure)
	waitFixedBindingCondition(t, func() bool { return manager.Snapshot().Slots[0].Failed })
	if err := manager.state.repairFailedSlots(t.Context()); err != nil {
		t.Fatalf("repair failed slot: %v", err)
	}

	snapshot := manager.Snapshot()
	if snapshot.Slots[0].Failed || snapshot.Slots[0].Repairing ||
		snapshot.SlotRepairSuccesses != 1 || snapshot.SlotRepairFailures != 0 || snapshot.RepairingSlots != 0 {
		t.Fatalf("repaired snapshot = %+v", snapshot)
	}
	manager.state.mu.Lock()
	repairedLink := manager.state.slotGroups[2][0].link
	healthyBindingLink := healthyBinding.state.slot.link
	manager.state.mu.Unlock()
	if repairedLink != replacement || healthyBindingLink != healthyLink {
		t.Fatal("slot repair did not replace only the failed physical link")
	}

	replacementBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind replacement: %v", err)
	}
	if replacementBinding.state.slot.link != replacement {
		t.Fatal("new binding did not use the repaired slot")
	}
	if _, err := replacementBinding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil {
		t.Fatalf("replacement request: %v", err)
	}
	waitFixedBindingCondition(t, func() bool {
		_, _, _, submissions, _ := replacement.stats()
		return len(submissions) == 1
	})

	eventContext, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := failedBinding.NextEvent(eventContext); !errors.Is(err, failure) {
		t.Fatalf("failed binding terminal error = %v", err)
	}
	healthyLink.emit(LinkEvent{
		Kind:         LinkEventSimpleAck,
		ConnectionID: healthyBinding.ConnectionID(),
		ConfirmKey:   17,
	})
	if event, err := healthyBinding.NextEvent(eventContext); err != nil || event.ConfirmKey != 17 {
		t.Fatalf("healthy binding after repair = %+v, %v", event, err)
	}
	if err := failedBinding.Close(); !errors.Is(err, failure) {
		t.Fatalf("Close failed binding: %v", err)
	}
	if err := healthyBinding.Close(); err != nil {
		t.Fatalf("Close healthy binding: %v", err)
	}
	if err := replacementBinding.Close(); err != nil {
		t.Fatalf("Close replacement binding: %v", err)
	}
}

func TestFixedBindingManagerRetriesAfterReplacementStartFailure(t *testing.T) {
	failure := errors.New("replace failed link")
	startFailure := errors.New("replacement bootstrap failed")
	failedLink := newFixedBindingFakeLink()
	healthyLink := newFixedBindingFakeLink()
	badReplacement := newFixedBindingFakeLink()
	badReplacement.startErr = startFailure
	goodReplacement := newFixedBindingFakeLink()
	attempt := 0
	manager, err := newFixedBindingManager(
		[]FixedBindingSlot{{DCID: 2, Link: failedLink}, {DCID: 2, Link: healthyLink}},
		fixedBindingTestLimits(),
		func(context.Context, DCID) (ClientLink, error) {
			attempt++
			if attempt == 1 {
				return badReplacement, nil
			}
			return goodReplacement, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	failedBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	healthyBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatal(err)
	}
	failedLink.peerClose(failure)
	waitFixedBindingCondition(t, func() bool { return manager.Snapshot().Slots[0].Failed })
	if err := manager.state.repairFailedSlots(t.Context()); !errors.Is(err, startFailure) {
		t.Fatalf("first repair error = %v", err)
	}
	firstSnapshot := manager.Snapshot()
	if !firstSnapshot.Slots[0].Failed || firstSnapshot.Slots[0].Repairing ||
		firstSnapshot.SlotRepairSuccesses != 0 || firstSnapshot.SlotRepairFailures != 1 {
		t.Fatalf("snapshot after failed replacement = %+v", firstSnapshot)
	}
	_, _, badCloses, _, _ := badReplacement.stats()
	if badCloses != 1 {
		t.Fatalf("failed replacement closes = %d, want 1", badCloses)
	}

	healthyLink.emit(LinkEvent{
		Kind:         LinkEventSimpleAck,
		ConnectionID: healthyBinding.ConnectionID(),
		ConfirmKey:   31,
	})
	eventContext, cancelEvent := context.WithTimeout(t.Context(), time.Second)
	defer cancelEvent()
	if event, err := healthyBinding.NextEvent(eventContext); err != nil || event.ConfirmKey != 31 {
		t.Fatalf("healthy binding after failed replacement = %+v, %v", event, err)
	}

	if err := manager.state.repairFailedSlots(t.Context()); err != nil {
		t.Fatalf("second repair: %v", err)
	}
	secondSnapshot := manager.Snapshot()
	if secondSnapshot.Slots[0].Failed || secondSnapshot.Slots[0].Repairing ||
		secondSnapshot.SlotRepairSuccesses != 1 || secondSnapshot.SlotRepairFailures != 1 {
		t.Fatalf("snapshot after successful retry = %+v", secondSnapshot)
	}
	if _, err := failedBinding.NextEvent(eventContext); !errors.Is(err, failure) {
		t.Fatalf("failed binding terminal error = %v", err)
	}
	if err := failedBinding.Close(); !errors.Is(err, failure) {
		t.Fatalf("Close failed binding: %v", err)
	}
	if err := healthyBinding.Close(); err != nil {
		t.Fatalf("Close healthy binding: %v", err)
	}
}

func TestFixedBindingManagerCloseCancelsBlockedSlotRepair(t *testing.T) {
	failure := errors.New("replace failed link")
	failedLink := newFixedBindingFakeLink()
	replacement := newFixedBindingFakeLink()
	startEntered := make(chan struct{})
	replacement.startGate = make(chan struct{})
	replacement.onStart = sync.OnceFunc(func() { close(startEntered) })
	manager, err := newFixedBindingManager(
		[]FixedBindingSlot{{DCID: 2, Link: failedLink}},
		fixedBindingTestLimits(),
		func(context.Context, DCID) (ClientLink, error) { return replacement, nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	failedLink.peerClose(failure)
	waitFixedBindingCondition(t, func() bool { return manager.Snapshot().Slots[0].Failed })

	repairResult := make(chan error, 1)
	go func() { repairResult <- manager.state.repairFailedSlots(t.Context()) }()
	select {
	case <-startEntered:
	case <-time.After(time.Second):
		t.Fatal("replacement Start was not entered")
	}
	closeResult := make(chan error, 1)
	go func() { closeResult <- manager.Close() }()
	select {
	case err := <-repairResult:
		if !errors.Is(err, ErrFixedBindingManagerClosed) {
			t.Fatalf("repair result after Close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked slot repair did not stop during manager Close")
	}
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("manager Close did not join canceled slot repair")
	}
	_, _, replacementCloses, _, _ := replacement.stats()
	if replacementCloses != 1 {
		t.Fatalf("canceled replacement closes = %d, want 1", replacementCloses)
	}
}

func TestFixedBindingManagerProbesEverySameDCLinkAndIsolatesTimeout(t *testing.T) {
	first := newFixedBindingFakeLink()
	second := newFixedBindingFakeLink()
	first.afterTry = func(accepted bool) {
		if !accepted {
			return
		}
		attempted := first.attemptedSubmissions()
		ping, err := ParsePing(attempted[len(attempted)-1].Payload)
		if err == nil {
			first.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
		}
	}
	manager := newStartedFixedBindingManager(
		t,
		FixedBindingSlot{DCID: -2, Link: first},
		FixedBindingSlot{DCID: -2, Link: second},
	)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := manager.Probe(ctx, -2); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Probe error = %v", err)
	}
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		group := manager.state.slotGroups[-2]
		return !group[0].failed && group[1].failed
	})
	_, _, _, firstSubmissions, _ := first.stats()
	_, _, _, secondSubmissions, _ := second.stats()
	if len(firstSubmissions) != 1 || len(secondSubmissions) != 1 {
		t.Fatalf("probe submissions = %d/%d, want 1/1", len(firstSubmissions), len(secondSubmissions))
	}
	if _, err := manager.Bind(-2); err != nil {
		t.Fatalf("Bind after one probe timeout: %v", err)
	}
}

func TestFixedBindingManagerSnapshotReportsPooledCapacityWithoutPayloads(t *testing.T) {
	first := newFixedBindingFakeLink()
	second := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(
		t,
		FixedBindingSlot{DCID: 2, Link: first},
		FixedBindingSlot{DCID: 2, Link: second},
	)
	failedBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind failed-link client: %v", err)
	}
	healthyBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind healthy-link client: %v", err)
	}
	second.emit(LinkEvent{
		Kind:         LinkEventSimpleAck,
		ConnectionID: healthyBinding.ConnectionID(),
		ConfirmKey:   41,
	})
	waitFixedBindingCondition(t, func() bool {
		return manager.Snapshot().ResponseItems == 1
	})
	failure := errors.New("snapshot pooled link failure")
	first.peerClose(failure)
	waitFixedBindingCondition(t, func() bool {
		snapshot := manager.Snapshot()
		return len(snapshot.Slots) == 2 && snapshot.Slots[0].Failed
	})

	snapshot := manager.Snapshot()
	if !snapshot.Ready || !snapshot.Accepting || snapshot.Closed || snapshot.ResidentBindings != 2 ||
		snapshot.ResponseItems != 1 || snapshot.ResponseBytes != SimpleAckPayloadSize {
		t.Fatalf("manager snapshot = %+v", snapshot)
	}
	if len(snapshot.Slots) != 2 || snapshot.Slots[0].DCID != 2 || snapshot.Slots[1].DCID != 2 {
		t.Fatalf("slot snapshots = %+v", snapshot.Slots)
	}
	if !snapshot.Slots[0].Failed || snapshot.Slots[0].Link.State != LinkStateClosed ||
		snapshot.Slots[1].Failed || snapshot.Slots[1].Link.State != LinkStateReady ||
		snapshot.Slots[1].ResponseItems != 1 || snapshot.Slots[1].ResponseBytes != SimpleAckPayloadSize {
		t.Fatalf("pooled slot snapshots = %+v", snapshot.Slots)
	}
	snapshot.Slots[0].DCID = 99
	if manager.Snapshot().Slots[0].DCID != 2 {
		t.Fatal("snapshot slots alias manager state")
	}

	eventContext, cancelEvent := context.WithTimeout(t.Context(), time.Second)
	defer cancelEvent()
	if _, err := failedBinding.NextEvent(eventContext); !errors.Is(err, failure) {
		t.Fatalf("failed binding event = %v", err)
	}
	if event, err := healthyBinding.NextEvent(eventContext); err != nil || event.ConfirmKey != 41 {
		t.Fatalf("healthy binding event = %+v, %v", event, err)
	}
	if err := healthyBinding.Close(); err != nil {
		t.Fatalf("Close healthy binding: %v", err)
	}
}

func TestFixedBindingManagerSlowClientBackpressureIsBindingLocal(t *testing.T) {
	link := newFixedBindingFakeLink()
	limits := fixedBindingTestLimits()
	limits.MaxPendingResponseItemsPerBinding = 1
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 2, Link: link}}, limits)
	if err != nil {
		t.Fatalf("NewFixedBindingManager: %v", err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("Close manager: %v", err)
		}
	})
	slowBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind slow client: %v", err)
	}
	healthyBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind healthy client: %v", err)
	}
	link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: slowBinding.ConnectionID(), ConfirmKey: 1})
	link.emit(LinkEvent{Kind: LinkEventSimpleAck, ConnectionID: slowBinding.ConnectionID(), ConfirmKey: 2})
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return slowBinding.state.terminal
	})

	eventContext, cancelEvent := context.WithTimeout(t.Context(), time.Second)
	defer cancelEvent()
	if _, err := slowBinding.NextEvent(eventContext); !errors.Is(err, ErrFixedBindingResponseBackpressure) {
		t.Fatalf("slow binding event error = %v, want response backpressure", err)
	}
	if snapshot := manager.Snapshot(); snapshot.Slots[0].Failed {
		t.Fatalf("slow client failed its shared link: %+v", snapshot.Slots[0])
	}
	waitFixedBindingCondition(t, func() bool {
		_, _, _, submissions, _ := link.stats()
		return len(submissions) == 1
	})
	_, _, _, submissions, _ := link.stats()
	closeRequest, err := ParseCloseConnection(submissions[0].Payload)
	if err != nil || closeRequest.ConnectionID != slowBinding.ConnectionID() {
		t.Fatalf("slow binding close submission = %+v, %v", closeRequest, err)
	}
	if _, err := healthyBinding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil {
		t.Fatalf("healthy binding request after peer backpressure: %v", err)
	}
	newBinding, err := manager.Bind(2)
	if err != nil {
		t.Fatalf("Bind after peer backpressure: %v", err)
	}
	if err := healthyBinding.Close(); err != nil {
		t.Fatalf("Close healthy binding: %v", err)
	}
	if err := newBinding.Close(); err != nil {
		t.Fatalf("Close new binding: %v", err)
	}
}

func TestFixedBindingManagerDrainsBufferedLinkEventsBeforeFailure(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	packet := []byte{4, 3, 2, 1}
	wantPacket := bytes.Clone(packet)
	link.emit(LinkEvent{
		Kind:         LinkEventProxyAnswer,
		ConnectionID: binding.ConnectionID(),
		AnswerFlags:  ProxyAnswerFlagSmallError,
		Packet:       packet,
	})
	link.peerClose(errors.New("link read failed"))
	event := nextFixedBindingEvent(t, binding)
	if event.AnswerFlags != ProxyAnswerFlagSmallError || !bytes.Equal(event.Packet, wantPacket) {
		t.Fatalf("buffered event = %+v", event)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := binding.NextEvent(ctx); !errors.Is(err, ErrFixedBindingSlotFailed) || !errors.Is(err, link.Err()) {
		t.Fatalf("terminal event error = %v", err)
	}
}

func TestClientBindingRemoteCloseRemainsNormalAfterLinkFailure(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	link.emit(LinkEvent{
		Kind:         LinkEventCloseExternal,
		ConnectionID: binding.ConnectionID(),
	})
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return binding.state.remoteClosed && binding.state.items == 1
	})

	link.peerClose(errors.New("link failed after external close"))
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return manager.state.slots[1].failed
	})
	event := nextFixedBindingEvent(t, binding)
	if event.Kind != LinkEventCloseExternal {
		t.Fatalf("event kind = %v", event.Kind)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := binding.NextEvent(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal event error = %v", err)
	}
	if _, err := manager.Bind(1); !errors.Is(err, ErrFixedBindingSlotFailed) {
		t.Fatalf("failed slot Bind = %v", err)
	}
}

func TestFixedBindingManagerIgnoresLinkKeepalives(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	manager.state.mu.Lock()
	slot := manager.state.slots[1]
	manager.state.mu.Unlock()
	if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventPing, KeepaliveID: 11}); err != nil {
		t.Fatalf("route ping = %v", err)
	}
	if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventPong, KeepaliveID: 12}); err != nil {
		t.Fatalf("route pong = %v", err)
	}
	manager.state.mu.Lock()
	items := binding.state.items
	failed := manager.state.slots[1].failed
	manager.state.mu.Unlock()
	if items != 0 || failed {
		t.Fatalf("keepalive state = items %d failed %v", items, failed)
	}
}

func TestFixedBindingManagerProbeSuccessAndCompatibility(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: -2, Link: link})
	result := make(chan error, 1)
	go func() { result <- manager.Probe(t.Context(), -2) }()

	submissions := waitFixedBindingSubmissions(t, link, 1)
	ping := fixedBindingProbePing(t, submissions[0])
	manager.state.mu.Lock()
	slot := manager.state.slots[-2]
	manager.state.mu.Unlock()
	if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID + 1}); err != nil {
		t.Fatalf("wrong pong: %v", err)
	}
	select {
	case err := <-result:
		t.Fatalf("wrong pong completed probe: %v", err)
	default:
	}
	if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventPing, KeepaliveID: 99}); err != nil {
		t.Fatalf("unsolicited ping: %v", err)
	}
	if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID}); err != nil {
		t.Fatalf("matching pong: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("Probe: %v", err)
	}
	manager.state.mu.Lock()
	defer manager.state.mu.Unlock()
	if slot.probe != nil || slot.controlItems != 0 || slot.controlBytes != 0 ||
		manager.state.controlItems != 0 || manager.state.controlBytes != 0 {
		t.Fatalf("probe cleanup = probe %v slot %d/%d global %d/%d", slot.probe != nil,
			slot.controlItems, slot.controlBytes, manager.state.controlItems, manager.state.controlBytes)
	}
}

func TestFixedBindingManagerProbePongPublishedBeforeTrySubmitReturns(t *testing.T) {
	link := newFixedBindingFakeLink()
	published := make(chan error, 1)
	allowReturn := make(chan struct{})
	releaseTrySubmit := sync.OnceFunc(func() { close(allowReturn) })
	defer releaseTrySubmit()
	link.afterTry = func(accepted bool) {
		if !accepted {
			published <- errors.New("probe submission was rejected")
			<-allowReturn
			return
		}
		_, _, _, submissions, _ := link.stats()
		if len(submissions) == 0 {
			published <- errors.New("accepted probe submission was not recorded")
			<-allowReturn
			return
		}
		ping, err := ParsePing(submissions[len(submissions)-1].Payload)
		if err == nil {
			link.emit(LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID})
		}
		published <- err
		<-allowReturn
	}
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- manager.Probe(ctx, 1) }()
	if err := <-published; err != nil {
		t.Fatal(err)
	}

	manager.state.mu.Lock()
	probe := manager.state.slots[1].probe
	if probe == nil || probe.submitted || probe.complete {
		manager.state.mu.Unlock()
		t.Fatalf("probe before TrySubmit return = present %v submitted %v complete %v",
			probe != nil, probe != nil && probe.submitted, probe != nil && probe.complete)
	}
	manager.state.mu.Unlock()
	if buffered := len(link.events); buffered != 1 {
		t.Fatalf("Events buffered before TrySubmit return = %d, want 1", buffered)
	}
	select {
	case err := <-result:
		t.Fatalf("Probe completed before TrySubmit returned: %v", err)
	default:
	}

	releaseTrySubmit()
	if err := <-result; err != nil {
		t.Fatalf("Probe after TrySubmit return = %v", err)
	}
}

func TestFixedBindingManagerProbeCancellationAndLatePong(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 2, Link: link})
	ctx, cancel := context.WithCancel(t.Context())
	firstResult := make(chan error, 1)
	go func() { firstResult <- manager.Probe(ctx, 2) }()
	firstSubmission := waitFixedBindingSubmissions(t, link, 1)[0]
	firstPing := fixedBindingProbePing(t, firstSubmission)
	attempted := link.attemptedSubmissions()
	if len(attempted) != 1 {
		t.Fatalf("attempted submissions = %d", len(attempted))
	}
	transferredPayload := attempted[0].Payload
	wantPayload := bytes.Clone(transferredPayload)
	cancel()
	if err := <-firstResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Probe = %v", err)
	}
	if !bytes.Equal(transferredPayload, wantPayload) {
		t.Fatalf("manager cleared transferred ping: got %x want %x", transferredPayload, wantPayload)
	}

	manager.state.mu.Lock()
	slot := manager.state.slots[2]
	manager.state.mu.Unlock()
	if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventPong, KeepaliveID: firstPing.ID}); err != nil {
		t.Fatalf("late pong: %v", err)
	}
	secondResult := make(chan error, 1)
	go func() { secondResult <- manager.Probe(t.Context(), 2) }()
	secondSubmission := waitFixedBindingSubmissions(t, link, 2)[1]
	secondPing := fixedBindingProbePing(t, secondSubmission)
	if secondPing.ID == firstPing.ID {
		t.Fatalf("probe ID reused: %d", secondPing.ID)
	}
	if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventPong, KeepaliveID: firstPing.ID}); err != nil {
		t.Fatalf("old late pong during next probe: %v", err)
	}
	select {
	case err := <-secondResult:
		t.Fatalf("late pong satisfied next probe: %v", err)
	default:
	}
	if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventPong, KeepaliveID: secondPing.ID}); err != nil {
		t.Fatalf("second matching pong: %v", err)
	}
	if err := <-secondResult; err != nil {
		t.Fatalf("second Probe: %v", err)
	}
}

func TestFixedBindingManagerProbeCancellationBeforeSubmitPreservesFIFO(t *testing.T) {
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	_ = binding.BeginClose()
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- manager.Probe(ctx, 1) }()
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return manager.state.slots[1].probe != nil
	})
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe = %v", err)
	}
	if attempts := len(link.attemptedSubmissions()); attempts != 1 {
		t.Fatalf("probe bypassed earlier control: attempts %d", attempts)
	}
	manager.state.mu.Lock()
	slot := manager.state.slots[1]
	defer manager.state.mu.Unlock()
	if slot.probe != nil || slot.controlItems != 1 || slot.controlBytes != ClosePayloadSize {
		t.Fatalf("post-cancel slot state = probe %v control %d/%d", slot.probe != nil, slot.controlItems, slot.controlBytes)
	}
}

func TestFixedBindingManagerProbeCancellationDuringSubmit(t *testing.T) {
	link := newFixedBindingFakeLink()
	tryGate := make(chan struct{})
	link.tryGate = tryGate
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- manager.Probe(ctx, 1) }()
	waitFixedBindingCondition(t, func() bool {
		link.mu.Lock()
		defer link.mu.Unlock()
		return link.tryCalls == 1
	})
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe = %v", err)
	}
	manager.state.mu.Lock()
	slot := manager.state.slots[1]
	if slot.probe != nil || slot.controlItems != 1 || slot.controlBytes != KeepalivePayloadSize {
		manager.state.mu.Unlock()
		t.Fatalf("in-flight cancellation state = probe %v control %d/%d", slot.probe != nil, slot.controlItems, slot.controlBytes)
	}
	manager.state.mu.Unlock()
	close(tryGate)
	submission := waitFixedBindingSubmissions(t, link, 1)[0]
	wantPayload := bytes.Clone(submission.Payload)
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return slot.controlItems == 0 && slot.controlBytes == 0 && manager.state.controlItems == 0 && manager.state.controlBytes == 0
	})
	if !bytes.Equal(submission.Payload, wantPayload) {
		t.Fatalf("manager cleared transferred canceled ping: got %x want %x", submission.Payload, wantPayload)
	}
}

func TestFixedBindingManagerProbeUsesReservedControlCapacity(t *testing.T) {
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	limits := fixedBindingTestLimits()
	limits.MaxPendingControlItemsPerSlot = 2
	limits.MaxPendingControlBytesPerSlot = ClosePayloadSize + KeepalivePayloadSize
	limits.MaxPendingControlItems = 2
	limits.MaxPendingControlBytes = ClosePayloadSize + KeepalivePayloadSize
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	_ = binding.BeginClose()
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	ctx, cancel := context.WithCancel(t.Context())
	probeResult := make(chan error, 1)
	go func() { probeResult <- manager.Probe(ctx, 1) }()
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return manager.state.slots[1].probe != nil && manager.state.controlItems == 2
	})
	manager.state.mu.Lock()
	if manager.state.probeID != 1 || manager.state.slots[1].failed {
		manager.state.mu.Unlock()
		t.Fatalf("reserved Probe state: ID %d failed %v", manager.state.probeID, manager.state.slots[1].failed)
	}
	manager.state.mu.Unlock()
	cancel()
	if err := <-probeResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reserved Probe = %v", err)
	}
}

func TestFixedBindingManagerProbeBackpressureKeepsStrictRequestFIFO(t *testing.T) {
	link := newFixedBindingFakeLink()
	link.setTryError(ErrLinkBackpressure)
	manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	if status, err := binding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil || status != PrepareProxyRequestQueued {
		t.Fatalf("PrepareProxyRequest = %v, %v", status, err)
	}
	waitFixedBindingCondition(t, func() bool { return len(link.attemptedSubmissions()) == 1 })
	probeResult := make(chan error, 1)
	go func() { probeResult <- manager.Probe(t.Context(), 1) }()
	waitFixedBindingCondition(t, func() bool {
		manager.state.mu.Lock()
		defer manager.state.mu.Unlock()
		return manager.state.slots[1].probe != nil
	})
	if attempts := len(link.attemptedSubmissions()); attempts != 1 {
		t.Fatalf("probe bypassed backpressured request: attempts %d", attempts)
	}

	link.setTryError(nil)
	signalSubmissionReady(link.ready)
	submissions := waitFixedBindingSubmissions(t, link, 2)
	if operation, err := ParseRPCOperation(submissions[0].Payload); err != nil || operation != OperationProxyRequest {
		t.Fatalf("first operation = %x, %v", operation, err)
	}
	ping := fixedBindingProbePing(t, submissions[1])
	manager.state.mu.Lock()
	slot := manager.state.slots[1]
	manager.state.mu.Unlock()
	if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID}); err != nil {
		t.Fatal(err)
	}
	if err := <-probeResult; err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

func TestFixedBindingManagerProbeConcurrentSlotsAndSameSlotRejection(t *testing.T) {
	first := newFixedBindingFakeLink()
	second := newFixedBindingFakeLink()
	manager := newStartedFixedBindingManager(t,
		FixedBindingSlot{DCID: -2, Link: first},
		FixedBindingSlot{DCID: 2, Link: second},
	)
	firstResult := make(chan error, 1)
	secondResult := make(chan error, 1)
	go func() { firstResult <- manager.Probe(t.Context(), -2) }()
	go func() { secondResult <- manager.Probe(t.Context(), 2) }()
	firstPing := fixedBindingProbePing(t, waitFixedBindingSubmissions(t, first, 1)[0])
	secondPing := fixedBindingProbePing(t, waitFixedBindingSubmissions(t, second, 1)[0])
	if err := manager.Probe(t.Context(), -2); !errors.Is(err, ErrFixedBindingProbePending) {
		t.Fatalf("concurrent same-slot Probe = %v", err)
	}
	manager.state.mu.Lock()
	firstSlot := manager.state.slots[-2]
	secondSlot := manager.state.slots[2]
	manager.state.mu.Unlock()
	if err := manager.state.routeEvent(firstSlot, LinkEvent{Kind: LinkEventPong, KeepaliveID: firstPing.ID}); err != nil {
		t.Fatal(err)
	}
	if err := manager.state.routeEvent(secondSlot, LinkEvent{Kind: LinkEventPong, KeepaliveID: secondPing.ID}); err != nil {
		t.Fatal(err)
	}
	if err := <-firstResult; err != nil {
		t.Fatalf("first Probe: %v", err)
	}
	if err := <-secondResult; err != nil {
		t.Fatalf("second Probe: %v", err)
	}
}

func TestFixedBindingManagerProbeSlotFailureAndClose(t *testing.T) {
	t.Run("slot failure", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		result := make(chan error, 1)
		go func() { result <- manager.Probe(t.Context(), 1) }()
		_ = waitFixedBindingSubmissions(t, link, 1)
		linkErr := errors.New("probe link failed")
		link.peerClose(linkErr)
		if err := <-result; !errors.Is(err, ErrFixedBindingSlotFailed) || !errors.Is(err, linkErr) {
			t.Fatalf("Probe failure = %v", err)
		}
		if err := manager.Probe(t.Context(), 1); !errors.Is(err, ErrFixedBindingSlotFailed) || !errors.Is(err, linkErr) {
			t.Fatalf("sticky Probe failure = %v", err)
		}
	})

	t.Run("manager close", func(t *testing.T) {
		link := newFixedBindingFakeLink()
		manager := newStartedFixedBindingManager(t, FixedBindingSlot{DCID: 1, Link: link})
		result := make(chan error, 1)
		go func() { result <- manager.Probe(t.Context(), 1) }()
		_ = waitFixedBindingSubmissions(t, link, 1)
		if err := manager.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, ErrFixedBindingManagerClosed) {
			t.Fatalf("Probe close result = %v", err)
		}
		if err := manager.Probe(t.Context(), 1); !errors.Is(err, ErrFixedBindingManagerClosed) {
			t.Fatalf("Probe after Close = %v", err)
		}
	})
}

func TestFixedBindingManagerProbeStateAndIDExhaustion(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Probe(t.Context(), 1); !errors.Is(err, ErrFixedBindingManagerNotStarted) {
		t.Fatalf("Probe before Start = %v", err)
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	if err := manager.Probe(t.Context(), -1); !errors.Is(err, ErrFixedBindingUnknownDC) {
		t.Fatalf("unknown Probe = %v", err)
	}
	restore := setFixedBindingProbeIDForTest(manager, math.MaxUint64-1)
	defer restore()
	result := make(chan error, 1)
	go func() { result <- manager.Probe(t.Context(), 1) }()
	ping := fixedBindingProbePing(t, waitFixedBindingSubmissions(t, link, 1)[0])
	if ping.ID != math.MaxUint64 {
		t.Fatalf("last probe ID = %d", ping.ID)
	}
	manager.state.mu.Lock()
	slot := manager.state.slots[1]
	manager.state.mu.Unlock()
	if err := manager.state.routeEvent(slot, LinkEvent{Kind: LinkEventPong, KeepaliveID: ping.ID}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := manager.Probe(t.Context(), 1); !errors.Is(err, ErrFixedBindingProbeIDExhausted) {
		t.Fatalf("exhausted Probe = %v", err)
	}
	<-manager.Done()
	if !errors.Is(manager.Err(), ErrFixedBindingProbeIDExhausted) {
		t.Fatalf("manager error = %v", manager.Err())
	}
	if err := manager.Probe(t.Context(), 1); !errors.Is(err, ErrFixedBindingProbeIDExhausted) {
		t.Fatalf("sticky exhausted Probe = %v", err)
	}
}

func TestFixedBindingManagerProbeInitialFailureAndContextValidation(t *testing.T) {
	link := newFixedBindingFakeLink()
	startErr := errors.New("probe start failed")
	link.startErr = startErr
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(t.Context()); !errors.Is(err, ErrFixedBindingInitialFailure) || !errors.Is(err, startErr) {
		t.Fatalf("Start = %v", err)
	}
	if err := manager.Probe(t.Context(), 1); !errors.Is(err, ErrFixedBindingInitialFailure) || !errors.Is(err, startErr) {
		t.Fatalf("Probe after initial failure = %v", err)
	}
	if err := manager.Probe(nil, 1); !errors.Is(err, ErrInvalidFixedBindingManager) {
		t.Fatalf("Probe(nil) = %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := manager.Probe(canceled, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe(pre-canceled) = %v", err)
	}
}

func TestFixedBindingManagerExternalCallsHoldNoManagerMutexForReadOnlyCallbacks(t *testing.T) {
	link := newFixedBindingFakeLink()
	manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
	if err != nil {
		t.Fatal(err)
	}
	link.onStart = func() {
		_ = manager.Err()
		_ = manager.Done()
		_ = manager.String()
		_ = manager.GoString()
	}
	if err := manager.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	binding, err := manager.Bind(1)
	if err != nil {
		t.Fatal(err)
	}
	link.onTry = func() {
		_ = manager.Err()
		_ = manager.Done()
		_ = manager.String()
		_ = manager.GoString()
		_ = binding.String()
		_ = binding.GoString()
		_ = binding.ConnectionID()
		_ = binding.DCID()
	}
	link.onClose = func() {
		_ = manager.Err()
		_ = manager.Done()
		_ = manager.String()
		_ = manager.GoString()
		_ = binding.String()
		_ = binding.GoString()
		_ = binding.ConnectionID()
		_ = binding.DCID()
	}
	if _, err := binding.PrepareProxyRequest(fixedBindingProxyRequest()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFixedBindingManagerConcurrentRaceStress(t *testing.T) {
	for range 50 {
		link := newFixedBindingFakeLink()
		manager, err := NewFixedBindingManager([]FixedBindingSlot{{DCID: 1, Link: link}}, fixedBindingTestLimits())
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		binding, err := manager.Bind(1)
		if err != nil {
			t.Fatal(err)
		}
		var wait sync.WaitGroup
		for range 8 {
			wait.Go(func() { _, _ = binding.PrepareProxyRequest(fixedBindingProxyRequest()) })
		}
		wait.Go(func() { _ = binding.Close() })
		wait.Go(func() { _ = manager.Close() })
		wait.Wait()
		select {
		case <-manager.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("stress manager leaked its consumer")
		}
	}
}
