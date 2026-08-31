package gproxy

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"

	"github.com/scratch-net/telego/pkg/transport/faketls"
	"github.com/scratch-net/telego/pkg/transport/middleend"
	"github.com/scratch-net/telego/pkg/transport/obfuscated2"
)

const (
	// Padded-intermediate has a four-byte header and at most three padding
	// bytes. Abridged and intermediate are no larger.
	middleEndMaxClientWire = middleend.MaxClientPacketSize + 7
	// One split record, the complete DRS probe window, and the steady-state
	// record count form a conservative maximum for every DRS state.
	middleEndMaxTLSRecords = 1 + faketls.DRSRampRecords +
		(middleEndMaxClientWire+faketls.MaxRecordPayload-1)/faketls.MaxRecordPayload
	middleEndMaxEncodedResponse = middleEndMaxClientWire +
		middleEndMaxTLSRecords*faketls.RecordHeaderSize
	middleEndDecryptChunk = 64 * 1024
	// Bound one owner-loop turn even when an authenticated peer fragments one
	// MTProto packet across minimal FakeTLS records. Reuse the conservative
	// complete-response record bound rather than introducing a runtime knob.
	middleEndTLSRecordWorkLimit = middleEndMaxTLSRecords
)

var (
	// ErrInvalidMiddleEndFrontend reports an invalid explicit frontend
	// dependency or bound.
	ErrInvalidMiddleEndFrontend = errors.New("invalid Middle-End frontend")
	// ErrMiddleEndClientBackpressure reports an authenticated client whose
	// unread input exceeded the configured owner-loop bound.
	ErrMiddleEndClientBackpressure = errors.New("Middle-End client input limit exceeded")
	// ErrMiddleEndClientProtocol reports invalid client framing or a source
	// event that cannot be represented on the client stream.
	ErrMiddleEndClientProtocol = errors.New("Middle-End client protocol failure")
)

// MiddleEndPrecommitAction selects the only allowed outcome when Middle-End
// setup fails before BindReady succeeds. A successful binding is irreversible.
type MiddleEndPrecommitAction uint8

const (
	MiddleEndPrecommitDirectFallback MiddleEndPrecommitAction = iota + 1
	MiddleEndPrecommitClose
)

// MiddleEndBindingSource is the exclusive binding and readiness source for one
// frontend. A source may route through one fixed manager or supervise multiple
// whole generations. BindReady must select once, fix the ready-token consumer,
// and never migrate a returned binding. Each binding must expose the public
// source IP of its selected physical link. Ready and Done must return stable
// channels, and TryNextReady has one consumer.
type MiddleEndBindingSource interface {
	BindReady(middleend.DCID) (*middleend.ClientBinding, error)
	Ready() <-chan struct{}
	TryNextReady() *middleend.ClientReadyToken
	Done() <-chan struct{}
}

var (
	_ MiddleEndBindingSource = (*middleend.FixedBindingManager)(nil)
	_ MiddleEndBindingSource = (*middleend.FixedBindingGenerationSupervisor)(nil)
)

// MiddleEndFrontendConfig injects an already-started, externally owned binding
// source. Every operational field is required except ProxyTag. The frontend
// consumes Source readiness exclusively but never closes the source or its
// engine runtimes. Source must remain open until gnet has delivered every
// connection OnClose callback and the serving engine has returned.
type MiddleEndFrontendConfig struct {
	Source                     MiddleEndBindingSource
	PrecommitFailure           MiddleEndPrecommitAction
	ProxyTag                   *middleend.ProxyTag
	MaxPendingClientBytes      int
	MaxPendingClientBytesTotal int
	MaxPendingOutputBytesTotal int
	OutputRetryInitial         time.Duration
	OutputRetryMax             time.Duration
	OutputStallTimeout         time.Duration
}

// String redacts the binding source and optional process-wide proxy tag.
func (MiddleEndFrontendConfig) String() string {
	return "gproxy.MiddleEndFrontendConfig{redacted}"
}

// GoString redacts the binding source and optional process-wide proxy tag.
func (c MiddleEndFrontendConfig) GoString() string { return c.String() }

// NewProxyHandlerWithMiddleEnd creates a handler with one explicit optional
// Middle-End branch. It constructs no link, engine, runtime, endpoint, or
// production configuration. Callers must start Source before accepting
// clients and must keep Source open until proxy shutdown and every connection
// OnClose callback have completed.
func NewProxyHandlerWithMiddleEnd(
	cfg *Config,
	logger Logger,
	frontend MiddleEndFrontendConfig,
) (*ProxyHandler, error) {
	if err := frontend.validate(); err != nil {
		return nil, err
	}
	handler := NewProxyHandler(cfg, logger)
	if handler.maxWriteBuffer < middleEndMaxEncodedResponse {
		return nil, fmt.Errorf(
			"%w: MaxWriteBuffer %d is below maximum encoded response %d",
			ErrInvalidMiddleEndFrontend,
			handler.maxWriteBuffer,
			middleEndMaxEncodedResponse,
		)
	}
	handler.middleEnd = newMiddleEndFrontend(frontend)
	return handler, nil
}

func (c MiddleEndFrontendConfig) validate() error {
	if nilMiddleEndBindingSource(c.Source) {
		return fmt.Errorf("%w: nil binding source", ErrInvalidMiddleEndFrontend)
	}
	switch c.PrecommitFailure {
	case MiddleEndPrecommitDirectFallback, MiddleEndPrecommitClose:
	default:
		return fmt.Errorf("%w: invalid precommit action %d", ErrInvalidMiddleEndFrontend, c.PrecommitFailure)
	}
	if c.MaxPendingClientBytes <= 0 || c.MaxPendingClientBytes > middleend.MaxLinkQueueBytes {
		return fmt.Errorf(
			"%w: MaxPendingClientBytes must be in [1,%d]",
			ErrInvalidMiddleEndFrontend,
			middleend.MaxLinkQueueBytes,
		)
	}
	if c.MaxPendingClientBytesTotal < c.MaxPendingClientBytes ||
		c.MaxPendingClientBytesTotal > middleend.MaxLinkQueueBytes {
		return fmt.Errorf(
			"%w: MaxPendingClientBytesTotal must be in [%d,%d]",
			ErrInvalidMiddleEndFrontend,
			c.MaxPendingClientBytes,
			middleend.MaxLinkQueueBytes,
		)
	}
	if c.MaxPendingOutputBytesTotal < middleEndMaxEncodedResponse ||
		c.MaxPendingOutputBytesTotal > middleend.MaxLinkQueueBytes {
		return fmt.Errorf(
			"%w: MaxPendingOutputBytesTotal must be in [%d,%d]",
			ErrInvalidMiddleEndFrontend,
			middleEndMaxEncodedResponse,
			middleend.MaxLinkQueueBytes,
		)
	}
	if c.OutputRetryInitial <= 0 || c.OutputRetryMax <= 0 || c.OutputRetryInitial > c.OutputRetryMax {
		return fmt.Errorf("%w: output retry durations must satisfy 0 < initial <= maximum", ErrInvalidMiddleEndFrontend)
	}
	if c.OutputStallTimeout <= 0 {
		return fmt.Errorf("%w: OutputStallTimeout must be positive", ErrInvalidMiddleEndFrontend)
	}
	return nil
}

func nilMiddleEndBindingSource(source MiddleEndBindingSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

type middleEndFrontend struct {
	source           MiddleEndBindingSource
	precommitFailure MiddleEndPrecommitAction
	tag              middleend.ProxyTag
	hasTag           bool
	maxPendingClient int
	retryInitial     time.Duration
	retryMax         time.Duration
	stallTimeout     time.Duration
	inputBudget      middleEndByteBudget
	outputBudget     middleEndByteBudget
	outputEvictions  atomic.Uint64
	middleEndCommits atomic.Uint64
	fallbackCommits  atomic.Uint64

	mu              sync.Mutex
	routes          map[int64]*middleEndRoute
	directFallbacks map[uint64]struct{}
	stopCh          chan struct{}

	startOnce sync.Once
	stopOnce  sync.Once
	wg        sync.WaitGroup
}

func newMiddleEndFrontend(config MiddleEndFrontendConfig) *middleEndFrontend {
	frontend := &middleEndFrontend{
		source:           config.Source,
		precommitFailure: config.PrecommitFailure,
		maxPendingClient: config.MaxPendingClientBytes,
		retryInitial:     config.OutputRetryInitial,
		retryMax:         config.OutputRetryMax,
		stallTimeout:     config.OutputStallTimeout,
		inputBudget:      newMiddleEndByteBudget(config.MaxPendingClientBytesTotal),
		outputBudget:     newMiddleEndByteBudget(config.MaxPendingOutputBytesTotal),
		routes:           make(map[int64]*middleEndRoute),
		directFallbacks:  make(map[uint64]struct{}),
		stopCh:           make(chan struct{}),
	}
	if config.ProxyTag != nil {
		frontend.tag = *config.ProxyTag
		frontend.hasTag = true
	}
	return frontend
}

func (f *middleEndFrontend) start() {
	f.startOnce.Do(func() {
		f.wg.Go(f.run)
	})
}

func (f *middleEndFrontend) stop() {
	f.stopOnce.Do(func() {
		close(f.stopCh)
	})
	f.wg.Wait()
}

func (f *middleEndFrontend) run() {
	for {
		select {
		case <-f.stopCh:
			return
		case <-f.source.Done():
			f.wakeAll()
			return
		case <-f.source.Ready():
			f.drainReady()
		}
	}
}

func (f *middleEndFrontend) drainReady() {
	for {
		f.mu.Lock()
		token := f.source.TryNextReady()
		if token == nil {
			f.mu.Unlock()
			return
		}
		route := f.routes[token.ConnectionID()]
		offered := route != nil && route.offer(token)
		f.mu.Unlock()

		if !offered {
			// Bind publication and removal are serialized with TryNextReady.
			// Therefore this is either a token invalidated by close or a
			// dependency that violated the frontend's exclusive-source rule.
			_ = token.Ack()
			return
		}
		if err := route.conn.Wake(nil); err != nil {
			_ = route.conn.Close()
		}
	}
}

func (f *middleEndFrontend) wakeAll() {
	f.mu.Lock()
	connections := make([]gnet.Conn, 0, len(f.routes))
	for _, route := range f.routes {
		connections = append(connections, route.conn)
	}
	f.mu.Unlock()
	for _, connection := range connections {
		if err := connection.Wake(nil); err != nil {
			_ = connection.Close()
		}
	}
}

type middleEndRoute struct {
	conn   gnet.Conn
	client *middleEndClient

	mu     sync.Mutex
	token  *middleend.ClientReadyToken
	closed bool
}

func (r *middleEndRoute) offer(token *middleend.ClientReadyToken) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.token != nil {
		return false
	}
	r.token = token
	return true
}

func (r *middleEndRoute) currentToken() *middleend.ClientReadyToken {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.token
}

func (r *middleEndRoute) clearToken(token *middleend.ClientReadyToken) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.token != token {
		return false
	}
	r.token = nil
	return true
}

func (r *middleEndRoute) retire() {
	r.mu.Lock()
	r.closed = true
	r.token = nil
	r.mu.Unlock()
}

type middleEndClient struct {
	frontend              *middleEndFrontend
	binding               *middleend.ClientBinding
	route                 *middleEndRoute
	mode                  ProtocolMode
	connectionType        obfuscated2.ConnectionType
	remoteAddr            netip.AddrPort
	proxyAddr             netip.AddrPort
	decryptor             cipher.Stream
	encryptor             cipher.Stream
	decoder               *middleend.ClientPacketDecoder
	encoder               *middleend.ClientPacketEncoder
	drs                   *faketls.DRSState
	pendingCipher         []byte
	pendingCipherRetained int
	pendingPlain          []byte
	pendingPlainRetained  int
	waiting               *middleend.ProxyRequest
	awaitingResult        bool
	closeAfterDrain       bool

	retryMu    sync.Mutex
	retryTimer *time.Timer
	retryDelay time.Duration
	closed     bool

	outputStallDeadline time.Time
	inputAccounted      int64
	outputAccounted     atomic.Int64
	outputEvicting      atomic.Bool
}

func (h *ProxyHandler) commitAuthenticatedRoute(c gnet.Conn, ctx *ConnContext) gnet.Action {
	if h.middleEnd == nil {
		return h.startDirectRoute(c, ctx)
	}
	committed, err := h.middleEnd.commit(
		c,
		ctx,
		h.config.EnableDRS,
		h.config.EnableSplitTLS,
		h.IdleTimeout(),
	)
	if err == nil {
		if h.clientSilenceCloseMs > 0 {
			h.relayConns.Store(ctx.id, &relayEntry{conn: c, ctx: ctx})
		}
		return gnet.None
	}
	h.logger.Debug("[%s] Middle-End route setup failed: %v", ctx.LogPrefix(), err)
	if !committed && h.middleEnd.precommitFailure == MiddleEndPrecommitDirectFallback {
		h.middleEnd.commitDirectFallback(ctx.id)
		return h.startDirectRoute(c, ctx)
	}
	h.recordHandshakeFailure(ctx, handshakeFailureBackendDial)
	return gnet.Close
}

func (h *ProxyHandler) startDirectRoute(c gnet.Conn, ctx *ConnContext) gnet.Action {
	ctx.SetState(StateDialingDC)
	c.SetReadDeadline(time.Time{})
	if idleTimeout := h.IdleTimeout(); idleTimeout > 0 {
		c.SetReadDeadline(time.Now().Add(idleTimeout))
	}
	go h.dialDC(c, ctx)
	return gnet.None
}

func (f *middleEndFrontend) commit(
	c gnet.Conn,
	ctx *ConnContext,
	enableDRS bool,
	enableSplitTLS bool,
	idleTimeout time.Duration,
) (bool, error) {
	ctx.mu.Lock()
	dcID := ctx.dcID
	connectionType := ctx.o2ConnectionType
	encryptor := ctx.encryptor
	decryptor := ctx.decryptor
	pendingCipher := ctx.pendingData
	ctx.mu.Unlock()
	if encryptor == nil || decryptor == nil {
		return false, fmt.Errorf("%w: missing client cipher", ErrMiddleEndClientProtocol)
	}

	inbound := c.InboundBuffered()
	if inbound > f.maxPendingClient || len(pendingCipher) > f.maxPendingClient-inbound {
		return false, fmt.Errorf(
			"%w: %d buffered plus %d pending > %d",
			ErrMiddleEndClientBackpressure,
			inbound,
			len(pendingCipher),
			f.maxPendingClient,
		)
	}

	remoteAddr, listenerAddr, err := middleEndClientTuple(c, ctx)
	if err != nil {
		return false, err
	}
	decoder, err := middleend.NewClientPacketDecoder(connectionType, middleend.MaxClientPacketSize)
	if err != nil {
		return false, fmt.Errorf("create Middle-End client decoder: %w", err)
	}
	encoder, err := middleend.NewClientPacketEncoder(connectionType, middleend.MaxClientPacketSize)
	if err != nil {
		_ = decoder.Close()
		return false, fmt.Errorf("create Middle-End client encoder: %w", err)
	}

	client := &middleEndClient{
		frontend:              f,
		mode:                  ctx.ProtocolMode(),
		connectionType:        connectionType,
		remoteAddr:            remoteAddr,
		decryptor:             decryptor,
		encryptor:             encryptor,
		decoder:               decoder,
		encoder:               encoder,
		pendingCipher:         pendingCipher,
		pendingCipherRetained: cap(pendingCipher),
		retryDelay:            f.retryInitial,
	}
	if client.mode == ModeEE {
		client.drs = faketls.NewDRSState(enableDRS, enableSplitTLS, faketls.MaxRecordPayload)
	}
	route := &middleEndRoute{conn: c, client: client}
	client.route = route
	if !client.reconcileInput(c) {
		client.releaseBudgets()
		_ = client.decoder.Close()
		return false, fmt.Errorf("%w: aggregate client input limit reached", ErrMiddleEndClientBackpressure)
	}

	// The dispatcher takes this same lock before TryNextReady, so no terminal
	// token can be leased between successful BindReady and route publication.
	f.start()
	f.mu.Lock()
	binding, err := f.source.BindReady(middleend.DCID(dcID))
	if err != nil {
		f.mu.Unlock()
		client.releaseBudgets()
		_ = client.decoder.Close()
		return false, fmt.Errorf("bind exact signed DC %d: %w", dcID, err)
	}
	proxyAddr, err := middleEndProxyAddr(listenerAddr, binding.SourceIP())
	if err != nil {
		f.mu.Unlock()
		_ = binding.BeginClose()
		client.releaseBudgets()
		_ = client.decoder.Close()
		return true, err
	}
	client.binding = binding
	client.proxyAddr = proxyAddr
	if _, exists := f.routes[binding.ConnectionID()]; exists {
		// Process-lifetime connection IDs make this unreachable unless the
		// dependency violates its allocator contract. BindReady has committed.
		f.mu.Unlock()
		_ = binding.BeginClose()
		client.clearOwnerState()
		return true, fmt.Errorf("%w: duplicate connection ID %d", ErrMiddleEndClientProtocol, binding.ConnectionID())
	}
	f.routes[binding.ConnectionID()] = route
	f.middleEndCommits.Add(1)

	ctx.mu.Lock()
	ctx.encryptor = nil
	ctx.decryptor = nil
	ctx.pendingData = nil
	ctx.middleEnd = client
	ctx.mu.Unlock()
	ctx.SetState(StateMiddleEnd)
	f.mu.Unlock()

	c.SetReadDeadline(time.Time{})
	if idleTimeout > 0 {
		c.SetReadDeadline(time.Now().Add(idleTimeout))
	}
	if err := c.Wake(nil); err != nil {
		return true, fmt.Errorf("wake committed Middle-End client: %w", err)
	}
	return true, nil
}

func (f *middleEndFrontend) commitDirectFallback(connectionID uint64) {
	f.mu.Lock()
	if f.directFallbacks == nil {
		f.directFallbacks = make(map[uint64]struct{})
	}
	if _, exists := f.directFallbacks[connectionID]; !exists {
		f.directFallbacks[connectionID] = struct{}{}
		f.fallbackCommits.Add(1)
	}
	f.mu.Unlock()
}

func (f *middleEndFrontend) closeDirectFallback(connectionID uint64) {
	f.mu.Lock()
	delete(f.directFallbacks, connectionID)
	f.mu.Unlock()
}

func middleEndClientTuple(
	c gnet.Conn,
	ctx *ConnContext,
) (netip.AddrPort, netip.AddrPort, error) {
	remote := c.RemoteAddr()
	local := c.LocalAddr()
	authenticated := false
	if source, destination, trusted := ctx.trustedProxyTuple(); trusted {
		authenticated = true
		remote = source
		if tcpDestination, ok := destination.(*net.TCPAddr); ok && tcpDestination != nil && tcpDestination.Port != 0 {
			local = destination
		}
	}
	remoteAddr, err := middleEndAddrPort("remote", remote, false, authenticated)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	// On Unix, gnet exposes the listener address for an accepted socket. Keep
	// its authoritative port. The selected ME link supplies the public IP.
	proxyAddr, err := middleEndAddrPort("proxy", local, true, false)
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, err
	}
	return remoteAddr, proxyAddr, nil
}

func middleEndProxyAddr(listenerAddr netip.AddrPort, sourceIP netip.Addr) (netip.AddrPort, error) {
	sourceIP = sourceIP.Unmap()
	if !sourceIP.IsValid() || sourceIP.IsUnspecified() || sourceIP.Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf(
			"%w: selected Middle-End link has no authoritative source IP",
			middleend.ErrInvalidProxyAddress,
		)
	}
	return netip.AddrPortFrom(sourceIP, listenerAddr.Port()), nil
}

func middleEndAddrPort(
	label string,
	address net.Addr,
	allowUnspecified bool,
	allowZeroPort bool,
) (netip.AddrPort, error) {
	tcpAddress, ok := address.(*net.TCPAddr)
	if !ok || tcpAddress == nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %s address has type %T", middleend.ErrInvalidProxyAddress, label, address)
	}
	addrPort := tcpAddress.AddrPort()
	if !addrPort.IsValid() || (addrPort.Port() == 0 && !allowZeroPort) {
		return netip.AddrPort{}, fmt.Errorf("%w: %s endpoint must have a valid address and permitted port", middleend.ErrInvalidProxyAddress, label)
	}
	addr := addrPort.Addr().Unmap()
	if addr.Zone() != "" || (addr.IsUnspecified() && !allowUnspecified) {
		return netip.AddrPort{}, fmt.Errorf("%w: %s endpoint is unspecified or zoned", middleend.ErrInvalidProxyAddress, label)
	}
	return netip.AddrPortFrom(addr, addrPort.Port()), nil
}

func (h *ProxyHandler) handleMiddleEnd(c gnet.Conn, ctx *ConnContext) gnet.Action {
	client := ctx.middleEnd
	if client == nil || client.binding == nil {
		return gnet.Close
	}
	if !client.reconcileInput(c) {
		h.logger.Debug("[%s] Middle-End aggregate client input limit reached", ctx.LogPrefix())
		return gnet.Close
	}
	defer client.reconcileInput(c)
	if !client.refreshOutput(c, 0) {
		h.logger.Debug("[%s] Middle-End client output made no progress before the stall deadline", ctx.LogPrefix())
		return gnet.Close
	}
	if buffered := c.InboundBuffered(); buffered > client.frontend.maxPendingClient {
		h.logger.Debug("[%s] Middle-End client input exceeded bound: %d > %d", ctx.LogPrefix(), buffered, client.frontend.maxPendingClient)
		return gnet.Close
	}
	if client.closeAfterDrain {
		return client.continueOrderlyClose(c)
	}
	select {
	case <-client.frontend.source.Done():
		return gnet.Close
	default:
	}

	blocked, action := h.handleMiddleEndToken(c, ctx, client)
	if action != gnet.None || blocked || client.awaitingResult {
		return action
	}

	packet, ok, err := client.nextPacket(c)
	if err != nil {
		h.logger.Debug("[%s] decode Middle-End client packet: %v", ctx.LogPrefix(), err)
		return gnet.Close
	}
	if !ok {
		return gnet.None
	}
	return h.prepareMiddleEndRequest(ctx, client, packet)
}

func (h *ProxyHandler) handleMiddleEndToken(
	c gnet.Conn,
	ctx *ConnContext,
	client *middleEndClient,
) (bool, gnet.Action) {
	token := client.route.currentToken()
	if token == nil {
		return false, gnet.None
	}
	processedReason := false

	reservation, reserved, err := token.TryTakePrepareReservation()
	if err != nil {
		return false, gnet.Close
	}
	if reserved {
		processedReason = true
		if client.waiting == nil {
			// A reservation is meaningful only for the exact request retained by
			// this owner loop. Binding close below retires the taken reservation.
			return false, gnet.Close
		}
		if err := client.binding.PrepareReservedProxyRequest(reservation, *client.waiting); err != nil {
			client.clearWaitingRequest()
			return false, gnet.Close
		}
		client.clearWaitingRequest()
	}

	result, ok, err := token.TryTakeRequestResult()
	if err != nil {
		return false, gnet.Close
	}
	if ok {
		processedReason = true
		if result.Err != nil || !result.Accepted {
			h.logger.Debug("[%s] Middle-End request rejected after commit: %v", ctx.LogPrefix(), result.Err)
			return false, gnet.Close
		}
		client.awaitingResult = false
	}

	terminalErr, terminal, err := token.TryTerminal()
	if err != nil {
		return false, gnet.Close
	}
	if terminal {
		if terminalErr != nil {
			h.logger.Debug("[%s] Middle-End binding terminated: %v", ctx.LogPrefix(), terminalErr)
		}
		if err := client.finishToken(token); err != nil {
			return false, gnet.Close
		}
		if terminalErr == nil {
			return false, client.beginOrderlyClose(c)
		}
		return false, gnet.Close
	}

	if !client.outputHeadroom(c, h.maxWriteBuffer) {
		if processedReason {
			if err := client.finishToken(token); err != nil {
				return false, gnet.Close
			}
			return false, gnet.None
		}
		return true, gnet.None
	}
	if !client.frontend.reserveOutput() {
		if processedReason {
			if err := client.finishToken(token); err != nil {
				return false, gnet.Close
			}
			return false, gnet.None
		}
		if client.frontend.evictOutputPressureVictim(client) {
			return false, gnet.Close
		}
		client.armOutputRetry(c, client.frontend.stallTimeout)
		return true, gnet.None
	}
	outputReservation := int64(middleEndMaxEncodedResponse)

	event, ok, err := token.TryNextEvent()
	if err != nil {
		client.frontend.outputBudget.release(outputReservation)
		return false, gnet.Close
	}
	if ok {
		action := h.writeMiddleEndEvent(c, ctx, client, event)
		if !client.refreshOutput(c, outputReservation) {
			action = gnet.Close
		}
		if err := client.finishToken(token); err != nil {
			return false, gnet.Close
		}
		return false, action
	}
	client.frontend.outputBudget.release(outputReservation)

	if !processedReason {
		terminalErr, terminal, err = token.TryTerminal()
		if err != nil {
			return false, gnet.Close
		}
		if terminal {
			if terminalErr != nil {
				h.logger.Debug("[%s] Middle-End binding terminated: %v", ctx.LogPrefix(), terminalErr)
			}
			if err := client.finishToken(token); err != nil {
				return false, gnet.Close
			}
			if terminalErr == nil {
				return false, client.beginOrderlyClose(c)
			}
			return false, gnet.Close
		}
	}
	if err := client.finishToken(token); err != nil {
		return false, gnet.Close
	}
	return false, gnet.None
}

func (c *middleEndClient) finishToken(token *middleend.ClientReadyToken) error {
	if !c.route.clearToken(token) {
		return middleend.ErrFixedBindingReadyToken
	}
	return token.Ack()
}

func (c *middleEndClient) outputHeadroom(connection gnet.Conn, maximum int) bool {
	return connection.OutboundBuffered() <= maximum-middleEndMaxEncodedResponse
}

func (c *middleEndClient) beginOrderlyClose(connection gnet.Conn) gnet.Action {
	c.closeAfterDrain = true
	return c.continueOrderlyClose(connection)
}

func (c *middleEndClient) continueOrderlyClose(connection gnet.Conn) gnet.Action {
	if connection.OutboundBuffered() == 0 {
		c.resetOutputProgress()
		return gnet.Close
	}
	if !c.waitForOutput(connection) {
		return gnet.Close
	}
	return gnet.None
}

func (c *middleEndClient) waitForOutput(connection gnet.Conn) bool {
	now := time.Now()
	if c.outputStallDeadline.IsZero() {
		c.outputStallDeadline = now.Add(c.frontend.stallTimeout)
	}
	if !now.Before(c.outputStallDeadline) {
		return false
	}
	c.armOutputRetry(connection, time.Until(c.outputStallDeadline))
	return true
}

func (c *middleEndClient) refreshOutput(connection gnet.Conn, reservation int64) bool {
	current, previous := c.reconcileOutput(connection, reservation)
	if current == 0 {
		c.resetOutputProgress()
		return true
	}
	now := time.Now()
	if c.outputStallDeadline.IsZero() || current < previous {
		c.outputStallDeadline = now.Add(c.frontend.stallTimeout)
		c.retryMu.Lock()
		c.retryDelay = c.frontend.retryInitial
		c.retryMu.Unlock()
	}
	if !now.Before(c.outputStallDeadline) {
		return false
	}
	c.armOutputRetry(connection, time.Until(c.outputStallDeadline))
	return true
}

func (c *middleEndClient) armOutputRetry(connection gnet.Conn, remaining time.Duration) {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	if c.closed || c.retryTimer != nil {
		return
	}
	delay := min(c.retryDelay, remaining)
	next := delay * 2
	if next < delay || next > c.frontend.retryMax {
		next = c.frontend.retryMax
	}
	c.retryDelay = next
	c.retryTimer = time.AfterFunc(delay, func() {
		c.retryMu.Lock()
		if c.closed {
			c.retryMu.Unlock()
			return
		}
		c.retryTimer = nil
		c.retryMu.Unlock()
		if err := connection.Wake(nil); err != nil {
			_ = connection.Close()
		}
	})
}

func (c *middleEndClient) resetOutputProgress() {
	c.outputStallDeadline = time.Time{}
	c.retryMu.Lock()
	c.retryDelay = c.frontend.retryInitial
	if c.retryTimer != nil {
		c.retryTimer.Stop()
		c.retryTimer = nil
	}
	c.retryMu.Unlock()
}

func (h *ProxyHandler) prepareMiddleEndRequest(
	ctx *ConnContext,
	client *middleEndClient,
	packet middleend.ClientPacket,
) gnet.Action {
	packetSize := len(packet.Payload)
	flags, err := middleend.ProxyRequestFlagsForClient(
		client.connectionType,
		packet.Payload,
		packet.QuickAck,
		client.frontend.hasTag,
	)
	if err != nil {
		h.logger.Debug("[%s] build Middle-End request flags: %v", ctx.LogPrefix(), err)
		clear(packet.Payload)
		return gnet.Close
	}
	request := middleend.ProxyRequest{
		Flags:      flags,
		RemoteAddr: client.remoteAddr,
		ProxyAddr:  client.proxyAddr,
		Packet:     packet.Payload,
	}
	if client.frontend.hasTag {
		request.Tag = &client.frontend.tag
	}
	status, err := client.binding.PrepareProxyRequest(request)
	if err != nil {
		clear(request.Packet)
		return gnet.Close
	}
	client.awaitingResult = true
	switch status {
	case middleend.PrepareProxyRequestQueued:
		clear(request.Packet)
	case middleend.PrepareProxyRequestWaiting:
		client.waiting = &request
	default:
		clear(request.Packet)
		return gnet.Close
	}
	if counter := ctx.TrafficIn(); counter != nil {
		counter.Add(int64(packetSize))
	}
	if h.clientSilenceCloseMs > 0 {
		ctx.lastClientByteMs.Store(time.Now().UnixMilli())
	}
	return gnet.None
}

func (h *ProxyHandler) writeMiddleEndEvent(
	c gnet.Conn,
	ctx *ConnContext,
	client *middleEndClient,
	event middleend.LinkEvent,
) gnet.Action {
	defer clear(event.Packet)
	var (
		wire        []byte
		payloadSize int
		err         error
	)
	switch event.Kind {
	case middleend.LinkEventProxyAnswer:
		// The pinned official frontend ignores both answer flags here and
		// forwards the packet through the normal client transport framing.
		payloadSize = len(event.Packet)
		wire, err = client.encoder.Encode(event.Packet)
	case middleend.LinkEventSimpleAck:
		payloadSize = 4
		wire, err = middleend.EncodeSimpleAckForClient(client.connectionType, event.ConfirmKey)
	case middleend.LinkEventCloseExternal:
		return client.beginOrderlyClose(c)
	default:
		err = fmt.Errorf("%w: unexpected event kind %d", ErrMiddleEndClientProtocol, event.Kind)
	}
	if err != nil {
		return gnet.Close
	}
	defer clear(wire)
	if err := client.writeWire(c, wire); err != nil {
		h.logger.Debug("[%s] write Middle-End response: %v", ctx.LogPrefix(), err)
		return gnet.Close
	}
	if counter := ctx.TrafficOut(); counter != nil {
		counter.Add(int64(payloadSize))
	}
	if h.clientSilenceCloseMs > 0 {
		ctx.lastServerByteMs.Store(time.Now().UnixMilli())
	}
	return gnet.None
}

func (c *middleEndClient) writeWire(connection gnet.Conn, wire []byte) error {
	if c.mode == ModeDD {
		out := make([]byte, len(wire))
		defer clear(out)
		c.encryptor.XORKeyStream(out, wire)
		return writeAllOwner(connection, out)
	}

	encodedSize := c.drs.PlanSize(len(wire))
	if encodedSize > middleEndMaxEncodedResponse {
		return fmt.Errorf("%w: encoded response %d exceeds %d", ErrMiddleEndClientProtocol, encodedSize, middleEndMaxEncodedResponse)
	}
	out := make([]byte, encodedSize)
	defer clear(out)
	sourceOffset := 0
	destinationOffset := 0
	for sourceOffset < len(wire) {
		chunk := c.drs.NextChunk(len(wire) - sourceOffset)
		if chunk <= 0 {
			return fmt.Errorf("%w: DRS produced an empty chunk", ErrMiddleEndClientProtocol)
		}
		out[destinationOffset] = faketls.RecordTypeApplicationData
		out[destinationOffset+1] = 0x03
		out[destinationOffset+2] = 0x03
		binary.BigEndian.PutUint16(out[destinationOffset+3:destinationOffset+5], uint16(chunk))
		destinationOffset += faketls.RecordHeaderSize
		c.encryptor.XORKeyStream(
			out[destinationOffset:destinationOffset+chunk],
			wire[sourceOffset:sourceOffset+chunk],
		)
		c.drs.Advance(chunk)
		sourceOffset += chunk
		destinationOffset += chunk
	}
	if destinationOffset != len(out) {
		return fmt.Errorf("%w: DRS planned %d bytes and wrote %d", ErrMiddleEndClientProtocol, len(out), destinationOffset)
	}
	return writeAllOwner(connection, out)
}

func writeAllOwner(connection gnet.Conn, wire []byte) error {
	written, err := connection.Write(wire)
	if err != nil {
		return err
	}
	if written != len(wire) {
		return io.ErrShortWrite
	}
	return nil
}

func (c *middleEndClient) nextPacket(connection gnet.Conn) (middleend.ClientPacket, bool, error) {
	tlsRecords := 0
	for {
		packet, ok, err := c.decoder.Next()
		if err != nil || ok {
			return packet, ok, err
		}
		if len(c.pendingPlain) > 0 {
			consumed, err := c.decoder.Feed(c.pendingPlain)
			if err != nil {
				return middleend.ClientPacket{}, false, err
			}
			clear(c.pendingPlain[:consumed])
			c.pendingPlain = c.pendingPlain[consumed:]
			if len(c.pendingPlain) == 0 {
				c.pendingPlain = nil
				c.pendingPlainRetained = 0
			}
			if consumed == 0 {
				return middleend.ClientPacket{}, false, fmt.Errorf("%w: decoder retained its maximum without a packet", ErrMiddleEndClientProtocol)
			}
			continue
		}
		if len(c.pendingCipher) > 0 {
			chunk := min(len(c.pendingCipher), middleEndDecryptChunk)
			c.decryptIntoPending(c.pendingCipher[:chunk])
			clear(c.pendingCipher[:chunk])
			c.pendingCipher = c.pendingCipher[chunk:]
			if len(c.pendingCipher) == 0 {
				c.pendingCipher = nil
				c.pendingCipherRetained = 0
			}
			continue
		}
		if c.mode == ModeDD {
			data, _ := connection.Peek(-1)
			if len(data) == 0 {
				return middleend.ClientPacket{}, false, nil
			}
			chunk := min(len(data), middleEndDecryptChunk)
			c.decryptIntoPending(data[:chunk])
			discarded, err := connection.Discard(chunk)
			if err != nil || discarded != chunk {
				if err == nil {
					err = io.ErrShortBuffer
				}
				return middleend.ClientPacket{}, false, err
			}
			continue
		}

		data, _ := connection.Peek(-1)
		if len(data) < faketls.RecordHeaderSize {
			return middleend.ClientPacket{}, false, nil
		}
		payloadSize := int(binary.BigEndian.Uint16(data[3:5]))
		if data[0] != faketls.RecordTypeApplicationData || payloadSize == 0 || payloadSize > faketls.MaxRecordPayload {
			return middleend.ClientPacket{}, false, fmt.Errorf(
				"%w: invalid post-handshake FakeTLS record type %d size %d",
				ErrMiddleEndClientProtocol,
				data[0],
				payloadSize,
			)
		}
		recordSize := faketls.RecordHeaderSize + payloadSize
		if len(data) < recordSize {
			return middleend.ClientPacket{}, false, nil
		}
		if tlsRecords == middleEndTLSRecordWorkLimit {
			if err := connection.Wake(nil); err != nil {
				return middleend.ClientPacket{}, false, err
			}
			return middleend.ClientPacket{}, false, nil
		}
		c.decryptIntoPending(data[faketls.RecordHeaderSize:recordSize])
		discarded, err := connection.Discard(recordSize)
		if err != nil || discarded != recordSize {
			if err == nil {
				err = io.ErrShortBuffer
			}
			return middleend.ClientPacket{}, false, err
		}
		tlsRecords++
	}
}

func (c *middleEndClient) decryptIntoPending(ciphertext []byte) {
	plaintext := make([]byte, len(ciphertext))
	c.decryptor.XORKeyStream(plaintext, ciphertext)
	c.pendingPlain = append(c.pendingPlain, plaintext...)
	c.pendingPlainRetained = cap(c.pendingPlain)
	clear(plaintext)
}

func (c *middleEndClient) clearWaitingRequest() {
	if c.waiting == nil {
		return
	}
	clear(c.waiting.Packet)
	*c.waiting = middleend.ProxyRequest{}
	c.waiting = nil
}

func (h *ProxyHandler) closeMiddleEnd(client *middleEndClient) {
	frontend := client.frontend
	frontend.mu.Lock()
	delete(frontend.routes, client.binding.ConnectionID())
	client.route.retire()
	// Removal precedes BeginClose while the dispatcher lock prevents a token
	// from being leased into the gap.
	_ = client.binding.BeginClose()
	frontend.mu.Unlock()
	client.clearOwnerState()
}

func (c *middleEndClient) clearOwnerState() {
	c.retryMu.Lock()
	c.closed = true
	if c.retryTimer != nil {
		c.retryTimer.Stop()
		c.retryTimer = nil
	}
	c.retryMu.Unlock()
	if c.decoder != nil {
		_ = c.decoder.Close()
		c.decoder = nil
	}
	c.clearWaitingRequest()
	clear(c.pendingCipher)
	clear(c.pendingPlain)
	c.pendingCipher = nil
	c.pendingCipherRetained = 0
	c.pendingPlain = nil
	c.pendingPlainRetained = 0
	c.decryptor = nil
	c.encryptor = nil
	c.encoder = nil
	c.drs = nil
	c.awaitingResult = false
	c.closeAfterDrain = false
	c.outputStallDeadline = time.Time{}
	c.releaseBudgets()
}
