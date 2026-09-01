package webproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
)

const (
	defaultPassthroughStatus       = 418
	defaultSanitizedFallbackStatus = 419
	defaultHeaderTimeout           = 10 * time.Second
	defaultBodyTimeout             = 30 * time.Second
	defaultIdleTimeout             = 60 * time.Second
	defaultWriteTimeout            = 30 * time.Second
	drainCheckInterval             = 5 * time.Millisecond

	// FallbackClassificationHeader marks which exact Nginx fallback contract
	// applies to an internal sentinel response.
	FallbackClassificationHeader = "X-Telego-Fallback"
	FallbackOrdinarySite         = "ordinary-site-v1"
	FallbackSanitizedPublic      = "sanitized-public-v1"

	// NginxPassthroughFallback is the exact Phase 5 contract for ordinary site
	// traffic. The named location must preserve the original method, complete
	// request URI (including args), body, Cookie, and all site request headers.
	NginxPassthroughFallback = "route every public TLS request through the private WEB upstream; set client_max_body_size to the public-site policy and at least 2 MiB; require proxy_request_buffering on before the private upstream; intercept only PassthroughStatus with X-Telego-Fallback: ordinary-site-v1; preserve original method, $request_uri including args, buffered request body, Host from $http_host, Cookie, Authorization, Forwarded, X-Forwarded-For, Connection, Upgrade, and all site request headers"

	// NginxSanitizedFallback is the exact Phase 5 contract for carrier-shaped
	// traffic that did not authenticate. The named location must force GET; use
	// $uri (never $request_uri) so args are empty; disable the request body; and
	// clear every listed carrier credential/header before proxying.
	NginxSanitizedFallback = "intercept only SanitizedFallbackStatus with X-Telego-Fallback: sanitized-public-v1; GET $uri; no args; no request body; preserve Host from $http_host; clear Content-Length, Content-Type, Transfer-Encoding, Authorization, Cookie, X-Up-Seq, X-Down-Cursor, X-Session-Token, X-Carrier-Mode, X-Up-Ack, X-Lane-ID, Sec-WebSocket-Key, Sec-WebSocket-Protocol, Sec-WebSocket-Version, Sec-WebSocket-Extensions, Forwarded, X-Forwarded-For, Connection, Upgrade"
)

var (
	ErrInvalidHTTPServerConfig = errors.New("invalid WEB HTTP server configuration")
	ErrHTTPServerStarted       = errors.New("WEB HTTP server already started")
)

// HTTPServerConfig configures the private HTTP/1.1 origin placed behind the
// deployment's TLS-terminating Nginx. It does not alter the public MTProxy
// gnet engine or own Manager shutdown.
type HTTPServerConfig struct {
	Bind                         string
	Hostname                     string
	Manager                      *Manager
	PassthroughStatus            int
	SanitizedFallbackStatus      int
	Multicore                    bool
	ReusePort                    bool
	LockOSThread                 bool
	NumEventLoop                 int
	SocketSendBuffer             int
	HeaderTimeout                time.Duration
	BodyTimeout                  time.Duration
	IdleTimeout                  time.Duration
	WriteTimeout                 time.Duration
	TrustedProxyCIDRs            []string
	webSocketBackpressureTimeout time.Duration
	webSocketBackpressureRetry   time.Duration
}

// HTTPServer is an independent gnet engine for HTTPS WEB carriers.
// Constructing it has no listener or process-global side effects.
type HTTPServer struct {
	config       HTTPServerConfig
	handler      *httpEventHandler
	renderBridge func(string, string, int, CarrierMode, int) (BridgePage, error)

	lifecycleMu    sync.Mutex
	started        bool
	stopping       atomic.Bool
	engine         atomic.Pointer[gnet.Engine]
	ready          chan struct{}
	done           chan struct{}
	errors         chan error
	runErrMu       sync.Mutex
	runErr         error
	readyOnce      sync.Once
	trustedProxies []netip.Prefix
}

// NewHTTPServer validates a WEB HTTP engine without starting it.
func NewHTTPServer(config HTTPServerConfig) (*HTTPServer, error) {
	if config.Manager == nil {
		return nil, fmt.Errorf("%w: manager is required", ErrInvalidHTTPServerConfig)
	}
	if config.Bind == "" {
		return nil, fmt.Errorf("%w: bind address is required", ErrInvalidHTTPServerConfig)
	}
	if strings.HasPrefix(config.Bind, "unix://") || strings.HasPrefix(config.Bind, "/") {
		return nil, fmt.Errorf("%w: Unix-socket WEB HTTP binds cannot authenticate a proxy peer", ErrInvalidHTTPServerConfig)
	}
	if strings.Contains(config.Bind, "://") && !strings.HasPrefix(config.Bind, "tcp://") {
		return nil, fmt.Errorf("%w: bind must use TCP", ErrInvalidHTTPServerConfig)
	}
	if _, _, err := net.SplitHostPort(strings.TrimPrefix(config.Bind, "tcp://")); err != nil {
		return nil, fmt.Errorf("%w: invalid TCP bind: %v", ErrInvalidHTTPServerConfig, err)
	}
	if err := ValidateHostname(config.Hostname); err != nil {
		return nil, fmt.Errorf("%w: hostname: %v", ErrInvalidHTTPServerConfig, err)
	}
	if config.PassthroughStatus == 0 {
		config.PassthroughStatus = defaultPassthroughStatus
	}
	if config.SanitizedFallbackStatus == 0 {
		config.SanitizedFallbackStatus = defaultSanitizedFallbackStatus
	}
	if invalidFallbackStatus(config.PassthroughStatus) || invalidFallbackStatus(config.SanitizedFallbackStatus) ||
		config.PassthroughStatus == config.SanitizedFallbackStatus {
		return nil, fmt.Errorf("%w: fallback statuses must be distinct 400..599 values reserved from carrier responses", ErrInvalidHTTPServerConfig)
	}
	if config.NumEventLoop < 0 {
		return nil, fmt.Errorf("%w: event-loop count cannot be negative", ErrInvalidHTTPServerConfig)
	}
	if config.SocketSendBuffer < 0 {
		return nil, fmt.Errorf("%w: socket send buffer cannot be negative", ErrInvalidHTTPServerConfig)
	}
	for value, fallback := range map[*time.Duration]time.Duration{
		&config.HeaderTimeout: defaultHeaderTimeout,
		&config.BodyTimeout:   defaultBodyTimeout,
		&config.IdleTimeout:   defaultIdleTimeout,
		&config.WriteTimeout:  defaultWriteTimeout,
	} {
		if *value < 0 {
			return nil, fmt.Errorf("%w: HTTP timeouts cannot be negative", ErrInvalidHTTPServerConfig)
		}
		if *value == 0 {
			*value = fallback
		}
	}
	if config.webSocketBackpressureTimeout < 0 || config.webSocketBackpressureRetry < 0 {
		return nil, fmt.Errorf("%w: WebSocket backpressure durations cannot be negative", ErrInvalidHTTPServerConfig)
	}
	if config.webSocketBackpressureTimeout == 0 {
		config.webSocketBackpressureTimeout = webSocketBackpressureTimeout
	}
	if config.webSocketBackpressureRetry == 0 {
		config.webSocketBackpressureRetry = webSocketBackpressureRetry
	}
	trustedProxies := make([]netip.Prefix, 0, len(config.TrustedProxyCIDRs))
	for _, value := range config.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || prefix.String() != value {
			return nil, fmt.Errorf("%w: trusted proxy CIDR %q is not canonical", ErrInvalidHTTPServerConfig, value)
		}
		trustedProxies = append(trustedProxies, prefix)
	}

	server := &HTTPServer{
		config:         config,
		renderBridge:   renderBridgeForCarrier,
		ready:          make(chan struct{}),
		done:           make(chan struct{}),
		errors:         make(chan error, 1),
		trustedProxies: trustedProxies,
	}
	server.handler = &httpEventHandler{server: server}
	return server, nil
}

func invalidFallbackStatus(status int) bool {
	if status < 400 || status > 599 {
		return true
	}
	switch status {
	case 400, 404, 429, 500, 502, 503:
		return true
	default:
		return false
	}
}

// Errors reports an unexpected gnet exit and then closes. A normal Stop closes
// the channel without sending a value.
func (s *HTTPServer) Errors() <-chan error { return s.errors }

// Start launches the independent gnet engine and waits until its listener is
// accepting or startup fails.
func (s *HTTPServer) Start(ctx context.Context) error {
	s.lifecycleMu.Lock()
	if s.started {
		s.lifecycleMu.Unlock()
		return ErrHTTPServerStarted
	}
	s.started = true
	s.lifecycleMu.Unlock()

	address := s.config.Bind
	if !strings.Contains(address, "://") {
		address = "tcp://" + address
	}
	options := []gnet.Option{
		gnet.WithMulticore(s.config.Multicore),
		gnet.WithReuseAddr(true),
		gnet.WithReusePort(s.config.ReusePort),
		gnet.WithLockOSThread(s.config.LockOSThread),
		gnet.WithReadBufferCap(64 * 1024),
		gnet.WithWriteBufferCap(256 * 1024),
	}
	if s.config.SocketSendBuffer > 0 {
		options = append(options, gnet.WithSocketSendBuffer(s.config.SocketSendBuffer))
	}
	if s.config.NumEventLoop > 0 {
		options = append(options, gnet.WithNumEventLoop(s.config.NumEventLoop))
	}
	go func() {
		err := gnet.Run(s.handler, address, options...)
		s.runErrMu.Lock()
		s.runErr = err
		s.runErrMu.Unlock()
		if err != nil {
			s.errors <- err
		}
		close(s.errors)
		close(s.done)
	}()

	select {
	case <-s.ready:
		return nil
	case <-s.done:
		return s.loadRunError()
	case <-ctx.Done():
		s.stopping.Store(true)
		if engine := s.engine.Load(); engine != nil {
			go func() { _ = stopGnetEngine(context.Background(), s.done, engine.Stop) }()
		}
		return ctx.Err()
	}
}

// Stop stops admission, closes carrier connections, and waits for the gnet
// engine. Manager shutdown remains the caller's responsibility.
func (s *HTTPServer) Stop(ctx context.Context) error {
	s.lifecycleMu.Lock()
	started := s.started
	s.lifecycleMu.Unlock()
	if !started {
		return nil
	}
	s.stopping.Store(true)

	select {
	case <-s.done:
		return s.loadRunError()
	case <-s.ready:
		if engine := s.engine.Load(); engine != nil {
			if err := stopGnetEngine(ctx, s.done, engine.Stop); err != nil {
				select {
				case <-s.done:
					return s.loadRunError()
				default:
					return err
				}
			}
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case <-s.done:
		return s.loadRunError()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// stopGnetEngine also watches Run completion because gnet can return from
// OnBoot without marking its Engine as stopped. Waiting only in Engine.Stop
// would then last until ctx expires.
func stopGnetEngine(ctx context.Context, done <-chan struct{}, stop func(context.Context) error) error {
	select {
	case <-done:
		return nil
	default:
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	stopCtx, cancelStop := context.WithCancel(ctx)
	defer cancelStop()
	result := make(chan error, 1)
	go func() { result <- stop(stopCtx) }()

	select {
	case <-done:
		return nil
	case err := <-result:
		return err
	case <-ctx.Done():
		select {
		case <-done:
			return nil
		default:
			return ctx.Err()
		}
	}
}

func (s *HTTPServer) loadRunError() error {
	s.runErrMu.Lock()
	defer s.runErrMu.Unlock()
	return s.runErr
}

type httpEventHandler struct {
	gnet.BuiltinEventEngine
	server *HTTPServer
}

func (h *httpEventHandler) OnBoot(engine gnet.Engine) gnet.Action {
	h.server.engine.Store(&engine)
	h.server.readyOnce.Do(func() { close(h.server.ready) })
	if h.server.stopping.Load() {
		return gnet.Shutdown
	}
	return gnet.None
}

func (*httpEventHandler) OnShutdown(gnet.Engine) {}

func (h *httpEventHandler) OnOpen(connection gnet.Conn) ([]byte, gnet.Action) {
	_ = connection.SetNoDelay(true)
	state := &httpConnectionState{peerIP: remoteIP(connection.RemoteAddr())}
	connection.SetContext(state)
	state.armDeadline(connection, h.server.config.HeaderTimeout)
	return nil, gnet.None
}

func (*httpEventHandler) OnClose(connection gnet.Conn, _ error) gnet.Action {
	if state, ok := connection.Context().(*httpConnectionState); ok {
		state.close()
	}
	return gnet.None
}

func (h *httpEventHandler) OnTraffic(connection gnet.Conn) gnet.Action {
	state, ok := connection.Context().(*httpConnectionState)
	if !ok {
		return gnet.Close
	}
	if transport := state.webSocketTransport(); transport != nil {
		return h.onWebSocketTraffic(connection, state, transport)
	}
	if state.isDraining() {
		if connection.InboundBuffered() > maxPipelineBytes {
			state.requestClose()
			_, _ = connection.Discard(connection.InboundBuffered())
		}
		if connection.OutboundBuffered() != 0 {
			state.armDrainWake(connection)
			return gnet.None
		}
		closeAfter := state.finishResponse()
		if closeAfter {
			return gnet.Close
		}
		if connection.InboundBuffered() == 0 {
			state.armDeadline(connection, h.server.config.IdleTimeout)
			return gnet.None
		}
		state.armDeadline(connection, h.server.config.HeaderTimeout)
	}
	if state.requestActive() {
		if connection.InboundBuffered() > maxPipelineBytes {
			state.cancelRequest()
			return gnet.Close
		}
		return gnet.None
	}

	for {
		if state.pending != nil {
			bodySize, validSize := checkedContentLength(state.pending.request.contentLength)
			if !validSize {
				return h.writeImmediate(connection, state, rejectResponse(400))
			}
			if len(state.input) < bodySize && !state.readBody(connection, bodySize) {
				return h.writeImmediate(connection, state, rejectResponse(400))
			}
			if len(state.input) < bodySize {
				return gnet.None
			}
			body := state.input
			state.input = nil
			prepared := state.pending
			state.pending = nil
			h.dispatch(connection, state, prepared, body)
			return gnet.None
		}

		if len(state.input) == 0 {
			if connection.InboundBuffered() == 0 {
				return gnet.None
			}
			state.armDeadline(connection, h.server.config.HeaderTimeout)
		}
		if !state.readHeader(connection) {
			return h.writeImmediate(connection, state, rejectResponse(400))
		}
		request, consumed, parseErr := parseCarrierRequestHeader(state.input)
		if errors.Is(parseErr, errHTTPIncomplete) {
			return gnet.None
		}
		if parseErr != nil {
			return h.writeImmediate(connection, state, rejectResponse(400))
		}
		prepared, disposition := h.prepare(request, state.peerIP, connection.InboundBuffered())
		switch disposition {
		case requestPassthrough:
			return h.writeImmediate(connection, state, h.passthroughFallback())
		case requestSanitizedFallback:
			return h.writeImmediate(connection, state, h.sanitizedFallback())
		case requestCarrier:
		default:
			return h.writeImmediate(connection, state, rejectResponse(500))
		}
		if consumed != len(state.input) {
			prepared.releaseWebSocket()
			return h.writeImmediate(connection, state, rejectResponse(400))
		}
		state.input = nil
		if prepared.kind == requestWebSocket {
			return h.upgradeWebSocket(connection, state, prepared)
		}
		state.pending = prepared
		state.armDeadline(connection, h.server.config.BodyTimeout)
	}
}

type httpConnectionState struct {
	mu         sync.Mutex
	active     bool
	draining   bool
	closeAfter bool
	cancel     context.CancelFunc
	lease      *PollLease
	deadline   *time.Timer
	deadlineID uint64
	drainWake  *time.Timer
	peerIP     string
	pending    *preparedRequest
	input      []byte
	websocket  *webSocketConnection
}

func (s *httpConnectionState) readHeader(connection gnet.Conn) bool {
	buffered := connection.InboundBuffered()
	if buffered == 0 {
		return true
	}
	remaining := maxHTTPHeaderBytes - len(s.input)
	if remaining <= 0 {
		return false
	}
	peekSize := min(buffered, remaining)
	peeked, err := connection.Peek(peekSize)
	if err != nil || len(peeked) != peekSize {
		return false
	}
	take := headerCompletion(s.input, peeked)
	if take == 0 {
		if buffered > peekSize || peekSize == remaining {
			return false
		}
		take = peekSize
	}
	data, err := connection.Next(take)
	if err != nil || len(data) != take {
		return false
	}
	s.input = append(s.input, data...)
	return true
}

func headerCompletion(prefix, next []byte) int {
	boundary := min(3, len(prefix))
	probe := make([]byte, 0, boundary+len(next))
	probe = append(probe, prefix[len(prefix)-boundary:]...)
	probe = append(probe, next...)
	if end := strings.Index(string(probe), "\r\n\r\n"); end >= 0 {
		consumed := end + 4 - boundary
		if consumed > 0 {
			return consumed
		}
	}
	return 0
}

func (s *httpConnectionState) readBody(connection gnet.Conn, bodySize int) bool {
	buffered := connection.InboundBuffered()
	need := bodySize - len(s.input)
	if buffered > need+maxPipelineBytes {
		return false
	}
	take := min(buffered, need)
	if take == 0 {
		return true
	}
	data, err := connection.Next(take)
	if err != nil || len(data) != take {
		return false
	}
	s.input = append(s.input, data...)
	return true
}

func (s *httpConnectionState) requestActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

func (s *httpConnectionState) isDraining() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.draining
}

func (s *httpConnectionState) requestClose() {
	s.mu.Lock()
	s.closeAfter = true
	s.mu.Unlock()
}

func (s *httpConnectionState) startRequest(
	connection gnet.Conn,
	cancel context.CancelFunc,
	duration time.Duration,
) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return false
	}
	s.active = true
	s.cancel = cancel
	s.armDeadlineLocked(connection, duration)
	return true
}

func (s *httpConnectionState) finishRequest() {
	s.mu.Lock()
	s.invalidateDeadlineLocked()
	s.active = false
	s.cancel = nil
	s.mu.Unlock()
}

func (s *httpConnectionState) beginResponse(
	connection gnet.Conn,
	cancel context.CancelFunc,
	lease *PollLease,
	closeAfter bool,
	writeTimeout time.Duration,
) {
	s.mu.Lock()
	s.cancel = nil
	s.draining = true
	s.closeAfter = closeAfter
	s.lease = lease
	s.armDeadlineLocked(connection, writeTimeout)
	s.mu.Unlock()
	cancel()
}

func (s *httpConnectionState) finishResponse() bool {
	s.mu.Lock()
	// Invalidate the write phase while holding the state lock. A fired timer
	// queued on the event loop can no longer close the next keep-alive phase or
	// race with releasing the session's carrier slot.
	s.invalidateDeadlineLocked()
	lease := s.lease
	closeAfter := s.closeAfter
	s.lease = nil
	s.active = false
	s.draining = false
	s.closeAfter = false
	if s.drainWake != nil {
		s.drainWake.Stop()
		s.drainWake = nil
	}
	s.mu.Unlock()
	lease.Release()
	return closeAfter
}

func (s *httpConnectionState) cancelRequest() {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *httpConnectionState) armDeadline(connection gnet.Conn, duration time.Duration) {
	s.mu.Lock()
	s.armDeadlineLocked(connection, duration)
	s.mu.Unlock()
}

func (s *httpConnectionState) armDeadlineLocked(connection gnet.Conn, duration time.Duration) {
	if s.deadline != nil {
		s.deadline.Stop()
	}
	s.deadlineID++
	id := s.deadlineID
	s.deadline = time.AfterFunc(duration, func() {
		_ = connection.EventLoop().Execute(context.Background(), gnet.RunnableFunc(func(context.Context) error {
			s.mu.Lock()
			if s.deadlineID != id {
				s.mu.Unlock()
				return nil
			}
			cancel := s.cancel
			s.cancel = nil
			s.invalidateDeadlineLocked()
			s.mu.Unlock()
			if cancel != nil {
				cancel()
			}
			// This runnable is executing on the owning event loop. No phase
			// transition can occur between the generation check and close.
			return connection.EventLoop().Close(connection)
		}))
	})
}

func (s *httpConnectionState) invalidateDeadlineLocked() {
	if s.deadline != nil {
		s.deadline.Stop()
		s.deadline = nil
	}
	s.deadlineID++
}

func (s *httpConnectionState) armDrainWake(connection gnet.Conn) {
	s.mu.Lock()
	if s.drainWake == nil {
		s.drainWake = time.AfterFunc(drainCheckInterval, func() {
			s.mu.Lock()
			s.drainWake = nil
			s.mu.Unlock()
			_ = connection.Wake(nil)
		})
	}
	s.mu.Unlock()
}

func (s *httpConnectionState) close() {
	s.mu.Lock()
	cancel := s.cancel
	lease := s.lease
	transport := s.websocket
	s.cancel = nil
	s.lease = nil
	s.websocket = nil
	s.invalidateDeadlineLocked()
	if s.drainWake != nil {
		s.drainWake.Stop()
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	lease.Release()
	if transport != nil {
		transport.close()
	}
}

func (s *httpConnectionState) beginWebSocket(
	connection gnet.Conn,
	transport *webSocketConnection,
	writeTimeout time.Duration,
) {
	s.mu.Lock()
	s.active = false
	s.draining = false
	s.cancel = nil
	s.websocket = transport
	s.armDeadlineLocked(connection, writeTimeout)
	s.mu.Unlock()
}

func (s *httpConnectionState) webSocketTransport() *webSocketConnection {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.websocket
}

func (s *httpConnectionState) invalidateDeadline() {
	s.mu.Lock()
	s.invalidateDeadlineLocked()
	s.mu.Unlock()
}

type requestKind uint8

const (
	requestBridge requestKind = iota + 1
	requestCreate
	requestUp
	requestDown
	requestDelete
	requestWebSocket
)

type requestDisposition uint8

const (
	requestCarrier requestDisposition = iota + 1
	requestPassthrough
	requestSanitizedFallback
)

type preparedRequest struct {
	request            carrierRequest
	kind               requestKind
	capability         Capability
	bootstrapAuth      *BootstrapAuthorization
	session            *Session
	token              string
	sequence           uint64
	cursor             uint64
	laneID             uint32
	clientIP           string
	webSocket          webSocketUpgrade
	webSocketLane      *WebSocketLaneLease
	webSocketMultiplex bool
}

func (h *httpEventHandler) prepare(
	request carrierRequest,
	peerIP string,
	trailingBytes int,
) (*preparedRequest, requestDisposition) {
	if !reservedCarrierRequest(request) {
		return nil, requestPassthrough
	}
	if request.path != webSocketPath && (request.upgrade || headerPresent(request, "upgrade")) {
		return nil, requestSanitizedFallback
	}
	config := h.server.config
	if request.headers["host"] != config.Hostname && request.headers["host"] != config.Hostname+":443" {
		return nil, requestSanitizedFallback
	}
	clientIP, ok := h.clientIP(request, peerIP)
	if !ok {
		return nil, requestSanitizedFallback
	}
	if request.path == "/" {
		prepared, matched := h.prepareBridge(request)
		if matched {
			prepared.clientIP = clientIP
			return prepared, requestCarrier
		}
		return nil, requestSanitizedFallback
	}
	if request.path == webSocketPath {
		upgrade, err := validateWebSocketUpgrade(request)
		if err != nil || trailingBytes != 0 {
			return nil, requestSanitizedFallback
		}
		session, err := config.Manager.Get(upgrade.token)
		if err != nil || upgrade.lanes && session.CarrierMode() != CarrierWebSocketLanes ||
			!upgrade.lanes && session.CarrierMode() != CarrierWebSocket {
			return nil, requestSanitizedFallback
		}
		prepared := &preparedRequest{
			request:   request,
			kind:      requestWebSocket,
			session:   session,
			clientIP:  clientIP,
			webSocket: upgrade,
		}
		if upgrade.lanes {
			prepared.webSocketLane = session.AcquireWebSocketLane(upgrade.laneID)
			if prepared.webSocketLane == nil {
				return nil, requestSanitizedFallback
			}
		} else {
			prepared.webSocketMultiplex = session.AcquireWebSocket()
			if !prepared.webSocketMultiplex {
				return nil, requestSanitizedFallback
			}
		}
		return prepared, requestCarrier
	}
	if cookie, present := request.headers["cookie"]; present && cookie != "" {
		return nil, requestSanitizedFallback
	}
	if request.query != "" || request.path != "/api/v1/session" &&
		request.path != "/api/v1/up" && request.path != "/api/v1/down" {
		return nil, requestSanitizedFallback
	}
	token, ok := bearerToken(request.headers["authorization"])
	if !ok {
		return nil, requestSanitizedFallback
	}

	switch request.path {
	case "/api/v1/session":
		if anyHeaderPresent(request, "x-up-seq", "x-down-cursor", "x-lane-id", "x-session-token", "x-carrier-mode", "x-up-ack") {
			return nil, requestSanitizedFallback
		}
		if request.method == "DELETE" {
			if !emptyRequestBody(request) || headerPresent(request, "content-type") {
				return nil, requestSanitizedFallback
			}
			return &preparedRequest{request: request, kind: requestDelete, token: token, clientIP: clientIP}, requestCarrier
		}
		if request.method != "POST" || request.headers["content-type"] != "application/octet-stream" ||
			!request.hasContentLength || request.contentLength > uint64(maxCreateBodyBytes) {
			return nil, requestSanitizedFallback
		}
		authorization, err := config.Manager.AuthenticateBootstrap(token)
		if err != nil {
			return nil, requestSanitizedFallback
		}
		return &preparedRequest{request: request, kind: requestCreate, bootstrapAuth: authorization, clientIP: clientIP}, requestCarrier

	case "/api/v1/up":
		if request.method != "POST" || request.headers["content-type"] != "application/octet-stream" ||
			!request.hasContentLength || request.contentLength > uint64(min(config.Manager.limits.MaxBodyBytes, maxCarrierBatchBytes)) ||
			anyHeaderPresent(request, "x-down-cursor", "x-session-token", "x-carrier-mode", "x-up-ack") {
			return nil, requestSanitizedFallback
		}
		laneID, ok := requestCarrierLane(request, config.Manager.CarrierMode())
		if !ok {
			return nil, requestSanitizedFallback
		}
		sequence, ok := canonicalDecimal(request.headers["x-up-seq"])
		if !ok || sequence == 0 {
			return nil, requestSanitizedFallback
		}
		session, err := config.Manager.Get(token)
		if err != nil {
			return nil, requestSanitizedFallback
		}
		return &preparedRequest{request: request, kind: requestUp, session: session, sequence: sequence, laneID: laneID, clientIP: clientIP}, requestCarrier

	case "/api/v1/down":
		if request.method != "POST" || !request.hasContentLength || request.contentLength != 0 ||
			headerPresent(request, "content-type") ||
			anyHeaderPresent(request, "x-up-seq", "x-session-token", "x-carrier-mode", "x-up-ack") {
			return nil, requestSanitizedFallback
		}
		laneID, ok := requestCarrierLane(request, config.Manager.CarrierMode())
		if !ok {
			return nil, requestSanitizedFallback
		}
		cursor, ok := canonicalDecimal(request.headers["x-down-cursor"])
		if !ok {
			return nil, requestSanitizedFallback
		}
		session, err := config.Manager.Get(token)
		if err != nil {
			return nil, requestSanitizedFallback
		}
		return &preparedRequest{request: request, kind: requestDown, session: session, cursor: cursor, laneID: laneID, clientIP: clientIP}, requestCarrier
	default:
		return nil, requestSanitizedFallback
	}
}

func requestCarrierLane(request carrierRequest, carrier CarrierMode) (uint32, bool) {
	value, present := request.headers["x-lane-id"]
	if carrier == CarrierHTTPS {
		return 0, !present
	}
	if carrier != CarrierHTTPSLanes || !present {
		return 0, false
	}
	lane, ok := canonicalDecimal(value)
	if !ok || lane > MaxStreamID {
		return 0, false
	}
	return uint32(lane), true
}

func reservedCarrierRequest(request carrierRequest) bool {
	if request.path == "/api/v1/session" || request.path == "/api/v1/up" ||
		request.path == "/api/v1/down" || request.path == webSocketPath {
		return true
	}
	if request.path == "/" && bridgeQueryPresent(request.query) {
		return true
	}
	for value := range strings.SplitSeq(request.headers["sec-websocket-protocol"], ",") {
		protocol := strings.Trim(value, " \t")
		if strings.HasPrefix(protocol, webSocketProtocolPrefix) ||
			strings.HasPrefix(protocol, webSocketLaneProtocolPrefix) {
			return true
		}
	}
	if _, ok := bearerToken(request.headers["authorization"]); !ok {
		return false
	}
	return anyHeaderPresent(request, "x-up-seq", "x-down-cursor", "x-lane-id", "x-session-token", "x-carrier-mode", "x-up-ack")
}

func (r *preparedRequest) releaseWebSocket() {
	if r == nil {
		return
	}
	if r.webSocketLane != nil {
		r.webSocketLane.Release()
		r.webSocketLane = nil
	}
	if r.webSocketMultiplex && r.session != nil {
		r.session.Close()
		r.webSocketMultiplex = false
	}
}

func bridgeQueryPresent(query string) bool {
	for field := range strings.SplitSeq(query, "&") {
		name, _, _ := strings.Cut(field, "=")
		if name == "bridge" {
			return true
		}
	}
	return false
}

func (h *httpEventHandler) clientIP(request carrierRequest, peer string) (string, bool) {
	peerAddress, err := netip.ParseAddr(peer)
	if err != nil || peerAddress.String() != peer || headerPresent(request, "forwarded") {
		return "", false
	}
	forwarded, present := request.headers["x-forwarded-for"]
	if !present {
		return peer, true
	}
	trusted := false
	for _, prefix := range h.server.trustedProxies {
		if prefix.Contains(peerAddress) {
			trusted = true
			break
		}
	}
	if !trusted || forwarded == "" || strings.ContainsAny(forwarded, ", \t") {
		return "", false
	}
	address, err := netip.ParseAddr(forwarded)
	if err != nil || address.String() != forwarded {
		return "", false
	}
	return forwarded, true
}

func (h *httpEventHandler) prepareBridge(request carrierRequest) (*preparedRequest, bool) {
	if request.method != "GET" || !emptyRequestBody(request) || headerPresent(request, "content-type") ||
		anyHeaderPresent(request, "authorization", "x-up-seq", "x-down-cursor", "x-lane-id", "x-session-token", "x-carrier-mode", "x-up-ack") {
		return nil, false
	}
	const prefix = "bridge="
	if !strings.HasPrefix(request.query, prefix) || len(request.query) != len(prefix)+capabilityLength {
		return nil, false
	}
	capability, err := ParseCapability(request.query[len(prefix):])
	if err != nil {
		return nil, false
	}
	if _, matched := h.server.config.Manager.MatchCapability(capability); !matched {
		return nil, false
	}
	return &preparedRequest{request: request, kind: requestBridge, capability: capability}, true
}

func emptyRequestBody(request carrierRequest) bool {
	return !request.hasContentLength || request.contentLength == 0
}

func checkedContentLength(value uint64) (int, bool) {
	converted := int(value)
	return converted, converted >= 0 && uint64(converted) == value
}

func headerPresent(request carrierRequest, name string) bool {
	_, exists := request.headers[name]
	return exists
}

func anyHeaderPresent(request carrierRequest, names ...string) bool {
	for _, name := range names {
		if headerPresent(request, name) {
			return true
		}
	}
	return false
}

func (h *httpEventHandler) dispatch(
	connection gnet.Conn,
	state *httpConnectionState,
	request *preparedRequest,
	body []byte,
) {
	ctx, cancel := context.WithCancel(context.Background())
	operationTimeout := h.server.config.BodyTimeout
	if request.kind == requestDown {
		operationTimeout = h.server.config.Manager.timeouts.LongPoll + h.server.config.WriteTimeout
	}
	if !state.startRequest(connection, cancel, operationTimeout) {
		cancel()
		_ = connection.Close()
		return
	}
	go func() {
		response := h.serve(ctx, request, body)
		if ctx.Err() != nil {
			response.lease.Release()
			state.finishRequest()
			return
		}
		closeAfter := request.request.close || response.close
		response.close = closeAfter
		if response.lease.Superseded() {
			response.lease.Release()
			response = carrierResponse{status: 204, headers: []responseHeader{
				{"Cache-Control", "no-store"},
				{"X-Down-Cursor", strconv.FormatUint(request.cursor, 10)},
			}, close: closeAfter}
		}
		err := connection.AsyncWritev(response.encodedParts(), func(current gnet.Conn, writeErr error) error {
			if writeErr != nil {
				response.lease.Release()
				cancel()
				state.finishRequest()
				return current.EventLoop().Close(current)
			}
			state.beginResponse(current, cancel, response.lease, closeAfter, h.server.config.WriteTimeout)
			if current.OutboundBuffered() != 0 {
				state.armDrainWake(current)
				return nil
			}
			if state.finishResponse() || closeAfter {
				return current.EventLoop().Close(current)
			}
			state.armDeadline(current, h.server.config.IdleTimeout)
			return current.Wake(nil)
		})
		if err != nil {
			response.lease.Release()
			cancel()
			state.finishRequest()
			_ = connection.Close()
		}
	}()
}

func (h *httpEventHandler) serve(
	ctx context.Context,
	request *preparedRequest,
	body []byte,
) carrierResponse {
	manager := h.server.config.Manager
	switch request.kind {
	case requestBridge:
		bootstrap, err := manager.IssueBootstrap(request.capability, request.clientIP)
		if err != nil {
			if errors.Is(err, ErrLimit) || errors.Is(err, ErrBackpressure) || errors.Is(err, ErrClosed) {
				return retryResponse()
			}
			return rejectResponse(500)
		}
		bridgeAuthority := h.server.config.Hostname
		if manager.CarrierMode().usesWebSocket() {
			bridgeAuthority = request.request.headers["host"]
		}
		page, err := h.server.renderBridge(
			bridgeAuthority,
			bootstrap,
			manager.limits.CarrierBatchBytes,
			manager.CarrierMode(),
			manager.limits.MaxStreamsPerSession,
		)
		if err != nil {
			return rejectResponse(500)
		}
		return newCarrierResponse(200, []responseHeader{
			{"Content-Type", "text/html; charset=utf-8"},
			{"Content-Security-Policy", page.CSP},
			{"Cache-Control", "no-store"},
			{"Referrer-Policy", "no-referrer"},
			{"X-Content-Type-Options", "nosniff"},
			{"X-DNS-Prefetch-Control", "off"},
			{"Permissions-Policy", PermissionsPolicy},
		}, page.Body)

	case requestCreate:
		result, err := request.bootstrapAuth.Create(request.clientIP, body)
		if err != nil {
			if errors.Is(err, ErrLimit) || errors.Is(err, ErrBackpressure) {
				return retryResponse()
			}
			return rejectResponse(400)
		}
		return newCarrierResponse(200, []responseHeader{
			{"Content-Type", "application/octet-stream"},
			{"Cache-Control", "no-store"},
			{"X-Session-Token", result.Token},
			{"X-Carrier-Mode", string(manager.CarrierMode())},
			{"X-Down-Cursor", "0"},
		}, result.Welcome)

	case requestUp:
		var ack uint64
		var err error
		if manager.CarrierMode() == CarrierHTTPSLanes {
			ack, err = request.session.ProcessUpLane(request.laneID, request.sequence, body)
		} else {
			ack, err = request.session.ProcessUp(request.sequence, body)
		}
		if err != nil {
			if errors.Is(err, ErrBackpressure) {
				return retryResponse()
			}
			return rejectResponse(400)
		}
		return carrierResponse{status: 204, headers: []responseHeader{
			{"Cache-Control", "no-store"},
			{"X-Up-Ack", strconv.FormatUint(ack, 10)},
		}}

	case requestDown:
		var responseBody []byte
		var cursor uint64
		var laneClosed bool
		var lease *PollLease
		var err error
		if manager.CarrierMode() == CarrierHTTPSLanes {
			responseBody, cursor, laneClosed, lease, err = request.session.PollCarrierLane(
				ctx,
				request.laneID,
				request.cursor,
			)
		} else {
			responseBody, cursor, lease, err = request.session.PollCarrier(ctx, request.cursor)
		}
		if err != nil {
			if ctx.Err() != nil {
				return carrierResponse{status: 204}
			}
			return rejectResponse(400)
		}
		headers := []responseHeader{
			{"Cache-Control", "no-store"},
			{"X-Down-Cursor", strconv.FormatUint(cursor, 10)},
		}
		if laneClosed {
			headers = append(headers, responseHeader{"X-Lane-Closed", "1"})
		}
		if len(responseBody) == 0 {
			return carrierResponse{status: 204, headers: headers, lease: lease}
		}
		headers = append(headers, responseHeader{"Content-Type", "application/octet-stream"})
		response := newCarrierResponse(200, headers, responseBody)
		response.lease = lease
		return response

	case requestDelete:
		if err := manager.Close(request.token); err != nil {
			return rejectResponse(400)
		}
		return carrierResponse{status: 204, headers: []responseHeader{{"Cache-Control", "no-store"}}}
	default:
		return rejectResponse(404)
	}
}

func remoteIP(address net.Addr) string {
	if tcp, ok := address.(*net.TCPAddr); ok && tcp.IP != nil {
		return tcp.IP.String()
	}
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		return host
	}
	return address.String()
}

type responseHeader struct {
	name  string
	value string
}

type carrierResponse struct {
	status  int
	headers []responseHeader
	body    []byte
	close   bool
	lease   *PollLease
}

func newCarrierResponse(status int, headers []responseHeader, body []byte) carrierResponse {
	return carrierResponse{status: status, headers: headers, body: body}
}

func retryResponse() carrierResponse {
	return carrierResponse{status: 503, headers: []responseHeader{
		{"Cache-Control", "no-store"},
		{"Retry-After", "1"},
	}}
}

func (h *httpEventHandler) passthroughFallback() carrierResponse {
	return carrierResponse{
		status: h.server.config.PassthroughStatus,
		headers: []responseHeader{
			{"Cache-Control", "no-store"},
			{FallbackClassificationHeader, FallbackOrdinarySite},
		},
		close: true,
	}
}

func (h *httpEventHandler) sanitizedFallback() carrierResponse {
	return carrierResponse{
		status: h.server.config.SanitizedFallbackStatus,
		headers: []responseHeader{
			{"Cache-Control", "no-store"},
			{FallbackClassificationHeader, FallbackSanitizedPublic},
		},
		close: true,
	}
}

func rejectResponse(status int) carrierResponse {
	return carrierResponse{
		status:  status,
		headers: []responseHeader{{"Cache-Control", "no-store"}},
		close:   true,
	}
}

func (h *httpEventHandler) writeImmediate(connection gnet.Conn, state *httpConnectionState, response carrierResponse) gnet.Action {
	response.close = true
	if !state.startRequest(connection, func() {}, h.server.config.WriteTimeout) {
		return gnet.Close
	}
	if _, err := connection.Write(response.encoded()); err != nil {
		state.finishRequest()
		return gnet.Close
	}
	state.beginResponse(connection, func() {}, nil, true, h.server.config.WriteTimeout)
	if connection.OutboundBuffered() == 0 {
		state.finishResponse()
		return gnet.Close
	}
	state.armDrainWake(connection)
	return gnet.None
}

func (r carrierResponse) encoded() []byte {
	header := r.encodedHeader()
	return append(header, r.body...)
}

func (r carrierResponse) encodedParts() [][]byte {
	header := r.encodedHeader()
	if len(r.body) == 0 {
		return [][]byte{header}
	}
	return [][]byte{header, r.body}
}

func (r carrierResponse) encodedHeader() []byte {
	var builder strings.Builder
	builder.Grow(256)
	builder.WriteString("HTTP/1.1 ")
	builder.WriteString(strconv.Itoa(r.status))
	builder.WriteByte(' ')
	builder.WriteString(statusText(r.status))
	builder.WriteString("\r\n")
	for _, header := range r.headers {
		builder.WriteString(header.name)
		builder.WriteString(": ")
		builder.WriteString(header.value)
		builder.WriteString("\r\n")
	}
	if r.status != 204 {
		builder.WriteString("Content-Length: ")
		builder.WriteString(strconv.Itoa(len(r.body)))
		builder.WriteString("\r\n")
	}
	if r.close {
		builder.WriteString("Connection: close\r\n")
	}
	builder.WriteString("\r\n")
	return []byte(builder.String())
}

func statusText(status int) string {
	switch status {
	case 200:
		return "OK"
	case 204:
		return "No Content"
	case 400:
		return "Bad Request"
	case 404:
		return "Not Found"
	case 418:
		return "I'm a teapot"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return "Fallback"
	}
}
