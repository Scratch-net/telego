package webproxy

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
	"github.com/zeebo/xxh3"
)

var (
	ErrAuthentication = errors.New("WEB authentication failed")
	ErrBackpressure   = errors.New("WEB temporary backpressure")
	ErrLimit          = errors.New("WEB resource limit reached")
	ErrProtocol       = errors.New("WEB protocol error")
	ErrClosed         = errors.New("WEB session closed")
)

// CreateResult is the idempotent HELLO/WELCOME session exchange.
type CreateResult struct {
	Token   string
	Welcome []byte
	Session *Session
}

// BootstrapAuthorization is an opaque, short-lived proof that a bootstrap
// bearer authenticated before its request body was read. Create revalidates the
// bootstrap under the manager lock, including expiry and prior idempotent use.
type BootstrapAuthorization struct {
	state *bootstrapAuthorization
}

type bootstrapAuthorization struct {
	manager *Manager
	token   sessionBearer
}

func (*BootstrapAuthorization) String() string { return "WEB bootstrap authorization" }

func (*BootstrapAuthorization) GoString() string { return "WEB bootstrap authorization" }

type bootstrap struct {
	token        sessionBearer
	diagnostic   *bridgeDiagnosticState
	expires      time.Time
	profile      Profile
	issuanceIP   string
	bodyDigest   [16]byte
	sessionToken string
	session      *Session
	used         bool
}

type closedToken struct {
	token      sessionBearer
	diagnostic *bridgeDiagnosticState
	expires    time.Time
	order      *list.Element
}

// Capacity is a point-in-time view of the manager's bounded resources.
type Capacity struct {
	Bootstraps   int
	Sessions     int
	ClosedTokens int
	Streams      int
	BackendDials int
	PendingBytes int64
	PendingItems int64
}

// Manager owns WEB bootstrap tokens, authenticated sessions, and process-wide
// stream and queue budgets.
type Manager struct {
	debugDiagnostics bool

	// Built from the copied profiles before publication; never mutated.
	capabilityPrefixes map[uint64]struct{}

	profiles       []Profile
	carrier        CarrierMode
	backendNet     string
	backend        string
	limits         Limits
	timeouts       Timeouts
	dialBackend    BackendDialContextFunc
	backendFactory BackendFactory
	budgetWake     chan struct{}
	budgetWaiters  map[backendBudgetKey]*list.Element
	budgetQueue    list.List
	budgetActive   *backendBudgetWake
	budgetTasks    map[*backendBudgetWake]struct{}

	mu                      sync.Mutex
	bootstraps              map[uint64]*bootstrap
	sessions                map[uint64]*Session
	closedTokens            map[uint64]*closedToken
	closedOrder             list.List
	streams                 int
	dials                   int
	pendingBytes            int64
	pendingItems            int64
	httpUpDiscards          int
	httpUpDiscardLimit      int
	httpUpDiscardPerSession int
	closed                  bool
	stop                    chan struct{}
	cleanupDone             chan struct{}
	shutdownDone            chan struct{}
	shutdownOnce            sync.Once

	sessionsCreated  atomic.Uint64
	sessionsClosed   [sessionCloseReasonCount]atomic.Uint64
	carrierRetries   [carrierOperationCount]atomic.Uint64
	backpressure     [carrierOperationCount]atomic.Uint64
	webSocketsActive atomic.Int64
}

// NewManager validates and copies config before starting its expiry worker.
func NewManager(config ManagerConfig) (*Manager, error) {
	if config.Carrier == "" {
		config.Carrier = CarrierHTTPS
	}
	if err := validateManagerConfig(config); err != nil {
		return nil, err
	}
	backendNetwork, backendAddress, _ := parseLocalBackend(config.Backend)
	discardLocal, discardLimit, _ := httpUpDiscardLimits(config.Limits)
	dialBackend := config.BackendDialContext
	if dialBackend == nil {
		dialContext := config.DialContext
		if dialContext == nil {
			dialContext = (&net.Dialer{}).DialContext
		}
		dialBackend = func(ctx context.Context, network, address, _ string) (net.Conn, error) {
			return dialContext(ctx, network, address)
		}
	}
	manager := &Manager{
		debugDiagnostics: config.DebugDiagnostics,

		capabilityPrefixes: make(map[uint64]struct{}, len(config.Profiles)),

		profiles:                slices.Clone(config.Profiles),
		carrier:                 config.Carrier,
		backendNet:              backendNetwork,
		backend:                 backendAddress,
		limits:                  config.Limits,
		httpUpDiscardLimit:      discardLimit,
		httpUpDiscardPerSession: discardLocal,
		timeouts:                config.Timeouts,
		dialBackend:             dialBackend,
		backendFactory:          config.BackendFactory,
		budgetWake:              make(chan struct{}, 1),
		bootstraps:              make(map[uint64]*bootstrap),
		sessions:                make(map[uint64]*Session),
		closedTokens:            make(map[uint64]*closedToken),
		stop:                    make(chan struct{}),
		cleanupDone:             make(chan struct{}),
		shutdownDone:            make(chan struct{}),
	}
	for _, profile := range manager.profiles {
		capability := profile.Capability()
		manager.capabilityPrefixes[binary.LittleEndian.Uint64(capability[:])] = struct{}{}
	}
	go manager.cleanupLoop()
	return manager, nil
}

// MatchCapability rejects unknown 8-byte prefixes before scanning every profile
// with constant-time comparisons. A prefix match alone never authenticates a
// credential. The returned profile does not alias manager-owned storage.
func (m *Manager) MatchCapability(capability Capability) (Profile, bool) {
	if _, ok := m.capabilityPrefixes[binary.LittleEndian.Uint64(capability[:])]; !ok {
		return Profile{}, false
	}
	matched := -1
	for index := range m.profiles {
		candidate := m.profiles[index].Capability()
		if subtle.ConstantTimeCompare(capability[:], candidate[:]) == 1 {
			matched = index
		}
	}
	if matched < 0 {
		return Profile{}, false
	}
	return m.profiles[matched], true
}

// IssueBootstrap authenticates a profile capability and issues a canonical
// two-minute bootstrap bearer.
func (m *Manager) IssueBootstrap(capability Capability, clientIP string) (string, error) {
	profile, matched := m.MatchCapability(capability)
	if !matched {
		return "", ErrAuthentication
	}
	token, key, err := newToken()
	if err != nil {
		return "", err
	}
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", ErrClosed
	}
	m.removeExpiredLocked(now)
	if len(m.bootstraps) >= m.limits.MaxBootstraps && !m.evictOldestUnusedBootstrapLocked() {
		m.recordBackpressure(carrierOperationBridge)
		return "", ErrLimit
	}
	for m.tokenPrefixUsedLocked(key) {
		token, key, err = newToken()
		if err != nil {
			return "", err
		}
	}
	var diagnostic *bridgeDiagnosticState
	if m.debugDiagnostics {
		diagnostic = &bridgeDiagnosticState{id: bridgeDiagnosticIDs.Add(1), user: profile.Name()}
	}
	m.bootstraps[key.prefix()] = &bootstrap{
		token:      key,
		diagnostic: diagnostic,
		expires:    now.Add(m.timeouts.BootstrapLifetime),
		profile:    profile,
		issuanceIP: clientIP,
	}
	return token, nil
}

// AuthenticateBootstrap authenticates a canonical bootstrap bearer without
// reading or parsing a request body. Unknown and malformed bearers return the
// same authentication error.
func (m *Manager) AuthenticateBootstrap(token string) (*BootstrapAuthorization, error) {
	bearer, err := parseToken(token)
	if err != nil {
		return nil, ErrAuthentication
	}
	if !m.bootstrapAuthenticated(bearer, time.Now()) {
		return nil, ErrAuthentication
	}
	return &BootstrapAuthorization{state: &bootstrapAuthorization{manager: m, token: bearer}}, nil
}

// Create atomically consumes a bootstrap for one exact HELLO body. Retrying the
// same token and identical body returns the original token and Session pointer.
// Authentication always completes before body parsing.
func (m *Manager) Create(token, clientIP string, body []byte) (CreateResult, error) {
	authorization, err := m.AuthenticateBootstrap(token)
	if err != nil {
		return CreateResult{}, err
	}
	return authorization.Create(clientIP, body)
}

// Create parses HELLO only after bootstrap authentication, then atomically
// creates or retries the session.
func (a *BootstrapAuthorization) Create(clientIP string, body []byte) (CreateResult, error) {
	return a.create(clientIP, body, nil)
}

func (a *BootstrapAuthorization) create(clientIP string, body []byte, owner gnet.EventLoop) (CreateResult, error) {
	if a == nil || a.state == nil || a.state.manager == nil {
		return CreateResult{}, ErrAuthentication
	}
	if !a.state.manager.bootstrapAuthenticated(a.state.token, time.Now()) {
		return CreateResult{}, ErrAuthentication
	}
	if err := ParseHello(body); err != nil {
		return CreateResult{}, ErrProtocol
	}
	bodyDigest := xxh3.Hash128(body).Bytes()
	now := time.Now()
	m := a.state.manager

	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.bootstraps[a.state.token.prefix()]
	if entry == nil || !entry.token.equal(a.state.token) || !now.Before(entry.expires) {
		return CreateResult{}, ErrAuthentication
	}
	if entry.used {
		if subtle.ConstantTimeCompare(entry.bodyDigest[:], bodyDigest[:]) != 1 || entry.session == nil {
			return CreateResult{}, ErrAuthentication
		}
		m.recordCarrierRetry(carrierOperationCreate)
		return CreateResult{
			Token:   entry.sessionToken,
			Welcome: welcomeFrame(),
			Session: entry.session,
		}, nil
	}
	if m.closed {
		return CreateResult{}, ErrClosed
	}
	if m.backendFactory != nil && owner == nil {
		return CreateResult{}, ErrProtocol
	}
	if len(m.sessions) >= m.limits.MaxSessions {
		m.recordBackpressure(carrierOperationCreate)
		return CreateResult{}, ErrLimit
	}

	sessionToken, sessionKey, err := newToken()
	if err != nil {
		return CreateResult{}, err
	}
	for m.tokenPrefixUsedLocked(sessionKey) {
		sessionToken, sessionKey, err = newToken()
		if err != nil {
			return CreateResult{}, err
		}
	}
	created := newSession(sessionOptions{
		profile:               entry.profile,
		carrier:               m.carrier,
		clientIP:              clientIP,
		backendNet:            m.backendNet,
		backend:               m.backend,
		limits:                m.limits,
		timeouts:              m.timeouts,
		dialBackend:           m.dialBackend,
		backendFactory:        m.backendFactory,
		owner:                 owner,
		budget:                m.changePendingBudget,
		manager:               m,
		onCarrierRetry:        m.recordCarrierRetry,
		onBackpressure:        m.recordBackpressure,
		acquireStream:         m.acquireStream,
		onBackendDialFinished: m.backendDialFinished,
		onStreamFinished:      m.streamFinished,
	})
	created.token = sessionKey
	created.diagnostic = entry.diagnostic
	created.onFinished = func(session *Session, reason sessionCloseReason) {
		m.sessionFinished(sessionKey, session, reason)
	}
	m.sessions[sessionKey.prefix()] = created
	m.sessionsCreated.Add(1)
	entry.used = true
	entry.bodyDigest = bodyDigest
	entry.sessionToken = sessionToken
	entry.session = created
	return CreateResult{
		Token:   sessionToken,
		Welcome: welcomeFrame(),
		Session: created,
	}, nil
}

// CarrierMode returns the transport used for newly created sessions.
func (m *Manager) CarrierMode() CarrierMode { return m.carrier }

func (m *Manager) bootstrapAuthenticated(key sessionBearer, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.bootstraps[key.prefix()]
	if entry == nil || !entry.token.equal(key) {
		return false
	}
	if !now.Before(entry.expires) {
		delete(m.bootstraps, key.prefix())
		return false
	}
	return true
}

// Get authenticates a canonical session bearer.
func (m *Manager) Get(token string) (*Session, error) {
	key, err := parseToken(token)
	if err != nil {
		return nil, ErrAuthentication
	}
	m.mu.Lock()
	session := m.sessions[key.prefix()]
	if session != nil && !session.token.equal(key) {
		session = nil
	}
	m.mu.Unlock()
	if session == nil {
		return nil, ErrAuthentication
	}
	return session, nil
}

// recognizesToken is only a fallback classification check. Retained tokens
// remain private after retirement without becoming valid credentials again.
func (m *Manager) recognizesToken(token string) bool {
	raw, ok := decodeFallbackCredential(token)
	if !ok {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recognizesTokenLocked(raw)
}

func (m *Manager) recognizesTokenLocked(token sessionBearer) bool {
	key := token.prefix()
	if entry := m.bootstraps[key]; entry != nil && entry.token.equal(token) {
		return true
	}
	if session := m.sessions[key]; session != nil && session.token.equal(token) {
		return true
	}
	return m.closedTokens[key] != nil && m.closedTokens[key].token.equal(token)
}

// decodeFallbackCredential recognizes equivalent base64 spellings only for
// fallback sanitization. Authentication continues to use canonical parsers.
func decodeFallbackCredential(value string) (sessionBearer, bool) {
	var raw sessionBearer
	if len(value) == capabilityLength+1 && value[len(value)-1] == '=' {
		value = value[:len(value)-1]
	}
	if len(value) != capabilityLength {
		return raw, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err != nil || len(decoded) != len(raw) {
		return raw, false
	}
	copy(raw[:], decoded)
	return raw, true
}

// Close terminates the authenticated session. A recently closed valid token is
// idempotent; an unknown token remains indistinguishable from bad authentication.
func (m *Manager) Close(token string) error {
	key, err := parseToken(token)
	if err != nil {
		return ErrAuthentication
	}
	m.mu.Lock()
	session := m.sessions[key.prefix()]
	if session != nil && !session.token.equal(key) {
		session = nil
	}
	closed := m.closedTokens[key.prefix()]
	recentlyClosed := closed != nil && closed.token.equal(key)
	m.mu.Unlock()
	if session == nil {
		if recentlyClosed {
			return nil
		}
		return ErrAuthentication
	}
	session.closeWithReason(sessionCloseClient)
	return nil
}

// Capacity returns resource accounting without exposing session tokens.
func (m *Manager) Capacity() Capacity {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Capacity{
		Bootstraps:   len(m.bootstraps),
		Sessions:     len(m.sessions),
		ClosedTokens: len(m.closedTokens),
		Streams:      m.streams,
		BackendDials: m.dials,
		PendingBytes: m.pendingBytes,
		PendingItems: m.pendingItems,
	}
}

// Shutdown stops admission, closes all sessions, and waits for backend workers
// and the cleanup worker. The wait may be bounded by ctx.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.shutdownOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		close(m.stop)
		sessions := make([]*Session, 0, len(m.sessions))
		for _, session := range m.sessions {
			sessions = append(sessions, session)
		}
		m.mu.Unlock()

		for _, session := range sessions {
			session.closeWithReason(sessionCloseShutdown)
		}
		go func() {
			for _, session := range sessions {
				session.wait()
			}
			<-m.cleanupDone
			close(m.shutdownDone)
		}()
	})

	select {
	case <-m.shutdownDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) retireBackendOwners(owners map[gnet.EventLoop]struct{}) {
	m.retireBudgetOwners(owners)
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		if _, stopped := owners[session.owner]; stopped {
			sessions = append(sessions, session)
		}
	}
	m.mu.Unlock()
	for _, session := range sessions {
		session.retireBackendOwner()
	}
}

func (m *Manager) acquireStream() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.streams >= m.limits.MaxStreams || m.dials >= m.limits.MaxBackendDialsInFlight {
		return false
	}
	m.streams++
	m.dials++
	return true
}

func (m *Manager) backendDialFinished() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dials <= 0 {
		panic("invalid WEB backend dial accounting")
	}
	m.dials--
}

func (m *Manager) streamFinished() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.streams <= 0 {
		panic("invalid WEB stream accounting")
	}
	m.streams--
}

func (m *Manager) changePendingBudget(byteDelta, itemDelta int, class pendingClass) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.changePendingBudgetLocked(byteDelta, itemDelta, class)
}

func (m *Manager) pendingBudgetLimits(class pendingClass) (int, int) {
	byteLimit := m.limits.MaxPendingGlobal
	itemLimit := m.limits.MaxPendingItemsGlobal
	if class != pendingControl {
		reserveBytes, reserveItems, _ := pendingControlReserve(m.limits)
		reserveBytes, _ = checkedMulInt(reserveBytes, m.limits.MaxSessions)
		reserveItems, _ = checkedMulInt(reserveItems, m.limits.MaxSessions)
		byteLimit -= reserveBytes
		itemLimit -= reserveItems
	}
	if m.backendFactory != nil && class != pendingControl && class != pendingHandoff {
		reserveBytes, reserveItems := backendHandoffReserve(m.limits)
		if class == pendingBackendInput {
			reserveBytes /= 2
			reserveItems /= 2
		}
		byteLimit -= reserveBytes * m.limits.MaxSessions
		itemLimit -= reserveItems * m.limits.MaxSessions
	}
	return byteLimit, itemLimit
}

func (m *Manager) changePendingBudgetLocked(byteDelta, itemDelta int, class pendingClass) bool {
	if byteDelta > 0 || itemDelta > 0 {
		byteLimit, itemLimit := m.pendingBudgetLimits(class)
		if byteDelta < 0 || itemDelta < 0 ||
			int64(byteDelta) > int64(byteLimit)-m.pendingBytes ||
			int64(itemDelta) > int64(itemLimit)-m.pendingItems {
			return false
		}
	}
	m.pendingBytes += int64(byteDelta)
	m.pendingItems += int64(itemDelta)
	if m.pendingBytes < 0 || m.pendingItems < 0 {
		panic("negative WEB global pending budget")
	}
	if byteDelta < 0 || itemDelta < 0 {
		m.signalBudgetWaitersLocked()
	}
	return true
}

func (m *Manager) sessionFinished(key sessionBearer, session *Session, reason sessionCloseReason) {
	m.mu.Lock()
	if m.sessions[key.prefix()] == session {
		delete(m.sessions, key.prefix())
		m.rememberClosedTokenLocked(key, time.Now().Add(m.timeouts.BootstrapLifetime))
		m.closedTokens[key.prefix()].diagnostic = session.diagnostic
	}
	for bootstrapKey, entry := range m.bootstraps {
		if entry.session == session {
			delete(m.bootstraps, bootstrapKey)
		}
	}
	m.mu.Unlock()
	if reason < sessionCloseReasonCount {
		m.sessionsClosed[reason].Add(1)
	}
}

func (m *Manager) rememberClosedTokenLocked(key sessionBearer, expires time.Time) {
	if existing := m.closedTokens[key.prefix()]; existing != nil {
		existing.expires = expires
		m.closedOrder.MoveToBack(existing.order)
		return
	}
	if len(m.closedTokens) >= m.limits.MaxClosedTokens {
		oldest := m.closedOrder.Front()
		delete(m.closedTokens, oldest.Value.(uint64))
		m.closedOrder.Remove(oldest)
	}
	entry := &closedToken{token: key, expires: expires}
	entry.order = m.closedOrder.PushBack(key.prefix())
	m.closedTokens[key.prefix()] = entry
}

func (m *Manager) tokenPrefixUsedLocked(key sessionBearer) bool {
	if _, exists := m.bootstraps[key.prefix()]; exists {
		return true
	}
	if _, exists := m.sessions[key.prefix()]; exists {
		return true
	}
	_, exists := m.closedTokens[key.prefix()]
	return exists
}

func (m *Manager) evictOldestUnusedBootstrapLocked() bool {
	var oldestKey uint64
	var oldest *bootstrap
	for key, entry := range m.bootstraps {
		if entry.used || (oldest != nil && !entry.expires.Before(oldest.expires)) {
			continue
		}
		oldestKey = key
		oldest = entry
	}
	if oldest == nil {
		return false
	}
	delete(m.bootstraps, oldestKey)
	return true
}

func (m *Manager) cleanupLoop() {
	interval := min(30*time.Second, m.timeouts.ReconnectGrace/2, m.timeouts.BootstrapLifetime/2)
	if interval <= 0 {
		interval = min(m.timeouts.ReconnectGrace, m.timeouts.BootstrapLifetime)
	}
	ticker := time.NewTicker(interval)
	defer func() {
		ticker.Stop()
		close(m.cleanupDone)
	}()
	for {
		select {
		case now := <-ticker.C:
			m.mu.Lock()
			m.removeExpiredLocked(now)
			sessions := make([]*Session, 0, len(m.sessions))
			for _, session := range m.sessions {
				sessions = append(sessions, session)
			}
			m.mu.Unlock()
			for _, session := range sessions {
				if now.Sub(session.LastActivity()) >= m.timeouts.ReconnectGrace {
					session.closeWithReason(sessionCloseExpired)
				}
			}
		case <-m.stop:
			return
		case <-m.budgetWake:
			m.wakeBudgetWaiter()
		}
	}
}

func (m *Manager) removeExpiredLocked(now time.Time) {
	for key, entry := range m.bootstraps {
		if !now.Before(entry.expires) {
			delete(m.bootstraps, key)
		}
	}
	for key, entry := range m.closedTokens {
		if !now.Before(entry.expires) {
			delete(m.closedTokens, key)
			m.closedOrder.Remove(entry.order)
		}
	}
}

func welcomeFrame() []byte {
	encoded, err := EncodeFrame(Frame{Type: FrameWelcome})
	if err != nil {
		panic(err)
	}
	return encoded
}

// sessionBearer retains the full random bearer. The prefix only selects a map
// entry; authentication always compares all 32 bytes in constant time.
type sessionBearer [32]byte

func (t sessionBearer) prefix() uint64 { return binary.LittleEndian.Uint64(t[:8]) }

func (t sessionBearer) equal(other sessionBearer) bool {
	return subtle.ConstantTimeCompare(t[:], other[:]) == 1
}

func newToken() (string, sessionBearer, error) {
	var raw sessionBearer
	if _, err := rand.Read(raw[:]); err != nil {
		return "", sessionBearer{}, fmt.Errorf("generate WEB bearer: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), raw, nil
}

func parseToken(token string) (sessionBearer, error) {
	var raw sessionBearer
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != len(raw) || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return raw, ErrAuthentication
	}
	copy(raw[:], decoded)
	return raw, nil
}
