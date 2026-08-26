package webproxy

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
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
	hash    [sha256.Size]byte
}

func (*BootstrapAuthorization) String() string { return "WEB bootstrap authorization" }

func (*BootstrapAuthorization) GoString() string { return "WEB bootstrap authorization" }

type bootstrap struct {
	expires      time.Time
	profile      Profile
	issuanceIP   string
	bodyDigest   [sha256.Size]byte
	sessionToken string
	session      *Session
	used         bool
}

type closedToken struct {
	expires time.Time
	order   *list.Element
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
	profiles    []Profile
	carrier     CarrierMode
	backendNet  string
	backend     string
	limits      Limits
	timeouts    Timeouts
	dialBackend BackendDialContextFunc

	mu           sync.Mutex
	bootstraps   map[[sha256.Size]byte]*bootstrap
	sessions     map[[sha256.Size]byte]*Session
	closedTokens map[[sha256.Size]byte]*closedToken
	closedOrder  list.List
	streams      int
	dials        int
	pendingBytes int64
	pendingItems int64
	closed       bool
	stop         chan struct{}
	cleanupDone  chan struct{}
	shutdownDone chan struct{}
	shutdownOnce sync.Once

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
		profiles:     append([]Profile(nil), config.Profiles...),
		carrier:      config.Carrier,
		backendNet:   backendNetwork,
		backend:      backendAddress,
		limits:       config.Limits,
		timeouts:     config.Timeouts,
		dialBackend:  dialBackend,
		bootstraps:   make(map[[sha256.Size]byte]*bootstrap),
		sessions:     make(map[[sha256.Size]byte]*Session),
		closedTokens: make(map[[sha256.Size]byte]*closedToken),
		stop:         make(chan struct{}),
		cleanupDone:  make(chan struct{}),
		shutdownDone: make(chan struct{}),
	}
	go manager.cleanupLoop()
	return manager, nil
}

// MatchCapability scans the complete profile set and never returns manager-owned
// profile storage.
func (m *Manager) MatchCapability(capability Capability) (Profile, bool) {
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
	token, hash, err := newToken()
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
	for m.tokenHashUsedLocked(hash) {
		token, hash, err = newToken()
		if err != nil {
			return "", err
		}
	}
	m.bootstraps[hash] = &bootstrap{
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
	tokenDigest, err := parseTokenHash(token)
	if err != nil {
		return nil, ErrAuthentication
	}
	if !m.bootstrapAuthenticated(tokenDigest, time.Now()) {
		return nil, ErrAuthentication
	}
	return &BootstrapAuthorization{state: &bootstrapAuthorization{manager: m, hash: tokenDigest}}, nil
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
	if a == nil || a.state == nil || a.state.manager == nil {
		return CreateResult{}, ErrAuthentication
	}
	if !a.state.manager.bootstrapAuthenticated(a.state.hash, time.Now()) {
		return CreateResult{}, ErrAuthentication
	}
	if err := ParseHello(body); err != nil {
		return CreateResult{}, ErrProtocol
	}
	bodyDigest := sha256.Sum256(body)
	now := time.Now()
	m := a.state.manager

	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.bootstraps[a.state.hash]
	if entry == nil || !now.Before(entry.expires) {
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
	if len(m.sessions) >= m.limits.MaxSessions {
		m.recordBackpressure(carrierOperationCreate)
		return CreateResult{}, ErrLimit
	}

	sessionToken, sessionHash, err := newToken()
	if err != nil {
		return CreateResult{}, err
	}
	for m.tokenHashUsedLocked(sessionHash) {
		sessionToken, sessionHash, err = newToken()
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
		budget:                m.changePendingBudget,
		onCarrierRetry:        m.recordCarrierRetry,
		onBackpressure:        m.recordBackpressure,
		acquireStream:         m.acquireStream,
		onBackendDialFinished: m.backendDialFinished,
		onStreamFinished:      m.streamFinished,
	})
	created.onFinished = func(session *Session, reason sessionCloseReason) {
		m.sessionFinished(sessionHash, session, reason)
	}
	m.sessions[sessionHash] = created
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

func (m *Manager) bootstrapAuthenticated(hash [sha256.Size]byte, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.bootstraps[hash]
	if entry == nil {
		return false
	}
	if !now.Before(entry.expires) {
		delete(m.bootstraps, hash)
		return false
	}
	return true
}

// Get authenticates a canonical session bearer.
func (m *Manager) Get(token string) (*Session, error) {
	hash, err := parseTokenHash(token)
	if err != nil {
		return nil, ErrAuthentication
	}
	m.mu.Lock()
	session := m.sessions[hash]
	m.mu.Unlock()
	if session == nil {
		return nil, ErrAuthentication
	}
	return session, nil
}

// Close terminates the authenticated session. A recently closed valid token is
// idempotent; an unknown token remains indistinguishable from bad authentication.
func (m *Manager) Close(token string) error {
	hash, err := parseTokenHash(token)
	if err != nil {
		return ErrAuthentication
	}
	m.mu.Lock()
	session := m.sessions[hash]
	_, recentlyClosed := m.closedTokens[hash]
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
	if byteDelta > 0 || itemDelta > 0 {
		byteLimit := m.limits.MaxPendingGlobal
		itemLimit := m.limits.MaxPendingItemsGlobal
		if class != pendingControl {
			reserveBytes, reserveItems, _ := pendingControlReserve(m.limits)
			reserveBytes, _ = checkedMulInt(reserveBytes, m.limits.MaxSessions)
			reserveItems, _ = checkedMulInt(reserveItems, m.limits.MaxSessions)
			byteLimit -= reserveBytes
			itemLimit -= reserveItems
		}
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
	return true
}

func (m *Manager) sessionFinished(hash [sha256.Size]byte, session *Session, reason sessionCloseReason) {
	m.mu.Lock()
	if m.sessions[hash] == session {
		delete(m.sessions, hash)
		m.rememberClosedTokenLocked(hash, time.Now().Add(m.timeouts.BootstrapLifetime))
	}
	for bootstrapHash, entry := range m.bootstraps {
		if entry.session == session {
			delete(m.bootstraps, bootstrapHash)
		}
	}
	m.mu.Unlock()
	if reason < sessionCloseReasonCount {
		m.sessionsClosed[reason].Add(1)
	}
}

func (m *Manager) rememberClosedTokenLocked(hash [sha256.Size]byte, expires time.Time) {
	if existing := m.closedTokens[hash]; existing != nil {
		existing.expires = expires
		m.closedOrder.MoveToBack(existing.order)
		return
	}
	if len(m.closedTokens) >= m.limits.MaxClosedTokens {
		oldest := m.closedOrder.Front()
		delete(m.closedTokens, oldest.Value.([sha256.Size]byte))
		m.closedOrder.Remove(oldest)
	}
	entry := &closedToken{expires: expires}
	entry.order = m.closedOrder.PushBack(hash)
	m.closedTokens[hash] = entry
}

func (m *Manager) tokenHashUsedLocked(hash [sha256.Size]byte) bool {
	if _, exists := m.bootstraps[hash]; exists {
		return true
	}
	if _, exists := m.sessions[hash]; exists {
		return true
	}
	_, exists := m.closedTokens[hash]
	return exists
}

func (m *Manager) evictOldestUnusedBootstrapLocked() bool {
	var oldestHash [sha256.Size]byte
	var oldest *bootstrap
	for hash, entry := range m.bootstraps {
		if entry.used || (oldest != nil && !entry.expires.Before(oldest.expires)) {
			continue
		}
		oldestHash = hash
		oldest = entry
	}
	if oldest == nil {
		return false
	}
	delete(m.bootstraps, oldestHash)
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
		}
	}
}

func (m *Manager) removeExpiredLocked(now time.Time) {
	for hash, entry := range m.bootstraps {
		if !now.Before(entry.expires) {
			delete(m.bootstraps, hash)
		}
	}
	for hash, entry := range m.closedTokens {
		if !now.Before(entry.expires) {
			delete(m.closedTokens, hash)
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

func newToken() (string, [sha256.Size]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [sha256.Size]byte{}, fmt.Errorf("generate WEB bearer: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), sha256.Sum256(raw[:]), nil
}

func parseTokenHash(token string) ([sha256.Size]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return [sha256.Size]byte{}, ErrAuthentication
	}
	return sha256.Sum256(raw), nil
}
