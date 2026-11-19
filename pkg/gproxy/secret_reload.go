package gproxy

import (
	"bytes"
	"slices"
)

// secretSet is one immutable published list of enabled secrets. Handshakes
// on the event loops read it through an atomic pointer without locks.
type secretSet struct {
	list []Secret
}

// secretSession links an authenticated client to its context, so a secret
// reload can close the sessions of a removed or disabled secret.
type secretSession struct {
	conn clientEndpoint
	ctx  *ConnContext
}

// sameSecret compares the fields that authenticate a client and label it.
// A renamed or rekeyed secret counts as a different secret.
func sameSecret(a, b *Secret) bool {
	return a.Name == b.Name && a.Host == b.Host && bytes.Equal(a.Key, b.Key)
}

func (s *secretSet) contains(secret *Secret) bool {
	if s == nil {
		return false
	}
	for i := range s.list {
		if sameSecret(&s.list[i], secret) {
			return true
		}
	}
	return false
}

// currentSecrets returns the published secret list. Callers must not modify it.
func (h *ProxyHandler) currentSecrets() []Secret {
	if set := h.secrets.Load(); set != nil {
		return set.list
	}
	return nil
}

// trackSecretSession records an authenticated client after ctx.secret is set.
// It returns false when a reload removed the secret after the match. The
// record precedes the check: either the reload's sweep sees the record, or
// this check sees the new list.
func (h *ProxyHandler) trackSecretSession(c clientEndpoint, ctx *ConnContext, secret *Secret) bool {
	h.secretSessions.Store(ctx.id, &secretSession{conn: c, ctx: ctx})
	return h.secrets.Load().contains(secret)
}

// ReplaceSecrets publishes a new enabled secret list. Sessions of unchanged
// secrets continue. Sessions of a secret that is not in the new list are
// closed. It returns the number of sessions it closed. The hot reloader
// serializes calls.
func (h *ProxyHandler) ReplaceSecrets(secrets []Secret) int {
	next := &secretSet{list: slices.Clone(secrets)}
	h.secrets.Store(next)
	closed := 0
	h.secretSessions.Range(func(key, value any) bool {
		session := value.(*secretSession)
		session.ctx.mu.Lock()
		secret := session.ctx.secret
		session.ctx.mu.Unlock()
		if secret == nil || next.contains(secret) {
			return true
		}
		h.secretSessions.Delete(key)
		session.ctx.noteClose(closeReasonSecretRevoked)
		// Close is safe on any goroutine: gnet and logical streams queue it
		// on the owner loop.
		_ = session.conn.Close()
		closed++
		return true
	})
	return closed
}
