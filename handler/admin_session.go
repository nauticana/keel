package handler

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ErrAdminSessionStoreFull is returned by Create when MaxRows is reached.
var ErrAdminSessionStoreFull = errors.New("admin session store full")

// AdminSessionStore is an in-memory token→expiry map for an admin/console
// area: opaque 32-byte hex token, lazy expiry sweep, configurable cap.
// Replaces the "cookie == static_admin_secret" pattern with revocable
// server-side state. Cookies are the caller's concern — keep this thin
// so it composes with any handler stack.
type AdminSessionStore struct {
	TTL     time.Duration
	MaxRows int

	mu    sync.Mutex
	items map[string]time.Time
}

// NewAdminSessionStore returns a ready-to-use store. ttl=0 disables expiry;
// maxRows=0 disables the cap.
func NewAdminSessionStore(ttl time.Duration, maxRows int) *AdminSessionStore {
	return &AdminSessionStore{TTL: ttl, MaxRows: maxRows, items: make(map[string]time.Time)}
}

// Create returns a new 64-char hex token bound to TTL from now.
func (s *AdminSessionStore) Create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	if s.MaxRows > 0 && len(s.items) >= s.MaxRows {
		return "", ErrAdminSessionStoreFull
	}
	if s.TTL > 0 {
		s.items[tok] = time.Now().Add(s.TTL)
	} else {
		s.items[tok] = time.Time{}
	}
	return tok, nil
}

// Valid reports whether tok exists and has not expired.
func (s *AdminSessionStore) Valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.items[tok]
	if !ok {
		return false
	}
	if !exp.IsZero() && time.Now().After(exp) {
		delete(s.items, tok)
		return false
	}
	return true
}

// Delete revokes tok (idempotent).
func (s *AdminSessionStore) Delete(tok string) {
	s.mu.Lock()
	delete(s.items, tok)
	s.mu.Unlock()
}

func (s *AdminSessionStore) sweepLocked() {
	now := time.Now()
	for k, exp := range s.items {
		if !exp.IsZero() && now.After(exp) {
			delete(s.items, k)
		}
	}
}
