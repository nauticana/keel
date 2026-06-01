package handler

import (
	"errors"
	"testing"
	"time"
)

func TestAdminSessionCreateValid(t *testing.T) {
	s := NewAdminSessionStore(time.Hour, 100)
	tok, err := s.Create()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 {
		t.Fatalf("token len = %d, want 64", len(tok))
	}
	if !s.Valid(tok) {
		t.Fatal("freshly issued token should be valid")
	}
}

func TestAdminSessionDelete(t *testing.T) {
	s := NewAdminSessionStore(time.Hour, 100)
	tok, _ := s.Create()
	s.Delete(tok)
	if s.Valid(tok) {
		t.Fatal("deleted token should be invalid")
	}
	s.Delete(tok) // idempotent
}

func TestAdminSessionExpiry(t *testing.T) {
	s := NewAdminSessionStore(10*time.Millisecond, 100)
	tok, _ := s.Create()
	time.Sleep(25 * time.Millisecond)
	if s.Valid(tok) {
		t.Fatal("expired token should be invalid")
	}
}

func TestAdminSessionUniqueness(t *testing.T) {
	s := NewAdminSessionStore(time.Hour, 1000)
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		tok, _ := s.Create()
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token on iteration %d", i)
		}
		seen[tok] = struct{}{}
	}
}

func TestAdminSessionFull(t *testing.T) {
	s := NewAdminSessionStore(time.Hour, 1)
	if _, err := s.Create(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(); !errors.Is(err, ErrAdminSessionStoreFull) {
		t.Fatalf("expected ErrAdminSessionStoreFull, got %v", err)
	}
}

func TestAdminSessionEmptyToken(t *testing.T) {
	if NewAdminSessionStore(time.Hour, 0).Valid("") {
		t.Fatal("empty token must not be valid")
	}
}
