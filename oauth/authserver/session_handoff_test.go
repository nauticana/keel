package authserver

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nauticana/keel/port"
)

type memHandoffRow struct {
	code           port.SessionHandoffCode
	expires        time.Time
	consumed       bool
	sessionHash    string
	sessionExpires time.Time
}

// memHandoffs mirrors SessionHandoffStoreDB's SQL predicates with a fake clock.
type memHandoffs struct {
	mu   sync.Mutex
	now  time.Time
	rows map[string]*memHandoffRow
}

func newMemHandoffs() *memHandoffs {
	return &memHandoffs{now: time.Unix(1_700_000_000, 0), rows: map[string]*memHandoffRow{}}
}

func (m *memHandoffs) advance(d time.Duration) { m.mu.Lock(); m.now = m.now.Add(d); m.mu.Unlock() }

func (m *memHandoffs) SaveHandoff(_ context.Context, h *port.SessionHandoffCode, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[h.CodeHash] = &memHandoffRow{code: *h, expires: m.now.Add(ttl)}
	return nil
}

func (m *memHandoffs) RedeemHandoff(_ context.Context, codeHash, returnURL, sessionHash string, ttl time.Duration) (*port.UserRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.rows[codeHash]
	if r == nil || r.consumed || !r.expires.After(m.now) || r.code.ReturnURL != returnURL {
		return nil, nil
	}
	r.consumed, r.sessionHash, r.sessionExpires = true, sessionHash, m.now.Add(ttl)
	return &port.UserRef{UserID: r.code.UserID, PartnerID: r.code.PartnerID}, nil
}

func (m *memHandoffs) ResolveHandoffSession(_ context.Context, sessionHash string) (*port.UserRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.sessionHash != "" && r.sessionHash == sessionHash && r.sessionExpires.After(m.now) {
			return &port.UserRef{UserID: r.code.UserID, PartnerID: r.code.PartnerID}, nil
		}
	}
	return nil, nil
}

var _ port.SessionHandoffStore = (*memHandoffs)(nil)

const testAuthorize = "https://as.example.com/oauth/authorize"

func newTestHandoff(t *testing.T) (*SessionHandoff, *memHandoffs) {
	t.Helper()
	store := newMemHandoffs()
	hs, err := NewSessionHandoff(store, testAuthorize)
	if err != nil {
		t.Fatal(err)
	}
	return hs, store
}

var alice = port.UserRef{UserID: 7, PartnerID: 3}

func TestNewSessionHandoffRejectsBadEndpoint(t *testing.T) {
	for _, ep := range []string{"", "/oauth/authorize", "https://as.example.com/other", "ftp://as.example.com/oauth/authorize",
		"https://u@as.example.com/oauth/authorize", "https://as.example.com/oauth/authorize?x=1"} {
		if _, err := NewSessionHandoff(newMemHandoffs(), ep); err == nil {
			t.Errorf("endpoint %q accepted", ep)
		}
	}
	if _, err := NewSessionHandoff(nil, testAuthorize); err == nil {
		t.Error("nil store accepted")
	}
	var zero SessionHandoff
	if _, err := zero.Mint(context.Background(), alice, testAuthorize); err == nil {
		t.Error("zero value minted")
	}
	if _, err := zero.Redeem(context.Background(), strings.Repeat("a", 64), testAuthorize); err == nil {
		t.Error("zero value redeemed")
	}
	if u, err := zero.Resolve(context.Background(), strings.Repeat("a", 64)); u != nil || err == nil {
		t.Error("zero value resolved")
	}
}

func TestHandoffMintRedeemResolve(t *testing.T) {
	hs, store := newTestHandoff(t)
	ctx := context.Background()
	ret := "/oauth/authorize?client_id=c&state=s"
	g, err := hs.Mint(ctx, alice, ret)
	if err != nil {
		t.Fatal(err)
	}
	if g.ReturnURL != testAuthorize+"?client_id=c&state=s" {
		t.Fatalf("canonical return = %q", g.ReturnURL)
	}
	for h := range store.rows {
		if h == g.Code || strings.Contains(h, g.Code) {
			t.Fatal("plaintext code persisted")
		}
	}
	redeem, _ := url.Parse(g.RedeemURL)
	if redeem.Host != "as.example.com" || redeem.Path != OAuthSessionPath ||
		redeem.Query().Get("code") != g.Code || redeem.Query().Get("return") != g.ReturnURL {
		t.Fatalf("redeem URL = %q", g.RedeemURL)
	}
	sess, err := hs.Redeem(ctx, g.Code, g.ReturnURL)
	if err != nil {
		t.Fatal(err)
	}
	if sess.ReturnURL != g.ReturnURL || sess.User.UserID != 7 || sess.User.PartnerID != 3 || sess.TTL != HandoffSessionTTL {
		t.Fatalf("session = %+v", sess)
	}
	u, err := hs.Resolve(ctx, sess.Token)
	if err != nil || u == nil || u.UserID != 7 || u.Subject != "user:7" {
		t.Fatalf("resolve = %+v, %v", u, err)
	}
	if _, err := hs.Redeem(ctx, g.Code, g.ReturnURL); !errors.Is(err, ErrHandoffCode) {
		t.Fatalf("replay err = %v, want ErrHandoffCode", err)
	}
	store.advance(HandoffSessionTTL)
	if u, _ := hs.Resolve(ctx, sess.Token); u != nil {
		t.Fatal("expired session resolved")
	}
}

func TestHandoffExpiredCodeRejected(t *testing.T) {
	hs, store := newTestHandoff(t)
	g, err := hs.Mint(context.Background(), alice, testAuthorize)
	if err != nil {
		t.Fatal(err)
	}
	store.advance(HandoffCodeTTL)
	if _, err := hs.Redeem(context.Background(), g.Code, g.ReturnURL); !errors.Is(err, ErrHandoffCode) {
		t.Fatalf("err = %v, want ErrHandoffCode", err)
	}
}

func TestHandoffRedeemReturnMismatch(t *testing.T) {
	hs, _ := newTestHandoff(t)
	ctx := context.Background()
	g, err := hs.Mint(ctx, alice, testAuthorize+"?state=a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hs.Redeem(ctx, g.Code, testAuthorize+"?state=b"); !errors.Is(err, ErrHandoffCode) {
		t.Fatalf("other authorize query: err = %v", err)
	}
	if _, err := hs.Redeem(ctx, g.Code, "https://evil.example/oauth/authorize?state=a"); !errors.Is(err, ErrHandoffReturn) {
		t.Fatalf("foreign host: err = %v", err)
	}
	if _, err := hs.Redeem(ctx, g.Code, g.ReturnURL); err != nil {
		t.Fatalf("matching return after rejected attempts: %v", err)
	}
}

func TestHandoffReturnConfinement(t *testing.T) {
	hs, _ := newTestHandoff(t)
	bad := []string{
		"",
		"https://evil.example/oauth/authorize",
		"http://as.example.com/oauth/authorize",
		"https://as.example.com:8443/oauth/authorize",
		"https://as.example.com/oauth/token",
		"https://as.example.com/oauth/authorize/",
		"https://as.example.com/oauth/authorize/../token",
		"https://as.example.com/OAUTH/authorize",
		"https://user:pw@as.example.com/oauth/authorize",
		"https://as.example.com@evil.example/oauth/authorize",
		"https://as.example.com/oauth/authorize#frag",
		"//evil.example/oauth/authorize",
		"///evil.example/oauth/authorize",
		"/\\evil.example/oauth/authorize",
		"oauth/authorize",
		"https:as.example.com/oauth/authorize",
		"javascript:alert(1)",
		"/oauth/authorize\r\nSet-Cookie: x=y",
		"/oauth/authorize?" + strings.Repeat("a", maxHandoffReturnLen),
	}
	for _, ret := range bad {
		if _, err := hs.Mint(context.Background(), alice, ret); !errors.Is(err, ErrHandoffReturn) {
			t.Errorf("mint return %q: err = %v, want ErrHandoffReturn", ret, err)
		}
		if _, err := hs.Redeem(context.Background(), strings.Repeat("a", 64), ret); !errors.Is(err, ErrHandoffReturn) {
			t.Errorf("redeem return %q: err = %v, want ErrHandoffReturn", ret, err)
		}
	}
	for _, ret := range []string{testAuthorize, "HTTPS://AS.EXAMPLE.COM/oauth/authorize?x=1", "/oauth/authorize"} {
		if _, err := hs.Mint(context.Background(), alice, ret); err != nil {
			t.Errorf("mint return %q rejected: %v", ret, err)
		}
	}
}

func TestHandoffRejectsAnonymousAndMalformed(t *testing.T) {
	hs, _ := newTestHandoff(t)
	ctx := context.Background()
	if _, err := hs.Mint(ctx, port.UserRef{}, testAuthorize); !errors.Is(err, ErrHandoffUser) {
		t.Fatalf("zero user: err = %v", err)
	}
	for _, code := range []string{"", "x", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if _, err := hs.Redeem(ctx, code, testAuthorize); !errors.Is(err, ErrHandoffCode) {
			t.Errorf("code %q: err = %v", code, err)
		}
		if u, err := hs.Resolve(ctx, code); u != nil || err != nil {
			t.Errorf("resolve %q = %+v, %v", code, u, err)
		}
	}
}
