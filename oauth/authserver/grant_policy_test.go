package authserver

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nauticana/keel/port"
)

func newPolicyAS(t *testing.T, replace bool, max int) (*Local, *memTokens) {
	t.Helper()
	signer, err := NewEphemeralRS256Signer()
	if err != nil {
		t.Fatal(err)
	}
	tokens := &memTokens{m: map[string]*port.RefreshToken{}}
	as := NewLocal(signer, &memClients{m: map[string]*port.OAuthClient{}}, &memCodes{m: map[string]*port.AuthCode{}}, tokens, Config{
		Issuer: "https://as.example", DefaultAudience: "https://rs.example", Scopes: []string{"read"},
		AccessTTL: time.Hour, RefreshTTL: time.Hour, CodeTTL: time.Minute,
		ReplaceSameAppGrant: replace, MaxGrantsPerUser: max,
	})
	return as, tokens
}

const policyVerifier = "v-1234567890-1234567890-1234567890-abcd"

func register(t *testing.T, as *Local, redirect string) *port.OAuthClient {
	t.Helper()
	c, err := as.Register(context.Background(), port.ClientRegistration{RedirectURIs: []string{redirect}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func authorizeCode(as *Local, c *port.OAuthClient) (string, error) {
	res, err := as.Authorize(context.Background(), port.AuthorizeRequest{
		ClientID: c.ClientID, RedirectURI: c.RedirectURIs[0], CodeChallenge: pkce(policyVerifier), CodeChallengeMethod: "S256",
		User: &port.UserRef{UserID: 7}, ConsentGranted: true,
	})
	if err != nil {
		return "", err
	}
	return res.Code, nil
}

func connect(t *testing.T, as *Local, c *port.OAuthClient) {
	t.Helper()
	code, err := authorizeCode(as, c)
	if err != nil {
		t.Fatalf("authorize %s: %v", c.RedirectURIs[0], err)
	}
	if _, err := as.Token(context.Background(), port.TokenRequest{GrantType: "authorization_code", Code: code,
		RedirectURI: c.RedirectURIs[0], CodeVerifier: policyVerifier, Client: port.ClientAuth{ClientID: c.ClientID}}); err != nil {
		t.Fatalf("token %s: %v", c.RedirectURIs[0], err)
	}
}

func liveClients(t *testing.T, tokens *memTokens) []string {
	t.Helper()
	ids, err := tokens.GrantClients(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestNewGrantReplacesSameApp(t *testing.T) {
	as, tokens := newPolicyAS(t, true, 0)
	old := register(t, as, "https://assistant.example/cb")
	other := register(t, as, "https://other.example/cb")
	native := register(t, as, "http://127.0.0.1:3000/cb")
	connect(t, as, old)
	connect(t, as, other)
	connect(t, as, native)

	reconnect := register(t, as, "https://Assistant.example/oauth/cb")
	if _, err := authorizeCode(as, reconnect); err != nil {
		t.Fatal(err)
	}
	if got := liveClients(t, tokens); !slices.Contains(got, old.ClientID) {
		t.Fatal("an unredeemed authorization must not end the old grant")
	}
	connect(t, as, reconnect)
	got := liveClients(t, tokens)
	if slices.Contains(got, old.ClientID) || !slices.Contains(got, reconnect.ClientID) || !slices.Contains(got, other.ClientID) {
		t.Fatalf("live grants = %v", got)
	}

	// Loopback redirects are shared by every native app, so they replace nothing.
	connect(t, as, register(t, as, "http://127.0.0.1:4000/cb"))
	if !slices.Contains(liveClients(t, tokens), native.ClientID) {
		t.Fatal("a loopback client replaced another")
	}
}

func TestReplacementOff(t *testing.T) {
	as, tokens := newPolicyAS(t, false, 0)
	first := register(t, as, "https://assistant.example/cb")
	connect(t, as, first)
	connect(t, as, register(t, as, "https://assistant.example/cb"))
	if len(liveClients(t, tokens)) != 2 {
		t.Fatalf("live grants = %v", liveClients(t, tokens))
	}
}

func TestGrantCapRefusesNewApp(t *testing.T) {
	as, tokens := newPolicyAS(t, true, 2)
	connect(t, as, register(t, as, "https://a.example/cb"))
	connect(t, as, register(t, as, "https://b.example/cb"))

	_, err := authorizeCode(as, register(t, as, "https://c.example/cb"))
	if !errors.Is(err, ErrOAuthAccessDenied) || ProtocolErrorDescription(err) == "" {
		t.Fatalf("over the cap = %v", err)
	}
	// A reconnect of a held app replaces rather than adds, so it is admitted.
	connect(t, as, register(t, as, "https://a.example/cb"))
	if len(liveClients(t, tokens)) != 2 {
		t.Fatalf("live grants = %v", liveClients(t, tokens))
	}
}

func TestGrantCapCountsSameAppWithoutReplacement(t *testing.T) {
	as, _ := newPolicyAS(t, false, 1)
	connect(t, as, register(t, as, "https://a.example/cb"))
	if _, err := authorizeCode(as, register(t, as, "https://a.example/cb")); !errors.Is(err, ErrOAuthAccessDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestGrantCapIsRecheckedWhenCodeIsRedeemed(t *testing.T) {
	as, tokens := newPolicyAS(t, true, 1)
	first := register(t, as, "https://a.example/cb")
	code, err := authorizeCode(as, first)
	if err != nil {
		t.Fatal(err)
	}
	connect(t, as, register(t, as, "https://b.example/cb"))
	_, err = as.Token(context.Background(), port.TokenRequest{GrantType: "authorization_code", Code: code,
		RedirectURI: first.RedirectURIs[0], CodeVerifier: policyVerifier, Client: port.ClientAuth{ClientID: first.ClientID}})
	if !errors.Is(err, ErrOAuthInvalidGrant) || ProtocolErrorDescription(err) == "" || len(liveClients(t, tokens)) != 1 {
		t.Fatalf("redeem after cap = %v, grants %v", err, liveClients(t, tokens))
	}
}

type failingGrants struct{ memTokens }

func (*failingGrants) GrantClients(context.Context, int64) ([]string, error) {
	return nil, errors.New("db down")
}

func TestGrantPolicyFailsClosed(t *testing.T) {
	p := &grantPolicy{clients: &memClients{m: map[string]*port.OAuthClient{}}, tokens: &failingGrants{}, replaceSameApp: true, maxPerUser: 1}
	c := &port.OAuthClient{ClientID: "c", GrantTypes: registrationGrants, RedirectURIs: []string{"https://a.example/cb"}}
	if err := p.admit(context.Background(), 7, c); err == nil {
		t.Fatal("admit ignored a store failure")
	}
	if err := p.redeem(context.Background(), 7, c); err == nil {
		t.Fatal("redeem ignored a store failure")
	}
	off := &grantPolicy{clients: p.clients, tokens: p.tokens}
	if err := off.admit(context.Background(), 7, c); err != nil {
		t.Fatalf("disabled policy touched the store: %v", err)
	}
	if err := off.redeem(context.Background(), 7, c); err != nil {
		t.Fatalf("disabled policy touched the store: %v", err)
	}
}

func TestAppHosts(t *testing.T) {
	c := &port.OAuthClient{RedirectURIs: []string{"https://App.example/cb", "https://app.example/other", "http://localhost:8080/cb", "http://[::1]/cb", "::bad"}}
	if got := appHosts(c); !slices.Equal(got, []string{"app.example"}) {
		t.Fatalf("hosts = %v", got)
	}
}
