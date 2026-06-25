package authserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"testing"
	"time"

	"github.com/nauticana/keel/port"
)

// --- in-memory stores (test doubles for the DB-backed ones) ---

type memClients struct{ m map[string]*port.OAuthClient }

func (s *memClients) CreateClient(_ context.Context, c *port.OAuthClient) error {
	s.m[c.ClientID] = c
	return nil
}
func (s *memClients) GetClient(_ context.Context, id string) (*port.OAuthClient, error) {
	return s.m[id], nil
}
func (s *memClients) UpdateClient(_ context.Context, c *port.OAuthClient) error {
	s.m[c.ClientID] = c
	return nil
}
func (s *memClients) DeleteClient(_ context.Context, id string) error { delete(s.m, id); return nil }

type memCodes struct{ m map[string]*port.AuthCode }

func (s *memCodes) SaveCode(_ context.Context, c *port.AuthCode, ttl time.Duration) error {
	cp := *c
	cp.ExpiresAt = time.Now().Add(ttl)
	s.m[c.Code] = &cp
	return nil
}
func (s *memCodes) ConsumeCode(_ context.Context, code string) (*port.AuthCode, error) {
	c, ok := s.m[code]
	if !ok {
		return nil, nil // single-use: already consumed
	}
	delete(s.m, code)
	if time.Now().After(c.ExpiresAt) {
		return nil, nil
	}
	return c, nil
}

type memTokens struct{ m map[string]*port.RefreshToken }

func (s *memTokens) SaveRefreshToken(_ context.Context, t *port.RefreshToken) error {
	cp := *t
	s.m[t.TokenHash] = &cp
	return nil
}
func (s *memTokens) GetRefreshToken(_ context.Context, h string) (*port.RefreshToken, error) {
	return s.m[h], nil
}
func (s *memTokens) RevokeRefreshToken(_ context.Context, h string) error {
	if t := s.m[h]; t != nil {
		now := time.Now()
		t.RevokedAt = &now
	}
	return nil
}
func (s *memTokens) RevokeFamily(_ context.Context, fam string) error {
	now := time.Now()
	for _, t := range s.m {
		if t.FamilyID == fam {
			t.RevokedAt = &now
		}
	}
	return nil
}
func (s *memTokens) RevokeForUser(_ context.Context, uid int64) error {
	now := time.Now()
	for _, t := range s.m {
		if t.UserID == uid {
			t.RevokedAt = &now
		}
	}
	return nil
}
func (s *memTokens) Rotate(_ context.Context, oldHash string, t *port.RefreshToken) error {
	old := s.m[oldHash]
	if old == nil || old.RevokedAt != nil {
		return errRefreshConsumed // already consumed → lost the race
	}
	now := time.Now()
	old.RevokedAt = &now
	cp := *t
	s.m[t.TokenHash] = &cp
	return nil
}

func newTestAS(t *testing.T) (*Local, *RS256Signer) {
	t.Helper()
	signer, err := NewEphemeralRS256Signer()
	if err != nil {
		t.Fatal(err)
	}
	clients := &memClients{m: map[string]*port.OAuthClient{}}
	codes := &memCodes{m: map[string]*port.AuthCode{}}
	tokens := &memTokens{m: map[string]*port.RefreshToken{}}
	cfg := Config{
		Issuer: "https://as.example", DefaultAudience: "https://rs.example",
		Scopes: []string{"read", "write"}, AccessTTL: time.Hour, RefreshTTL: 24 * time.Hour, CodeTTL: time.Minute,
	}
	return NewLocal(signer, clients, codes, tokens, cfg), signer
}

func pkce(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// registers a public client + runs authorize, returns the code.
func authCodeFor(t *testing.T, as *Local, challenge string) (string, *port.OAuthClient) {
	t.Helper()
	client, err := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs: []string{"https://app.example/cb"}, Scopes: []string{"read", "write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := as.Authorize(context.Background(), port.AuthorizeRequest{
		ClientID: client.ClientID, RedirectURI: "https://app.example/cb",
		Scopes: []string{"read"}, CodeChallenge: challenge, CodeChallengeMethod: "S256",
		Resource: "https://rs.example", State: "xyz",
		User: &port.UserRef{UserID: 7, PartnerID: 3}, ConsentGranted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.State != "xyz" {
		t.Fatalf("state = %q", res.State)
	}
	return res.Code, client
}

func TestAuthCodeFlowWithPKCE(t *testing.T) {
	as, _ := newTestAS(t)
	verifier := "v-1234567890-1234567890-1234567890-abcd"
	code, client := authCodeFor(t, as, pkce(verifier))

	resp, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example/cb",
		CodeVerifier: verifier, Client: port.ClientAuth{ClientID: client.ClientID},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" || resp.TokenType != "Bearer" {
		t.Fatalf("resp = %+v", resp)
	}
	// access token validates and carries the granted scope + partner.
	p, err := as.validator.Validate(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("validate access: %v", err)
	}
	if p.Subject != "user:7" || len(p.Scopes) != 1 || p.Scopes[0] != "read" {
		t.Fatalf("principal = %+v", p)
	}
}

func TestAuthCodeSingleUse(t *testing.T) {
	as, _ := newTestAS(t)
	verifier := "v-1234567890-1234567890-1234567890-abcd"
	code, client := authCodeFor(t, as, pkce(verifier))
	req := port.TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example/cb", CodeVerifier: verifier, Client: port.ClientAuth{ClientID: client.ClientID}}
	if _, err := as.Token(context.Background(), req); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := as.Token(context.Background(), req); err != ErrOAuthInvalidGrant {
		t.Fatalf("replay want invalid_grant, got %v", err)
	}
}

func TestAuthCodeWrongPKCE(t *testing.T) {
	as, _ := newTestAS(t)
	code, client := authCodeFor(t, as, pkce("the-real-verifier-aaaaaaaaaaaaaaaaaaaa"))
	_, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example/cb",
		CodeVerifier: "wrong-verifier", Client: port.ClientAuth{ClientID: client.ClientID},
	})
	if err != ErrOAuthInvalidGrant {
		t.Fatalf("want invalid_grant, got %v", err)
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	as, _ := newTestAS(t)
	verifier := "v-1234567890-1234567890-1234567890-abcd"
	code, client := authCodeFor(t, as, pkce(verifier))
	first, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example/cb",
		CodeVerifier: verifier, Client: port.ClientAuth{ClientID: client.ClientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	// rotate
	second, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "refresh_token", RefreshToken: first.RefreshToken, Client: port.ClientAuth{ClientID: client.ClientID},
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token must rotate")
	}
	// replay the old (already-rotated) token → reuse detected, family killed
	if _, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "refresh_token", RefreshToken: first.RefreshToken, Client: port.ClientAuth{ClientID: client.ClientID},
	}); err != ErrOAuthInvalidGrant {
		t.Fatalf("replay want invalid_grant, got %v", err)
	}
	// the rotated (second) token is now also dead — whole family revoked
	if _, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "refresh_token", RefreshToken: second.RefreshToken, Client: port.ClientAuth{ClientID: client.ClientID},
	}); err != ErrOAuthInvalidGrant {
		t.Fatalf("family revoke: want invalid_grant for rotated token, got %v", err)
	}
}

func TestAuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	as, _ := newTestAS(t)
	client, _ := as.Register(context.Background(), port.ClientRegistration{RedirectURIs: []string{"https://app.example/cb"}})
	_, _, err := as.ValidateAuthorizeRequest(context.Background(), port.AuthorizeRequest{
		ClientID: client.ClientID, RedirectURI: "https://evil.example/cb",
		CodeChallenge: "x", CodeChallengeMethod: "S256",
	})
	if err != ErrOAuthInvalidRequest {
		t.Fatalf("want invalid_request for bad redirect, got %v", err)
	}
}

func TestTokenUnsupportedGrant(t *testing.T) {
	as, _ := newTestAS(t)
	client, _ := as.Register(context.Background(), port.ClientRegistration{RedirectURIs: []string{"https://app.example/cb"}})
	_, err := as.Token(context.Background(), port.TokenRequest{GrantType: "password", Client: port.ClientAuth{ClientID: client.ClientID}})
	if err != ErrOAuthUnsupportedGrant {
		t.Fatalf("want unsupported_grant_type, got %v", err)
	}
}

func TestIntrospectRequiresClientAuthAndOwnership(t *testing.T) {
	as, _ := newTestAS(t)
	verifier := "v-1234567890-1234567890-1234567890-abcd"
	code, client := authCodeFor(t, as, pkce(verifier))
	tok, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example/cb",
		CodeVerifier: verifier, Client: port.ClientAuth{ClientID: client.ClientID},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Unauthenticated caller is rejected (no info leak).
	if _, err := as.Introspect(context.Background(), tok.AccessToken, port.ClientAuth{}); err != ErrOAuthInvalidClient {
		t.Fatalf("want invalid_client, got %v", err)
	}
	// Owning client sees the token as active.
	res, err := as.Introspect(context.Background(), tok.AccessToken, port.ClientAuth{ClientID: client.ClientID})
	if err != nil || !res.Active {
		t.Fatalf("owner introspect: res=%+v err=%v", res, err)
	}
	// A different client must NOT see another client's token.
	other, _ := as.Register(context.Background(), port.ClientRegistration{RedirectURIs: []string{"https://other.example/cb"}})
	res, err = as.Introspect(context.Background(), tok.AccessToken, port.ClientAuth{ClientID: other.ClientID})
	if err != nil || res.Active {
		t.Fatalf("cross-client introspect must be inactive: res=%+v err=%v", res, err)
	}
}

func TestRevokeRequiresClientAuth(t *testing.T) {
	as, _ := newTestAS(t)
	if err := as.Revoke(context.Background(), "anything", "", port.ClientAuth{}); err != ErrOAuthInvalidClient {
		t.Fatalf("want invalid_client, got %v", err)
	}
}

func TestTokenEnforcesClientGrantTypes(t *testing.T) {
	as, _ := newTestAS(t)
	client, _ := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs:    []string{"https://app.example/cb"},
		GrantTypes:      []string{"authorization_code"}, // NOT client_credentials
		TokenAuthMethod: "client_secret_basic",
	})
	_, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "client_credentials",
		Client:    port.ClientAuth{ClientID: client.ClientID, ClientSecret: client.Secret, Method: "client_secret_basic"},
	})
	if err != ErrOAuthUnauthorizedClient {
		t.Fatalf("want unauthorized_client, got %v", err)
	}
}

func TestScopelessClientBoundedToASSupported(t *testing.T) {
	as, _ := newTestAS(t)                                                                                                     // cfg.Scopes = read, write
	client, _ := as.Register(context.Background(), port.ClientRegistration{RedirectURIs: []string{"https://app.example/cb"}}) // no scopes
	base := port.AuthorizeRequest{ClientID: client.ClientID, RedirectURI: "https://app.example/cb", CodeChallenge: "x", CodeChallengeMethod: "S256"}

	base.Scopes = []string{"admin"} // not AS-supported
	if _, _, err := as.ValidateAuthorizeRequest(context.Background(), base); err != ErrOAuthInvalidScope {
		t.Fatalf("arbitrary scope: want invalid_scope, got %v", err)
	}
	base.Scopes = []string{"read"} // AS-supported
	if _, _, err := as.ValidateAuthorizeRequest(context.Background(), base); err != nil {
		t.Fatalf("supported scope should pass, got %v", err)
	}
}

// mintToken registers a client (with the given scopes) and runs the full
// auth-code flow, returning an access token + the client.
func mintToken(t *testing.T, as *Local, scopes []string, resource string) (string, *port.OAuthClient) {
	t.Helper()
	client, err := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs: []string{"https://app.example/cb"}, Scopes: scopes,
		GrantTypes: []string{"authorization_code", "refresh_token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := "v-1234567890-1234567890-1234567890-abcd"
	res, err := as.Authorize(context.Background(), port.AuthorizeRequest{
		ClientID: client.ClientID, RedirectURI: "https://app.example/cb", Scopes: scopes,
		CodeChallenge: pkce(verifier), CodeChallengeMethod: "S256", Resource: resource,
		User: &port.UserRef{UserID: 7, PartnerID: 3}, ConsentGranted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "authorization_code", Code: res.Code, RedirectURI: "https://app.example/cb",
		CodeVerifier: verifier, Client: port.ClientAuth{ClientID: client.ClientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok.AccessToken, client
}

func TestRegisterRejectsUnsupportedScopeAndAuthMethod(t *testing.T) {
	as, _ := newTestAS(t) // supports read, write
	if _, err := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs: []string{"https://app.example/cb"}, Scopes: []string{"admin"},
	}); err != ErrOAuthInvalidScope {
		t.Fatalf("admin registration: want invalid_scope, got %v", err)
	}
	if _, err := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs: []string{"https://app.example/cb"}, TokenAuthMethod: "magic",
	}); err != ErrOAuthInvalidRequest {
		t.Fatalf("bad auth method: want invalid_request, got %v", err)
	}
}

func TestRegisterRejectsUserinfoRedirect(t *testing.T) {
	as, _ := newTestAS(t)
	for _, uri := range []string{
		"https://app.example@evil.example/cb", // host is evil.example, reads as app.example
		"https://user:pass@app.example/cb",
	} {
		if _, err := as.Register(context.Background(), port.ClientRegistration{
			RedirectURIs: []string{uri},
		}); err != ErrOAuthInvalidRequest {
			t.Fatalf("userinfo redirect %q: want invalid_request, got %v", uri, err)
		}
	}
}

func TestBoundScopesClampsToSupported(t *testing.T) {
	as, _ := newTestAS(t) // supports read, write
	// A client whose stored scopes include an unsupported one (defense-in-depth):
	// omitting the request must NOT yield the unsupported scope.
	got, err := as.issuer.boundScopes(nil, []string{"read", "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got, "admin") || !slices.Contains(got, "read") {
		t.Fatalf("clamp failed: got %v, want just read", got)
	}
}

func TestAuthCodeNoRefreshWhenGrantNotRegistered(t *testing.T) {
	as, _ := newTestAS(t)
	client, _ := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs: []string{"https://app.example/cb"}, Scopes: []string{"read"},
		GrantTypes: []string{"authorization_code"}, // no refresh_token
	})
	verifier := "v-1234567890-1234567890-1234567890-abcd"
	res, _ := as.Authorize(context.Background(), port.AuthorizeRequest{
		ClientID: client.ClientID, RedirectURI: "https://app.example/cb", Scopes: []string{"read"},
		CodeChallenge: pkce(verifier), CodeChallengeMethod: "S256",
		User: &port.UserRef{UserID: 1}, ConsentGranted: true,
	})
	tok, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "authorization_code", Code: res.Code, RedirectURI: "https://app.example/cb",
		CodeVerifier: verifier, Client: port.ClientAuth{ClientID: client.ClientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != "" {
		t.Fatal("must not issue a refresh token when refresh_token grant is not registered")
	}
}

func TestTokenExchangeBoundedByClientScopes(t *testing.T) {
	as, _ := newTestAS(t)
	// Subject token carries read+write.
	subject, _ := mintToken(t, as, []string{"read", "write"}, "https://rs.example")
	// Exchanger client is only allowed read.
	ex, _ := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs:    []string{"https://app.example/cb"},
		Scopes:          []string{"read"},
		GrantTypes:      []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
		TokenAuthMethod: "client_secret_basic",
	})
	exchange := func(scope []string) error {
		_, err := as.Token(context.Background(), port.TokenRequest{
			GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken:     subject,
			SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			Scopes:           scope,
			Client:           port.ClientAuth{ClientID: ex.ClientID, ClientSecret: ex.Secret, Method: "client_secret_basic"},
		})
		return err
	}
	if err := exchange([]string{"write"}); err != ErrOAuthInvalidScope {
		t.Fatalf("exchange up to write: want invalid_scope, got %v", err)
	}
	if err := exchange([]string{"read"}); err != nil {
		t.Fatalf("exchange down to read should pass, got %v", err)
	}
}

func TestMultiResourceIntrospect(t *testing.T) {
	signer, _ := NewEphemeralRS256Signer()
	cfg := Config{
		Issuer: "https://as.example", DefaultAudience: "https://rs.example",
		Resources: []string{"https://rs2.example"}, Scopes: []string{"read"},
		AccessTTL: time.Hour, RefreshTTL: time.Hour, CodeTTL: time.Minute,
	}
	as := NewLocal(signer,
		&memClients{m: map[string]*port.OAuthClient{}},
		&memCodes{m: map[string]*port.AuthCode{}},
		&memTokens{m: map[string]*port.RefreshToken{}}, cfg)
	// Token minted for the SECOND resource must still introspect active.
	token, client := mintToken(t, as, []string{"read"}, "https://rs2.example")
	res, err := as.Introspect(context.Background(), token, port.ClientAuth{ClientID: client.ClientID})
	if err != nil || !res.Active {
		t.Fatalf("multi-resource token must introspect active: res=%+v err=%v", res, err)
	}
}

func TestResourceMustBeKnown(t *testing.T) {
	as, _ := newTestAS(t) // DefaultAudience = https://rs.example
	client, _ := as.Register(context.Background(), port.ClientRegistration{RedirectURIs: []string{"https://app.example/cb"}})
	req := port.AuthorizeRequest{
		ClientID: client.ClientID, RedirectURI: "https://app.example/cb",
		CodeChallenge: "x", CodeChallengeMethod: "S256", Resource: "https://evil.example",
	}
	if _, _, err := as.ValidateAuthorizeRequest(context.Background(), req); err != ErrOAuthInvalidTarget {
		t.Fatalf("unknown resource: want invalid_target, got %v", err)
	}
	req.Resource = "https://rs.example" // the configured audience
	if _, _, err := as.ValidateAuthorizeRequest(context.Background(), req); err != nil {
		t.Fatalf("known resource should pass, got %v", err)
	}
}

func TestRegisterRejectsUnsupportedGrant(t *testing.T) {
	as, _ := newTestAS(t)
	if _, err := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs: []string{"https://app.example/cb"}, GrantTypes: []string{"password"},
	}); err != ErrOAuthInvalidRequest {
		t.Fatalf("unsupported grant: want invalid_request, got %v", err)
	}
}

func TestClientAuthMethodEnforced(t *testing.T) {
	as, _ := newTestAS(t)
	client, _ := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs: []string{"https://app.example/cb"}, Scopes: []string{"read"},
		GrantTypes: []string{"client_credentials"}, TokenAuthMethod: "client_secret_basic",
	})
	cc := func(method string) error {
		_, err := as.Token(context.Background(), port.TokenRequest{
			GrantType: "client_credentials",
			Client:    port.ClientAuth{ClientID: client.ClientID, ClientSecret: client.Secret, Method: method},
		})
		return err
	}
	if err := cc("client_secret_basic"); err != nil {
		t.Fatalf("registered method should authenticate, got %v", err)
	}
	if err := cc("client_secret_post"); err != ErrOAuthInvalidClient {
		t.Fatalf("wrong auth method: want invalid_client, got %v", err)
	}
}

func TestValidateAuthorizeReturnsGrantedScopesForOmittedRequest(t *testing.T) {
	as, _ := newTestAS(t)
	client, _ := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs: []string{"https://app.example/cb"}, Scopes: []string{"read"},
	})
	_, scopes, err := as.ValidateAuthorizeRequest(context.Background(), port.AuthorizeRequest{
		ClientID: client.ClientID, RedirectURI: "https://app.example/cb",
		CodeChallenge: "x", CodeChallengeMethod: "S256", // scope omitted
	})
	if err != nil {
		t.Fatal(err)
	}
	// The consent page renders THIS, so it must equal what the code will store.
	if len(scopes) != 1 || scopes[0] != "read" {
		t.Fatalf("omitted scope should resolve to the client ceiling [read], got %v", scopes)
	}
}

func TestTokenExchangeRequiresAccessTokenType(t *testing.T) {
	as, _ := newTestAS(t)
	subject, _ := mintToken(t, as, []string{"read"}, "https://rs.example")
	ex, _ := as.Register(context.Background(), port.ClientRegistration{
		RedirectURIs: []string{"https://app.example/cb"}, Scopes: []string{"read"},
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:token-exchange"}, TokenAuthMethod: "client_secret_basic",
	})
	tx := func(typ string) error {
		_, err := as.Token(context.Background(), port.TokenRequest{
			GrantType: "urn:ietf:params:oauth:grant-type:token-exchange", SubjectToken: subject,
			SubjectTokenType: typ, Scopes: []string{"read"},
			Client: port.ClientAuth{ClientID: ex.ClientID, ClientSecret: ex.Secret, Method: "client_secret_basic"},
		})
		return err
	}
	if err := tx(""); err != ErrOAuthInvalidRequest {
		t.Fatalf("missing subject_token_type: want invalid_request, got %v", err)
	}
	if err := tx("urn:ietf:params:oauth:token-type:refresh_token"); err != ErrOAuthInvalidRequest {
		t.Fatalf("unsupported subject_token_type: want invalid_request, got %v", err)
	}
	if err := tx("urn:ietf:params:oauth:token-type:access_token"); err != nil {
		t.Fatalf("access_token type should pass, got %v", err)
	}
}
