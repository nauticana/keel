package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/oidc"
	"github.com/nauticana/keel/user"
)

// contractUsers records the identity each sign-in path hands the user service.
type contractUsers struct {
	user.UserService
	identity user.ExternalIdentity
	methods  []string
}

func (u *contractUsers) GetOrCreateUserFromSocial(id user.ExternalIdentity, _ *user.SignupConsent) (*model.UserSession, bool, error) {
	u.identity = id
	return &model.UserSession{Id: 5, PartnerId: 9}, true, nil
}
func (u *contractUsers) GetUserFromExternal(id user.ExternalIdentity) (*model.UserSession, error) {
	u.identity = id
	return &model.UserSession{Id: 5, PartnerId: 9}, nil
}
func (u *contractUsers) ExternalSignInMethod(int64, user.ExternalIdentity) (string, error) {
	return user.SignInExternal, nil
}
func (u *contractUsers) CheckSignInMethod(_ int, method string) error {
	u.methods = append(u.methods, method)
	return nil
}
func (u *contractUsers) CreateJWT(*model.UserSession) (string, error) { return "jwt", nil }
func (u *contractUsers) CreateRefreshToken(int, string, time.Duration) (string, error) {
	return "refresh", nil
}
func (u *contractUsers) GetUserMenu(int) ([]model.UserMenu, error) { return nil, nil }

type socialKeys struct {
	key *rsa.PrivateKey
	srv *httptest.Server
}

func newSocialKeys(t *testing.T) *socialKeys {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k := &socialKeys{key: key}
	k.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		enc := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			{"kty": "RSA", "kid": "k", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())},
		}})
	}))
	t.Cleanup(k.srv.Close)
	return k
}

func (k *socialKeys) verifier() *oidc.SocialVerifier {
	keys := crypto.NewJWKSProvider(k.srv.URL, time.Hour, k.srv.Client())
	return &oidc.SocialVerifier{GoogleKeys: keys, AppleKeys: keys}
}

func (k *socialKeys) token(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k"
	s, err := tok.SignedString(k.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func withSocialClients(t *testing.T) {
	t.Helper()
	c := config.Config()
	google, apple := c.GoogleClientID, c.AppleClientID
	c.GoogleClientID, c.AppleClientID = "google-client", "apple-client"
	t.Cleanup(func() { c.GoogleClientID, c.AppleClientID = google, apple })
}

func postSocial(h *SocialLoginHandler, provider, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	body := `{"provider":"` + provider + `","token":"` + token + `"}`
	h.LoginSocial(w, httptest.NewRequest(http.MethodPost, "/public/login/social", strings.NewReader(body)))
	return w
}

// The wire contract first-party clients depend on: request shape, response
// fields, the identity handed to the user service, and the opaque refusal.
func TestLoginSocialContract(t *testing.T) {
	withSocialClients(t)
	keys := newSocialKeys(t)
	nonces := cache.NewMemoryCacheService()
	defer nonces.Close()
	users := &contractUsers{}
	h := &SocialLoginHandler{AbstractHandler: AbstractHandler{UserService: users}, NonceCache: nonces, Verifier: keys.verifier()}
	exp := time.Now().Add(time.Hour).Unix()

	nonce := issueNonce(t, h)
	w := postSocial(h, "google", keys.token(t, jwt.MapClaims{"iss": "accounts.google.com", "aud": "google-client", "sub": "g-1",
		"exp": exp, "nonce": nonce, "email": "ada@acme.example", "email_verified": true, "given_name": "Ada", "family_name": "L", "hd": "acme.example"}))
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
		t.Fatalf("google = %d %s", w.Code, w.Body.String())
	}
	for k, want := range map[string]any{"token": "jwt", "refreshToken": "refresh", "isNewUser": true, "partnerId": float64(9), "userId": float64(5)} {
		if resp.Data[k] != want {
			t.Errorf("%s = %v, want %v", k, resp.Data[k], want)
		}
	}
	if users.identity != (user.ExternalIdentity{Provider: "google", Issuer: user.GoogleIssuer, Subject: "g-1", Email: "ada@acme.example",
		EmailVerified: true, FirstName: "Ada", LastName: "L", HostedDomain: "acme.example"}) {
		t.Fatalf("google identity = %+v", users.identity)
	}
	if len(users.methods) != 1 || users.methods[0] != user.SignInExternal {
		t.Fatalf("sign-in methods checked = %v", users.methods)
	}

	// Apple returns the SHA-256 of the issued nonce.
	nonce = issueNonce(t, h)
	sum := sha256.Sum256([]byte(nonce))
	w = postSocial(h, "apple", keys.token(t, jwt.MapClaims{"iss": user.AppleIssuer, "aud": "apple-client", "sub": "a-1",
		"exp": exp, "nonce": hex.EncodeToString(sum[:]), "email": "x@privaterelay.appleid.com", "email_verified": "true", "given_name": "ignored"}))
	if w.Code != http.StatusOK || users.identity != (user.ExternalIdentity{Provider: "apple", Issuer: user.AppleIssuer, Subject: "a-1",
		Email: "x@privaterelay.appleid.com", EmailVerified: true}) {
		t.Fatalf("apple = %d %s, identity %+v", w.Code, w.Body.String(), users.identity)
	}

	replay := postSocial(h, "apple", keys.token(t, jwt.MapClaims{"iss": user.AppleIssuer, "aud": "apple-client", "sub": "a-1",
		"exp": exp, "nonce": hex.EncodeToString(sum[:])}))
	forged := postSocial(h, "google", keys.token(t, jwt.MapClaims{"iss": "https://evil.example", "aud": "google-client", "sub": "g-1", "exp": exp}))
	for name, w := range map[string]*httptest.ResponseRecorder{"replayed nonce": replay, "foreign issuer": forged} {
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "invalid social token") {
			t.Errorf("%s = %d %s", name, w.Code, w.Body.String())
		}
	}
	if w := postSocial(h, "facebook", "t"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "provider_not_enabled") {
		t.Fatalf("unknown provider = %d %s", w.Code, w.Body.String())
	}
}

func TestLoginGoogleContract(t *testing.T) {
	withSocialClients(t)
	var tokenStatus = http.StatusOK
	var tokenBody, info string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.WriteHeader(tokenStatus)
			_, _ = w.Write([]byte(tokenBody))
			return
		}
		_, _ = w.Write([]byte(info))
	}))
	defer srv.Close()
	c := config.Config()
	size := c.OutboundMaxResponseSize
	c.OutboundMaxResponseSize = 1 << 20
	t.Cleanup(func() { c.OutboundMaxResponseSize = size })

	users := &contractUsers{}
	h := &PublicHandler{AbstractHandler: AbstractHandler{UserService: users}, Secrets: contractSecrets{},
		GoogleCode: &oidc.GoogleCode{TokenURL: srv.URL + "/token", UserInfoURL: srv.URL + "/userinfo", HTTP: srv.Client()}}
	login := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.LoginGoogle(w, httptest.NewRequest(http.MethodPost, "/public/login/gmail", strings.NewReader(`{"code":"c"}`)))
		return w
	}

	tokenBody, info = `{"access_token":"at"}`, `{"id":"g-1","email":"ada@acme.example","verified_email":true,"given_name":"Ada","hd":"acme.example"}`
	if w := login(); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"twoFactorRequired":false`) {
		t.Fatalf("success = %d %s", w.Code, w.Body.String())
	}
	if users.identity != (user.ExternalIdentity{Provider: "google", Issuer: user.GoogleIssuer, Subject: "g-1", Email: "ada@acme.example",
		EmailVerified: true, FirstName: "Ada", HostedDomain: "acme.example"}) {
		t.Fatalf("identity = %+v", users.identity)
	}
	tokenStatus, tokenBody = http.StatusBadRequest, `{"error":"invalid_grant","error_description":"Bad Request"}`
	if w := login(); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "token exchange failed: invalid_grant") {
		t.Fatalf("refused code = %d %s", w.Code, w.Body.String())
	}
	tokenStatus, tokenBody, info = http.StatusOK, `{"access_token":"at"}`, `{"id":"g-1","verified_email":false}`
	if w := login(); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "email not verified") {
		t.Fatalf("unverified = %d %s", w.Code, w.Body.String())
	}
}

type contractSecrets struct{}

func (contractSecrets) GetSecret(context.Context, string) (string, error) { return "secret", nil }
