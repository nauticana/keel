package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/config"
)

// fakeIdP is an OpenID Provider on a TLS test server. The token endpoint
// answers with an ID token built from claims, signed by sign.
type fakeIdP struct {
	t        *testing.T
	srv      *httptest.Server
	rsaKey   *rsa.PrivateKey
	ecKey    *ecdsa.PrivateKey
	algs     []string
	issuer   string // discovery issuer; empty = server URL
	authMeth []string

	mu      sync.Mutex
	claims  jwt.MapClaims
	sign    func(claims jwt.MapClaims) string
	status  int
	body    string // overrides the token response
	lastReq url.Values
	lastHdr http.Header
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, rsaKey: rsaKey, ecKey: ecKey, algs: []string{"RS256"}, status: http.StatusOK,
		authMeth: []string{AuthSecretPost, AuthSecretBasic, AuthPrivateKey}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		issuer := f.issuer
		if issuer == "" {
			issuer = f.srv.URL
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": f.algs,
			"token_endpoint_auth_methods_supported": f.authMeth,
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		enc := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			{"kty": "RSA", "kid": "rsa", "n": enc(f.rsaKey.N.Bytes()), "e": enc(big.NewInt(int64(f.rsaKey.E)).Bytes())},
			{"kty": "EC", "kid": "ec", "crv": "P-256", "x": enc(f.ecKey.X.FillBytes(make([]byte, 32))), "y": enc(f.ecKey.Y.FillBytes(make([]byte, 32)))},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastReq, f.lastHdr = r.PostForm, r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		if f.body != "" {
			_, _ = w.Write([]byte(f.body))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "id_token": f.sign(f.claims)})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	f.sign = f.signRSA
	return f
}

func (f *fakeIdP) signRSA(c jwt.MapClaims) string {
	return f.signWith(jwt.SigningMethodRS256, "rsa", f.rsaKey, c)
}

func (f *fakeIdP) signWith(m jwt.SigningMethod, kid string, key any, c jwt.MapClaims) string {
	tok := jwt.NewWithClaims(m, c)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// baseClaims are valid ID-token claims for clientID and nonce.
func (f *fakeIdP) baseClaims(clientID, nonce string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": f.srv.URL, "sub": "user-1", "aud": clientID, "exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(), "nonce": nonce, "email": "ada@acme.example", "email_verified": true,
		"given_name": "Ada", "family_name": "Lovelace", "amr": []any{"pwd", "mfa"}, "groups": []any{"g1", "g2"},
	}
}

func (f *fakeIdP) client(cred ClientCredential) *Client {
	return &Client{
		Issuer: f.srv.URL, DiscoveryURL: f.srv.URL + "/.well-known/openid-configuration", ClientID: "client-1",
		Credential: cred, Scopes: []string{"email", "profile"}, HTTP: f.srv.Client(), MetadataTTL: time.Hour,
	}
}

// withConfig sets the flags these tests read and restores them afterwards.
func withConfig(t *testing.T, googleID, appleID string) {
	t.Helper()
	c := config.Config()
	google, apple, size := c.GoogleClientID, c.AppleClientID, c.OutboundMaxResponseSize
	c.GoogleClientID, c.AppleClientID, c.OutboundMaxResponseSize = googleID, appleID, 1<<20
	t.Cleanup(func() { c.GoogleClientID, c.AppleClientID, c.OutboundMaxResponseSize = google, apple, size })
}
