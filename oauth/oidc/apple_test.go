package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/crypto"
)

const appleTestClient = "com.example.app"

// fakeApple answers Apple's token and revoke endpoints.
type fakeApple struct {
	srv          *httptest.Server
	idSubject    string
	tokenErr     string
	revokeErr    string
	forms        map[string]url.Values
	signingKey   *rsa.PrivateKey
	forgeToken   bool
	expiredToken bool
}

func newFakeApple(t *testing.T) *fakeApple {
	t.Helper()
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeApple{idSubject: "apple-sub", forms: map[string]url.Values{}, signingKey: signingKey}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.forms[r.URL.Path] = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/token" && f.tokenErr != "":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": f.tokenErr})
		case r.URL.Path == "/token":
			exp := time.Now().Add(time.Hour)
			if f.expiredToken {
				exp = time.Now().Add(-time.Hour)
			}
			key := f.signingKey
			if f.forgeToken {
				key, _ = rsa.GenerateKey(rand.Reader, 2048)
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": AppleIssuer, "aud": appleTestClient, "sub": f.idSubject, "exp": exp.Unix()})
			token.Header["kid"] = "apple"
			idToken, _ := token.SignedString(key)
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "refresh_token": "apple-refresh", "id_token": idToken})
		case r.URL.Path == "/keys":
			enc := base64.RawURLEncoding.EncodeToString
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
				"kty": "RSA", "kid": "apple", "alg": "RS256", "n": enc(f.signingKey.N.Bytes()), "e": enc(big.NewInt(int64(f.signingKey.E)).Bytes()),
			}}})
		case r.URL.Path == "/revoke" && f.revokeErr != "":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": f.revokeErr})
		case r.URL.Path == "/revoke":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func newTestAppleGrants(t *testing.T, f *fakeApple) (*AppleGrants, *ecdsa.PrivateKey) {
	t.Helper()
	withConfig(t, "", appleTestClient)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	c := config.Config()
	team, keyID, secretName := c.AppleTeamID, c.AppleKeyID, c.AppleKeySecret
	c.AppleTeamID, c.AppleKeyID, c.AppleKeySecret = "TEAM123456", "KEY1234567", "apple_key"
	t.Cleanup(func() { c.AppleTeamID, c.AppleKeyID, c.AppleKeySecret = team, keyID, secretName })
	secrets := fakeSecrets{"apple_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
	a, err := NewAppleGrants(context.Background(), secrets, testSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	a.TokenURL, a.RevokeURL, a.HTTP = f.srv.URL+"/token", f.srv.URL+"/revoke", f.srv.Client()
	a.AppleKeys = crypto.NewJWKSProvider(f.srv.URL+"/keys", time.Hour, f.srv.Client())
	return a, key
}

// checkClientSecret verifies the ES256 client secret Apple expects.
func checkClientSecret(t *testing.T, form url.Values, key *ecdsa.PrivateKey) {
	t.Helper()
	if form.Get("client_id") != appleTestClient {
		t.Fatalf("client_id = %q", form.Get("client_id"))
	}
	parsed, err := jwt.Parse(form.Get("client_secret"), func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer("TEAM123456"), jwt.WithSubject(appleTestClient), jwt.WithAudience(AppleIssuer), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("client secret: %v", err)
	}
	if parsed.Header["kid"] != "KEY1234567" {
		t.Errorf("kid = %v", parsed.Header["kid"])
	}
}

func TestAppleGrantsRedeemSealsRefreshToken(t *testing.T) {
	f := newFakeApple(t)
	a, key := newTestAppleGrants(t, f)
	sealed, err := a.Redeem(context.Background(), "the-code", "apple-sub")
	if err != nil {
		t.Fatal(err)
	}
	form := f.forms["/token"]
	if form.Get("code") != "the-code" || form.Get("grant_type") != "authorization_code" || form.Has("redirect_uri") {
		t.Fatalf("token form: %v", form)
	}
	checkClientSecret(t, form, key)
	if sealed == "apple-refresh" {
		t.Fatal("the refresh token must leave Redeem sealed")
	}
	if plain, err := a.sealer.Open(sealed); err != nil || plain != "apple-refresh" {
		t.Fatalf("sealed grant opens to the refresh token: %q, %v", plain, err)
	}
}

func TestAppleGrantsRedeemRefusesAnotherAccountsCode(t *testing.T) {
	f := newFakeApple(t)
	f.idSubject = "someone-else"
	a, _ := newTestAppleGrants(t, f)
	if _, err := a.Redeem(context.Background(), "the-code", "apple-sub"); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("want ErrInvalidResponse, got %v", err)
	}
}

func TestAppleGrantsRedeemVerifiesTokenResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fakeApple)
	}{
		{"forged", func(f *fakeApple) { f.forgeToken = true }},
		{"expired", func(f *fakeApple) { f.expiredToken = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeApple(t)
			tc.mutate(f)
			a, _ := newTestAppleGrants(t, f)
			if _, err := a.Redeem(context.Background(), "the-code", "apple-sub"); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("want ErrInvalidResponse, got %v", err)
			}
		})
	}
}

func TestAppleGrantsRedeemReportsRefusedCode(t *testing.T) {
	f := newFakeApple(t)
	f.tokenErr = "invalid_grant"
	a, _ := newTestAppleGrants(t, f)
	var refused *TokenError
	if _, err := a.Redeem(context.Background(), "used-code", "apple-sub"); !errors.As(err, &refused) || refused.Code != "invalid_grant" {
		t.Fatalf("want TokenError invalid_grant, got %v", err)
	}
}

func TestAppleGrantsRevokeGrant(t *testing.T) {
	f := newFakeApple(t)
	a, key := newTestAppleGrants(t, f)
	sealed, err := a.Redeem(context.Background(), "the-code", "apple-sub")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.RevokeGrant(context.Background(), AppleIssuer, sealed); err != nil {
		t.Fatal(err)
	}
	form := f.forms["/revoke"]
	if form.Get("token") != "apple-refresh" || form.Get("token_type_hint") != "refresh_token" {
		t.Fatalf("revoke form: %v", form)
	}
	checkClientSecret(t, form, key)

	f.revokeErr = "invalid_client"
	var refused *TokenError
	if err := a.RevokeGrant(context.Background(), AppleIssuer, sealed); !errors.As(err, &refused) || refused.Code != "invalid_client" {
		t.Fatalf("want TokenError invalid_client, got %v", err)
	}
}

func TestAppleGrantsRevokeGrantRefusesOtherIssuerAndForeignSeal(t *testing.T) {
	f := newFakeApple(t)
	a, _ := newTestAppleGrants(t, f)
	if err := a.RevokeGrant(context.Background(), GoogleIssuer, "x"); err == nil {
		t.Fatal("a grant from another issuer is not Apple's to revoke")
	}
	if err := a.RevokeGrant(context.Background(), AppleIssuer, "apple-refresh"); err == nil {
		t.Fatal("an unsealed value is refused")
	}
	if len(f.forms) != 0 {
		t.Fatalf("nothing reaches Apple: %v", f.forms)
	}
}

func TestNewAppleGrantsRequiresConfiguration(t *testing.T) {
	withConfig(t, "", "")
	if _, err := NewAppleGrants(context.Background(), fakeSecrets{}, testSealer(t)); !errors.Is(err, ErrBadConfiguration) {
		t.Fatalf("want ErrBadConfiguration, got %v", err)
	}
	var zero AppleGrants
	if err := zero.RevokeGrant(context.Background(), AppleIssuer, "x"); err == nil {
		t.Fatal("a zero AppleGrants fails instead of panicking")
	}
}
