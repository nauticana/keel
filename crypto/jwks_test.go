package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// rotatingJWKS serves whatever key set is current and counts fetches.
type rotatingJWKS struct {
	mu      sync.Mutex
	keys    []map[string]string
	fetches atomic.Int32
	srv     *httptest.Server
}

func newRotatingJWKS(t *testing.T, keys ...map[string]string) *rotatingJWKS {
	r := &rotatingJWKS{keys: keys}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.fetches.Add(1)
		r.mu.Lock()
		defer r.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": r.keys})
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rotatingJWKS) set(keys ...map[string]string) {
	r.mu.Lock()
	r.keys = keys
	r.mu.Unlock()
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signRS256(t *testing.T, kid string, key *rsa.PrivateKey, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	for k, v := range header {
		tok.Header[k] = v
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeyForKidUnknownKidRefreshesWithinTTL(t *testing.T) {
	oldKey, newKey := mustRSA(t), mustRSA(t)
	idp := newRotatingJWKS(t, rsaJWK("old", "", oldKey))
	now := time.Unix(1_700_000_000, 0)
	p := NewJWKSProvider(idp.srv.URL, time.Hour, idp.srv.Client())
	p.now = func() time.Time { return now }
	ctx := context.Background()

	if _, err := p.KeyForKid(ctx, "old"); err != nil {
		t.Fatal(err)
	}
	idp.set(rsaJWK("old", "", oldKey), rsaJWK("new", "", newKey))
	now = now.Add(jwksMissRefreshInterval)
	if _, err := p.KeyForKid(ctx, "new"); err != nil {
		t.Fatalf("a rotated kid within the TTL must force a refresh: %v", err)
	}
	if got := idp.fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2", got)
	}
}

func TestKeyForKidUnknownKidRefreshIsRateLimited(t *testing.T) {
	key := mustRSA(t)
	idp := newRotatingJWKS(t, rsaJWK("known", "", key))
	now := time.Unix(1_700_000_000, 0)
	p := NewJWKSProvider(idp.srv.URL, time.Hour, idp.srv.Client())
	p.now = func() time.Time { return now }
	ctx := context.Background()

	if _, err := p.KeyForKid(ctx, "known"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := p.KeyForKid(ctx, "attacker-kid"); err == nil {
			t.Fatal("an unknown kid must not resolve")
		}
	}
	if got := idp.fetches.Load(); got != 1 {
		t.Fatalf("fetches within the miss interval = %d, want 1", got)
	}
	now = now.Add(jwksMissRefreshInterval)
	_, _ = p.KeyForKid(ctx, "attacker-kid")
	if got := idp.fetches.Load(); got != 2 {
		t.Fatalf("fetches after the miss interval = %d, want 2", got)
	}
	if _, err := p.KeyForKid(ctx, "known"); err != nil {
		t.Fatalf("a known kid still resolves: %v", err)
	}
}

func TestKeyForKidServesStaleKeyWithinHardCap(t *testing.T) {
	key := mustRSA(t)
	idp := newRotatingJWKS(t, rsaJWK("k", "", key))
	now := time.Unix(1_700_000_000, 0)
	p := NewJWKSProvider(idp.srv.URL, time.Minute, idp.srv.Client())
	p.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := p.KeyForKid(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	idp.srv.Close()
	now = now.Add(time.Hour)
	if _, err := p.KeyForKid(ctx, "k"); err != nil {
		t.Fatalf("within the hard cap the last good key is served: %v", err)
	}
	now = now.Add(jwksHardCap)
	if _, err := p.KeyForKid(ctx, "k"); err == nil {
		t.Fatal("past the hard cap a failed refresh must error")
	}
}

func TestJWKSSkipsNonSignatureKeys(t *testing.T) {
	key := mustRSA(t)
	enc := rsaJWK("enc", "", key)
	enc["use"] = "enc"
	sig := rsaJWK("sig", "", key)
	sig["use"] = "sig"
	idp := newRotatingJWKS(t, enc, sig, rsaJWK("unspecified", "", key))
	p := NewJWKSProvider(idp.srv.URL, time.Hour, idp.srv.Client())
	ctx := context.Background()
	claims := jwt.MapClaims{"aud": "client", "exp": time.Now().Add(time.Minute).Unix()}
	if _, err := VerifyRS256(ctx, p, signRS256(t, "enc", key, claims, nil), "client", ""); err == nil {
		t.Error("a key with use=enc must not verify signatures")
	}
	for _, kid := range []string{"sig", "unspecified"} {
		if _, err := VerifyRS256(ctx, p, signRS256(t, kid, key, claims, nil), "client", ""); err != nil {
			t.Errorf("%s: %v", kid, err)
		}
	}
}

func TestVerifyRefusesCritHeader(t *testing.T) {
	key := mustRSA(t)
	idp := newRotatingJWKS(t, rsaJWK("k", "", key))
	p := NewJWKSProvider(idp.srv.URL, time.Hour, idp.srv.Client())
	ctx := context.Background()
	claims := jwt.MapClaims{"aud": "client", "iss": "https://idp.example", "exp": time.Now().Add(time.Minute).Unix()}
	crit := signRS256(t, "k", key, claims, map[string]any{"crit": []string{"exp"}, "exp": 1})
	if _, err := VerifyRS256(ctx, p, crit, "client", ""); err == nil {
		t.Error("VerifyRS256 must refuse a crit header")
	}
	if _, err := VerifyAsymmetric(ctx, p, crit, "client", "https://idp.example", []string{"RS256"}); err == nil {
		t.Error("VerifyAsymmetric must refuse a crit header")
	}
}

func TestVerifyToleratesClockSkew(t *testing.T) {
	key := mustRSA(t)
	idp := newRotatingJWKS(t, rsaJWK("k", "", key))
	p := NewJWKSProvider(idp.srv.URL, time.Hour, idp.srv.Client())
	ctx := context.Background()
	now := time.Now()
	for name, tc := range map[string]struct {
		claims jwt.MapClaims
		ok     bool
	}{
		"expired within leeway":     {jwt.MapClaims{"exp": now.Add(-30 * time.Second).Unix()}, true},
		"expired past leeway":       {jwt.MapClaims{"exp": now.Add(-2 * jwtLeeway).Unix()}, false},
		"not yet valid within skew": {jwt.MapClaims{"exp": now.Add(time.Hour).Unix(), "nbf": now.Add(30 * time.Second).Unix()}, true},
		"not yet valid past skew":   {jwt.MapClaims{"exp": now.Add(time.Hour).Unix(), "nbf": now.Add(2 * jwtLeeway).Unix()}, false},
	} {
		tc.claims["aud"] = "client"
		_, err := VerifyRS256(ctx, p, signRS256(t, "k", key, tc.claims, nil), "client", "")
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
		}
	}
}
