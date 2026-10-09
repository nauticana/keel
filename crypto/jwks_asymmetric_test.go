package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWK(kid, alg string, key *rsa.PrivateKey) map[string]string {
	return map[string]string{"kty": "RSA", "kid": kid, "alg": alg, "n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}
}

func ecJWK(kid, crv string, key *ecdsa.PrivateKey) map[string]string {
	size := (key.Curve.Params().BitSize + 7) / 8
	return map[string]string{"kty": "EC", "kid": kid, "crv": crv, "x": b64(key.X.FillBytes(make([]byte, size))), "y": b64(key.Y.FillBytes(make([]byte, size)))}
}

func TestVerifyAsymmetric(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	offCurve := ecJWK("off", "P-256", p256)
	offCurve["y"] = b64(make([]byte, 32))
	keys := []map[string]string{
		rsaJWK("rsa", "", rsaKey), rsaJWK("pinned", "RS256", rsaKey), rsaJWK("weak", "", weak),
		ecJWK("p256", "P-256", p256), ecJWK("p384", "P-384", p384), offCurve,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	defer srv.Close()
	jwks := NewJWKSProvider(srv.URL, time.Minute, srv.Client())
	sign := func(method jwt.SigningMethod, kid string, key any) string {
		tok := jwt.NewWithClaims(method, jwt.MapClaims{"aud": "client", "iss": "https://idp.example", "exp": time.Now().Add(time.Minute).Unix()})
		tok.Header["kid"] = kid
		s, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ctx := context.Background()
	advertised := []string{"RS256", "RS512", "PS256", "ES256", "ES384", "HS256", "none"}
	verify := func(token string) error {
		_, err := VerifyAsymmetric(ctx, jwks, token, "client", "https://idp.example", advertised)
		return err
	}
	for name, token := range map[string]string{
		"RS256": sign(jwt.SigningMethodRS256, "rsa", rsaKey),
		"RS512": sign(jwt.SigningMethodRS512, "rsa", rsaKey),
		"PS256": sign(jwt.SigningMethodPS256, "rsa", rsaKey),
		"ES256": sign(jwt.SigningMethodES256, "p256", p256),
		"ES384": sign(jwt.SigningMethodES384, "p384", p384),
	} {
		if err := verify(token); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	hmacWithPublicKey := sign(jwt.SigningMethodHS256, "rsa", rsaKey.N.Bytes())
	unsigned := sign(jwt.SigningMethodNone, "rsa", jwt.UnsafeAllowNoneSignatureType)
	for name, token := range map[string]string{
		"symmetric algorithm":    hmacWithPublicKey,
		"none":                   unsigned,
		"short RSA key":          sign(jwt.SigningMethodRS256, "weak", weak),
		"key pinned to RS256":    sign(jwt.SigningMethodPS256, "pinned", rsaKey),
		"ES256 with a P-384 key": sign(jwt.SigningMethodES256, "p384", p256),
		"RSA algorithm, EC key":  sign(jwt.SigningMethodRS256, "p256", rsaKey),
		"key off the curve":      sign(jwt.SigningMethodES256, "off", p256),
		"signed by another key":  sign(jwt.SigningMethodES256, "p256", mustP256(t)),
	} {
		if err := verify(token); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	// Only algorithms the issuer advertises verify, and only accepted ones count.
	es256 := sign(jwt.SigningMethodES256, "p256", p256)
	for name, list := range map[string][]string{"not advertised": {"RS256"}, "nothing advertised": nil, "only refused algorithms": {"HS256", "none"}} {
		if _, err := VerifyAsymmetric(ctx, jwks, es256, "client", "https://idp.example", list); err == nil {
			t.Errorf("%s: an ES256 token must be refused", name)
		}
	}
	if _, err := VerifyAsymmetric(ctx, jwks, es256, "client", "https://idp.example", []string{"ES256"}); err != nil {
		t.Errorf("advertised ES256: %v", err)
	}
	if _, err := VerifyRS256(ctx, jwks, sign(jwt.SigningMethodES256, "p256", p256), "client", ""); err == nil {
		t.Error("VerifyRS256 must stay pinned to RS256")
	}
	if _, err := VerifyRS256(ctx, jwks, sign(jwt.SigningMethodRS256, "weak", weak), "client", ""); err == nil {
		t.Error("VerifyRS256 must refuse an RSA key shorter than 2048 bits")
	}
	if _, err := jwks.KeyForKid(ctx, "p256"); err == nil {
		t.Error("KeyForKid returns RSA keys only")
	}
	if key, err := jwks.KeyForKid(ctx, "rsa"); err != nil || key.N.Cmp(rsaKey.N) != 0 {
		t.Errorf("KeyForKid(rsa) = %v", err)
	}
}

func mustP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
