package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

// jwksHardCap bounds how far past the soft TTL a cached key set stays
// usable. Past this window a refresh failure errors instead of serving
// keys the issuer may have rotated days ago (outage / DNS-hijack guard).
const jwksHardCap = 24 * time.Hour

// jwksMissRefreshInterval spaces refreshes forced by an unknown kid, so
// attacker-chosen kids cannot hammer the issuer's JWKS endpoint.
const jwksMissRefreshInterval = 30 * time.Second

// jwtLeeway tolerates clock skew between keel and the token issuer.
const jwtLeeway = 60 * time.Second

// JWKSProvider caches a remote JWKS in memory, refreshing on the soft TTL
// or on an unknown `kid`. Shared by social ID-token verification and the
// OAuth 2.1 resource-server validator. Concurrent refreshes collapse to a
// single fetch via singleflight.
type JWKSProvider struct {
	url         string
	ttl         time.Duration
	httpc       *http.Client
	now         func() time.Time
	mu          sync.RWMutex
	keys        map[string]jwk
	fetchedAt   time.Time
	attemptedAt time.Time
	sf          singleflight.Group
}

// NewJWKSProvider returns a provider for url. ttl is the soft cache
// lifetime; pass an *http.Client with a timeout (nil → 10s default).
func NewJWKSProvider(url string, ttl time.Duration, httpc *http.Client) *JWKSProvider {
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}
	return &JWKSProvider{url: url, ttl: ttl, httpc: httpc, now: time.Now, keys: map[string]jwk{}}
}

// jwk is one parsed key: an *rsa.PublicKey or *ecdsa.PublicKey, and the
// algorithm the key set pins it to, when it names one.
type jwk struct {
	key any
	alg string
}

// KeyForKid returns the RSA public key for kid, refreshing on elapsed TTL
// or on an unknown kid (at most once per jwksMissRefreshInterval).
// Concurrent misses dedup through a singleflight keyed on the URL. On
// refresh failure within jwksHardCap, the last good key is served; past the
// cap the error propagates.
func (p *JWKSProvider) KeyForKid(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	k, err := p.keyForKid(ctx, kid)
	if err != nil {
		return nil, err
	}
	key, ok := k.key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jwks: kid %q is not an RSA key", kid)
	}
	return key, nil
}

func (p *JWKSProvider) keyForKid(ctx context.Context, kid string) (jwk, error) {
	p.mu.RLock()
	key, ok := p.keys[kid]
	stale := p.now().Sub(p.fetchedAt) > p.ttl
	p.mu.RUnlock()
	if ok && !stale {
		return key, nil
	}
	if _, err, _ := p.sf.Do(p.url, func() (any, error) {
		now := p.now()
		p.mu.RLock()
		_, known := p.keys[kid]
		fresh := now.Sub(p.fetchedAt) <= p.ttl
		throttled := now.Sub(p.attemptedAt) < jwksMissRefreshInterval
		p.mu.RUnlock()
		if fresh && (known || throttled) {
			return nil, nil
		}
		return nil, p.refresh(ctx)
	}); err != nil {
		p.mu.RLock()
		within := !p.fetchedAt.IsZero() && p.now().Sub(p.fetchedAt) < jwksHardCap
		p.mu.RUnlock()
		if ok && within {
			return key, nil
		}
		return jwk{}, err
	}
	p.mu.RLock()
	key, ok = p.keys[kid]
	p.mu.RUnlock()
	if !ok {
		return jwk{}, fmt.Errorf("jwks: kid %q not found", kid)
	}
	return key, nil
}

// refresh fetches the JWKS URL and atomically swaps the key map.
func (p *JWKSProvider) refresh(ctx context.Context) error {
	p.mu.Lock()
	p.attemptedAt = p.now()
	p.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return fmt.Errorf("jwks: build request: %w", err)
	}
	resp, err := p.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	// JWKS documents are a few KB; cap the body — anything larger is suspicious.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("jwks: read: %w", err)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("jwks: parse: %w", err)
	}
	keys := make(map[string]jwk, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Kty == "EC" {
			if key := ecKey(k.Crv, k.X, k.Y); key != nil {
				keys[k.Kid] = jwk{key: key, alg: k.Alg}
			}
			continue
		}
		if k.Kty != "RSA" || k.N == "" || k.E == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		eInt := 0
		for _, b := range eBytes {
			eInt = eInt<<8 | int(b)
		}
		if eInt == 0 {
			continue
		}
		keys[k.Kid] = jwk{key: &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: eInt}, alg: k.Alg}
	}
	p.mu.Lock()
	p.keys = keys
	p.fetchedAt = p.now()
	p.mu.Unlock()
	return nil
}

// VerifyRS256 parses and validates an RS256 JWT against p, asserting
// expiry, audience, and (when non-empty) issuer, with an RSA key of at least
// 2048 bits. expectedAud is required. Returns the validated claims.
func VerifyRS256(ctx context.Context, p *JWKSProvider, tokenStr, expectedAud, expectedIss string) (jwt.MapClaims, error) {
	return verify(ctx, p, tokenStr, expectedAud, expectedIss, []string{"RS256"})
}

// asymmetricAlgorithms are the signature algorithms VerifyAsymmetric accepts.
// Symmetric algorithms and "none" are never accepted.
var asymmetricAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"}

const minRSABits = 2048

// VerifyAsymmetric validates an ID token from an issuer that may sign with
// an RSA or ECDSA algorithm, asserting expiry, audience and (when non-empty)
// issuer. advertised is the issuer's id_token_signing_alg_values_supported;
// only algorithms in both it and the accepted list verify. The key must suit
// the algorithm: RSA keys are at least 2048 bits, an EC key matches the
// algorithm's curve, and a key the set pins to another algorithm is refused.
func VerifyAsymmetric(ctx context.Context, p *JWKSProvider, tokenStr, expectedAud, expectedIss string, advertised []string) (jwt.MapClaims, error) {
	var algorithms []string
	for _, alg := range asymmetricAlgorithms {
		if slices.Contains(advertised, alg) {
			algorithms = append(algorithms, alg)
		}
	}
	if len(algorithms) == 0 {
		return nil, fmt.Errorf("jwks: the issuer advertises no accepted signing algorithm")
	}
	return verify(ctx, p, tokenStr, expectedAud, expectedIss, algorithms)
}

// verify refuses a `crit` header: keel understands no JWS extension
// (RFC 7515 §4.1.11).
func verify(ctx context.Context, p *JWKSProvider, tokenStr, expectedAud, expectedIss string, algorithms []string) (jwt.MapClaims, error) {
	if expectedAud == "" {
		return nil, fmt.Errorf("jwks: expectedAud is required")
	}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(algorithms),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(jwtLeeway),
		jwt.WithAudience(expectedAud),
	}
	if expectedIss != "" {
		opts = append(opts, jwt.WithIssuer(expectedIss))
	}
	tok, err := jwt.NewParser(opts...).ParseWithClaims(tokenStr, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Header["crit"]; ok {
			return nil, fmt.Errorf("jwks: unsupported critical header parameters")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("jwks: missing kid header")
		}
		k, err := p.keyForKid(ctx, kid)
		if err != nil {
			return nil, err
		}
		alg := t.Method.Alg()
		if k.alg != "" && k.alg != alg {
			return nil, fmt.Errorf("jwks: kid %q is pinned to %s, token uses %s", kid, k.alg, alg)
		}
		switch key := k.key.(type) {
		case *rsa.PublicKey:
			if key.N.BitLen() < minRSABits {
				return nil, fmt.Errorf("jwks: kid %q RSA key is shorter than %d bits", kid, minRSABits)
			}
		case *ecdsa.PublicKey:
			if want := map[string]string{"ES256": "P-256", "ES384": "P-384"}[alg]; key.Curve.Params().Name != want {
				return nil, fmt.Errorf("jwks: kid %q curve does not suit %s", kid, alg)
			}
		}
		return k.key, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("jwks: invalid token")
	}
	return claims, nil
}

// ecKey parses a P-256 or P-384 public key, or returns nil when the
// coordinates are malformed or not on the curve.
func ecKey(crv, x, y string) *ecdsa.PublicKey {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil
	}
	xb, errX := base64.RawURLEncoding.DecodeString(x)
	yb, errY := base64.RawURLEncoding.DecodeString(y)
	if errX != nil || errY != nil || len(xb) == 0 || len(yb) == 0 {
		return nil
	}
	key := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if _, err := key.ECDH(); err != nil {
		return nil
	}
	return key
}
