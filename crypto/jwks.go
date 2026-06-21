package crypto

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

// jwksHardCap bounds how far past the soft TTL a cached key set stays
// usable. Past this window a refresh failure errors instead of serving
// keys the issuer may have rotated days ago (outage / DNS-hijack guard).
const jwksHardCap = 24 * time.Hour

// JWKSProvider caches a remote JWKS in memory, refreshing on the soft TTL
// or on an unknown `kid`. Shared by social ID-token verification and the
// OAuth 2.1 resource-server validator. Concurrent refreshes collapse to a
// single fetch via singleflight.
type JWKSProvider struct {
	url       string
	ttl       time.Duration
	httpc     *http.Client
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	sf        singleflight.Group
}

// NewJWKSProvider returns a provider for url. ttl is the soft cache
// lifetime; pass an *http.Client with a timeout (nil → 10s default).
func NewJWKSProvider(url string, ttl time.Duration, httpc *http.Client) *JWKSProvider {
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}
	return &JWKSProvider{url: url, ttl: ttl, httpc: httpc, keys: map[string]*rsa.PublicKey{}}
}

// KeyForKid returns the RSA public key for kid, refreshing on unknown kid
// or elapsed TTL. Concurrent misses dedup through a singleflight keyed on
// the URL. On refresh failure within jwksHardCap, the last good key is
// served; past the cap the error propagates.
func (p *JWKSProvider) KeyForKid(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.RLock()
	key, ok := p.keys[kid]
	stale := time.Since(p.fetchedAt) > p.ttl
	p.mu.RUnlock()
	if ok && !stale {
		return key, nil
	}
	if _, err, _ := p.sf.Do(p.url, func() (any, error) {
		p.mu.RLock()
		fresh := time.Since(p.fetchedAt) <= p.ttl
		p.mu.RUnlock()
		if fresh {
			return nil, nil
		}
		return nil, p.refresh(ctx)
	}); err != nil {
		p.mu.RLock()
		within := !p.fetchedAt.IsZero() && time.Since(p.fetchedAt) < jwksHardCap
		p.mu.RUnlock()
		if ok && within {
			return key, nil
		}
		return nil, err
	}
	p.mu.RLock()
	key, ok = p.keys[kid]
	p.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("jwks: kid %q not found", kid)
	}
	return key, nil
}

// refresh fetches the JWKS URL and atomically swaps the key map.
func (p *JWKSProvider) refresh(ctx context.Context) error {
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
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("jwks: parse: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
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
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: eInt}
	}
	p.mu.Lock()
	p.keys = keys
	p.fetchedAt = time.Now()
	p.mu.Unlock()
	return nil
}

// VerifyRS256 parses and validates an RS256 JWT against p, asserting
// expiry, audience, and (when non-empty) issuer. expectedAud is required.
// Returns the validated claims.
func VerifyRS256(ctx context.Context, p *JWKSProvider, tokenStr, expectedAud, expectedIss string) (jwt.MapClaims, error) {
	if expectedAud == "" {
		return nil, fmt.Errorf("jwks: expectedAud is required")
	}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(expectedAud),
	}
	if expectedIss != "" {
		opts = append(opts, jwt.WithIssuer(expectedIss))
	}
	tok, err := jwt.NewParser(opts...).ParseWithClaims(tokenStr, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("jwks: missing kid header")
		}
		return p.KeyForKid(ctx, kid)
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
