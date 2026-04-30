package handler

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

// jwksHardCap bounds how far past the soft TTL the cache is considered
// usable. Past this window every refresh failure returns an error to
// the caller instead of silently serving stale keys. Without the hard
// cap, a long-running upstream outage / DNS hijack could keep the
// process validating against keys that the issuer rotated days ago.
// 24h is generous enough that a single bad day at the issuer doesn't
// cause cascading verify failures, but tight enough that genuinely
// retired keys leave the cache.
const jwksHardCap = 24 * time.Hour

// jwksProvider caches a remote JWKs set in memory and refreshes it on a
// timer. Used by the Google and Apple ID-token verifiers so keel no
// longer relies on Google's `tokeninfo` debug endpoint or, worse, Apple
// JWTs whose signature is never checked at all.
//
// The cache holds parsed RSA public keys keyed by the `kid` header. On
// cache miss (unknown kid in the inbound token) the provider re-fetches
// the JWKs URL synchronously — Apple and Google both rotate keys
// occasionally, and the unknown-kid path is the standard signal.
type jwksProvider struct {
	url       string
	ttl       time.Duration
	httpc     *http.Client
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time

	// sf deduplicates concurrent refresh calls (v0.4.3 perf). At an
	// Apple/Google key rotation, N inbound requests carry the new
	// `kid` simultaneously and all miss the cache. Without
	// singleflight every one of them fires its own JWKs HTTPS
	// fetch — N round-trips, N JSON parses, N map rebuilds. With
	// singleflight only the first request actually fetches; the
	// rest block until that fetch completes and reuse the result.
	sf singleflight.Group
}

// newJWKsProvider returns a provider configured for the given URL. ttl
// is the soft cache lifetime; once exceeded the next verify will
// refresh. Pass http.DefaultClient with a timeout — the provider does
// not enforce its own.
func newJWKsProvider(url string, ttl time.Duration, httpc *http.Client) *jwksProvider {
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}
	return &jwksProvider{url: url, ttl: ttl, httpc: httpc, keys: map[string]*rsa.PublicKey{}}
}

// keyForKid returns the RSA public key matching kid, refreshing the
// cache if either the kid is unknown or the soft TTL has elapsed.
//
// Concurrent misses are deduplicated through a singleflight.Group
// keyed on the constant URL — every refresh in flight collapses to
// a single HTTPS fetch regardless of how many goroutines requested
// it (v0.4.3 perf). The singleflight key is the JWKs URL because
// that's the unit-of-work; per-kid keys would still let N kids
// trigger N fetches, which is exactly what we're avoiding.
func (p *jwksProvider) keyForKid(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.RLock()
	key, ok := p.keys[kid]
	stale := time.Since(p.fetchedAt) > p.ttl
	p.mu.RUnlock()
	if ok && !stale {
		return key, nil
	}
	if _, err, _ := p.sf.Do(p.url, func() (any, error) {
		// Inside the singleflight closure: re-check freshness now
		// that we hold the de-dup slot. A previous goroutine that
		// just completed could have populated the cache; in that
		// case skip the network fetch entirely.
		p.mu.RLock()
		fresh := time.Since(p.fetchedAt) <= p.ttl
		p.mu.RUnlock()
		if fresh {
			return nil, nil
		}
		return nil, p.refresh(ctx)
	}); err != nil {
		// On refresh failure, fall back to whatever we already have
		// so the verify path doesn't hard-fail on a transient JWKs
		// outage. BUT only within jwksHardCap: past that window we
		// refuse to serve potentially-retired keys, since a long-
		// running upstream outage / DNS hijack could otherwise let
		// the process keep validating against keys the issuer
		// rotated days ago.
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

// refresh fetches the JWKs URL and rebuilds the in-memory key map.
// Atomically swaps so concurrent reads always see a consistent set.
func (p *jwksProvider) refresh(ctx context.Context) error {
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
	// Cap the response body — JWKs documents are small (a few KB);
	// anything larger is suspicious.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("jwks: read: %w", err)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
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
		// Common 'e' value is 65537 (0x010001). Accept any positive
		// big-endian-encoded integer that fits in int.
		eInt := 0
		for _, b := range eBytes {
			eInt = eInt<<8 | int(b)
		}
		if eInt == 0 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: eInt,
		}
	}
	p.mu.Lock()
	p.keys = keys
	p.fetchedAt = time.Now()
	p.mu.Unlock()
	return nil
}

// verifyJWKsToken parses and validates an RS256 JWT against the given
// JWKs provider, asserting the audience and (optionally) issuer. Returns
// the validated claims on success.
//
// expectedAud is required (Apple and Google both reject unaudienced
// tokens). expectedIss may be empty when caller wants to skip issuer
// validation; when set, the token's `iss` claim must match exactly.
func verifyJWKsToken(ctx context.Context, p *jwksProvider, tokenStr, expectedAud, expectedIss string) (jwt.MapClaims, error) {
	if expectedAud == "" {
		return nil, fmt.Errorf("jwks: expectedAud is required")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(expectedAud),
	)
	if expectedIss != "" {
		parser = jwt.NewParser(
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithExpirationRequired(),
			jwt.WithAudience(expectedAud),
			jwt.WithIssuer(expectedIss),
		)
	}
	tok, err := parser.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("jwks: missing kid header")
		}
		return p.keyForKid(ctx, kid)
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
