package authserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/oauth/claims"
	"github.com/nauticana/keel/port"
)

// RS256Signer is the local-AS TokenSigner: it mints RS256 access tokens with a
// single RSA key and publishes that key's public half as a one-entry JWKS. kid
// is the RFC 7638 thumbprint, so it is stable across restarts that load the
// same key and changes when the key rotates.
type RS256Signer struct {
	priv *rsa.PrivateKey
	kid  string
}

var _ port.TokenSigner = (*RS256Signer)(nil)

// NewRS256Signer builds a signer from a PEM-encoded RSA private key (PKCS#1 or
// PKCS#8). Use a key loaded from the keystore so all nodes sign alike.
func NewRS256Signer(privPEM string) (*RS256Signer, error) {
	priv, err := parseRSAPrivateKey(privPEM)
	if err != nil {
		return nil, err
	}
	return &RS256Signer{priv: priv, kid: thumbprint(&priv.PublicKey)}, nil
}

// NewEphemeralRS256Signer generates a throwaway 2048-bit key — dev/single-node
// only; issued tokens die on restart and differ per node.
func NewEphemeralRS256Signer() (*RS256Signer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &RS256Signer{priv: priv, kid: thumbprint(&priv.PublicKey)}, nil
}

func (s *RS256Signer) Sign(_ context.Context, claims map[string]any) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	tok.Header["kid"] = s.kid
	return tok.SignedString(s.priv)
}

func (s *RS256Signer) KeyID() string { return s.kid }

func (s *RS256Signer) JWKS() port.JWKS {
	pub := s.priv.PublicKey
	return port.JWKS{Keys: []port.JWK{{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: s.kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}}
}

// PublicKey exposes the verification key so a local-mode resource-server
// validator can verify in-process, without an HTTP JWKS round-trip to self.
func (s *RS256Signer) PublicKey() *rsa.PublicKey { return &s.priv.PublicKey }

// LocalValidator verifies tokens minted by an in-process RS256Signer
// (local AS mode), asserting issuer, audience, expiry, and sub — the same
// guarantees as the JWKS-backed JWTValidator but without the HTTP fetch. With a
// single audience it pins it (resource-server use); with several it accepts a
// token whose aud matches any (the AS's own introspection / token-exchange
// across every resource it mints for).
type LocalValidator struct {
	signer    *RS256Signer
	issuer    string
	audiences []string
}

var _ port.TokenValidator = (*LocalValidator)(nil)

func NewLocalValidator(signer *RS256Signer, issuer, audience string) *LocalValidator {
	return &LocalValidator{signer: signer, issuer: issuer, audiences: []string{audience}}
}

// NewLocalValidatorMulti accepts a token whose audience matches ANY of
// audiences — for AS-internal introspection / token-exchange across resources.
func NewLocalValidatorMulti(signer *RS256Signer, issuer string, audiences []string) *LocalValidator {
	return &LocalValidator{signer: signer, issuer: issuer, audiences: audiences}
}

func (v *LocalValidator) Validate(_ context.Context, bearer string) (*port.Principal, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(v.issuer),
	}
	if len(v.audiences) == 1 {
		opts = append(opts, jwt.WithAudience(v.audiences[0]))
	}
	tok, err := jwt.NewParser(opts...).ParseWithClaims(bearer, jwt.MapClaims{}, func(*jwt.Token) (any, error) {
		return v.signer.PublicKey(), nil
	})
	if err != nil {
		return nil, err
	}
	mc, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("oauth: invalid token")
	}
	if len(v.audiences) > 1 && !audienceAllowed(mc["aud"], v.audiences) {
		return nil, fmt.Errorf("oauth: token audience not in allowed set")
	}
	return claims.Principal(mc)
}

// audienceAllowed reports whether the token's aud claim intersects allowed.
func audienceAllowed(raw any, allowed []string) bool {
	for _, aud := range claims.Audience(raw) {
		if slices.Contains(allowed, aud) {
			return true
		}
	}
	return false
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("oauth signer: no PEM block in signing key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("oauth signer: parse private key: %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("oauth signer: signing key is not RSA")
	}
	return key, nil
}

// thumbprint is the RFC 7638 JWK SHA-256 thumbprint (base64url) of the public
// key — a deterministic, collision-resistant kid.
func thumbprint(pub *rsa.PublicKey) string {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	canonical := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
