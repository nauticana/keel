package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestRS256SignerRoundTrip(t *testing.T) {
	signer, err := NewEphemeralRS256Signer()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := signer.Sign(context.Background(), map[string]any{
		"iss": "https://as.example", "sub": "user:1", "aud": "https://rs.example",
		"exp": 9999999999, "scope": "read write",
	})
	if err != nil {
		t.Fatal(err)
	}
	v := NewLocalJWTValidator(signer, "https://as.example", "https://rs.example")
	p, err := v.Validate(context.Background(), tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if p.Subject != "user:1" {
		t.Fatalf("sub = %q", p.Subject)
	}
	if len(p.Scopes) != 2 || p.Scopes[0] != "read" {
		t.Fatalf("scopes = %v", p.Scopes)
	}
}

func TestRS256SignerWrongAudienceRejected(t *testing.T) {
	signer, _ := NewEphemeralRS256Signer()
	tok, _ := signer.Sign(context.Background(), map[string]any{
		"iss": "https://as.example", "sub": "u", "aud": "https://other", "exp": 9999999999,
	})
	v := NewLocalJWTValidator(signer, "https://as.example", "https://rs.example")
	if _, err := v.Validate(context.Background(), tok); err == nil {
		t.Fatal("want audience mismatch rejected")
	}
}

func TestJWKSHasSigningKey(t *testing.T) {
	signer, _ := NewEphemeralRS256Signer()
	jwks := signer.JWKS()
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kid != signer.KeyID() || jwks.Keys[0].Kty != "RSA" {
		t.Fatalf("jwks = %+v", jwks)
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if !verifyPKCE(verifier, challenge, "S256") {
		t.Fatal("valid S256 should pass")
	}
	if verifyPKCE("wrong", challenge, "S256") {
		t.Fatal("wrong verifier should fail")
	}
	if verifyPKCE(verifier, verifier, "plain") {
		t.Fatal("plain must be rejected (OAuth 2.1)")
	}
	if verifyPKCE("", "", "S256") {
		t.Fatal("empty should fail")
	}
}
