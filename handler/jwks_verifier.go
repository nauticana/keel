package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/crypto"
)

// JWKS verification moved to crypto.JWKSProvider in keel 1.2.0 so social
// ID-token verification and the OAuth 2.1 resource-server validator share
// one implementation. These aliases keep the social handler call sites
// unchanged.

type jwksProvider = crypto.JWKSProvider

func newJWKsProvider(url string, ttl time.Duration, httpc *http.Client) *crypto.JWKSProvider {
	return crypto.NewJWKSProvider(url, ttl, httpc)
}

func verifyJWKsToken(ctx context.Context, p *crypto.JWKSProvider, tokenStr, expectedAud, expectedIss string) (jwt.MapClaims, error) {
	return crypto.VerifyRS256(ctx, p, tokenStr, expectedAud, expectedIss)
}
