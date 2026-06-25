package resource

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/oauth/claims"
	"github.com/nauticana/keel/port"
)

const oauthJWKSCacheTTL = time.Hour

// JWTValidator is a JWKS-backed OAuth 2.1 resource-server token validator:
// it verifies RS256 access tokens against one authorization server's JWKS,
// asserting audience (RFC 8707) and issuer.
type JWTValidator struct {
	jwks     *crypto.JWKSProvider
	issuer   string
	audience string
}

var _ port.TokenValidator = (*JWTValidator)(nil)

// NewJWTValidator builds a validator for one trusted issuer. audience is the
// protected-resource identifier access tokens must target; both are required.
func NewJWTValidator(jwksURL, issuer, audience string, httpc *http.Client) *JWTValidator {
	return &JWTValidator{
		jwks:     crypto.NewJWKSProvider(jwksURL, oauthJWKSCacheTTL, httpc),
		issuer:   issuer,
		audience: audience,
	}
}

// NewJWTValidatorFromFlags builds a validator from the --oauth_* flags:
// (nil, nil) when --oauth_issuer is unset; an error when it is set but
// --oauth_jwks_url or --oauth_audience is empty (fail fast). Returns the
// interface so the disabled case is a true nil a `!= nil` guard catches.
func NewJWTValidatorFromFlags(httpc *http.Client) (port.TokenValidator, error) {
	if *common.OAuthIssuer == "" {
		return nil, nil
	}
	if *common.OAuthJWKSURL == "" || *common.OAuthAudience == "" {
		return nil, fmt.Errorf("oauth: --oauth_issuer is set but --oauth_jwks_url or --oauth_audience is empty")
	}
	return NewJWTValidator(*common.OAuthJWKSURL, *common.OAuthIssuer, *common.OAuthAudience, httpc), nil
}

func (v *JWTValidator) Validate(ctx context.Context, bearer string) (*port.Principal, error) {
	mc, err := crypto.VerifyRS256(ctx, v.jwks, bearer, v.audience, v.issuer)
	if err != nil {
		return nil, err
	}
	return claims.Principal(mc)
}
