package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/crypto"
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
	claims, err := crypto.VerifyRS256(ctx, v.jwks, bearer, v.audience, v.issuer)
	if err != nil {
		return nil, err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("oauth: token missing sub claim")
	}
	iss, _ := claims["iss"].(string)
	return &port.Principal{
		Subject:  sub,
		Issuer:   iss,
		Audience: audienceClaim(claims["aud"]),
		Scopes:   scopeClaim(claims),
		Claims:   claims,
	}, nil
}

// scopeClaim reads OAuth scopes from the space-delimited `scope` string
// (RFC 8693) or a `scp` array (Entra and others).
func scopeClaim(claims map[string]any) []string {
	if s, ok := claims["scope"].(string); ok && s != "" {
		return strings.Fields(s)
	}
	if arr, ok := claims["scp"].([]any); ok {
		out := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func audienceClaim(raw any) []string {
	switch a := raw.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, v := range a {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
