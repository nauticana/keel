package oidc

import (
	"context"
	"fmt"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/port"
)

// First-party providers whose ID tokens a client obtains itself and posts.
const (
	ProviderGoogle = "google"
	ProviderApple  = "apple"

	GoogleIssuer = "https://accounts.google.com"
	AppleIssuer  = "https://appleid.apple.com"

	googleBareIssuer = "accounts.google.com"
	googleKeysURL    = "https://www.googleapis.com/oauth2/v3/certs"
	appleKeysURL     = "https://appleid.apple.com/auth/keys"
)

var (
	defaultKeysOnce sync.Once
	defaultGoogle   *crypto.JWKSProvider
	defaultApple    *crypto.JWKSProvider
)

// SocialVerifier verifies Google and Apple ID tokens against google_client_id
// and apple_client_id. A provider without a client id is ErrProviderDisabled.
// Nil key sets use the providers' published keys.
type SocialVerifier struct {
	GoogleKeys *crypto.JWKSProvider
	AppleKeys  *crypto.JWKSProvider
}

// Verify returns the identity, with the canonical issuer, and the token's
// nonce for the caller's replay check. Both providers sign with RS256 only.
// A Google azp is not checked: a mobile client's token names the server
// client as aud and its own platform client of the same project as azp.
func (v *SocialVerifier) Verify(ctx context.Context, provider, token string) (*port.IdentityAssertion, string, error) {
	googleKeys, appleKeys := v.keys()
	var (
		claims jwt.MapClaims
		issuer string
		err    error
	)
	switch provider {
	case ProviderGoogle:
		aud := config.Config().GoogleClientID
		if aud == "" {
			return nil, "", ErrProviderDisabled
		}
		if claims, err = crypto.VerifyRS256(ctx, googleKeys, token, aud, ""); err != nil {
			return nil, "", err
		}
		if iss, _ := claims["iss"].(string); iss != GoogleIssuer && iss != googleBareIssuer {
			return nil, "", fmt.Errorf("%w: google issuer %q", ErrInvalidResponse, iss)
		}
		if err := checkSoleAudience(claims, aud); err != nil {
			return nil, "", err
		}
		issuer = GoogleIssuer
	case ProviderApple:
		aud := config.Config().AppleClientID
		if aud == "" {
			return nil, "", ErrProviderDisabled
		}
		if claims, err = crypto.VerifyRS256(ctx, appleKeys, token, aud, AppleIssuer); err != nil {
			return nil, "", err
		}
		if err := checkAudience(claims, aud); err != nil {
			return nil, "", err
		}
		issuer = AppleIssuer
	default:
		return nil, "", ErrProviderDisabled
	}
	a, err := assertionFromClaims(issuer, claims, "", "")
	if err != nil {
		return nil, "", err
	}
	nonce, _ := claims["nonce"].(string)
	return a, nonce, nil
}

func (v *SocialVerifier) keys() (*crypto.JWKSProvider, *crypto.JWKSProvider) {
	return googleKeySet(v.GoogleKeys), appleKeySet(v.AppleKeys)
}

func googleKeySet(set *crypto.JWKSProvider) *crypto.JWKSProvider {
	if set != nil {
		return set
	}
	defaultKeysOnce.Do(initDefaultKeys)
	return defaultGoogle
}

func appleKeySet(set *crypto.JWKSProvider) *crypto.JWKSProvider {
	if set != nil {
		return set
	}
	defaultKeysOnce.Do(initDefaultKeys)
	return defaultApple
}

func initDefaultKeys() {
	ttl := config.Config().SocialJWKSCacheTTL
	defaultGoogle = crypto.NewJWKSProvider(googleKeysURL, ttl, common.HTTPClient())
	defaultApple = crypto.NewJWKSProvider(appleKeysURL, ttl, common.HTTPClient())
}
