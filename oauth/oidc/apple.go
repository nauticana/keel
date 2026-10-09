package oidc

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/secret"
)

const (
	appleTokenURL     = "https://appleid.apple.com/auth/token"
	appleRevokeURL    = "https://appleid.apple.com/auth/revoke"
	appleSecretTTL    = 5 * time.Minute
	appleRevokeMaxErr = 64 << 10
)

// AppleGrants redeems the authorization code a Sign in with Apple client
// receives beside its ID token, and revokes the resulting grant when the
// account is deleted, as Apple requires. The refresh token leaves this type
// only sealed. Empty endpoints use Apple's.
type AppleGrants struct {
	TokenURL    string
	RevokeURL   string
	RedirectURI string               // the web flow's redirect URI; empty for native apps
	HTTP        *http.Client         // nil = common.HTTPClient()
	AppleKeys   *crypto.JWKSProvider // nil = Apple's published keys

	clientID string
	teamID   string
	keyID    string
	key      *ecdsa.PrivateKey
	sealer   *crypto.Sealer
}

var _ port.IdentityGrantRevoker = (*AppleGrants)(nil)

// NewAppleGrants reads apple_client_id, apple_team_id and apple_key_id, and
// the .p8 PEM from the secret named by apple_key_secret. sealer seals the
// refresh tokens it returns.
func NewAppleGrants(ctx context.Context, secrets secret.SecretProvider, sealer *crypto.Sealer) (*AppleGrants, error) {
	cfg := config.Config()
	if cfg.AppleClientID == "" || cfg.AppleTeamID == "" || cfg.AppleKeyID == "" {
		return nil, fmt.Errorf("%w: apple_client_id, apple_team_id and apple_key_id are required", ErrBadConfiguration)
	}
	if secrets == nil || sealer == nil {
		return nil, fmt.Errorf("%w: apple grants need a secret provider and a sealer", ErrBadConfiguration)
	}
	pem, err := secrets.GetSecret(ctx, cfg.AppleKeySecret)
	if err != nil {
		return nil, fmt.Errorf("oidc: read secret %q: %w", cfg.AppleKeySecret, err)
	}
	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(pem))
	if err != nil {
		return nil, fmt.Errorf("%w: apple key: %v", ErrBadConfiguration, err)
	}
	return &AppleGrants{clientID: cfg.AppleClientID, teamID: cfg.AppleTeamID, keyID: cfg.AppleKeyID, key: key, sealer: sealer}, nil
}

// Redeem exchanges code for a refresh token and returns it sealed. The grant
// must belong to subject, the verified ID token's sub. A refused code is
// *TokenError.
func (a *AppleGrants) Redeem(ctx context.Context, code, subject string) (string, error) {
	if err := a.ready(); err != nil {
		return "", err
	}
	if code == "" || subject == "" {
		return "", fmt.Errorf("%w: apple code and subject are required", ErrInvalidResponse)
	}
	assertion, err := a.clientSecret(time.Now())
	if err != nil {
		return "", err
	}
	form := url.Values{"code": {code}, "grant_type": {"authorization_code"}}
	if a.RedirectURI != "" {
		form.Set("redirect_uri", a.RedirectURI)
	}
	set, err := exchangeCode(ctx, a.httpClient(), endpointOr(a.TokenURL, appleTokenURL), a.clientID, ClientCredential{Method: AuthSecretPost, Secret: assertion}, form)
	if err != nil {
		return "", err
	}
	if set.RefreshToken == "" || set.IDToken == "" {
		return "", &TokenError{}
	}
	claims, err := crypto.VerifyRS256(ctx, appleKeySet(a.AppleKeys), set.IDToken, a.clientID, AppleIssuer)
	if err != nil {
		return "", fmt.Errorf("%w: apple id_token: %v", ErrInvalidResponse, err)
	}
	if err := checkAudience(claims, a.clientID); err != nil {
		return "", err
	}
	if sub, _ := claims["sub"].(string); sub != subject {
		return "", fmt.Errorf("%w: apple code belongs to another account", ErrInvalidResponse)
	}
	return a.sealer.Seal(set.RefreshToken)
}

// RevokeGrant revokes a refresh token Redeem returned, which ends the user's
// authorization of the app.
func (a *AppleGrants) RevokeGrant(ctx context.Context, issuer, sealedGrant string) error {
	if err := a.ready(); err != nil {
		return err
	}
	if issuer != AppleIssuer {
		return fmt.Errorf("%w: apple cannot revoke a grant from %q", ErrBadConfiguration, issuer)
	}
	token, err := a.sealer.Open(sealedGrant)
	if err != nil {
		return fmt.Errorf("oidc: open apple grant: %w", err)
	}
	assertion, err := a.clientSecret(time.Now())
	if err != nil {
		return err
	}
	form := url.Values{"client_id": {a.clientID}, "client_secret": {assertion}, "token": {token}, "token_type_hint": {"refresh_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointOr(a.RevokeURL, appleRevokeURL), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	noRedirect := *a.httpClient()
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: apple revoke: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, appleRevokeMaxErr))
	if err != nil {
		return fmt.Errorf("oidc: read apple revoke response: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var failure tokenErrorBody
	if json.Unmarshal(body, &failure) != nil || failure.Error == "" {
		return fmt.Errorf("oidc: apple revoke: http status %d", resp.StatusCode)
	}
	return &TokenError{Code: failure.Error, Description: failure.ErrorDescription}
}

// clientSecret is the ES256 JWT Apple takes as client_secret.
func (a *AppleGrants) clientSecret(now time.Time) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": a.teamID,
		"sub": a.clientID,
		"aud": AppleIssuer,
		"iat": now.Unix(),
		"exp": now.Add(appleSecretTTL).Unix(),
	})
	t.Header["kid"] = a.keyID
	signed, err := t.SignedString(a.key)
	if err != nil {
		return "", fmt.Errorf("oidc: sign apple client secret: %w", err)
	}
	return signed, nil
}

func (a *AppleGrants) ready() error {
	if a.key == nil || a.sealer == nil {
		return fmt.Errorf("%w: apple grants are not configured; use NewAppleGrants", ErrBadConfiguration)
	}
	return nil
}

func (a *AppleGrants) httpClient() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return common.HTTPClient()
}

func endpointOr(set, fallback string) string {
	if set != "" {
		return set
	}
	return fallback
}
