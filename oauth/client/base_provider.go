package client

import (
	"context"
	"fmt"

	"github.com/nauticana/keel/logger"
	"golang.org/x/oauth2"
)

// BaseProvider is the embeddable engine implementing the default oauth2-library
// flow. Concrete providers set its config; ones with a non-standard auth shape
// override AuthURL/Callback on the outer struct. Four optional hooks cover the
// common variations without subclassing:
//
//	DeriveAPIEndpoint — per-connection api_endpoint (e.g. GBP account name)
//	DeriveCredential  — map exchanged token → stored credential (Meta long-lived swap)
//	PostCallback      — extra writes after UpsertConnection (GBP SaveRefreshToken)
//	TestHealthcheck   — custom Test API call (Meta query-string auth)
type BaseProvider struct {
	Service      CredentialStore
	CallbackURL  string
	ProviderName string
	ConnType     string                   // defaults to ConnTypeOAuth
	Journal      logger.ApplicationLogger // optional; logs provider-side failures (e.g. GBP discovery 429/403) instead of swallowing them

	ClientID        string
	SecretName      string
	Endpoint        oauth2.Endpoint
	Scopes          []string
	AuthCodeOptions []oauth2.AuthCodeOption
	RequireRefresh  bool // fail Callback when the exchange returns no refresh token

	APIEndpoint       string
	DeriveAPIEndpoint func(ctx context.Context, accessToken string) string
	DeriveCredential  func(ctx context.Context, t *oauth2.Token) (string, error)
	PostCallback      func(ctx context.Context, partnerID int64, t *oauth2.Token) error
	TestEndpoint      string // default Test does a bearer healthcheck here; empty = status-only
	TestHealthcheck   func(ctx context.Context, svc CredentialStore, partnerID int64, accessToken, apiEndpoint string) error
}

var _ Provider = (*BaseProvider)(nil)

func (b *BaseProvider) connType() string {
	if b.ConnType == "" {
		return ConnTypeOAuth
	}
	return b.ConnType
}

func (b *BaseProvider) oauthConfig(ctx context.Context) (*oauth2.Config, error) {
	if b.ClientID == "" || b.SecretName == "" {
		return nil, fmt.Errorf("%s: missing ClientID or SecretName", b.ProviderName)
	}
	secret, err := b.Service.GetSecret(ctx, b.SecretName)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", b.SecretName, err)
	}
	return &oauth2.Config{
		ClientID:     b.ClientID,
		ClientSecret: secret,
		Endpoint:     b.Endpoint,
		RedirectURL:  b.CallbackURL,
		Scopes:       b.Scopes,
	}, nil
}

// AuthURL is the default oauth2-library consent URL builder. Providers with a
// custom URL shape (PKCE, client_key) override this on the outer struct.
func (b *BaseProvider) AuthURL(ctx context.Context, partnerID int64, _ map[string]string) (string, error) {
	cfg, err := b.oauthConfig(ctx)
	if err != nil {
		return "", err
	}
	state, err := b.Service.CreateOAuthState(ctx, partnerID, b.ProviderName, nil)
	if err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(state, b.AuthCodeOptions...), nil
}

// Callback is the default exchange + persist flow. Providers with manual token
// exchanges override this on the outer struct.
func (b *BaseProvider) Callback(ctx context.Context, code, state string) error {
	cfg, err := b.oauthConfig(ctx)
	if err != nil {
		return err
	}
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("token exchange: %w", err)
	}
	if b.RequireRefresh && token.RefreshToken == "" {
		return fmt.Errorf("%s: no refresh token; re-authorize with prompt=consent", b.ProviderName)
	}
	partnerID, _, err := b.Service.ConsumeOAuthState(ctx, state, b.ProviderName)
	if err != nil {
		return err
	}
	credRef, err := b.deriveCredential(ctx, token)
	if err != nil {
		return err
	}
	apiEndpoint := b.APIEndpoint
	if b.DeriveAPIEndpoint != nil {
		apiEndpoint = b.DeriveAPIEndpoint(ctx, token.AccessToken)
	}
	if err := b.Service.UpsertConnection(ctx, partnerID, b.ProviderName, b.connType(), credRef, apiEndpoint); err != nil {
		return err
	}
	if b.PostCallback != nil {
		return b.PostCallback(ctx, partnerID, token)
	}
	return nil
}

// deriveCredential returns the value stored as the connection credential.
// Hook-overridable; default prefers the refresh token, falling back to access.
func (b *BaseProvider) deriveCredential(ctx context.Context, t *oauth2.Token) (string, error) {
	if b.DeriveCredential != nil {
		return b.DeriveCredential(ctx, t)
	}
	if t.RefreshToken != "" {
		return t.RefreshToken, nil
	}
	return t.AccessToken, nil
}

// Test refreshes the stored credential and optionally hits an API endpoint to
// confirm the resulting access token works, recording the outcome as the
// connection status.
func (b *BaseProvider) Test(ctx context.Context, partnerID int64) error {
	credRef, apiEndpoint, err := b.Service.GetConnectionCredentials(ctx, partnerID, b.ProviderName)
	if err != nil {
		return err
	}
	accessToken, err := b.Service.RefreshAccessToken(ctx, partnerID, b.ProviderName, credRef)
	if err != nil {
		return err
	}
	switch {
	case b.TestHealthcheck != nil:
		return b.TestHealthcheck(ctx, b.Service, partnerID, accessToken, apiEndpoint)
	case b.TestEndpoint != "":
		return bearerHealthcheck(ctx, b.Service, partnerID, b.ProviderName, b.connType(), b.TestEndpoint, accessToken)
	default:
		return b.Service.UpdateConnectionStatus(ctx, partnerID, b.ProviderName, b.connType(), ConnStatusActive)
	}
}
