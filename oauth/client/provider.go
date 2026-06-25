// Package client is keel's OAuth2 client framework: on behalf of each partner it
// connects an app to external providers (Google APIs, Meta, …) and persists the
// resulting credentials. Every provider shares one engine (BaseProvider) and
// differs only by config + optional hooks; persistence is the app's, behind
// CredentialStore.
package client

import "context"

// Connection type + status codes stored on a partner connection.
const (
	ConnTypeOAuth    = "O"
	ConnStatusActive = "A"
	ConnStatusError  = "E"
)

// Provider is one partner-scoped OAuth connection flow: AuthURL starts consent,
// Callback finishes it (exchange + persist), Test re-validates stored creds.
type Provider interface {
	AuthURL(ctx context.Context, partnerID int64, params map[string]string) (string, error)
	Callback(ctx context.Context, code, state string) error
	Test(ctx context.Context, partnerID int64) error
}

// CredentialStore is the persistence the providers depend on; the app implements
// it (e.g. over a partner_credential table), which keeps this package free of any
// schema coupling. extra on the state methods carries provider-specific values
// (e.g. a shop domain) across the consent redirect.
type CredentialStore interface {
	CreateOAuthState(ctx context.Context, partnerID int64, provider string, extra map[string]string) (string, error)
	ConsumeOAuthState(ctx context.Context, state, provider string) (partnerID int64, extra map[string]string, err error)
	UpsertConnection(ctx context.Context, partnerID int64, provider, connType, credRef, apiEndpoint string) error
	UpdateConnectionStatus(ctx context.Context, partnerID int64, provider, connType, status string) error
	GetConnectionCredentials(ctx context.Context, partnerID int64, provider string) (credRef, apiEndpoint string, err error)
	SaveRefreshToken(ctx context.Context, partnerID int64, provider, refreshToken string) error
	RefreshAccessToken(ctx context.Context, partnerID int64, provider, refreshToken string) (string, error)
	GetSecret(ctx context.Context, key string) (string, error)
}
