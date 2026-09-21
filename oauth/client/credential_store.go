package client

import (
	"context"
)

// Connection is one partner connection as it is persisted. GrantedScopes is
// what the provider returned at the exchange, or the requested set when the
// provider omitted scope under RFC 6749 §5.1; empty when neither is known.
type Connection struct {
	Provider      string
	ConnType      string
	CredRef       string
	APIEndpoint   string
	GrantedScopes []string
}

// CredentialStore is the persistence the providers depend on; the app implements
// it (e.g. over a partner_credential table), which keeps this package free of any
// schema coupling. extra on the state methods carries provider-specific values
// (e.g. a shop domain) across the consent redirect.
type CredentialStore interface {
	CreateOAuthState(ctx context.Context, partnerID int64, provider string, extra map[string]string) (string, error)
	ConsumeOAuthState(ctx context.Context, state, provider string) (partnerID int64, extra map[string]string, err error)
	UpsertConnection(ctx context.Context, partnerID int64, conn Connection) error
	UpdateConnectionStatus(ctx context.Context, partnerID int64, provider, connType, status string) error
	GetConnectionCredentials(ctx context.Context, partnerID int64, provider string) (credRef, apiEndpoint string, err error)
	// GrantedScopes returns the scopes the stored connection carries, so a
	// feature can tell a too-narrow grant from a missing connection before it
	// calls the provider and gets a 403.
	GrantedScopes(ctx context.Context, partnerID int64, provider string) ([]string, error)
	// RefreshAccessToken re-reads the stored credential and mints a fresh access
	// token, persisting any rotation itself (the store owns the credential, so no
	// stale token is passed in).
	RefreshAccessToken(ctx context.Context, partnerID int64, provider string) (string, error)
	GetSecret(ctx context.Context, key string) (string, error)
}
