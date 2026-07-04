// Package client is keel's OAuth2 client framework: on behalf of each partner it
// connects an app to external providers (Google APIs, Meta, …) and persists the
// resulting credentials. Every provider shares one engine (BaseProvider) and
// differs only by config + optional hooks; persistence is the app's, behind
// CredentialStore.
package client

import (
	"context"
)

// Connection type + status codes stored on a partner connection.
const (
	ConnTypeOAuth  = "O"
	ConnTypeAPIKey = "A"

	ConnStatusActive   = "A"
	ConnStatusError    = "E"
	ConnStatusPending  = "P"
	ConnStatusInactive = "I"
)

// Provider is one partner-scoped OAuth connection flow: AuthURL starts consent,
// Callback finishes it (exchange + persist), Test re-validates stored creds.
type Provider interface {
	AuthURL(ctx context.Context, partnerID int64, params map[string]string) (string, error)
	Callback(ctx context.Context, code, state string) error
	Test(ctx context.Context, partnerID int64) error
}
