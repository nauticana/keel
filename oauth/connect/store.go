package connect

import (
	"context"

	"github.com/nauticana/keel/oauth/client"
)

// ActiveCredential is one row from ListActiveCredentials.
type ActiveCredential struct {
	PartnerID      int64
	EntityID       int64
	Provider       string
	ConnectionType string
	Rev            int // version at read time; the sweep CAS-writes on it
}

// Store is keel's client.CredentialStore plus the connect extras (api_endpoint
// cache + refresh sweep list). PKCE verifiers ride the OAuth state (auth_nonce)
// via CreateOAuthState's extra, never the credential row — so an in-flight
// re-authorization can't clobber a working credential.
type Store interface {
	client.CredentialStore
	GetAPIEndpoint(ctx context.Context, partnerID int64, provider string) (string, error)
	SetAPIEndpoint(ctx context.Context, partnerID int64, provider, endpoint string) error
	ListActiveCredentials(ctx context.Context) ([]ActiveCredential, error)
	// RefreshDue atomically claims and refreshes one credential if it is still at
	// expectRev (a lease gives exactly-one-worker exclusivity for the multi-replica
	// sweep). refreshed is false when another replica already held it.
	RefreshDue(ctx context.Context, partnerID int64, provider string, expectRev int) (refreshed bool, err error)
}
