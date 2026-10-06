package authserver

import (
	"context"
	"slices"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/port"
)

const (
	oauthInsertClient = "oauth_insert_client"
	oauthGetClient    = "oauth_get_client"
	oauthUpdateClient = "oauth_update_client"
	oauthDeleteClient = "oauth_delete_client"
	oauthLockClients  = "oauth_lock_clients"
	oauthPendingCount = "oauth_pending_clients"
)

var oauthClientQueries = map[string]string{
	oauthInsertClient: `
INSERT INTO oauth_client (id, client_id, secret_hash, client_name, redirect_uris, grant_types, scopes, token_auth_method)
VALUES (nextval('oauth_client_seq'), ?, ?, ?, ?, ?, ?, ?)`,
	oauthGetClient: `
SELECT client_id, secret_hash, client_name, redirect_uris, grant_types, scopes, token_auth_method, created_at
  FROM oauth_client WHERE client_id = ?`,
	oauthUpdateClient: `
UPDATE oauth_client SET secret_hash = ?, client_name = ?, redirect_uris = ?, grant_types = ?, scopes = ?, token_auth_method = ?
 WHERE client_id = ?`,
	oauthDeleteClient: `DELETE FROM oauth_client WHERE client_id = ?`,
	oauthLockClients:  `SELECT pg_advisory_xact_lock(hashtext('oauth_client'))`,
	// The clients PurgeUnauthorizedClients would delete.
	oauthPendingCount: `
SELECT COUNT(*) FROM oauth_client c
 WHERE c.token_auth_method = 'none'
   AND c.grant_types LIKE '%refresh_token%'
   AND NOT EXISTS (SELECT 1 FROM oauth_refresh_token t WHERE t.client_id = c.client_id)
   AND NOT EXISTS (SELECT 1 FROM oauth_authorization_code a WHERE a.client_id = c.client_id)`,
}

// purgeable reports whether a client is one PurgeUnauthorizedClients covers:
// public, registered for refresh tokens.
func purgeable(method string, grants []string) bool {
	return method == "none" && slices.Contains(grants, "refresh_token")
}

// ClientStoreDB persists DCR clients in the oauth_client table.
type ClientStoreDB struct {
	DB port.DatabaseRepository
	// MaxPending bounds the public refresh-token clients that never completed
	// an authorization; registering one more is ErrOAuthClientLimit. 0 is
	// unbounded.
	MaxPending int
	qs         port.QueryService
}

var _ port.OAuthClientStore = (*ClientStoreDB)(nil)

func (s *ClientStoreDB) Init(ctx context.Context) {
	if s.qs == nil {
		s.qs = s.DB.GetQueryService(ctx, oauthClientQueries)
	}
}

func (s *ClientStoreDB) CreateClient(ctx context.Context, c *port.OAuthClient) error {
	if s.MaxPending <= 0 || !purgeable(c.TokenAuthMethod, c.GrantTypes) {
		return insertClient(ctx, s.qs, c)
	}
	tx, err := s.DB.BeginTx(ctx, oauthClientQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	if _, err := tx.Query(ctx, oauthLockClients); err != nil {
		return err
	}
	res, err := tx.Query(ctx, oauthPendingCount)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 || common.AsInt64(res.Rows[0][0]) >= int64(s.MaxPending) {
		return ErrOAuthClientLimit
	}
	if err := insertClient(ctx, tx, c); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func insertClient(ctx context.Context, qs port.QueryService, c *port.OAuthClient) error {
	_, err := qs.Query(ctx, oauthInsertClient, c.ClientID, c.SecretHash, c.Name,
		joinSpace(c.RedirectURIs), joinSpace(c.GrantTypes), joinSpace(c.Scopes), c.TokenAuthMethod)
	return err
}

func (s *ClientStoreDB) GetClient(ctx context.Context, clientID string) (*port.OAuthClient, error) {
	res, err := s.qs.Query(ctx, oauthGetClient, clientID)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, nil
	}
	r := res.Rows[0]
	created, _ := r[7].(time.Time)
	return &port.OAuthClient{
		ClientID:        common.AsString(r[0]),
		SecretHash:      common.AsString(r[1]),
		Name:            common.AsString(r[2]),
		RedirectURIs:    splitSpace(common.AsString(r[3])),
		GrantTypes:      splitSpace(common.AsString(r[4])),
		Scopes:          splitSpace(common.AsString(r[5])),
		TokenAuthMethod: common.AsString(r[6]),
		CreatedAt:       created,
	}, nil
}

func (s *ClientStoreDB) UpdateClient(ctx context.Context, c *port.OAuthClient) error {
	_, err := s.qs.Query(ctx, oauthUpdateClient, c.SecretHash, c.Name,
		joinSpace(c.RedirectURIs), joinSpace(c.GrantTypes), joinSpace(c.Scopes), c.TokenAuthMethod, c.ClientID)
	return err
}

func (s *ClientStoreDB) DeleteClient(ctx context.Context, clientID string) error {
	_, err := s.qs.Query(ctx, oauthDeleteClient, clientID)
	return err
}
