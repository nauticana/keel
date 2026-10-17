package authserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/guard"
	"github.com/nauticana/keel/port"
)

const (
	oauthInsertClient = "oauth_insert_client"
	oauthGetClient    = "oauth_get_client"
	oauthUpdateClient = "oauth_update_client"
	oauthDeleteClient = "oauth_delete_client"
	oauthPendingCount = "oauth_pending_clients"
)

// clientPurgeSQL deletes registered clients that never completed an
// authorization: no refresh token ever issued and no code in flight.
const clientPurgeSQL = `
DELETE FROM oauth_client
 WHERE id IN (SELECT c.id FROM oauth_client c
               WHERE c.registered = TRUE
                 AND c.grant_types LIKE '%refresh_token%'
                 AND c.created_at < CURRENT_TIMESTAMP - (CAST(? AS INTEGER) * INTERVAL '1 second')
                 AND NOT EXISTS (SELECT 1 FROM oauth_refresh_token t WHERE t.client_id = c.client_id)
                 AND NOT EXISTS (SELECT 1 FROM oauth_authorization_code a WHERE a.client_id = c.client_id)
               ORDER BY c.id
               LIMIT ?)
RETURNING client_id`

var oauthClientQueries = map[string]string{
	oauthInsertClient: `
INSERT INTO oauth_client (id, client_id, secret_hash, client_name, redirect_uris, grant_types, scopes, token_auth_method, registered)
VALUES (nextval('oauth_client_seq'), ?, ?, ?, ?, ?, ?, ?, ?)`,
	oauthGetClient: `
SELECT client_id, secret_hash, client_name, redirect_uris, grant_types, scopes, token_auth_method, created_at, registered
  FROM oauth_client WHERE client_id = ?`,
	oauthUpdateClient: `
UPDATE oauth_client SET secret_hash = ?, client_name = ?, redirect_uris = ?, grant_types = ?, scopes = ?, token_auth_method = ?
 WHERE client_id = ?`,
	oauthDeleteClient: `DELETE FROM oauth_client WHERE client_id = ?`,
	// The clients clientPurgeSQL would delete.
	oauthPendingCount: `
SELECT COUNT(*) FROM oauth_client c
 WHERE c.registered = TRUE
   AND c.grant_types LIKE '%refresh_token%'
   AND NOT EXISTS (SELECT 1 FROM oauth_refresh_token t WHERE t.client_id = c.client_id)
   AND NOT EXISTS (SELECT 1 FROM oauth_authorization_code a WHERE a.client_id = c.client_id)`,
	oauthClientPurge: clientPurgeSQL,
}

var oauthClientTxQueries = common.MergeMaps(oauthClientQueries, guard.Queries)

// purgeable reports whether a client is one clientPurgeSQL covers:
// openly registered, for refresh tokens.
func purgeable(c *port.OAuthClient) bool {
	return c.Registered && slices.Contains(c.GrantTypes, "refresh_token")
}

// ClientStoreDB persists clients in the oauth_client table.
type ClientStoreDB struct {
	DB port.DatabaseRepository
	// MaxPending bounds the registered clients that never completed an
	// authorization; registering one more is ErrOAuthClientLimit. 0 is
	// unbounded.
	MaxPending int
	// PurgeAge is how old an abandoned registration must be before the next
	// registration deletes it; 0 keeps them.
	PurgeAge time.Duration
	qs       port.QueryService
}

var _ port.OAuthClientStore = (*ClientStoreDB)(nil)

func (s *ClientStoreDB) Init(ctx context.Context) {
	if s.qs == nil {
		s.qs = s.DB.GetQueryService(ctx, oauthClientQueries)
	}
}

// CreateClient first deletes up to a batch of abandoned registrations, so
// they never hold pending slots and need no scheduled purge.
func (s *ClientStoreDB) CreateClient(ctx context.Context, c *port.OAuthClient) (err error) {
	if !purgeable(c) {
		return insertClient(ctx, s.qs, c)
	}
	if s.MaxPending <= 0 {
		if err := s.purge(ctx, s.qs); err != nil {
			return err
		}
		return insertClient(ctx, s.qs, c)
	}
	tx, err := s.DB.BeginTx(ctx, oauthClientTxQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, data.RollbackDetached(tx))
		}
	}()
	if err := guard.Lock(ctx, tx, "oauth:pending-clients"); err != nil {
		return err
	}
	if err := s.purge(ctx, tx); err != nil {
		return err
	}
	res, err := tx.Query(ctx, oauthPendingCount)
	if err != nil {
		return err
	}
	if len(res.Rows) != 1 || len(res.Rows[0]) != 1 {
		return fmt.Errorf("oauth: pending client count returned %d rows", len(res.Rows))
	}
	pending, ok := common.AsInt64OK(res.Rows[0][0])
	if !ok {
		return fmt.Errorf("oauth: pending client count has type %T", res.Rows[0][0])
	}
	if pending >= int64(s.MaxPending) {
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

func (s *ClientStoreDB) purge(ctx context.Context, qs port.QueryService) error {
	if s.PurgeAge <= 0 {
		return nil
	}
	_, err := qs.Query(ctx, oauthClientPurge, int(s.PurgeAge/time.Second), purgeBatch)
	return err
}

func insertClient(ctx context.Context, qs port.QueryService, c *port.OAuthClient) error {
	_, err := qs.Query(ctx, oauthInsertClient, c.ClientID, c.SecretHash, c.Name,
		joinSpace(c.RedirectURIs), joinSpace(c.GrantTypes), joinSpace(c.Scopes), c.TokenAuthMethod, c.Registered)
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
		Registered:      common.AsBool(r[8]),
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
