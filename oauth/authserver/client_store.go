package authserver

import (
	"context"
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
}

// ClientStoreDB persists DCR clients in the oauth_client table.
type ClientStoreDB struct {
	DB data.DatabaseRepository
	qs data.QueryService
}

var _ port.OAuthClientStore = (*ClientStoreDB)(nil)

func (s *ClientStoreDB) Init(ctx context.Context) {
	if s.qs == nil {
		s.qs = s.DB.GetQueryService(ctx, oauthClientQueries)
	}
}

func (s *ClientStoreDB) CreateClient(ctx context.Context, c *port.OAuthClient) error {
	_, err := s.qs.Query(ctx, oauthInsertClient, c.ClientID, c.SecretHash, c.Name,
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
