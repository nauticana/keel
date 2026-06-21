package oauth

import (
	"context"
	"time"

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

// OAuthClientStoreDB persists DCR clients in the oauth_client table.
type OAuthClientStoreDB struct {
	DB data.DatabaseRepository
	qs data.QueryService
}

var _ port.OAuthClientStore = (*OAuthClientStoreDB)(nil)

func (s *OAuthClientStoreDB) Init(ctx context.Context) {
	if s.qs == nil {
		s.qs = s.DB.GetQueryService(ctx, oauthClientQueries)
	}
}

func (s *OAuthClientStoreDB) CreateClient(ctx context.Context, c *port.OAuthClient) error {
	_, err := s.qs.Query(ctx, oauthInsertClient, c.ClientID, c.SecretHash, c.Name,
		joinSpace(c.RedirectURIs), joinSpace(c.GrantTypes), joinSpace(c.Scopes), c.TokenAuthMethod)
	return err
}

func (s *OAuthClientStoreDB) GetClient(ctx context.Context, clientID string) (*port.OAuthClient, error) {
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
		ClientID:        oauthStr(r[0]),
		SecretHash:      oauthStr(r[1]),
		Name:            oauthStr(r[2]),
		RedirectURIs:    splitSpace(oauthStr(r[3])),
		GrantTypes:      splitSpace(oauthStr(r[4])),
		Scopes:          splitSpace(oauthStr(r[5])),
		TokenAuthMethod: oauthStr(r[6]),
		CreatedAt:       created,
	}, nil
}

func (s *OAuthClientStoreDB) UpdateClient(ctx context.Context, c *port.OAuthClient) error {
	_, err := s.qs.Query(ctx, oauthUpdateClient, c.SecretHash, c.Name,
		joinSpace(c.RedirectURIs), joinSpace(c.GrantTypes), joinSpace(c.Scopes), c.TokenAuthMethod, c.ClientID)
	return err
}

func (s *OAuthClientStoreDB) DeleteClient(ctx context.Context, clientID string) error {
	_, err := s.qs.Query(ctx, oauthDeleteClient, clientID)
	return err
}
