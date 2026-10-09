package authserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/guard"
	"github.com/nauticana/keel/port"
)

// ErrGrantNotFound: the user has no live grant for the client.
var ErrGrantNotFound = errors.New("oauth: no active grant for this client")

const (
	oauthGrantList   = "oauth_grant_list"
	oauthGrantRevoke = "oauth_grant_revoke"
	oauthGrantActive = "oauth_grant_active"
	oauthClientPurge = "oauth_client_purge"

	purgeBatch = 500
)

const liveRefresh = `revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP`

var oauthGrantQueries = map[string]string{
	oauthGrantList: `
SELECT a.client_id, c.client_name, a.scopes, h.first_at, a.last_at
  FROM (SELECT client_id, string_agg(DISTINCT scopes, ' ') AS scopes, MAX(created_at) AS last_at
          FROM oauth_refresh_token
         WHERE user_id = ? AND ` + liveRefresh + `
         GROUP BY client_id) a
  JOIN (SELECT client_id, MIN(created_at) AS first_at
          FROM oauth_refresh_token
         WHERE user_id = ?
         GROUP BY client_id) h ON h.client_id = a.client_id
  JOIN oauth_client c ON c.client_id = a.client_id
 ORDER BY a.client_id`,
	oauthGrantRevoke: `
UPDATE oauth_refresh_token SET revoked_at = CURRENT_TIMESTAMP
 WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL
RETURNING id`,
	oauthGrantActive: `SELECT 1 FROM oauth_refresh_token WHERE user_id = ? AND client_id = ? AND ` + liveRefresh + ` LIMIT 1`,
	// Registered clients that never completed an authorization: no refresh
	// token ever issued and no code in flight.
	oauthClientPurge: `
DELETE FROM oauth_client
 WHERE id IN (SELECT c.id FROM oauth_client c
               WHERE c.registered = TRUE
                 AND c.grant_types LIKE '%refresh_token%'
                 AND c.created_at < CURRENT_TIMESTAMP - (CAST(? AS INTEGER) * INTERVAL '1 second')
                 AND NOT EXISTS (SELECT 1 FROM oauth_refresh_token t WHERE t.client_id = c.client_id)
                 AND NOT EXISTS (SELECT 1 FROM oauth_authorization_code a WHERE a.client_id = c.client_id)
               ORDER BY c.id
               LIMIT ?)
RETURNING client_id`,
}

var oauthGrantTxQueries = common.MergeMaps(oauthGrantQueries, guard.Queries)

// Grant is a client's standing authorization from a user: the live refresh
// tokens the client holds for that user. A client registered without the
// refresh_token grant holds only short-lived access tokens and has no Grant.
type Grant struct {
	ClientID     string    `json:"clientId"`
	ClientName   string    `json:"clientName"`
	Scopes       []string  `json:"scopes"`
	AuthorizedAt time.Time `json:"authorizedAt"` // first authorization of the client
	LastIssuedAt time.Time `json:"lastIssuedAt"` // newest live refresh token
}

// GrantService lists and revokes the clients a user has authorized on the
// local authorization server.
type GrantService struct {
	DB port.DatabaseRepository

	once sync.Once
	qs   port.QueryService
}

func (s *GrantService) query(ctx context.Context) port.QueryService {
	s.once.Do(func() { s.qs = s.DB.GetQueryService(ctx, oauthGrantQueries) })
	return s.qs
}

// List returns the clients holding a live grant from the user.
func (s *GrantService) List(ctx context.Context, userID int64) ([]Grant, error) {
	if userID <= 0 {
		return nil, nil
	}
	res, err := s.query(ctx).Query(ctx, oauthGrantList, userID, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Grant, 0, len(res.Rows))
	for _, r := range res.Rows {
		scopes := strings.Fields(common.AsString(r[2]))
		slices.Sort(scopes)
		out = append(out, Grant{
			ClientID: common.AsString(r[0]), ClientName: common.AsString(r[1]), Scopes: slices.Compact(scopes),
			AuthorizedAt: common.AsTime(r[3]), LastIssuedAt: common.AsTime(r[4]),
		})
	}
	return out, nil
}

// Revoke ends the user's grant to a client by revoking every refresh token
// of the pair. Access tokens already issued stay valid until they expire
// unless the resource server checks Active; a client without refresh tokens
// has nothing to revoke and simply runs out with its access token.
func (s *GrantService) Revoke(ctx context.Context, userID int64, clientID string) error {
	if userID <= 0 || clientID == "" {
		return ErrGrantNotFound
	}
	tx, err := s.DB.BeginTx(ctx, oauthGrantTxQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = data.RollbackDetached(tx)
		}
	}()
	// Serialized with refresh rotation, which would otherwise insert a
	// replacement token this statement cannot see.
	if err := guard.Lock(ctx, tx, grantLockKey(userID, clientID)); err != nil {
		return err
	}
	res, err := tx.Query(ctx, oauthGrantRevoke, userID, clientID)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return ErrGrantNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

// Active reports whether the user's grant to the client is still live, for a
// resource server that must honor a revocation before the access token expires.
func (s *GrantService) Active(ctx context.Context, userID int64, clientID string) (bool, error) {
	if userID <= 0 || clientID == "" {
		return false, nil
	}
	res, err := s.query(ctx).Query(ctx, oauthGrantActive, userID, clientID)
	if err != nil {
		return false, err
	}
	return len(res.Rows) > 0, nil
}

// PurgeUnauthorizedClients deletes up to purgeBatch registered clients that
// registered more than olderThan ago and never completed an authorization,
// and returns how many it deleted; a worker calls it until it returns fewer.
func (s *GrantService) PurgeUnauthorizedClients(ctx context.Context, olderThan time.Duration) (int, error) {
	if olderThan < time.Minute {
		return 0, fmt.Errorf("oauth: purge age must be at least a minute, got %s", olderThan)
	}
	res, err := s.query(ctx).Query(ctx, oauthClientPurge, int(olderThan/time.Second), purgeBatch)
	if err != nil {
		return 0, err
	}
	return len(res.Rows), nil
}
