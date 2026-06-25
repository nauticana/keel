package authserver

import (
	"context"
	"errors"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/oauth/claims"
	"github.com/nauticana/keel/port"
)

// errRefreshConsumed signals that the presented refresh token was already
// revoked/rotated — the atomic consume matched no active row, so a concurrent
// refresh (or a replay) won the race. The caller treats it as reuse.
var errRefreshConsumed = errors.New("oauth: refresh token already consumed")

const (
	oauthInsertRefresh  = "oauth_insert_refresh"
	oauthGetRefresh     = "oauth_get_refresh"
	oauthConsumeRefresh = "oauth_consume_refresh"
	oauthRevokeRefresh  = "oauth_revoke_refresh"
	oauthRevokeFamily   = "oauth_revoke_family"
	oauthRevokeUser     = "oauth_revoke_user"
)

var oauthTokenQueries = map[string]string{
	oauthInsertRefresh: `
INSERT INTO oauth_refresh_token (id, token_hash, family_id, client_id, user_id, partner_id, scopes, resource, expires_at)
VALUES (nextval('oauth_refresh_token_seq'), ?, ?, ?, ?, ?, ?, ?, ?)`,
	oauthGetRefresh: `
SELECT token_hash, family_id, client_id, user_id, partner_id, scopes, resource, expires_at, revoked_at
  FROM oauth_refresh_token WHERE token_hash = ?`,
	// Atomic single-use consume: only one concurrent refresh flips an active row.
	oauthConsumeRefresh: `UPDATE oauth_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ? AND revoked_at IS NULL RETURNING token_hash`,
	oauthRevokeRefresh:  `UPDATE oauth_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ?`,
	oauthRevokeFamily:   `UPDATE oauth_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE family_id = ? AND revoked_at IS NULL`,
	oauthRevokeUser:     `UPDATE oauth_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = ? AND revoked_at IS NULL`,
}

// TokenStoreDB persists refresh tokens (token_hash, never the raw token).
// The caller hashes before storing/looking up.
type TokenStoreDB struct {
	DB data.DatabaseRepository
	qs data.QueryService
}

var _ port.OAuthTokenStore = (*TokenStoreDB)(nil)

func (s *TokenStoreDB) Init(ctx context.Context) {
	if s.qs == nil {
		s.qs = s.DB.GetQueryService(ctx, oauthTokenQueries)
	}
}

func (s *TokenStoreDB) SaveRefreshToken(ctx context.Context, t *port.RefreshToken) error {
	_, err := s.qs.Query(ctx, oauthInsertRefresh, t.TokenHash, t.FamilyID, t.ClientID, t.UserID,
		t.PartnerID, joinSpace(t.Scopes), t.Resource, t.ExpiresAt)
	return err
}

func (s *TokenStoreDB) Rotate(ctx context.Context, oldHash string, t *port.RefreshToken) error {
	tx, err := s.DB.BeginTx(ctx, oauthTokenQueries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	// Consume the old token atomically; no active row means it was already
	// rotated/revoked (concurrent refresh or replay) — abort without inserting.
	res, err := tx.Query(ctx, oauthConsumeRefresh, oldHash)
	if err != nil {
		return err
	}
	if len(res.Rows) == 0 {
		return errRefreshConsumed
	}
	if _, err := tx.Query(ctx, oauthInsertRefresh, t.TokenHash, t.FamilyID, t.ClientID, t.UserID,
		t.PartnerID, joinSpace(t.Scopes), t.Resource, t.ExpiresAt); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *TokenStoreDB) GetRefreshToken(ctx context.Context, tokenHash string) (*port.RefreshToken, error) {
	res, err := s.qs.Query(ctx, oauthGetRefresh, tokenHash)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, nil
	}
	r := res.Rows[0]
	expires, _ := r[7].(time.Time)
	t := &port.RefreshToken{
		TokenHash: common.AsString(r[0]),
		FamilyID:  common.AsString(r[1]),
		ClientID:  common.AsString(r[2]),
		UserID:    claims.Int64(r[3]),
		PartnerID: claims.Int64(r[4]),
		Scopes:    splitSpace(common.AsString(r[5])),
		Resource:  common.AsString(r[6]),
		ExpiresAt: expires,
	}
	if rev, ok := r[8].(time.Time); ok && !rev.IsZero() {
		t.RevokedAt = &rev
	}
	return t, nil
}

func (s *TokenStoreDB) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := s.qs.Query(ctx, oauthRevokeRefresh, tokenHash)
	return err
}

func (s *TokenStoreDB) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := s.qs.Query(ctx, oauthRevokeFamily, familyID)
	return err
}

func (s *TokenStoreDB) RevokeForUser(ctx context.Context, userID int64) error {
	_, err := s.qs.Query(ctx, oauthRevokeUser, userID)
	return err
}
