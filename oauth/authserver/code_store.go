package authserver

import (
	"context"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/oauth/claims"
	"github.com/nauticana/keel/port"
)

const (
	oauthInsertCode  = "oauth_insert_code"
	oauthConsumeCode = "oauth_consume_code"
	oauthPurgeCodes  = "oauth_purge_codes"
)

var oauthCodeQueries = map[string]string{
	oauthInsertCode: `
INSERT INTO oauth_authorization_code
  (id, code_hash, client_id, user_id, partner_id, scopes, redirect_uri, code_challenge, code_challenge_method, resource, expires_at)
VALUES (nextval('oauth_authorization_code_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	// The row lock makes redemption single-use; prior.consumed_at reports a
	// replay. Rows stay until expiry so a replay can be recognized.
	oauthConsumeCode: `
UPDATE oauth_authorization_code c SET consumed_at = COALESCE(prior.consumed_at, CURRENT_TIMESTAMP)
  FROM (SELECT id, consumed_at FROM oauth_authorization_code WHERE code_hash = ? FOR UPDATE) prior
 WHERE c.id = prior.id
RETURNING c.client_id, c.user_id, c.partner_id, c.scopes, c.redirect_uri, c.code_challenge, c.code_challenge_method, c.resource, c.expires_at, prior.consumed_at`,
	oauthPurgeCodes: `DELETE FROM oauth_authorization_code WHERE expires_at < CURRENT_TIMESTAMP - INTERVAL '1 day'`,
}

// CodeStoreDB persists single-use authorization codes (hashed) in the DB.
// Code redemption is login-rate, not request-rate, so it does not pressure the
// hot path.
type CodeStoreDB struct {
	DB port.DatabaseRepository
	qs port.QueryService
}

var _ port.AuthCodeStore = (*CodeStoreDB)(nil)

func (s *CodeStoreDB) Init(ctx context.Context) {
	if s.qs == nil {
		s.qs = s.DB.GetQueryService(ctx, oauthCodeQueries)
	}
}

func (s *CodeStoreDB) SaveCode(ctx context.Context, c *port.AuthCode, ttl time.Duration) error {
	_, err := s.qs.Query(ctx, oauthInsertCode, hashToken(c.Code), c.ClientID, c.UserID, c.PartnerID,
		joinSpace(c.Scopes), c.RedirectURI, c.CodeChallenge, c.CodeChallengeMethod, c.Resource, time.Now().Add(ttl))
	return err
}

func (s *CodeStoreDB) ConsumeCode(ctx context.Context, code string) (*port.AuthCode, error) {
	res, err := s.qs.Query(ctx, oauthConsumeCode, hashToken(code))
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, nil
	}
	r := res.Rows[0]
	expires, _ := r[8].(time.Time)
	prior, _ := r[9].(time.Time)
	replayed := !prior.IsZero()
	if !replayed && time.Now().After(expires) {
		return nil, nil
	}
	return &port.AuthCode{
		Code:                code,
		ClientID:            common.AsString(r[0]),
		UserID:              claims.Int64(r[1]),
		PartnerID:           claims.Int64(r[2]),
		Scopes:              splitSpace(common.AsString(r[3])),
		RedirectURI:         common.AsString(r[4]),
		CodeChallenge:       common.AsString(r[5]),
		CodeChallengeMethod: common.AsString(r[6]),
		Resource:            common.AsString(r[7]),
		ExpiresAt:           expires,
		Replayed:            replayed,
	}, nil
}

// PurgeExpired deletes codes a day past expiry, after which a replay is
// refused as unknown; a worker calls it periodically.
func (s *CodeStoreDB) PurgeExpired(ctx context.Context) error {
	_, err := s.qs.Query(ctx, oauthPurgeCodes)
	return err
}
