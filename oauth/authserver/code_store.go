package authserver

import (
	"context"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/oauth/claims"
	"github.com/nauticana/keel/port"
)

const (
	oauthInsertCode  = "oauth_insert_code"
	oauthConsumeCode = "oauth_consume_code"
)

var oauthCodeQueries = map[string]string{
	oauthInsertCode: `
INSERT INTO oauth_authorization_code
  (id, code_hash, client_id, user_id, partner_id, scopes, redirect_uri, code_challenge, code_challenge_method, resource, expires_at)
VALUES (nextval('oauth_authorization_code_seq'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	// DELETE ... RETURNING makes redemption atomic and single-use: a replayed
	// code finds no row.
	oauthConsumeCode: `
DELETE FROM oauth_authorization_code WHERE code_hash = ?
RETURNING client_id, user_id, partner_id, scopes, redirect_uri, code_challenge, code_challenge_method, resource, expires_at`,
}

// CodeStoreDB persists single-use authorization codes (hashed) in the DB.
// Code redemption is login-rate, not request-rate, so it does not pressure the
// hot path; DELETE ... RETURNING gives atomic single-use the cache can't.
type CodeStoreDB struct {
	DB data.DatabaseRepository
	qs data.QueryService
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
	if time.Now().After(expires) {
		return nil, nil // consumed but expired — reject
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
	}, nil
}
