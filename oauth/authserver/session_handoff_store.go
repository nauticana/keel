package authserver

import (
	"context"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

const (
	oauthPruneHandoffs  = "oauth_prune_handoffs"
	oauthInsertHandoff  = "oauth_insert_handoff"
	oauthRedeemHandoff  = "oauth_redeem_handoff"
	oauthResolveHandoff = "oauth_resolve_handoff"
	oauthEndHandoff     = "oauth_end_handoff"
)

var oauthHandoffQueries = map[string]string{
	oauthPruneHandoffs: `
DELETE FROM oauth_session_handoff
 WHERE user_id = ? AND expires_at < CURRENT_TIMESTAMP
   AND (session_expires_at IS NULL OR session_expires_at < CURRENT_TIMESTAMP)`,
	oauthInsertHandoff: `
INSERT INTO oauth_session_handoff (id, code_hash, user_id, partner_id, return_url, expires_at)
VALUES (nextval('oauth_session_handoff_seq'), ?, ?, ?, ?, CURRENT_TIMESTAMP + CAST(? AS INTEGER) * INTERVAL '1 second')`,
	oauthRedeemHandoff: `
UPDATE oauth_session_handoff h
   SET consumed_at = CURRENT_TIMESTAMP, session_hash = ?,
       session_expires_at = CURRENT_TIMESTAMP + CAST(? AS INTEGER) * INTERVAL '1 second'
 WHERE code_hash = ? AND return_url = ? AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP` + handoffNotRevoked + `
RETURNING user_id, partner_id`,
	oauthResolveHandoff: `
SELECT h.user_id, h.partner_id FROM oauth_session_handoff h
 WHERE h.session_hash = ? AND h.session_expires_at > CURRENT_TIMESTAMP` + handoffNotRevoked,
	oauthEndHandoff: `
UPDATE oauth_session_handoff SET session_expires_at = CURRENT_TIMESTAMP
 WHERE session_hash = ? AND session_expires_at > CURRENT_TIMESTAMP`,
}

// handoffNotRevoked ends a hand-off with the access tokens it was minted from:
// logout-everywhere, a password change and account deletion all move the cutoff.
const handoffNotRevoked = `
   AND EXISTS (SELECT 1 FROM user_account u
                WHERE u.id = h.user_id
                  AND (u.tokens_valid_after IS NULL OR h.created_at > u.tokens_valid_after))`

// SessionHandoffStoreDB keeps hand-offs in oauth_session_handoff so any replica
// can redeem a code minted by another. The conditional UPDATE ... RETURNING is
// the atomic single-use step.
type SessionHandoffStoreDB struct {
	DB port.DatabaseRepository
	qs port.QueryService
}

var _ port.SessionHandoffStore = (*SessionHandoffStoreDB)(nil)

func (s *SessionHandoffStoreDB) Init(ctx context.Context) {
	if s.qs == nil {
		s.qs = s.DB.GetQueryService(ctx, oauthHandoffQueries)
	}
}

// SaveHandoff first prunes the user's dead rows, which bounds table growth
// without a sweeper.
func (s *SessionHandoffStoreDB) SaveHandoff(ctx context.Context, h *port.SessionHandoffCode, ttl time.Duration) error {
	if _, err := s.qs.Query(ctx, oauthPruneHandoffs, h.UserID); err != nil {
		return err
	}
	_, err := s.qs.Query(ctx, oauthInsertHandoff, h.CodeHash, h.UserID, nullablePartner(h.PartnerID), h.ReturnURL, seconds(ttl))
	return err
}

func (s *SessionHandoffStoreDB) RedeemHandoff(ctx context.Context, codeHash, returnURL, sessionHash string, sessionTTL time.Duration) (*port.UserRef, error) {
	res, err := s.qs.Query(ctx, oauthRedeemHandoff, sessionHash, seconds(sessionTTL), codeHash, returnURL)
	return firstUserRef(res, err)
}

func (s *SessionHandoffStoreDB) ResolveHandoffSession(ctx context.Context, sessionHash string) (*port.UserRef, error) {
	res, err := s.qs.Query(ctx, oauthResolveHandoff, sessionHash)
	return firstUserRef(res, err)
}

func (s *SessionHandoffStoreDB) EndHandoffSession(ctx context.Context, sessionHash string) error {
	_, err := s.qs.Query(ctx, oauthEndHandoff, sessionHash)
	return err
}

func firstUserRef(res *model.QueryResult, err error) (*port.UserRef, error) {
	if err != nil {
		return nil, err
	}
	if res == nil || len(res.Rows) == 0 {
		return nil, nil
	}
	r := res.Rows[0]
	return &port.UserRef{UserID: common.AsInt64(r[0]), PartnerID: common.AsInt64(r[1])}, nil
}

func seconds(d time.Duration) int64 { return int64(d / time.Second) }

func nullablePartner(id int64) any {
	if id <= 0 {
		return nil
	}
	return id
}
