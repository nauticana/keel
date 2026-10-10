package actiontoken

const (
	qPrune  = "action_token_prune"
	qInsert = "action_token_insert"
	qClaim  = "action_token_claim"
	qLoad   = "action_token_load"
)

var queries = map[string]string{
	qPrune: `DELETE FROM action_token WHERE user_id = ? AND claimed_at IS NULL AND expires_at <= CURRENT_TIMESTAMP`,
	qInsert: `
INSERT INTO action_token (id, token_hash, user_id, partner_id, action, resource_key, content_digest, expires_at)
VALUES (nextval('action_token_seq'), ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP + CAST(? AS INTEGER) * INTERVAL '1 second')`,
	qClaim: `
UPDATE action_token t SET claimed_at = COALESCE(t.claimed_at, CURRENT_TIMESTAMP)
 WHERE t.token_hash = ? AND t.action = ? AND t.resource_key = ? AND t.content_digest = ?
   AND (t.claimed_at IS NOT NULL OR (t.expires_at > CURRENT_TIMESTAMP AND EXISTS (
        SELECT 1 FROM user_account u
         WHERE u.id = t.user_id AND (u.tokens_valid_after IS NULL OR t.created_at > u.tokens_valid_after))))
RETURNING t.id, t.user_id, t.partner_id, t.action, t.resource_key, t.content_digest`,
	qLoad: `
SELECT id, user_id, partner_id, action, resource_key, content_digest
  FROM action_token WHERE id = ? AND claimed_at IS NOT NULL`,
}
