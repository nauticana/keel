package erasure

const (
	qLockUser          = "lock_user"
	qActiveHold        = "active_hold"
	qOpenRequest       = "open_request"
	qInsertRequest     = "insert_request"
	qGetRequest        = "get_request"
	qCancelRequest     = "cancel_request"
	qInsertAudit       = "insert_audit"
	qListAudit         = "list_audit"
	qPlaceHold         = "place_hold"
	qReleaseHold       = "release_hold"
	qListHolds         = "list_holds"
	qEnsurePseudonym   = "ensure_pseudonym"
	qGetPseudonym      = "get_pseudonym"
	qResolvePseudonym  = "resolve_pseudonym"
	qInsertLookup      = "insert_lookup"
	qDropPseudonym     = "drop_pseudonym"
	qWorkerPending     = "erasure_pending"
	qWorkerClaim       = "erasure_claim"
	qWorkerReclaim     = "erasure_reclaim"
	qWorkerDone        = "erasure_done"
	qWorkerHeld        = "erasure_held"
	qWorkerRetry       = "erasure_retry"
	qWorkerFail        = "erasure_fail"
	accountTable       = "user_account"
	openStatuses       = `('P', 'A', 'H')`
	selectRequestField = `SELECT id, user_id, status, requested_by, requested_at, attempts, completed_at, last_error FROM erasure_request`
)

var queries = map[string]string{
	qLockUser:      `SELECT id FROM user_account WHERE id = ? FOR UPDATE`,
	qActiveHold:    `SELECT 1 FROM user_legal_hold WHERE user_id = ? AND released_at IS NULL LIMIT 1`,
	qOpenRequest:   selectRequestField + ` WHERE user_id = ? AND status IN ` + openStatuses + ` ORDER BY id DESC LIMIT 1`,
	qInsertRequest: `INSERT INTO erasure_request (id, user_id, status, requested_by) VALUES (?, ?, ?, ?)`,
	qGetRequest:    selectRequestField + ` WHERE id = ?`,
	qCancelRequest: `
UPDATE erasure_request SET status = 'X', completed_at = CURRENT_TIMESTAMP
 WHERE id = ? AND status IN ('P', 'H') RETURNING id`,
	qInsertAudit: `
INSERT INTO erasure_audit (request_id, table_name, row_key, action, reason) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (request_id, table_name, row_key) DO NOTHING RETURNING request_id`,
	qListAudit: `
SELECT table_name, row_key, action, reason, executed_at FROM erasure_audit
 WHERE request_id = ? ORDER BY executed_at, table_name, row_key`,
	qPlaceHold: `INSERT INTO user_legal_hold (id, user_id, reason, placed_by) VALUES (?, ?, ?, ?)`,
	qReleaseHold: `
UPDATE user_legal_hold SET released_by = ?, released_at = CURRENT_TIMESTAMP
 WHERE id = ? AND released_at IS NULL RETURNING id`,
	qListHolds: `
SELECT id, user_id, reason, placed_by, placed_at FROM user_legal_hold
 WHERE user_id = ? AND released_at IS NULL ORDER BY id`,
	qEnsurePseudonym:  `INSERT INTO user_pseudonym (user_id, pseudonym) VALUES (?, ?) ON CONFLICT (user_id) DO NOTHING`,
	qGetPseudonym:     `SELECT pseudonym FROM user_pseudonym WHERE user_id = ?`,
	qResolvePseudonym: `SELECT user_id FROM user_pseudonym WHERE pseudonym = ?`,
	qInsertLookup:     `INSERT INTO user_pseudonym_lookup (id, user_id, actor_id, reason) VALUES (?, ?, ?, ?)`,
	qDropPseudonym:    `DELETE FROM user_pseudonym WHERE user_id = ?`,

	// Held requests are picked up again once every hold of the user is released.
	qWorkerPending: `
SELECT r.id FROM erasure_request r
 WHERE ((r.status = 'P' AND r.available_at <= CURRENT_TIMESTAMP) OR r.status = 'H')
   AND NOT EXISTS (SELECT 1 FROM user_legal_hold h WHERE h.user_id = r.user_id AND h.released_at IS NULL)
 ORDER BY r.id LIMIT 10`,
	qWorkerClaim: `
UPDATE erasure_request SET status = 'A', lease_token = ?, lease_until = CURRENT_TIMESTAMP + INTERVAL '30 minutes'
 WHERE id = ? AND status IN ('P', 'H')
RETURNING id, user_id, attempts, lease_token`,
	qWorkerReclaim: `
UPDATE erasure_request SET status = 'P', lease_token = NULL, lease_until = NULL
 WHERE status = 'A' AND lease_until < CURRENT_TIMESTAMP
RETURNING id`,
	qWorkerDone: `
UPDATE erasure_request SET status = 'D', completed_at = CURRENT_TIMESTAMP, last_error = NULL, lease_token = NULL, lease_until = NULL
 WHERE id = ? AND lease_token = ? RETURNING id`,
	qWorkerHeld: `
UPDATE erasure_request SET status = 'H', lease_token = NULL, lease_until = NULL
 WHERE id = ? AND lease_token = ? RETURNING id`,
	qWorkerRetry: `
UPDATE erasure_request SET status = 'P', attempts = attempts + 1, last_error = ?, lease_token = NULL, lease_until = NULL,
       available_at = CURRENT_TIMESTAMP + (INTERVAL '1 minute' * ?)
 WHERE id = ? AND lease_token = ? RETURNING id`,
	qWorkerFail: `
UPDATE erasure_request SET status = 'F', attempts = attempts + 1, last_error = ?, completed_at = CURRENT_TIMESTAMP,
       lease_token = NULL, lease_until = NULL
 WHERE id = ? AND lease_token = ? RETURNING id`,
}
