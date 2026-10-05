package approval

const (
	qInsertRequest = "insert_request"
	qInsertEvent   = "insert_event"
	qGet           = "get"
	qLock          = "lock"
	qOpenFor       = "open_for"
	qLatestFor     = "latest_for"
	qPending       = "pending"
	qAllowSingle   = "allow_single"
	qSetDecision   = "set_decision"
	qClose         = "close"
	qDue           = "due"
	qEvents        = "events"
)

// The last column is the store clock's verdict on expires_at.
const selectRequestFields = `
SELECT id, partner_id, object_type, object_id, status, maker_id, submitted_at,
       checker_id, decided_at, decision_note, expires_at,
       (expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP)
  FROM approval_request`

var queries = map[string]string{
	qInsertRequest: `INSERT INTO approval_request (id, partner_id, object_type, object_id, status, maker_id, expires_at) VALUES (?, ?, ?, ?, 'P', ?, ?)`,
	qInsertEvent:   `INSERT INTO approval_event (id, request_id, event_type, actor_id, note) VALUES (?, ?, ?, ?, ?)`,
	qGet:           selectRequestFields + ` WHERE partner_id = ? AND id = ?`,
	qLock:          selectRequestFields + ` WHERE partner_id = ? AND id = ? FOR UPDATE`,
	qOpenFor: `
SELECT id, (expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP)
  FROM approval_request
 WHERE partner_id = ? AND object_type = ? AND object_id = ? AND status = 'P'
   FOR UPDATE`,
	qLatestFor:   selectRequestFields + ` WHERE partner_id = ? AND object_type = ? AND object_id = ? ORDER BY submitted_at DESC, id DESC LIMIT 1`,
	qPending:     selectRequestFields + ` WHERE partner_id = ? AND status = 'P' ORDER BY submitted_at, id`,
	qAllowSingle: `SELECT allow_single_person FROM approval_policy WHERE partner_id = ?`,
	qSetDecision: `UPDATE approval_request SET status = ?, checker_id = ?, decided_at = CURRENT_TIMESTAMP, decision_note = ? WHERE id = ?`,
	// Withdrawal and expiry close a request without a checker.
	qClose: `UPDATE approval_request SET status = ?, decided_at = CURRENT_TIMESTAMP, decision_note = ? WHERE id = ? AND status = 'P'`,
	qDue: `
SELECT id FROM approval_request
 WHERE status = 'P' AND expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP
 ORDER BY expires_at, id
 LIMIT ?
   FOR UPDATE SKIP LOCKED`,
	qEvents: `SELECT id, request_id, event_type, actor_id, note, created_at FROM approval_event WHERE request_id = ? ORDER BY id`,
}
