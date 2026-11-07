package approval

const (
	qInsertRequest     = "insert_request"
	qInsertEvent       = "insert_event"
	qGet               = "get"
	qLock              = "lock"
	qOpenFor           = "open_for"
	qLatestFor         = "latest_for"
	qPending           = "pending"
	qAllowSingle       = "allow_single"
	qClosePolicy       = "close_policy"
	qInsertPolicy      = "insert_policy"
	qLockPendingPolicy = "lock_pending_policy"
	qConfirmPolicy     = "confirm_policy"
	qSetDecision       = "set_decision"
	qClose             = "close"
	qDue               = "due"
	qPendingBy         = "pending_by"
	qEvents            = "events"
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
	qLatestFor: selectRequestFields + ` WHERE partner_id = ? AND object_type = ? AND object_id = ? ORDER BY submitted_at DESC, id DESC LIMIT 1`,
	qPending:   selectRequestFields + ` WHERE partner_id = ? AND status = 'P' ORDER BY submitted_at, id`,
	// The partner's open row before the platform's; one pending confirmation (begda NULL) answers no.
	qAllowSingle: `
SELECT allow_single_person AND begda IS NOT NULL FROM approval_policy
 WHERE object_type = ? AND endda IS NULL AND (partner_id = ? OR partner_id IS NULL)
 ORDER BY partner_id IS NULL LIMIT 1`,
	qClosePolicy:       `UPDATE approval_policy SET endda = CURRENT_TIMESTAMP WHERE partner_id IS NOT DISTINCT FROM ? AND object_type = ? AND endda IS NULL`,
	qInsertPolicy:      `INSERT INTO approval_policy (id, partner_id, object_type, allow_single_person, changed_by, begda) VALUES (?, ?, ?, ?, ?, CASE WHEN ? THEN CURRENT_TIMESTAMP END)`,
	qLockPendingPolicy: `SELECT id, changed_by FROM approval_policy WHERE partner_id IS NOT DISTINCT FROM ? AND object_type = ? AND begda IS NULL AND endda IS NULL FOR UPDATE`,
	qConfirmPolicy:     `UPDATE approval_policy SET confirmed_by = ?, begda = CURRENT_TIMESTAMP WHERE id = ?`,
	qSetDecision:       `UPDATE approval_request SET status = ?, checker_id = ?, decided_at = CURRENT_TIMESTAMP, decision_note = ? WHERE id = ?`,
	// Withdrawal and expiry close a request without a checker.
	qClose: `UPDATE approval_request SET status = ?, decided_at = CURRENT_TIMESTAMP, decision_note = ? WHERE id = ? AND status = 'P'`,
	qDue: `
SELECT id FROM approval_request
 WHERE status = 'P' AND expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP
 ORDER BY expires_at, id
 LIMIT ?
   FOR UPDATE SKIP LOCKED`,
	qPendingBy: `SELECT id FROM approval_request WHERE maker_id = ? AND status = 'P' ORDER BY id FOR UPDATE`,
	qEvents:    `SELECT id, request_id, event_type, actor_id, note, created_at FROM approval_event WHERE request_id = ? ORDER BY id`,
}
