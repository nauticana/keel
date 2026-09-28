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
	qEvents        = "events"
)

const selectRequestFields = `
SELECT id, partner_id, object_type, object_id, status, maker_id, submitted_at,
       checker_id, decided_at, decision_note
  FROM approval_request`

var queries = map[string]string{
	qInsertRequest: `INSERT INTO approval_request (id, partner_id, object_type, object_id, status, maker_id) VALUES (?, ?, ?, ?, 'P', ?)`,
	qInsertEvent:   `INSERT INTO approval_event (id, request_id, event_type, actor_id, note) VALUES (?, ?, ?, ?, ?)`,
	qGet:           selectRequestFields + ` WHERE partner_id = ? AND id = ?`,
	qLock:          selectRequestFields + ` WHERE partner_id = ? AND id = ? FOR UPDATE`,
	qOpenFor:       `SELECT id FROM approval_request WHERE partner_id = ? AND object_type = ? AND object_id = ? AND status = 'P'`,
	qLatestFor:     selectRequestFields + ` WHERE partner_id = ? AND object_type = ? AND object_id = ? ORDER BY submitted_at DESC, id DESC LIMIT 1`,
	qPending:       selectRequestFields + ` WHERE partner_id = ? AND status = 'P' ORDER BY submitted_at, id`,
	qAllowSingle:   `SELECT allow_single_person FROM approval_policy WHERE partner_id = ?`,
	qSetDecision:   `UPDATE approval_request SET status = ?, checker_id = ?, decided_at = CURRENT_TIMESTAMP, decision_note = ? WHERE id = ?`,
	qEvents:        `SELECT id, request_id, event_type, actor_id, note, created_at FROM approval_event WHERE request_id = ? ORDER BY id`,
}
