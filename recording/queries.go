package recording

const (
	qInsertSession        = "insert_session"
	qInsertParticipant    = "insert_participant"
	qGetSession           = "get_session"
	qGetSessionByCtx      = "get_session_by_context"
	qLockSession          = "lock_session"
	qListParticipants     = "list_participants"
	qSetStatus            = "set_status"
	qSetCapture           = "set_capture"
	qReopen               = "reopen"
	qInsertInvite         = "insert_invite"
	qInviteSession        = "invite_session"
	qInsertMedia          = "insert_media"
	qGetMediaByKey        = "get_media_by_key"
	qResetMedia           = "reset_media"
	qSetMediaStatus       = "set_media_status"
	qGetMedia             = "get_media"
	qGetMediaByID         = "get_media_by_id"
	qListMedia            = "list_media"
	qMediaCounts          = "media_counts"
	qSessionsWithDueMedia = "sessions_with_due_media"
	qDueMedia             = "due_media"
	qSetMediaPurged       = "set_media_purged"

	selectSessionFields = "SELECT id, partner_id, context_ref, consent_type, status, capture_token_hash, capture_expires_at, policy_id, attempt, created_at FROM recording_session"
	selectMediaFields   = "SELECT id, session_id, bucket, object_key, content_type, size_bytes, status FROM recording_media"
)

var queries = map[string]string{
	qInsertSession: `
INSERT INTO recording_session (id, partner_id, context_ref, consent_type, policy_id, created_by)
VALUES (?, ?, ?, ?, ?, ?)`,
	qInsertParticipant: `INSERT INTO recording_participant (session_id, user_id, role) VALUES (?, ?, ?)`,
	qGetSession:        selectSessionFields + ` WHERE id = ?`,
	qGetSessionByCtx:   selectSessionFields + ` WHERE partner_id = ? AND context_ref = ?`,
	qLockSession:       selectSessionFields + ` WHERE id = ? FOR UPDATE`,
	qListParticipants:  `SELECT user_id, role FROM recording_participant WHERE session_id = ? ORDER BY user_id`,
	qSetStatus:         `UPDATE recording_session SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
	qSetCapture:        `UPDATE recording_session SET capture_token_hash = ?, capture_expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
	qReopen: `
UPDATE recording_session
   SET status = 'W', attempt = attempt + 1, capture_token_hash = NULL, capture_expires_at = NULL, updated_at = CURRENT_TIMESTAMP
 WHERE id = ?`,
	qInsertInvite:  `INSERT INTO recording_invite (token_hash, session_id, expires_at, created_by) VALUES (?, ?, ?, ?)`,
	qInviteSession: `SELECT session_id FROM recording_invite WHERE token_hash = ? AND expires_at > ?`,
	qInsertMedia: `
INSERT INTO recording_media (id, session_id, bucket, object_key, content_type, size_bytes, uploaded_by)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
	qGetMediaByKey:  selectMediaFields + ` WHERE session_id = ? AND object_key = ?`,
	qResetMedia:     `UPDATE recording_media SET status = 'P', size_bytes = 0, content_type = ?, uploaded_by = ?, completed_at = NULL WHERE id = ?`,
	qSetMediaStatus: `UPDATE recording_media SET status = ?, size_bytes = ?, completed_at = CASE WHEN ? = 'U' THEN CURRENT_TIMESTAMP ELSE completed_at END WHERE id = ?`,
	qGetMedia:       selectMediaFields + ` WHERE id = ? AND session_id = ?`,
	qGetMediaByID:   selectMediaFields + ` WHERE id = ?`,
	qListMedia:      selectMediaFields + ` WHERE session_id = ? ORDER BY id`,
	qMediaCounts:    `SELECT COALESCE(SUM(CASE WHEN status = 'U' THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN status = 'P' THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN status = 'X' THEN 1 ELSE 0 END), 0) FROM recording_media WHERE session_id = ?`,
	qSessionsWithDueMedia: `
SELECT DISTINCT session_id FROM recording_media
 WHERE status = 'U' AND completed_at < ? AND session_id > ?
 ORDER BY session_id LIMIT ?`,
	qDueMedia:       selectMediaFields + ` WHERE session_id = ? AND status = 'U' AND completed_at < ? ORDER BY id`,
	qSetMediaPurged: `UPDATE recording_media SET status = 'R', purged_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'U'`,
}
