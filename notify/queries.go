package notify

import "fmt"

const (
	qTypePreferences = "keel_notify_type_preferences"
	qInsert          = "keel_notify_insert"
	qSetPreference   = "keel_notify_set_preference"
	qUserPreferences = "keel_notify_user_preferences"

	qPending    = "keel_notify_pending"
	qClaim      = "keel_notify_claim"
	qReclaim    = "keel_notify_reclaim"
	qSent       = "keel_notify_sent"
	qSuppressed = "keel_notify_suppressed"
	qRetry      = "keel_notify_retry"
	qFail       = "keel_notify_fail"
)

var queries = map[string]string{
	qTypePreferences: `SELECT channel, enabled FROM notification_preference WHERE user_id = ? AND notification_type = ? ORDER BY channel`,
	qInsert: `
INSERT INTO notification (id, user_id, partner_id, notification_type, channel, title, body, data)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
	qSetPreference: `
INSERT INTO notification_preference (user_id, notification_type, channel, enabled)
VALUES (?, ?, ?, ?)
ON CONFLICT (user_id, notification_type, channel)
DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = CURRENT_TIMESTAMP`,
	qUserPreferences: `SELECT notification_type, channel, enabled FROM notification_preference WHERE user_id = ? ORDER BY notification_type, channel`,
}

// WriteQueries returns the named queries a caller merges into its BeginTx
// query map so Queue.EnqueueTx can run inside the caller's transaction.
func WriteQueries() map[string]string {
	return map[string]string{
		qTypePreferences: queries[qTypePreferences],
		qInsert:          queries[qInsert],
	}
}

func workerQueries(leaseSeconds, batch int) map[string]string {
	return map[string]string{
		qPending: fmt.Sprintf(`SELECT id FROM notification
 WHERE status = 'P' AND available_at <= CURRENT_TIMESTAMP
 ORDER BY available_at
 LIMIT %d`, batch),
		// Token first, id second (LeasedQueueWorker contract).
		qClaim: fmt.Sprintf(`UPDATE notification
   SET status = 'A', lease_token = ?, lease_until = CURRENT_TIMESTAMP + INTERVAL '%d seconds', updated_at = CURRENT_TIMESTAMP
 WHERE id = ? AND status = 'P'
RETURNING id, user_id, partner_id, notification_type, channel, title, body, data, attempts, lease_token`, leaseSeconds),
		qReclaim: `UPDATE notification
   SET status = 'P', lease_token = NULL, lease_until = NULL, updated_at = CURRENT_TIMESTAMP
 WHERE status = 'A' AND lease_until < CURRENT_TIMESTAMP
RETURNING id`,
		qSent: `UPDATE notification
   SET status = 'S', attempts = attempts + 1, lease_token = NULL, lease_until = NULL, sent_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
 WHERE id = ? AND lease_token = ? RETURNING id`,
		qSuppressed: `UPDATE notification
   SET status = 'X', attempts = attempts + 1, lease_token = NULL, lease_until = NULL, last_error = ?, updated_at = CURRENT_TIMESTAMP
 WHERE id = ? AND lease_token = ? RETURNING id`,
		qRetry: `UPDATE notification
   SET status = 'P', attempts = attempts + 1, lease_token = NULL, lease_until = NULL,
       available_at = CURRENT_TIMESTAMP + (INTERVAL '1 second' * ?), last_error = ?, updated_at = CURRENT_TIMESTAMP
 WHERE id = ? AND lease_token = ? RETURNING id`,
		qFail: `UPDATE notification
   SET status = 'F', attempts = attempts + 1, lease_token = NULL, lease_until = NULL, last_error = ?, updated_at = CURRENT_TIMESTAMP
 WHERE id = ? AND lease_token = ? RETURNING id`,
	}
}
