package domain

import (
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/guard"
)

const (
	qDomain           = "dv_domain"
	qMember           = "dv_member"
	qOtherHolders     = "dv_other_holders"
	qCurrentSame      = "dv_current_same"
	qRefresh          = "dv_refresh"
	qInsert           = "dv_insert"
	qGetCurrent       = "dv_get_current"
	qCurrent          = "dv_current"
	qHistory          = "dv_history"
	qHolders          = "dv_holders"
	qCancel           = "dv_cancel"
	qIssueChallenge   = "dv_issue_challenge"
	qAttemptChallenge = "dv_attempt_challenge"
	qDeleteChallenge  = "dv_delete_challenge"
	qDue              = "dv_due"
	qCheckHeld        = "dv_check_held"
	qCheckFailed      = "dv_check_failed"
	qCheckError       = "dv_check_error"
	qPartnerCurrent   = "dv_partner_current"
	qIdentityHolders  = "dv_identity_holders"
	qSupersede        = "dv_supersede"
)

const currentRow = ` AND lapsed_at IS NULL AND cancelled_at IS NULL`

// heldWithin keeps evidence whose last passed check is younger than the bound seconds.
const heldWithin = ` AND last_held_at > CURRENT_TIMESTAMP - (CAST(? AS INTEGER) * INTERVAL '1 second')`

const selectFields = `
SELECT partner_id, domain_url, verified_at, domain_name, method, verified_by, evidence_ref,
       last_checked_at, failing_since, last_error, lapsed_at, cancelled_at, cancelled_by, last_held_at
  FROM partner_domain_verification`

// TxQueries returns the named queries a caller merges into its BeginTx query
// map to run RecordTx inside its own transaction: the dv_-prefixed queries
// and guard.Queries.
func TxQueries() map[string]string { return common.MergeMaps(queries, guard.Queries) }

var queries = map[string]string{
	qDomain: `SELECT domain_url FROM partner_domain WHERE partner_id = ? AND domain_url = ?`,
	qMember: `
SELECT 1 FROM partner_user
 WHERE partner_id = ? AND user_id = ?
   AND begda <= CURRENT_TIMESTAMP AND (endda IS NULL OR endda > CURRENT_TIMESTAMP)
 LIMIT 1`,
	qOtherHolders: `
SELECT partner_id FROM partner_domain_verification
 WHERE domain_name = ? AND method = ANY(CAST(? AS TEXT[])) AND partner_id <> ?` + currentRow + heldWithin + `
 LIMIT 1`,
	// Run after qOtherHolders found no fresh holder: what remains is stale.
	qSupersede: `
UPDATE partner_domain_verification
   SET lapsed_at = CURRENT_TIMESTAMP, last_error = 'superseded by another partner'
 WHERE domain_name = ? AND method = ANY(CAST(? AS TEXT[])) AND partner_id <> ?` + currentRow,
	qIdentityHolders: `
SELECT DISTINCT partner_id FROM partner_domain_verification
 WHERE domain_name = ? AND method = ANY(CAST(? AS TEXT[]))` + currentRow + heldWithin + `
 ORDER BY partner_id`,
	qCurrentSame: `SELECT verified_at FROM partner_domain_verification WHERE partner_id = ? AND domain_url = ? AND method = ?` + currentRow,
	qRefresh: `
UPDATE partner_domain_verification
   SET last_checked_at = CURRENT_TIMESTAMP, last_held_at = CURRENT_TIMESTAMP, failing_since = NULL, last_error = NULL, token_hash = ?, evidence_ref = ?
 WHERE partner_id = ? AND domain_url = ? AND method = ?` + currentRow,
	// Statement time, not transaction start: one transaction may record several methods.
	qInsert: `
INSERT INTO partner_domain_verification (partner_id, domain_url, verified_at, domain_name, method, verified_by, token_hash, evidence_ref)
VALUES (?, ?, CAST(clock_timestamp() AS TIMESTAMP), ?, ?, ?, ?, ?)`,
	qGetCurrent:     selectFields + ` WHERE partner_id = ? AND domain_url = ? AND method = ?` + currentRow,
	qCurrent:        selectFields + ` WHERE partner_id = ? AND domain_url = ? AND method = ANY(CAST(? AS TEXT[]))` + currentRow + ` ORDER BY verified_at`,
	qPartnerCurrent: selectFields + ` WHERE partner_id = ? AND method = ANY(CAST(? AS TEXT[]))` + currentRow + ` ORDER BY domain_url, verified_at`,
	qHistory:        selectFields + ` WHERE partner_id = ? AND domain_url = ? ORDER BY verified_at DESC LIMIT ?`,
	qHolders: `
SELECT DISTINCT partner_id FROM partner_domain_verification
 WHERE domain_name = ? AND method = ANY(CAST(? AS TEXT[]))` + currentRow + `
 ORDER BY partner_id`,
	qCancel: `
UPDATE partner_domain_verification
   SET cancelled_at = CURRENT_TIMESTAMP, cancelled_by = ?
 WHERE partner_id = ? AND domain_url = ? AND (CAST(? AS TEXT) = '' OR method = ?)` + currentRow + `
RETURNING method`,
	// Replaces an open challenge only once the cooldown has passed; no row back means it has not.
	qIssueChallenge: `
INSERT INTO partner_domain_challenge (partner_id, domain_url, method, token_hash, recipient, issued_by, expires_at)
VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP + (CAST(? AS INTEGER) * INTERVAL '1 second'))
ON CONFLICT (partner_id, domain_url, method) DO UPDATE
   SET token_hash = EXCLUDED.token_hash, recipient = EXCLUDED.recipient, issued_by = EXCLUDED.issued_by,
       issued_at = CURRENT_TIMESTAMP, expires_at = EXCLUDED.expires_at, attempts = 0
 WHERE partner_domain_challenge.issued_at <= CURRENT_TIMESTAMP - (CAST(? AS INTEGER) * INTERVAL '1 second')
RETURNING expires_at`,
	// Autocommitted before the check, so a failed guess still counts.
	qAttemptChallenge: `
UPDATE partner_domain_challenge SET attempts = LEAST(attempts + 1, CAST(? AS SMALLINT))
 WHERE partner_id = ? AND domain_url = ? AND method = ? AND expires_at > CURRENT_TIMESTAMP
RETURNING attempts, token_hash`,
	qDeleteChallenge: `DELETE FROM partner_domain_challenge WHERE partner_id = ? AND domain_url = ? AND method = ?`,
	qDue: `
SELECT partner_id, domain_url, verified_at, domain_name, method, verified_by, evidence_ref,
       last_checked_at, failing_since, last_error, lapsed_at, cancelled_at, cancelled_by, last_held_at, token_hash
  FROM partner_domain_verification
 WHERE method = ANY(CAST(? AS TEXT[]))` + currentRow + `
   AND last_checked_at <= CURRENT_TIMESTAMP - (CAST(? AS INTEGER) * INTERVAL '1 second')
 ORDER BY last_checked_at
 LIMIT ?`,
	qCheckHeld: `
UPDATE partner_domain_verification
   SET last_checked_at = CURRENT_TIMESTAMP, last_held_at = CURRENT_TIMESTAMP, failing_since = NULL, last_error = NULL
 WHERE partner_id = ? AND domain_url = ? AND verified_at = ?` + currentRow,
	qCheckFailed: `
UPDATE partner_domain_verification
   SET last_checked_at = CURRENT_TIMESTAMP,
       failing_since = COALESCE(failing_since, CURRENT_TIMESTAMP),
       last_error = ?,
       lapsed_at = CASE WHEN COALESCE(failing_since, CURRENT_TIMESTAMP) <= CURRENT_TIMESTAMP - (CAST(? AS INTEGER) * INTERVAL '1 second')
                        THEN CURRENT_TIMESTAMP END
 WHERE partner_id = ? AND domain_url = ? AND verified_at = ?` + currentRow + `
RETURNING lapsed_at`,
	qCheckError: `
UPDATE partner_domain_verification
   SET last_checked_at = CURRENT_TIMESTAMP, last_error = ?
 WHERE partner_id = ? AND domain_url = ? AND verified_at = ?` + currentRow,
}
