package document

import "strings"

const (
	qGetType          = "get_type"
	qRepositoryOwner  = "repository_owner"
	qListRepositories = "list_repositories"
	qNextVersion      = "next_version"
	qInsert           = "insert"
	qSupersede        = "supersede"
	qGet              = "get"
	qLock             = "lock"
	qLockGroup        = "lock_group"
	qListByPartner    = "list_by_partner"
	qListByUser       = "list_by_user"
	qApproved         = "approved"
	qByVersion        = "by_version"
	qLatest           = "latest"
	qReviewedBy       = "reviewed_by"
	qPending          = "pending"
	qSetReview        = "set_review"
	qRetire           = "retire"
	qRetiredBefore    = "retired_before"
	qSetPurged        = "set_purged"
)

const selectFields = `
SELECT id, contrep_id, doc_key, partner_id, document_type, user_id, title, file_name, version_no,
       document_number, expires_on, origin_ip, uploaded_by, uploaded_at, status,
       reviewer_id, reviewed_at, reviewer_notes, superseded_at, retired_at, purged_at
  FROM partner_document`

var queries = map[string]string{
	qGetType:         `SELECT contrep_id, max_bytes, media_types, requires_review, supersedes FROM document_type WHERE id = ?`,
	qRepositoryOwner: `SELECT partner_id FROM content_repository WHERE id = ?`,
	qListRepositories: `
SELECT id, caption, storage_mode, bucket, project, region, endpoint, account_url, public_base_url,
       credential_secret, path_prefix, default_doc_prot, status
  FROM content_repository ORDER BY id`,
	qNextVersion: `
SELECT COALESCE(MAX(version_no), 0) + 1 FROM partner_document
 WHERE partner_id = ? AND document_type = ? AND user_id IS NOT DISTINCT FROM ?`,
	qInsert: `
INSERT INTO partner_document (id, contrep_id, doc_key, partner_id, document_type, user_id, title, file_name,
       version_no, document_number, expires_on, origin_ip, uploaded_by, status)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	qSupersede: `
UPDATE partner_document SET status = 'X', superseded_at = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND document_type = ? AND user_id IS NOT DISTINCT FROM ? AND status = 'Y' AND id <> ?`,
	qGet:           selectFields + ` WHERE partner_id = ? AND id = ?`,
	qLock:          selectFields + ` WHERE partner_id = ? AND id = ? FOR UPDATE`,
	qLockGroup:     `SELECT pg_advisory_xact_lock(hashtext(?::text || ':' || ? || ':' || COALESCE(?::text, '')))`,
	qListByPartner: selectFields + ` WHERE partner_id = ? AND status <> 'R' ORDER BY document_type, user_id, version_no DESC`,
	qListByUser:    selectFields + ` WHERE partner_id = ? AND user_id = ? AND status <> 'R' ORDER BY document_type, version_no DESC`,
	qApproved:      selectFields + ` WHERE partner_id = ? AND document_type = ? AND user_id IS NOT DISTINCT FROM ? AND status = 'Y' ORDER BY version_no DESC`,
	qByVersion:     selectFields + ` WHERE partner_id = ? AND user_id IS NOT DISTINCT FROM ? AND document_type = ? AND version_no = ?`,
	qLatest: `SELECT DISTINCT ON (document_type)` + strings.TrimPrefix(strings.TrimSpace(selectFields), "SELECT") + `
 WHERE partner_id = ? AND user_id IS NOT DISTINCT FROM ? AND status <> 'R' ORDER BY document_type, version_no DESC`,
	qReviewedBy: selectFields + ` WHERE partner_id = ? AND reviewer_id = ? ORDER BY reviewed_at DESC, id DESC`,
	qPending:    selectFields + ` WHERE partner_id = ? AND status = 'P' ORDER BY uploaded_at, id`,
	qSetReview:  `UPDATE partner_document SET status = ?, reviewer_id = ?, reviewed_at = CURRENT_TIMESTAMP, reviewer_notes = ? WHERE id = ?`,
	qRetire:     `UPDATE partner_document SET status = 'R', retired_at = CURRENT_TIMESTAMP WHERE id = ?`,
	qRetiredBefore: `
SELECT id, contrep_id, doc_key, retired_at FROM partner_document
 WHERE status = 'R' AND purged_at IS NULL AND retired_at < ? AND (retired_at, id) > (?, ?)
 ORDER BY retired_at, id LIMIT ?`,
	qSetPurged: `UPDATE partner_document SET purged_at = CURRENT_TIMESTAMP WHERE id = ?`,
}
