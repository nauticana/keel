package sso

import "github.com/nauticana/keel/common"

const (
	qSCIMManaged          = "scim_managed"
	qActiveSCIMUsers      = "scim_active_users"
	qLockSCIMTokens       = "scim_lock_tokens"
	qTokenByHash          = "scim_token_by_hash"
	qTouchToken           = "scim_touch_token"
	qActiveTokens         = "scim_active_tokens"
	qInsertToken          = "scim_insert_token"
	qRevokeToken          = "scim_revoke_token"
	qSCIMUser             = "scim_user"
	qSCIMUsers            = "scim_users"
	qSCIMUserCount        = "scim_user_count"
	qSCIMUserGroups       = "scim_user_groups"
	qSCIMUserConflict     = "scim_user_conflict"
	qInsertSCIMUser       = "scim_insert_user"
	qUpdateSCIMUser       = "scim_update_user"
	qDeleteSCIMUser       = "scim_delete_user"
	qSCIMGroup            = "scim_group"
	qSCIMGroups           = "scim_groups"
	qSCIMGroupCount       = "scim_group_count"
	qSCIMGroupMembers     = "scim_group_members"
	qSCIMGroupMemberCount = "scim_group_member_count"
	qSCIMGroupConflict    = "scim_group_conflict"
	qInsertSCIMGroup      = "scim_insert_group"
	qUpdateSCIMGroup      = "scim_update_group"
	qDeleteSCIMGroup      = "scim_delete_group"
	qAddGroupMember       = "scim_add_group_member"
	qRemoveGroupMember    = "scim_remove_group_member"
	qRemoveAllMembers     = "scim_remove_all_members"
)

const scimUserColumns = `
SELECT su.user_id, COALESCE(su.external_id, ''), su.user_name, su.active, su.created_at, su.updated_at,
       COALESCE(ua.first_name, ''), COALESCE(ua.last_name, ''), COALESCE(ua.user_email, '')
  FROM partner_scim_user su
  JOIN user_account ua ON ua.id = su.user_id`

// An empty filter value matches every row.
const scimUserFilter = ` WHERE su.partner_id = ?
   AND (CAST(? AS TEXT) = '' OR su.user_name = ?)
   AND (CAST(? AS TEXT) = '' OR su.external_id = ?)`

const scimGroupColumns = `SELECT id, COALESCE(external_id, ''), display_name, created_at, updated_at FROM partner_scim_group`

const scimGroupFilter = ` WHERE partner_id = ?
   AND (CAST(? AS TEXT) = '' OR display_name = ?)
   AND (CAST(? AS TEXT) = '' OR external_id = ?)`

var scimQueries = map[string]string{
	qSCIMManaged:     `SELECT 1 FROM partner_scim_user WHERE partner_id = ? AND user_id = ? AND active`,
	qLockSCIMTokens:  `SELECT id FROM business_partner WHERE id = ? FOR NO KEY UPDATE`,
	qActiveSCIMUsers: `SELECT user_id FROM partner_scim_user WHERE partner_id = ? AND active ORDER BY user_id`,
	qTokenByHash: `
SELECT id, partner_id FROM partner_scim_token
 WHERE token_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
	// Written at most once a minute per token.
	qTouchToken: `
UPDATE partner_scim_token SET last_used_at = CURRENT_TIMESTAMP
 WHERE id = ? AND (last_used_at IS NULL OR last_used_at < CURRENT_TIMESTAMP - INTERVAL '1 minute')`,
	qActiveTokens: `
SELECT COUNT(*) FROM partner_scim_token
 WHERE partner_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
	qInsertToken: `
INSERT INTO partner_scim_token (id, partner_id, caption, token_hash, created_by, expires_at)
VALUES (nextval('partner_scim_token_seq'), ?, ?, ?, ?,
        CASE WHEN CAST(? AS INTEGER) > 0 THEN CURRENT_TIMESTAMP + CAST(? AS INTEGER) * INTERVAL '1 day' END)
RETURNING id`,
	qRevokeToken: `
UPDATE partner_scim_token SET revoked_at = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND id = ? AND revoked_at IS NULL
RETURNING id`,
	qSCIMUser:      scimUserColumns + ` WHERE su.partner_id = ? AND su.user_id = ?`,
	qSCIMUsers:     scimUserColumns + scimUserFilter + ` ORDER BY su.user_id LIMIT ? OFFSET ?`,
	qSCIMUserCount: `SELECT COUNT(*) FROM partner_scim_user su` + scimUserFilter,
	qSCIMUserGroups: `
SELECT g.id, g.display_name, COALESCE(g.external_id, '')
  FROM partner_scim_group_member m
  JOIN partner_scim_group g ON g.partner_id = m.partner_id AND g.id = m.group_id
 WHERE m.partner_id = ? AND m.user_id = ?
 ORDER BY g.id`,
	qSCIMUserConflict: `
SELECT user_id FROM partner_scim_user
 WHERE partner_id = ? AND user_id <> ? AND (user_name = ? OR (CAST(? AS TEXT) <> '' AND external_id = ?))`,
	qInsertSCIMUser: `INSERT INTO partner_scim_user (partner_id, user_id, user_name, external_id, active) VALUES (?, ?, ?, ?, ?)`,
	qUpdateSCIMUser: `
UPDATE partner_scim_user SET user_name = ?, external_id = ?, active = ?, updated_at = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND user_id = ?`,
	qDeleteSCIMUser: `DELETE FROM partner_scim_user WHERE partner_id = ? AND user_id = ?`,
	qSCIMGroup:      scimGroupColumns + ` WHERE partner_id = ? AND id = ?`,
	qSCIMGroups:     scimGroupColumns + scimGroupFilter + ` ORDER BY id LIMIT ? OFFSET ?`,
	qSCIMGroupCount: `SELECT COUNT(*) FROM partner_scim_group` + scimGroupFilter,
	qSCIMGroupMembers: `
SELECT m.user_id, su.user_name
  FROM partner_scim_group_member m
  JOIN partner_scim_user su ON su.partner_id = m.partner_id AND su.user_id = m.user_id
 WHERE m.partner_id = ? AND m.group_id = ?
 ORDER BY m.user_id
 LIMIT ?`,
	qSCIMGroupMemberCount: `SELECT COUNT(*) FROM partner_scim_group_member WHERE partner_id = ? AND group_id = ?`,
	qSCIMGroupConflict: `
SELECT id FROM partner_scim_group
 WHERE partner_id = ? AND id <> ? AND (display_name = ? OR (CAST(? AS TEXT) <> '' AND external_id = ?))`,
	qInsertSCIMGroup: `
INSERT INTO partner_scim_group (id, partner_id, display_name, external_id)
VALUES (nextval('partner_scim_group_seq'), ?, ?, ?)
RETURNING id`,
	qUpdateSCIMGroup: `
UPDATE partner_scim_group SET display_name = ?, external_id = ?, updated_at = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND id = ?`,
	qDeleteSCIMGroup: `DELETE FROM partner_scim_group WHERE partner_id = ? AND id = ?`,
	qAddGroupMember: `
INSERT INTO partner_scim_group_member (partner_id, group_id, user_id) VALUES (?, ?, ?)
ON CONFLICT DO NOTHING`,
	qRemoveGroupMember: `DELETE FROM partner_scim_group_member WHERE partner_id = ? AND group_id = ? AND user_id = ?`,
	qRemoveAllMembers:  `DELETE FROM partner_scim_group_member WHERE partner_id = ? AND group_id = ? RETURNING user_id`,
}

// allQueries is every named query of the package, for one query service and
// for transactions that mix sign-in, role and provisioning statements.
var allQueries = common.MergeMaps(queries, scimQueries)
