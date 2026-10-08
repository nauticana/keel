package sso

const (
	qActiveConnection   = "sso_active_connection"
	qConnection         = "sso_connection"
	qConnectionClient   = "sso_connection_client"
	qInsertConnection   = "sso_insert_connection"
	qInsertOIDC         = "sso_insert_oidc"
	qUpdateConnection   = "sso_update_connection"
	qUpdateOIDC         = "sso_update_oidc"
	qInsertSAML         = "sso_insert_saml"
	qUpdateSAML         = "sso_update_saml"
	qMarkTested         = "sso_mark_tested"
	qLockConnections    = "sso_lock_connections"
	qDeactivateOthers   = "sso_deactivate_others"
	qActivate           = "sso_activate"
	qDisable            = "sso_disable"
	qPartnerDomains     = "sso_partner_domains"
	qTenantSessionUsers = "sso_tenant_session_users"
	qRoleMappings       = "sso_role_mappings"
	qOpenRoles          = "sso_open_roles"
	qMappedGrants       = "sso_mapped_grants"
	qGrantRole          = "sso_grant_role"
	qRecordGrant        = "sso_record_grant"
	qEndRole            = "sso_end_role"
	qEndProviderRoles   = "sso_end_provider_roles"
)

const connectionColumns = `SELECT id, partner_id, protocol, issuer, subject_claim, email_claim, require_mfa, status, tested_at IS NOT NULL
  FROM partner_identity_provider`

var queries = map[string]string{
	qActiveConnection: connectionColumns + ` WHERE partner_id = ? AND status = 'A'`,
	qConnection:       connectionColumns + ` WHERE partner_id = ? AND id = ?`,
	qConnectionClient: `SELECT client_id FROM partner_idp_oidc WHERE partner_id = ? AND provider_id = ?`,
	qInsertConnection: `
INSERT INTO partner_identity_provider (id, partner_id, caption, protocol, status, issuer, subject_claim, email_claim, require_mfa, created_by)
VALUES (nextval('partner_identity_provider_seq'), ?, ?, ?, 'D', ?, ?, ?, ?, ?)
RETURNING id`,
	qInsertOIDC: `
INSERT INTO partner_idp_oidc (partner_id, provider_id, discovery_url, client_id, client_auth, secret_name, credential_sealed, scopes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
	// keep_test is false when the issuer or client changed, which voids the last test.
	qUpdateConnection: `
UPDATE partner_identity_provider
   SET caption = ?, issuer = ?, subject_claim = ?, email_claim = ?, require_mfa = ?,
       tested_at = CASE WHEN CAST(? AS BOOLEAN) THEN tested_at END,
       tested_by = CASE WHEN CAST(? AS BOOLEAN) THEN tested_by END
 WHERE partner_id = ? AND id = ?`,
	qUpdateOIDC: `
UPDATE partner_idp_oidc
   SET discovery_url = ?, client_id = ?, client_auth = ?, secret_name = ?, credential_sealed = ?, scopes = ?
 WHERE partner_id = ? AND provider_id = ?`,
	qInsertSAML: `INSERT INTO partner_idp_saml (partner_id, provider_id, idp_metadata) VALUES (?, ?, ?)`,
	qUpdateSAML: `UPDATE partner_idp_saml SET idp_metadata = ? WHERE partner_id = ? AND provider_id = ?`,
	qMarkTested: `
UPDATE partner_identity_provider SET tested_at = CURRENT_TIMESTAMP, tested_by = ?
 WHERE partner_id = ? AND id = ? AND status <> 'X'`,
	// NO KEY UPDATE serializes connection writers without blocking inserts that reference them.
	qLockConnections: `SELECT id FROM partner_identity_provider WHERE partner_id = ? ORDER BY id FOR NO KEY UPDATE`,
	qDeactivateOthers: `
UPDATE partner_identity_provider SET status = 'X', status_changed_by = ?, status_changed_at = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND id <> ? AND status = 'A'
RETURNING id`,
	qActivate: `
UPDATE partner_identity_provider SET status = 'A', status_changed_by = ?, status_changed_at = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND id = ? AND tested_at IS NOT NULL
RETURNING id`,
	qDisable: `
UPDATE partner_identity_provider SET status = 'X', status_changed_by = ?, status_changed_at = CURRENT_TIMESTAMP
 WHERE partner_id = ? AND id = ? AND status <> 'X'
RETURNING id`,
	qPartnerDomains: `SELECT domain_url FROM partner_domain WHERE partner_id = ?`,
	qTenantSessionUsers: `
SELECT DISTINCT rt.user_id
  FROM user_refresh_token rt
  JOIN partner_user pu ON pu.user_id = rt.user_id AND pu.partner_id = ? AND pu.endda IS NULL
 WHERE rt.sign_in_method = 'T' AND rt.revoked_at IS NULL`,
	qRoleMappings: `SELECT claim_name, claim_value, role_id FROM partner_idp_role_mapping WHERE partner_id = ? AND provider_id = ?`,
	qOpenRoles:    `SELECT role_id FROM user_permission WHERE user_id = ? AND endda IS NULL`,
	qMappedGrants: `
SELECT g.role_id, g.begda
  FROM partner_idp_role_grant g
  JOIN user_permission p ON p.user_id = g.user_id AND p.role_id = g.role_id AND p.begda = g.begda AND p.endda IS NULL
 WHERE g.partner_id = ? AND g.provider_id = ? AND g.user_id = ?`,
	// Only a partner-scoped role is ever granted from a mapping.
	qGrantRole: `
INSERT INTO user_permission (user_id, role_id, begda)
SELECT CAST(? AS BIGINT), id, CURRENT_TIMESTAMP FROM authorization_role WHERE id = ? AND partner_scoped = TRUE
RETURNING begda`,
	qRecordGrant: `INSERT INTO partner_idp_role_grant (user_id, role_id, begda, partner_id, provider_id) VALUES (?, ?, ?, ?, ?)`,
	qEndRole: `
UPDATE user_permission SET endda = CURRENT_TIMESTAMP
 WHERE user_id = ? AND role_id = ? AND begda = ? AND endda IS NULL`,
	qEndProviderRoles: `
UPDATE user_permission p SET endda = CURRENT_TIMESTAMP
  FROM partner_idp_role_grant g
 WHERE g.partner_id = ? AND g.provider_id = ?
   AND p.user_id = g.user_id AND p.role_id = g.role_id AND p.begda = g.begda
   AND p.endda IS NULL`,
}
