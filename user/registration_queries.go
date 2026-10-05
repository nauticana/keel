package user

const (
	qAddUserRegistration      = "add_user_registration"
	qGetUserRegistration      = "get_user_registration"
	qSetUserRegistration      = "set_user_registration"
	qBumpRegistrationAttempts = "bump_registration_attempts"
	qExpireRegistration       = "expire_registration"
	qAddPartner               = "add_partner"
	qAddAddress               = "add_address"
	qAddDomain                = "add_domain"
	qAddUserAccount           = "add_user_account"
	qRegistrantEmail          = "registrant_email"
	qMarkEmailVerifiedByEmail = "mark_email_verified_by_email"
	qAddPartnerUser           = "add_partner_user"
	qAddPartnerRole           = "add_partner_role"
	qGetPlan                  = "get_plan"
	qPlanPrices               = "plan_prices"
	qAddSubscription          = "add_subscription"
	qActivateSubscription     = "activate_subscription"
	qListActivePlans          = "list_active_plans"
)

var registerQueries = map[string]string{
	qAddUserRegistration: `
INSERT INTO user_registration
 (user_email, confirmation, payload)
VALUES
 (?, ?, ?)
`,
	// The TTL filter stops a minted-but-unused code from being guessed
	// indefinitely. Rows with a user_id are login tokens and contact changes,
	// which must never pass as a registration or password-reset code.
	qGetUserRegistration: "SELECT confirmation, payload, attempts FROM user_registration WHERE user_email = ? AND user_id IS NULL AND status = 'P' AND created_at > ? ORDER BY created_at DESC LIMIT 1",
	qSetUserRegistration: "UPDATE user_registration SET confirmed_at = CURRENT_TIMESTAMP, status = 'C' WHERE user_email = ? AND user_id IS NULL AND status = 'P'",
	qBumpRegistrationAttempts: `
UPDATE user_registration
   SET attempts = attempts + 1
 WHERE user_email = ?
   AND confirmation = ?
   AND user_id IS NULL
   AND status = 'P'
RETURNING attempts
`,
	qExpireRegistration: "UPDATE user_registration SET status = 'X' WHERE user_email = ? AND user_id IS NULL AND status = 'P'",
	qAddPartner: `
INSERT INTO business_partner
 (id, caption)
VALUES
 (nextval('business_partner_seq'), ?)
RETURNING id
`,
	qAddAddress: `
INSERT INTO partner_address
 (partner_id, address, city, state, zipcode, country, phone, latitude, longitude)
VALUES
 (?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
	qAddDomain: `
INSERT INTO partner_domain
 (partner_id, domain_url, is_primary)
VALUES
 (?, ?, TRUE)
`,
	// The emailed code proved the address.
	qAddUserAccount: `
INSERT INTO user_account
 (id, first_name, last_name, user_name, user_email, status, passtext, passdate, login_attempts,
  email_verification_method, email_verified_at)
VALUES
 (?, ?, ?, ?, ?, 'A', ?, CURRENT_TIMESTAMP, 0, 'R', CURRENT_TIMESTAMP)
`,
	qRegistrantEmail: "SELECT user_email, email_verified_at IS NOT NULL FROM user_account WHERE id = ?",
	qMarkEmailVerifiedByEmail: `
UPDATE user_account
   SET email_verified_at = CURRENT_TIMESTAMP, email_verification_method = 'P'
 WHERE user_email = ?
`,
	qAddPartnerUser: `
INSERT INTO partner_user
 (partner_id, user_id, begda)
VALUES
 (?, ?, CURRENT_TIMESTAMP)
`,
	// Only a partner-scoped role can be granted to a partner's creator.
	qAddPartnerRole: `
INSERT INTO user_permission
 (user_id, role_id, begda)
SELECT CAST(? AS BIGINT), id, CURRENT_TIMESTAMP
  FROM authorization_role
 WHERE id = ? AND partner_scoped = TRUE
RETURNING role_id
`,
	qGetPlan: `
SELECT currency, activation_mode FROM subscription_plan WHERE id = ? AND is_active = TRUE
`,
	qPlanPrices: `
SELECT billing_cycle, term_type, term_count, amount_minor, currency, COALESCE(provider_price_id, '')
  FROM subscription_plan_price WHERE plan_id = ?
`,
	qAddSubscription: `
INSERT INTO partner_plan_subscription
 (partner_id, plan_id, begda, status, monthly_cost, currency, auto_renew,
  billing_cycle, term_count, term_type, amount_minor, renewal_date, next_charge_date)
VALUES
 (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, TRUE, ?, ?, ?, ?, ?, ?)
`,
	qActivateSubscription: `
UPDATE partner_plan_subscription
   SET status = 'A'
 WHERE partner_id = ? AND plan_id = ? AND status = 'P'
`,
	qListActivePlans: `
SELECT sp.id, sp.caption, sp.activation_mode, sp.trial_days,
       pp.billing_cycle, pp.term_count, pp.term_type, pp.amount_minor, pp.currency, pp.provider_price_id
  FROM subscription_plan sp
  LEFT JOIN subscription_plan_price pp ON pp.plan_id = sp.id
 WHERE sp.is_active = TRUE
 ORDER BY sp.id, pp.term_type, pp.term_count, pp.billing_cycle
`,
}
