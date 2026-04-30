package user

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
	"github.com/nauticana/keel/model"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nyaruka/phonenumbers"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// Sentinel errors signalling a unique-index violation on user_account.
// Callers can use errors.Is(err, ErrDuplicateEmail) etc. to detect a
// collision and route the user to a "an account with this contact already
// exists — sign in instead?" flow rather than retrying the create.
var (
	ErrDuplicateEmail = errors.New("user_account.user_email already exists")
	ErrDuplicatePhone = errors.New("user_account.phone already exists")
)

// classifyUniqueViolation maps a pgx unique-index error from user_account
// onto one of the sentinel duplicate errors. Returns the original error
// unchanged when it is not a unique violation or not on a tracked index.
//
// Deliberately drops pgErr.Detail — pgx's Detail message includes the
// conflicting value (e.g. "Key (user_email)=(foo@bar.com) already exists.")
// which would leak PII into error logs and 4xx response bodies. Callers
// that need the underlying value should look it up themselves.
func classifyUniqueViolation(err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return err
	}
	switch pgErr.ConstraintName {
	case "user_account_email_uq":
		return ErrDuplicateEmail
	case "user_account_phone_uq":
		return ErrDuplicatePhone
	}
	return err
}

const (
	UserStatusActive     = "A"
	UserStatusSelfLocked = "X"
	UserStatusExpired    = "E"
	UserStatusAdminLock  = "S"
	UserStatusInitial    = "I"
	UserStatusDeleted    = "D"

	UserActivityCreate = "C"
	UserActivityLogin  = "L"
	UserActivityFailed = "F"
	UserActivityLogout = "O"
	UserActivityLock   = "X"
	UserActivityUnlock = "U"
	UserActivityPasswd = "P"
	UserActivityDelete = "D"

	// EncryptionCost is the bcrypt work factor for password hashes.
	// Bumped from 10 → 12 in v0.4.1 to track OWASP 2024 guidance.
	// Existing 10-cost hashes continue to verify; on the next
	// successful login keel upgrades them to the new cost via
	// SetPassword in any flow that re-hashes.
	EncryptionCost = 12

	qUserAccountPolicy  = "user_account_policy"
	qUserMenu           = "user_menu"
	qUserByLogin        = "user_by_login"
	qUserById           = "user_by_id"
	qPartnerUserByid    = "partner_user_by_id"
	qPartnerUserByEmail = "partner_user_by_email"
	qSetPassword        = "set_password"
	qSetLoginAttempt    = "set_login_attempt"
	qBumpLoginAttempt   = "bump_login_attempt"
	qSetLastLogin       = "set_last_login"
	qAddUserActivity    = "add_user_activity"
	qSetLockStatus      = "set_lock_status"

	// 2FA queries
	qGet2FASecret      = "get_2fa_secret"
	qSet2FAEnabled     = "set_2fa_enabled"
	qDisable2FA        = "disable_2fa"
	qConsumeBackupCode = "consume_backup_code"

	// Login token queries
	qInsertLoginToken       = "insert_login_token"
	qGetLoginToken          = "get_login_token"
	qDeleteLoginToken       = "delete_login_token"
	qExpireLoginToken       = "expire_login_token"
	qIncrementLoginAttempts = "increment_login_attempts"

	// Login-token brute-force ceiling. After MaxLoginTokenAttempts wrong
	// confirmations against a user's pending token, the row is marked
	// expired and the user must re-initiate the login flow.
	MaxLoginTokenAttempts = 5

	// Refresh token queries
	qInsertRefreshToken          = "insert_refresh_token"
	qGetRefreshToken             = "get_refresh_token"
	qRevokeRefreshToken          = "revoke_refresh_token"
	qRevokeAllRefreshTokensForID = "revoke_all_refresh_tokens_for_user"

	// Trusted device queries
	qInsertTrustedDevice  = "insert_trusted_device"
	qCheckTrustedDevice   = "check_trusted_device"
	qGetTrustedDevices    = "get_trusted_devices"
	qRevokeTrustedDevice  = "revoke_trusted_device"
	qUpdateDeviceLastSeen = "update_device_last_seen"

	// OTP queries
	qUserByPhone                     = "user_by_phone"
	qUserBySocial                    = "user_by_social"
	qCreateSocialUser                = "create_social_user"
	qLinkSocialProvider              = "link_social_provider"
	qAnonymizeUserAccount            = "anonymize_user_account"
	qDeleteSocialLinks               = "delete_social_links_for_user"
	qDeleteTrustedDevices            = "delete_trusted_devices_for_user"
	qSetSingleDevicePolicy           = "set_single_device_policy"
	qRevokePriorOnSingleDevicePolicy = "revoke_prior_on_single_device_policy"

	// Device-token queries (P-2)
	qInsertDeviceToken             = "insert_device_token"
	qReactivateDeviceToken         = "reactivate_device_token"
	qDeactivateDeviceToken         = "deactivate_device_token"
	qGetActiveDeviceTokensForUser  = "get_active_device_tokens_for_user"
	qDeactivateDeviceTokensForUser = "deactivate_device_tokens_for_user"
	qGenerateOTP                   = "generate_otp"
	qVerifyOTP                     = "verify_otp"
	qIncrementOTP                  = "increment_otp_attempts"
	qClearOTP                      = "clear_otp"
)

var LocalUserQueries = map[string]string{
	qUserAccountPolicy: "SELECT id, policy_value FROM user_account_policy",

	qUserMenu: `
SELECT DISTINCT
       u.user_id,
       p.menu_id,
       p.item_id AS page_id,
       p.caption AS page_caption,
       p.rest_uri,
       m.caption AS menu_caption,
       m.display_order AS menu_order,
       p.display_order AS page_order
  FROM authorization_role_permission t, user_permission u, application_menu_item p, application_menu m
 WHERE t.role_id = u.role_id
   AND t.authorization_object_id = 'PAGE'
   AND t.action = 'ACCESS'
   AND t.low_limit IN (p.item_id, '*')
   AND m.id = p.menu_id
   AND u.user_id = ?
 ORDER BY m.display_order, p.display_order
`,

	qUserByLogin: `
SELECT id, user_name, first_name, last_name, user_email, status, passdate, passtext, login_attempts, last_login_attempt, lock_time
  FROM user_account
 WHERE user_name = ?
`,

	qUserById: `
SELECT id, user_name, first_name, last_name, user_email, status, passdate, passtext, login_attempts, last_login_attempt, lock_time
  FROM user_account
 WHERE id = ?
`,

	qPartnerUserByid: `
SELECT U.id, U.first_name, U.last_name, U.user_email, U.status, U.passdate, U.passtext, U.login_attempts, U.last_login_attempt, U.lock_time, p.partner_id
  FROM user_account U, partner_user p
 WHERE p.user_id = U.id
   AND U.id = ?
`,

	qPartnerUserByEmail: `
SELECT U.id, U.first_name, U.last_name, U.user_email, U.status, U.passdate, U.passtext, U.login_attempts, U.last_login_attempt, U.lock_time, p.partner_id
  FROM user_account U, partner_user p
 WHERE p.user_id = U.id
   AND U.user_email = ?
`,

	qSetPassword: `
UPDATE user_account
   SET passdate = ?,
       passtext = ?,
       login_attempts = 0,
       lock_time = NULL,
       status = 'A'
 WHERE id = ?
`,

	qSetLoginAttempt: `
UPDATE user_account
   SET login_attempts = ?,
       last_login_attempt = ?
 WHERE id = ?
`,

	// Atomic counter bump used by every brute-force-protected verify
	// path (password, 2FA, backup-code, OTP). Returning the
	// post-increment value lets the caller decide whether the
	// account just crossed MaxAttempts and should be self-locked,
	// without a read-then-write race window between two concurrent
	// failed attempts (MAJOR 8).
	qBumpLoginAttempt: `
UPDATE user_account
   SET login_attempts = login_attempts + 1,
       last_login_attempt = ?
 WHERE id = ?
RETURNING login_attempts
`,

	qSetLastLogin: `
UPDATE user_account
   SET last_login_attempt = ?,
       login_attempts = 0,
       lock_time = NULL,
       status = 'A'
 WHERE id = ?
`,

	qAddUserActivity: `
INSERT INTO user_account_history (user_id, action_time, action_type, status, object_name, client_address)
VALUES (?,?,?,?,?,?)
`,

	qSetLockStatus: `
UPDATE user_account
   SET status = ?, lock_time = ?
 WHERE id = ?
`,

	// qGet2FASecret returns both 2FA columns and the lockout-status
	// columns Verify2FA / VerifyBackupCode need to gate the verify
	// path. Returning everything in one round-trip cuts the per-call
	// DB cost from 2 queries to 1 (v0.4.4 perf). Column order:
	//   0 twofa_secret
	//   1 twofa_enabled
	//   2 twofa_backup_codes
	//   3 user_email
	//   4 status
	//   5 login_attempts
	//   6 last_login_attempt
	qGet2FASecret: `
SELECT twofa_secret, twofa_enabled, twofa_backup_codes, user_email,
       status, login_attempts, last_login_attempt
  FROM user_account
 WHERE id = ?
`,

	qSet2FAEnabled: `
UPDATE user_account
   SET twofa_enabled = TRUE,
       twofa_method = 'T',
       twofa_secret = ?,
       twofa_backup_codes = ?,
       twofa_enabled_at = CURRENT_TIMESTAMP
 WHERE id = ?
`,

	qDisable2FA: `
UPDATE user_account
   SET twofa_enabled = FALSE,
       twofa_method = NULL,
       twofa_secret = NULL,
       twofa_backup_codes = NULL,
       twofa_enabled_at = NULL
 WHERE id = ?
`,

	// Conditional consume: writes the new backup-codes string ONLY if the
	// column still holds the pre-consume value. The caller treats a
	// zero-row UPDATE result as "another verifier consumed first" and
	// reports failure, eliminating the race where two parallel verifies
	// would both succeed on the same code.
	qConsumeBackupCode: `
UPDATE user_account
   SET twofa_secret = ?,
       twofa_backup_codes = ?
 WHERE id = ?
   AND twofa_backup_codes = ?
`,

	qInsertLoginToken: `
INSERT INTO user_registration (user_email, confirmation, payload, status, user_id, attempts)
VALUES (?, ?, 'LOGIN', 'P', ?, 0)
`,

	// Lookup is bound to user_id so two pending LOGIN tokens with the same
	// 8-digit confirmation cannot collide across users. Caller obtains
	// user_id by parsing the token string ("<user_id>-<confirmation>").
	qGetLoginToken: `
SELECT user_email, attempts FROM user_registration
 WHERE user_id = ?
   AND confirmation = ?
   AND payload = 'LOGIN'
   AND status = 'P'
   AND created_at > CURRENT_TIMESTAMP - INTERVAL '5 minutes'
`,

	// Used after MaxAttempts is exceeded — destroys the row so subsequent
	// /verify calls return "expired" rather than continuing to leak the
	// presence of an active token.
	qExpireLoginToken: `
UPDATE user_registration
   SET status = 'X'
 WHERE user_id = ?
   AND payload = 'LOGIN'
`,

	// Atomic-bump variant of qIncrementLoginAttempts: returns the
	// post-increment attempts value when a pending row exists, or
	// zero rows when no row matches. Lets ValidateLoginToken
	// distinguish "real victim with a live token" from "attacker
	// guessing against a user_id that never started a login flow"
	// in a single round-trip — and avoids the read-then-write race
	// the previous read+UPDATE pattern carried (MAJOR 9).
	qIncrementLoginAttempts: `
UPDATE user_registration
   SET attempts = attempts + 1
 WHERE user_id = ?
   AND payload = 'LOGIN'
   AND status = 'P'
RETURNING attempts
`,

	qDeleteLoginToken: `
DELETE FROM user_registration
 WHERE user_id = ?
   AND payload = 'LOGIN'
`,

	qInsertRefreshToken: `
INSERT INTO user_refresh_token (id, user_id, token_hash, expires_at)
VALUES (nextval('user_refresh_token_seq'), ?, ?, CURRENT_TIMESTAMP + INTERVAL '30 days')
`,

	qGetRefreshToken: `
SELECT t.user_id, U.first_name, U.last_name, U.user_email, U.status, U.twofa_enabled, p.partner_id
  FROM user_refresh_token t, user_account U, partner_user p
 WHERE t.token_hash = ?
   AND t.revoked_at IS NULL
   AND t.expires_at > CURRENT_TIMESTAMP
   AND U.id = t.user_id
   AND p.user_id = U.id
`,

	qRevokeRefreshToken: `
UPDATE user_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = ?
`,

	qRevokeAllRefreshTokensForID: `
UPDATE user_refresh_token SET revoked_at = CURRENT_TIMESTAMP
 WHERE user_id = ? AND revoked_at IS NULL
`,

	qInsertTrustedDevice: `
INSERT INTO user_trusted_device (id, user_id, device_fingerprint, device_name, trusted_at, expires_at)
VALUES (nextval('user_trusted_device_seq'), ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '30 days')
`,

	qCheckTrustedDevice: `
SELECT id FROM user_trusted_device
 WHERE user_id = ?
   AND device_fingerprint = ?
   AND expires_at > CURRENT_TIMESTAMP
 LIMIT 1
`,

	qGetTrustedDevices: `
SELECT id, device_name, device_fingerprint, last_seen_at, trusted_at
  FROM user_trusted_device
 WHERE user_id = ?
   AND expires_at > CURRENT_TIMESTAMP
 ORDER BY trusted_at DESC
`,

	qRevokeTrustedDevice: `
DELETE FROM user_trusted_device WHERE id = ? AND user_id = ?
`,

	qUpdateDeviceLastSeen: `
UPDATE user_trusted_device SET last_seen_at = CURRENT_TIMESTAMP
 WHERE user_id = ? AND device_fingerprint = ?
`,

	qUserByPhone: `
SELECT U.id, U.first_name, U.last_name, U.user_email, U.phone, U.locale, U.status, p.partner_id
  FROM user_account U
  LEFT JOIN partner_user p ON p.user_id = U.id
 WHERE U.phone = ?
`,

	qUserBySocial: `
SELECT U.id, U.first_name, U.last_name, U.user_email, U.phone, U.locale, U.status, p.partner_id
  FROM user_account U
  LEFT JOIN partner_user p ON p.user_id = U.id
  JOIN user_social_provider sp ON sp.user_id = U.id
 WHERE sp.provider = ? AND sp.provider_id = ?
`,

	qCreateSocialUser: `
INSERT INTO user_account (id, first_name, last_name, user_email, phone, status, user_name)
VALUES (?, ?, ?, ?, ?, 'A', ?)
`,

	qLinkSocialProvider: `
INSERT INTO user_social_provider (user_id, provider, provider_id)
VALUES (?, ?, ?)
`,

	qAnonymizeUserAccount: `
UPDATE user_account
   SET first_name = 'Deleted',
       last_name = 'User',
       user_email = ?,
       user_name = ?,
       phone = NULL,
       passtext = NULL,
       passdate = NULL,
       twofa_enabled = FALSE,
       twofa_method = NULL,
       twofa_secret = NULL,
       twofa_backup_codes = NULL,
       twofa_enabled_at = NULL,
       status = 'D',
       deleted_at = CURRENT_TIMESTAMP
 WHERE id = ?
`,

	qDeleteSocialLinks: `
DELETE FROM user_social_provider WHERE user_id = ?
`,

	qDeleteTrustedDevices: `
DELETE FROM user_trusted_device WHERE user_id = ?
`,

	qSetSingleDevicePolicy: `
UPDATE user_account SET single_device_session = ? WHERE id = ?
`,

	// Conditional bulk revoke: only affects users whose single_device_session
	// bit is TRUE. Runs unconditionally before every CreateRefreshToken so
	// the policy is enforced at issuance time without an extra round-trip.
	qRevokePriorOnSingleDevicePolicy: `
UPDATE user_refresh_token
   SET revoked_at = CURRENT_TIMESTAMP
 WHERE user_id = ?
   AND revoked_at IS NULL
   AND EXISTS (SELECT 1 FROM user_account WHERE id = ? AND single_device_session = TRUE)
`,

	// --- device_token queries (P-2 push promotion) ---

	// Single-statement upsert (MAJOR 13). The previous two-query
	// implementation (UPDATE-then-INSERT-if-no-rows) relied on
	// driver-specific row-count semantics — pgx's UPDATE returns
	// zero rows even on success unless RETURNING is used, so the
	// fallback INSERT always fired and surfaced a UNIQUE-violation
	// error to the caller. ON CONFLICT against the (user_id, token)
	// unique index does the right thing in one round-trip and is
	// race-free.
	qInsertDeviceToken: `
INSERT INTO device_token
 (id, user_id, platform, token, app_version, device_model, is_active, created_at, updated_at, last_seen_at)
VALUES
 (nextval('device_token_seq'), ?, ?, ?, ?, ?, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (user_id, token) DO UPDATE
   SET is_active     = TRUE,
       platform      = EXCLUDED.platform,
       app_version   = EXCLUDED.app_version,
       device_model  = EXCLUDED.device_model,
       updated_at    = CURRENT_TIMESTAMP,
       last_seen_at  = CURRENT_TIMESTAMP
`,

	// qReactivateDeviceToken is retained as a no-op-friendly alias
	// in case downstream callers reference it directly. Modern code
	// should call qInsertDeviceToken — its ON CONFLICT clause makes
	// it the canonical idempotent upsert.
	qReactivateDeviceToken: `
UPDATE device_token
   SET is_active = TRUE,
       platform = ?,
       app_version = ?,
       device_model = ?,
       updated_at = CURRENT_TIMESTAMP,
       last_seen_at = CURRENT_TIMESTAMP
 WHERE user_id = ? AND token = ?
`,

	qDeactivateDeviceToken: `
UPDATE device_token
   SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
 WHERE user_id = ? AND token = ?
`,

	qGetActiveDeviceTokensForUser: `
SELECT id, platform, token, COALESCE(app_version,''), COALESCE(device_model,''), created_at, COALESCE(last_seen_at, created_at)
  FROM device_token
 WHERE user_id = ? AND is_active = TRUE
`,

	qDeactivateDeviceTokensForUser: `
UPDATE device_token
   SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
 WHERE user_id = ?
`,

	qGenerateOTP: `
INSERT INTO user_otp (id, user_id, code, purpose, expires_at, attempts)
VALUES (nextval('user_otp_seq'), ?, ?, ?, CURRENT_TIMESTAMP + INTERVAL '2 minutes', 0)
RETURNING id
`,

	qVerifyOTP: `
SELECT id, code, attempts FROM user_otp
 WHERE user_id = ?
   AND expires_at > CURRENT_TIMESTAMP
 ORDER BY id DESC LIMIT 1
`,

	qIncrementOTP: `
UPDATE user_otp SET attempts = attempts + 1
 WHERE user_id = ?
   AND id = (SELECT MAX(id) FROM user_otp WHERE user_id = ?)
`,

	qClearOTP: `
DELETE FROM user_otp WHERE user_id = ?
`,
}

type LocalUserService struct {
	database        data.DatabaseRepository
	queryService    data.QueryService
	jwtSecret       []byte
	sSessionTimeout int64
	passwordPolicy  model.PasswordPolicy
	Issuer          string
	// ConsentService is optional. When set, signup flows that create a new
	// user_account (social, phone OTP) record consent inside the account
	// creation transaction. When nil, consent recording is skipped.
	ConsentService ConsentService

	// Ctx is the parent context used by every service method that needs
	// to issue a DB query. Set by NewLocalUserService / Init from the
	// caller-supplied ctx so process-shutdown propagates through. May
	// be replaced post-construction (e.g. on graceful shutdown) by
	// re-assigning the field directly. Falls back to context.Background()
	// when unset so legacy callers that constructed LocalUserService
	// by struct-literal still work.
	//
	// LIMITATION: this is a process-lifetime ctx, NOT a per-request
	// ctx. A slow query here will continue to occupy a connection
	// even after the originating HTTP request has been cancelled by
	// the client. The fix is to thread ctx through every method on
	// UserService, but that is a breaking API change requiring every
	// downstream consumer to update every call site. Tracked as a
	// future major-version migration; for now the impact is bounded
	// because pgxpool reaps idle connections aggressively and queries
	// that genuinely take >5s under load are rare in this codebase.
	Ctx context.Context
}

// ctx returns the active service context, defaulting to
// context.Background() when the field is unset. Centralized so the
// fallback is in one place rather than 39 branches across the file.
func (s *LocalUserService) ctx() context.Context {
	if s.Ctx == nil {
		return context.Background()
	}
	return s.Ctx
}

// EmailFor satisfies port.RecipientResolver. Returns the user's
// stored email address (already normalized at write-time) or "" when
// the user has no email — deleted accounts, OTP-only signups, or
// "Hide My Email" Apple-relay accounts that were never updated.
func (s *LocalUserService) EmailFor(userID int) (string, error) {
	session, err := s.GetUserById(userID)
	if err != nil {
		return "", err
	}
	if session == nil {
		return "", nil
	}
	return session.Email, nil
}

// PhoneFor satisfies port.RecipientResolver. Returns the user's
// E.164 phone, or "" when the user has no phone on file.
func (s *LocalUserService) PhoneFor(userID int) (string, error) {
	session, err := s.GetUserById(userID)
	if err != nil {
		return "", err
	}
	if session == nil {
		return "", nil
	}
	return session.PhoneNumber, nil
}

func NewLocalUserService(ctx context.Context, database data.DatabaseRepository, jwtSecret string, issuer string) (*LocalUserService, error) {
	svc := &LocalUserService{
		Issuer: issuer,
	}
	if err := svc.Init(ctx, database, jwtSecret); err != nil {
		return nil, err
	}
	return svc, nil
}

func (r *LocalUserService) Init(ctx context.Context, database data.DatabaseRepository, jwtSecret string) error {
	r.database = database
	r.Ctx = ctx
	r.queryService = database.GetQueryService(ctx, LocalUserQueries)
	r.sSessionTimeout = int64(*common.SessionTimeout) * int64(time.Second)
	r.jwtSecret = []byte(jwtSecret)
	if r.Issuer == "" {
		r.Issuer = "keel"
	}
	r.passwordPolicy = model.PasswordPolicy{
		PasswordExpire:    90,
		MinPasswordLength: 8,
		MinPasswordUpper:  1,
		MinPasswordLower:  1,
		MinPasswordDigit:  1,
		MaxAttempts:       5,
		// AutoLogout / AutoUnlock are stored as nanoseconds so they can be
		// compared against time.Time.UnixNano() differences without unit drift.
		AutoLogout: int64(5 * time.Minute),
		AutoUnlock: int64(5 * time.Minute),
	}
	res, err := r.queryService.Query(ctx, qUserAccountPolicy)
	if err != nil {
		return err
	}
	for _, row := range res.Rows {
		policy := common.AsString(row[0])
		value := int(common.AsInt32(row[1]))
		switch policy {
		case "PASSWORD_EXPIRE_DAYS":
			r.passwordPolicy.PasswordExpire = value
		case "MIN_PASSWORD_LENGTH":
			r.passwordPolicy.MinPasswordLength = value
		case "MIN_PASSWORD_UPPER":
			r.passwordPolicy.MinPasswordUpper = value
		case "MIN_PASSWORD_LOWER":
			r.passwordPolicy.MinPasswordLower = value
		case "MIN_PASSWORD_DIGIT":
			r.passwordPolicy.MinPasswordDigit = value
		case "MIN_PASSWORD_SPECIAL":
			r.passwordPolicy.MinPasswordSpecial = value
		case "MAX_ATTEMPTS":
			r.passwordPolicy.MaxAttempts = value
		case "AUTO_UNLOCK_MINUTES":
			r.passwordPolicy.AutoUnlock = int64(value) * int64(time.Minute)
		case "AUTO_LOGOUT_MINUTES":
			r.passwordPolicy.AutoLogout = int64(value) * int64(time.Minute)
		default:
			return fmt.Errorf("unknown password policy found in database: %s", policy)
		}
	}
	return nil
}

// checkAccountStatus returns nil when the account can proceed to a session
// issue, or an error describing why it cannot. Centralizes the expiry/
// lock/auto-unlock logic so GetUserById, GetUserByLogin, and GetUserByEmail
// can never disagree.
//
// When status is self-locked but lastAttempt is zero (NULL in the DB), we
// treat the account as unlocked rather than perma-locked. The lockout
// window is anchored to the most recent failed attempt; without a recorded
// timestamp we have no anchor, and choosing "still locked" would prevent
// any user with a NULL last_login_attempt from ever signing in. That risk
// is preferable to the alternative of a self-locked-then-data-migrated
// account being indefinitely shut out.
func (s *LocalUserService) checkAccountStatus(uStatus string, lastAttempt time.Time) error {
	if uStatus == UserStatusExpired {
		return fmt.Errorf("user account is expired")
	}
	if uStatus == UserStatusAdminLock {
		return fmt.Errorf("user account is locked")
	}
	if uStatus == UserStatusSelfLocked {
		if lastAttempt.IsZero() {
			return nil
		}
		if s.passwordPolicy.AutoUnlock > time.Now().UnixNano()-lastAttempt.UnixNano() {
			return fmt.Errorf("user account is locked")
		}
	}
	return nil
}

func (r *LocalUserService) GetUserMenu(userid int) ([]model.UserMenu, error) {
	ctx := r.ctx()
	res, err := r.queryService.Query(ctx, qUserMenu, userid)
	if err != nil {
		return nil, err
	}
	var m []model.UserMenu
	for _, row := range res.Rows {
		m = append(m, model.UserMenu{
			Menu:        common.AsString(row[1]),
			MenuCaption: common.AsString(row[5]),
			PageCaption: common.AsString(row[3]),
			Url:         common.AsString(row[4]),
			MenuOrder:   int(common.AsInt32(row[6])),
			PageOrder:   int(common.AsInt32(row[7])),
		})
	}
	return m, nil
}

func (s *LocalUserService) AddUserHistory(id int, byId int, clientaddress, actionType string, status string, objectName string) error {
	ctx := s.ctx()
	_, err := s.queryService.Query(ctx, qAddUserActivity, id, time.Now(), actionType, status, objectName, clientaddress)
	return err
}

// bumpLoginAttempts atomically increments user_account.login_attempts
// for the given user and returns the post-increment value. When the
// returned value crosses the policy ceiling, the account is flipped
// to self-locked status. Used by every brute-force-protected verify
// path (password, 2FA, backup code) so two concurrent failed attempts
// never both observe `attempts == n` and both write `n+1` (MAJOR 8).
func (s *LocalUserService) bumpLoginAttempts(userID int, reason string) (int, error) {
	ctx := s.ctx()
	res, err := s.queryService.Query(ctx, qBumpLoginAttempt, time.Now(), userID)
	if err != nil {
		return 0, err
	}
	attempts := 0
	if res != nil && len(res.Rows) > 0 {
		attempts = int(common.AsInt32(res.Rows[0][0]))
	}
	if attempts >= s.passwordPolicy.MaxAttempts {
		_, _ = s.queryService.Query(ctx, qSetLockStatus, UserStatusSelfLocked, time.Now(), userID)
		_ = s.AddUserHistory(userID, 0, "", UserActivityLock, UserStatusSelfLocked, reason)
	}
	return attempts, nil
}

// verifyPasswordByID is the re-auth-gate verify path: looks up the
// password hash by user id (so phone/social signups, whose Subject
// is "First Last" rather than user_name, can still re-auth via the
// password they happen to have set), bcrypt-compares, and bumps the
// shared login_attempts counter on mismatch (MAJOR 8 atomic). On
// success the counter is reset via qSetLastLogin.
//
// Used by handler.requireRecentAuth — see BLOCKER 3 for the bug
// this replaces (the previous implementation looked up by
// session.Subject, which silently failed for non-password signups).
func (s *LocalUserService) verifyPasswordByID(userID int, password string) (bool, error) {
	ctx := s.ctx()
	res, err := s.queryService.Query(ctx, qUserById, userID)
	if err != nil {
		return false, err
	}
	if len(res.Rows) == 0 {
		return false, fmt.Errorf("user not found")
	}
	row := res.Rows[0]
	uStatus := common.AsString(row[5])
	lastAttempt, _ := row[9].(time.Time)
	if err := s.checkAccountStatus(uStatus, lastAttempt); err != nil {
		return false, err
	}
	if row[7] == nil {
		return false, fmt.Errorf("password authentication not enabled for this account")
	}
	passtext := common.AsString(row[7])
	if bcrypt.CompareHashAndPassword([]byte(passtext), []byte(password)) != nil {
		_, _ = s.bumpLoginAttempts(userID, "re-auth-fail")
		return false, nil
	}
	_, _ = s.queryService.Query(ctx, qSetLastLogin, time.Now(), userID)
	return true, nil
}

// VerifyPasswordByID is the public re-auth-gate verify path. Used by
// handler.requireRecentAuth so the gate works for users whose
// session.Subject isn't the canonical user_name (phone-OTP /
// social-login signups). Returns (true, nil) on a correct password,
// (false, nil) on mismatch, (false, err) on a service / lookup
// failure.
func (s *LocalUserService) VerifyPasswordByID(userID int, password string) (bool, error) {
	return s.verifyPasswordByID(userID, password)
}

func (s *LocalUserService) GetUserById(userId int) (*model.UserSession, error) {
	ctx := s.ctx()
	res, err := s.queryService.Query(ctx, qUserById, userId)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("user account not found for userid: %d", userId)
	}
	row := res.Rows[0]
	userAccountId := int(common.AsInt64(row[0]))
	uStatus := common.AsString(row[5])
	lastAttempt, _ := row[9].(time.Time)

	if err := s.checkAccountStatus(uStatus, lastAttempt); err != nil {
		return nil, err
	}

	session := &model.UserSession{
		Id:        userAccountId,
		Subject:   common.AsString(row[1]),
		Issuer:    s.Issuer,
		FirstName: common.AsString(row[2]),
		LastName:  common.AsString(row[3]),
		Email:     common.AsString(row[4]),
		Status:    uStatus,
		Provider:  "local",
		ExpiresAt: time.Now().Add(time.Duration(s.sSessionTimeout)).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	partnerRes, err := s.queryService.Query(ctx, qPartnerUserByid, userAccountId)
	if err == nil && len(partnerRes.Rows) > 0 {
		session.PartnerId = common.AsInt64(partnerRes.Rows[0][10])
	}

	return session, nil
}

func (s *LocalUserService) GetUserByLogin(username string, password string) (*model.UserSession, error) {
	ctx := s.ctx()
	res, err := s.queryService.Query(ctx, qUserByLogin, username)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("user account not found for username: %s", username)
	}
	row := res.Rows[0]
	userAccountId := int(common.AsInt64(row[0]))
	uStatus := common.AsString(row[5])
	passdate, _ := row[6].(time.Time)
	attempts := int(common.AsInt32(row[8]))
	lastAttempt, _ := row[9].(time.Time)

	if err := s.checkAccountStatus(uStatus, lastAttempt); err != nil {
		return nil, err
	}
	if row[7] == nil {
		return nil, fmt.Errorf("password authentication not enabled for this account")
	}
	passtext := common.AsString(row[7])
	if bcrypt.CompareHashAndPassword([]byte(passtext), []byte(password)) != nil {
		// Atomic increment closes the read-then-write race that
		// previously let two parallel failed attempts both write
		// the same counter value (MAJOR 8). bumpLoginAttempts also
		// flips status to self-locked when the ceiling is crossed.
		newAttempts, _ := s.bumpLoginAttempts(userAccountId, "password-attempts-exceeded")
		s.AddUserHistory(userAccountId, 0, "", UserActivityFailed, "A", "")
		if newAttempts >= s.passwordPolicy.MaxAttempts {
			return nil, fmt.Errorf("too many failed login attempts, user account is locked")
		}
		_ = attempts // legacy local kept for clarity; not used after the bump
		return nil, fmt.Errorf("invalid password")
	}

	session := &model.UserSession{
		Id:        userAccountId,
		Subject:   common.AsString(row[1]),
		Issuer:    s.Issuer,
		FirstName: common.AsString(row[2]),
		LastName:  common.AsString(row[3]),
		Email:     common.AsString(row[4]),
		Status:    uStatus,
		Provider:  "local",
		ExpiresAt: time.Now().Add(time.Duration(s.sSessionTimeout)).Unix(),
		IssuedAt:  time.Now().Unix(),
	}
	if passdate.AddDate(0, 0, s.passwordPolicy.PasswordExpire).Before(time.Now()) {
		return nil, fmt.Errorf("password expired")
	}
	s.AddUserHistory(userAccountId, 0, "", UserActivityLogin, "A", "")
	s.queryService.Query(ctx, qSetLastLogin, time.Now(), userAccountId)
	return session, nil
}

func (s *LocalUserService) GetUserByUsername(username string) (*model.UserSession, error) {
	ctx := s.ctx()
	res, err := s.queryService.Query(ctx, qUserByLogin, username)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("user account not found for username: %s", username)
	}
	row := res.Rows[0]
	session := s.newSession(
		int(common.AsInt64(row[0])),
		common.AsString(row[2]),
		common.AsString(row[3]),
		common.AsString(row[4]),
		common.AsString(row[5]),
		"local",
	)
	session.Subject = common.AsString(row[1])
	return session, nil
}

// GetUserByEmail looks up a user by email and returns a session-shaped
// model. This is a read-only lookup — it does NOT log a login event or
// touch last_login_attempt; callers that intend the session as the keel
// for a real login (rather than internal lookup, e.g. inside ValidateLoginToken
// or social-login email-link branches) must record the activity themselves.
func (s *LocalUserService) GetUserByEmail(email string) (*model.UserSession, error) {
	ctx := s.ctx()
	email = normalizeEmail(email)
	res, err := s.queryService.Query(ctx, qPartnerUserByEmail, email)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("user account not found for email: %s", email)
	}
	row := res.Rows[0]
	userAccountId := int(common.AsInt64(row[0]))
	uStatus := common.AsString(row[4])
	lastAttempt, _ := row[8].(time.Time)

	if err := s.checkAccountStatus(uStatus, lastAttempt); err != nil {
		return nil, err
	}
	session := &model.UserSession{
		Id:        userAccountId,
		Subject:   common.AsString(row[1]) + " " + common.AsString(row[2]),
		Issuer:    s.Issuer,
		FirstName: common.AsString(row[1]),
		LastName:  common.AsString(row[2]),
		Email:     common.AsString(row[3]),
		PartnerId: common.AsInt64(row[10]),
		Provider:  "local",
		ExpiresAt: time.Now().Add(time.Duration(s.sSessionTimeout)).Unix(),
		IssuedAt:  time.Now().Unix(),
	}
	return session, nil
}

func (s *LocalUserService) SetPassword(userid int, password string) error {
	if err := s.passwordPolicy.Check(password); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), EncryptionCost)
	if err != nil {
		return err
	}
	ctx := s.ctx()
	_, err = s.queryService.Query(ctx, qSetPassword, time.Now(), hash, userid)
	if err != nil {
		return err
	}
	// Password change invalidates every active session — attacker's stale
	// refresh token must not continue to work after credential rotation.
	s.revokeAllRefreshTokens(userid)
	return s.AddUserHistory(userid, 0, "", UserActivityPasswd, "A", "")
}

// LogoutEverywhere revokes all active refresh tokens for a user. Public
// alias for consumers that want to expose a "log out of all devices"
// action without tying it to a password change or 2FA event.
func (s *LocalUserService) LogoutEverywhere(userID int) error {
	return s.revokeAllRefreshTokens(userID)
}

// revokeAllRefreshTokens is the package-internal primitive invoked from
// every sensitive-event method. Silent on error — revocation is defense
// in depth; the caller's primary action (SetPassword, 2FA toggle, etc.)
// has already committed by the time we're here.
func (s *LocalUserService) revokeAllRefreshTokens(userID int) error {
	_, err := s.queryService.Query(s.ctx(), qRevokeAllRefreshTokensForID, userID)
	return err
}

func (s *LocalUserService) CreateJWT(u *model.UserSession) (string, error) {
	return u.GetToken().SignedString(s.jwtSecret)
}

// ParseJWT validates the bearer token and returns the parsed session.
// Pins the signing algorithm to HMAC-SHA — rejects `none`, RS256, ES256,
// or any other alg the attacker might submit in the header. jwt/v5 also
// validates RegisteredClaims.ExpiresAt automatically once the embedded
// claim is populated (UserSession.SyncTimestamps does this on issuance).
func (s *LocalUserService) ParseJWT(tokenString string) (*model.UserSession, error) {
	token, err := jwt.ParseWithClaims(tokenString, &model.UserSession{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	}, jwt.WithExpirationRequired())
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*model.UserSession)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	// As of v0.4.3 the wire format only carries the embedded
	// RegisteredClaims (`iss`, `sub`, `exp`, `iat`); the in-Go
	// mirror fields on UserSession are tagged `json:"-"` to keep
	// the JWT body lean. Callers that read session.Subject /
	// session.Issuer / session.ExpiresAt / session.IssuedAt
	// directly need those mirrors hydrated from the validated
	// claims before we hand the session back.
	claims.HydrateFromRegisteredClaims()
	return claims, nil
}

// --- Refresh Token ---

func (s *LocalUserService) CreateRefreshToken(userID int) (string, error) {
	ctx := s.ctx()
	// Enforce single-device policy: if the bit is set on user_account, this
	// revokes every prior active refresh token for the user before we issue
	// a new one. When the bit is off the UPDATE is a no-op (EXISTS clause
	// matches nothing). Keeps the fast path a single round-trip.
	if _, err := s.queryService.Query(ctx, qRevokePriorOnSingleDevicePolicy, userID, userID); err != nil {
		return "", err
	}
	raw, err := generateRandomToken(48)
	if err != nil {
		return "", err
	}
	hash := sha256Hex(raw)
	if _, err := s.queryService.Query(ctx, qInsertRefreshToken, userID, hash); err != nil {
		return "", err
	}
	return raw, nil
}

// RegisterDeviceToken upserts a device_token row for a user. The
// underlying query is a single INSERT … ON CONFLICT (user_id, token)
// DO UPDATE — race-free and unaffected by driver-specific UPDATE
// row-count behaviour (MAJOR 13). Idempotent: the mobile client can
// call this on every app-launch without creating duplicates and
// without surfacing a UNIQUE-violation error.
func (s *LocalUserService) RegisterDeviceToken(userID int, platform, token, appVersion, deviceModel string) error {
	if userID <= 0 || token == "" {
		return fmt.Errorf("register device: user id and token are required")
	}
	_, err := s.queryService.Query(s.ctx(), qInsertDeviceToken,
		userID, platform, token, nullIfEmpty(appVersion), nullIfEmpty(deviceModel))
	return err
}

// RevokeDeviceToken marks a specific (user, token) pair inactive. Used on
// explicit logout. Push providers also mark tokens inactive autonomously
// when FCM reports them stale (see service/push/fcm.go).
func (s *LocalUserService) RevokeDeviceToken(userID int, token string) error {
	if userID <= 0 || token == "" {
		return fmt.Errorf("revoke device: user id and token are required")
	}
	_, err := s.queryService.Query(s.ctx(), qDeactivateDeviceToken, userID, token)
	return err
}

// ListActiveDeviceTokens returns every active device row for a user.
// Used by PushProvider implementations to fan out notifications.
func (s *LocalUserService) ListActiveDeviceTokens(userID int) ([]model.DeviceToken, error) {
	res, err := s.queryService.Query(s.ctx(), qGetActiveDeviceTokensForUser, userID)
	if err != nil {
		return nil, err
	}
	tokens := make([]model.DeviceToken, 0, len(res.Rows))
	for _, row := range res.Rows {
		tokens = append(tokens, model.DeviceToken{
			ID:          common.AsInt64(row[0]),
			UserID:      userID,
			Platform:    common.AsString(row[1]),
			Token:       common.AsString(row[2]),
			AppVersion:  common.AsString(row[3]),
			DeviceModel: common.AsString(row[4]),
			IsActive:    true,
			CreatedAt:   common.AsString(row[5]),
			LastSeenAt:  common.AsString(row[6]),
		})
	}
	return tokens, nil
}

// SetSingleDevicePolicy flips the per-user single_device_session bit.
// When on, CreateRefreshToken revokes every prior refresh token before
// issuing a new one — the user ends up logged in on exactly the device
// that most recently authenticated.
func (s *LocalUserService) SetSingleDevicePolicy(userID int, on bool) error {
	_, err := s.queryService.Query(s.ctx(), qSetSingleDevicePolicy, on, userID)
	return err
}

// ValidateRefreshToken accepts a presented refresh token, looks up
// the row by its SHA-256 hash, and (P1-02) ROTATES the token on use:
// the presented token is revoked and a fresh one is issued in the
// same call. Callers must replace their stored refresh-token value
// with NewRefreshToken on the returned session — sticking with the
// old token will fail on the next refresh.
//
// Rotation closes the long-lived-stolen-token threat: a stolen
// refresh token has the same TTL as the active access token (a few
// minutes), and re-using it after a legitimate rotation is detected
// as a replay (the row is already revoked).
func (s *LocalUserService) ValidateRefreshToken(token string) (*model.UserSession, error) {
	ctx := s.ctx()
	hash := sha256Hex(token)
	res, err := s.queryService.Query(ctx, qGetRefreshToken, hash)
	if err != nil {
		return nil, err
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("invalid or expired refresh token")
	}
	row := res.Rows[0]
	userID := int(common.AsInt64(row[0]))
	session := &model.UserSession{
		Id:               userID,
		FirstName:        common.AsString(row[1]),
		LastName:         common.AsString(row[2]),
		Email:            common.AsString(row[3]),
		Status:           common.AsString(row[4]),
		TwoFactorEnabled: common.AsBool(row[5]),
		PartnerId:        common.AsInt64(row[6]),
		Issuer:           s.Issuer,
		ExpiresAt:        time.Now().Add(15 * time.Minute).Unix(),
		IssuedAt:         time.Now().Unix(),
	}

	// Issue a fresh refresh token, then revoke the presented one. The
	// order matters: a transient failure between mint and revoke leaves
	// the user holding two valid tokens (which is benign), whereas the
	// reverse order would leave the user with NO refresh token if the
	// mint failed mid-step. The new token is returned via the session's
	// NewRefreshToken field; clients overwrite their stored value.
	rotated, err := generateRandomToken(48)
	if err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}
	rotatedHash := sha256Hex(rotated)
	if _, err := s.queryService.Query(ctx, qInsertRefreshToken, userID, rotatedHash); err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}
	if _, err := s.queryService.Query(ctx, qRevokeRefreshToken, hash); err != nil {
		// Already minted; leave the new token in place and let the old
		// one age out naturally. Caller still gets a usable session.
		s.logRotationFailure(userID, err)
	}
	session.NewRefreshToken = rotated
	return session, nil
}

// logRotationFailure is a small hook so a future structured logger can
// record refresh-token rotation cleanup misses. Today it's a no-op so
// the rotation path doesn't require an injected logger.
func (s *LocalUserService) logRotationFailure(userID int, _ error) {
	_ = userID
}

func (s *LocalUserService) RevokeRefreshToken(token string) error {
	hash := sha256Hex(token)
	_, err := s.queryService.Query(s.ctx(), qRevokeRefreshToken, hash)
	return err
}

// --- 2FA (TOTP) ---

func (s *LocalUserService) Setup2FA(userID int) (string, string, []string, error) {
	res, err := s.queryService.Query(s.ctx(), qGet2FASecret, userID)
	if err != nil {
		return "", "", nil, err
	}
	if len(res.Rows) == 0 {
		return "", "", nil, fmt.Errorf("user not found")
	}
	email := common.AsString(res.Rows[0][3])

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.Issuer,
		AccountName: email,
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Generate 10 codes + their salted SHA-256 hashes. Cost shifted
	// from bcrypt-12 (≈ 2.5s for the full Setup2FA call) down to
	// microseconds per code (v0.4.3 perf). See hashBackupCode for
	// the security trade-off rationale.
	backupCodes := make([]string, 10)
	hashedCodes := make([]string, 10)
	for i := 0; i < 10; i++ {
		code, err := generateRandomCode(8)
		if err != nil {
			return "", "", nil, err
		}
		backupCodes[i] = code
		stored, hashErr := hashBackupCode(code)
		if hashErr != nil {
			return "", "", nil, hashErr
		}
		hashedCodes[i] = stored
	}
	backupCodesJSON := strings.Join(hashedCodes, "|")

	_, err = s.queryService.Query(s.ctx(), qSet2FAEnabled, key.Secret(), backupCodesJSON, userID)
	if err != nil {
		return "", "", nil, err
	}
	// Enabling 2FA is a security-posture change; force re-auth everywhere.
	s.revokeAllRefreshTokens(userID)

	return key.Secret(), key.URL(), backupCodes, nil
}

// Verify2FA validates a TOTP code against the user's stored secret and
// also enforces a brute-force cap shared with the password-login path:
// every wrong code increments user_account.login_attempts; once the
// password-policy MaxAttempts threshold is hit, the account is flipped to
// self-locked status and further verifications are refused. Successful
// codes reset the counter.
func (s *LocalUserService) Verify2FA(userID int, code string) (bool, error) {
	ctx := s.ctx()
	// Single round-trip (v0.4.4 perf): qGet2FASecret returns the
	// 2FA secret AND the lockout-status columns this method needs
	// to gate the verify path, replacing the previous
	// qGet2FASecret + qUserById pair.
	res, err := s.queryService.Query(ctx, qGet2FASecret, userID)
	if err != nil {
		return false, err
	}
	if len(res.Rows) == 0 {
		return false, fmt.Errorf("user not found")
	}
	row := res.Rows[0]
	secret := common.AsString(row[0])
	if secret == "" {
		return false, fmt.Errorf("2FA not configured")
	}
	uStatus := common.AsString(row[4])
	attempts := int(common.AsInt32(row[5]))
	lastAttempt, _ := row[6].(time.Time)
	if err := s.checkAccountStatus(uStatus, lastAttempt); err != nil {
		return false, err
	}

	if !totp.Validate(code, secret) {
		// Atomic increment via UPDATE … RETURNING (MAJOR 8) so two
		// parallel failed verifies can't both observe `attempts == n`
		// and both write `n+1`.
		newAttempts, _ := s.bumpLoginAttempts(userID, "2fa-attempts-exceeded")
		_ = attempts // pre-bump value retained for clarity
		if newAttempts >= s.passwordPolicy.MaxAttempts {
			return false, fmt.Errorf("too many failed 2FA attempts, user account is locked")
		}
		return false, nil
	}

	// Success: clear the counter so a partially-failed sequence doesn't
	// haunt later sign-ins.
	_, _ = s.queryService.Query(ctx, qSetLastLogin, time.Now(), userID)
	return true, nil
}

func (s *LocalUserService) Disable2FA(userID int) error {
	_, err := s.queryService.Query(s.ctx(), qDisable2FA, userID)
	if err != nil {
		return err
	}
	// Disabling 2FA weakens auth posture; force re-auth everywhere.
	s.revokeAllRefreshTokens(userID)
	return nil
}

// VerifyBackupCode validates a one-shot 2FA backup code, atomically
// consuming it on success. Atomicity matters: two parallel verifications
// of the same code must NOT both succeed. The consume step uses a
// conditional UPDATE keyed on the still-current backup-codes string so
// the loser of a race writes nothing and reports failure to the caller.
//
// A failed verification increments login_attempts (shared with the 2FA
// and password-login paths) so backup codes — which are individually
// brute-forceable through their fixed alphabet — can't be enumerated
// against a stable user_id.
func (s *LocalUserService) VerifyBackupCode(userID int, code string) (bool, error) {
	ctx := s.ctx()
	// Single round-trip (v0.4.4 perf): qGet2FASecret returns the
	// stored backup-codes string AND the lockout-status columns
	// this method needs, replacing the previous two-query path.
	res, err := s.queryService.Query(ctx, qGet2FASecret, userID)
	if err != nil {
		return false, err
	}
	if len(res.Rows) == 0 {
		return false, fmt.Errorf("user not found")
	}
	row := res.Rows[0]

	uStatus := common.AsString(row[4])
	attempts := int(common.AsInt32(row[5]))
	lastAttempt, _ := row[6].(time.Time)
	if err := s.checkAccountStatus(uStatus, lastAttempt); err != nil {
		return false, err
	}

	codesStr := common.AsString(row[2])
	if codesStr == "" {
		return false, nil
	}
	secret := common.AsString(row[0])
	// Salted-SHA-256 verify (v0.4.3 perf). Worst-case 10 × O(microseconds)
	// instead of 10 × O(250ms) bcrypt-12 — a legitimate user with a
	// typo'd code no longer waits ~2.5s for the failure. Each code's
	// per-row salt prevents rainbow tables across the encoded set.
	codes := strings.Split(codesStr, "|")
	matchIdx := -1
	for i, hashedCode := range codes {
		if verifyBackupCodeHash(hashedCode, code) {
			matchIdx = i
			break
		}
	}
	if matchIdx < 0 {
		newAttempts, _ := s.bumpLoginAttempts(userID, "backup-code-attempts-exceeded")
		_ = attempts
		if newAttempts >= s.passwordPolicy.MaxAttempts {
			return false, fmt.Errorf("too many failed backup code attempts, user account is locked")
		}
		return false, nil
	}

	// Atomic consume: rebuild the joined string without the matched code
	// and write it back ONLY if the column still holds the expected
	// pre-consume value. Two parallel verifications of the same code each
	// see codesStr; only the first UPDATE flips the row, the second
	// affects zero rows and we treat that as failure.
	remaining := make([]string, 0, len(codes)-1)
	remaining = append(remaining, codes[:matchIdx]...)
	remaining = append(remaining, codes[matchIdx+1:]...)
	newCodes := strings.Join(remaining, "|")

	updateRes, err := s.queryService.Query(ctx, qConsumeBackupCode, secret, newCodes, userID, codesStr)
	if err != nil {
		return false, err
	}
	if updateRes != nil && len(updateRes.Rows) == 0 {
		// Another verifier consumed the code first.
		return false, nil
	}
	_, _ = s.queryService.Query(ctx, qSetLastLogin, time.Now(), userID)
	return true, nil
}

// --- Login Token ---

// CreateLoginToken issues a single-use login token bound to the userID.
// The returned string has the shape "<userID>-<8digit>" — both halves are
// required by ValidateLoginToken so two pending tokens with the same
// 8-digit confirmation cannot collide across users. Token lifetime is
// 5 minutes (enforced by the SELECT query); after MaxLoginTokenAttempts
// failed confirmations the row is marked expired.
func (s *LocalUserService) CreateLoginToken(userID int) (string, error) {
	if userID <= 0 {
		return "", fmt.Errorf("login token: user id is required")
	}
	confirmBig, err := crand.Int(crand.Reader, big.NewInt(90000000))
	if err != nil {
		return "", fmt.Errorf("login token: rng: %w", err)
	}
	confirmation := int(confirmBig.Int64()) + 10000000
	res, err := s.queryService.Query(s.ctx(), qGet2FASecret, userID)
	if err != nil {
		return "", err
	}
	if len(res.Rows) == 0 {
		return "", fmt.Errorf("user not found")
	}
	email := common.AsString(res.Rows[0][3])
	if _, err := s.queryService.Query(s.ctx(), qInsertLoginToken, email, confirmation, int64(userID)); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%d", userID, confirmation), nil
}

// ValidateLoginToken parses the "<userID>-<confirmation>" string, verifies
// against a pending row whose user_id and confirmation both match, and
// consumes the row on success. On mismatch the per-user attempts counter
// is incremented; after MaxLoginTokenAttempts the pending row is marked
// expired so the caller cannot keep retrying.
func (s *LocalUserService) ValidateLoginToken(token string) (int, error) {
	userID, confirmation, err := parseLoginToken(token)
	if err != nil {
		return 0, fmt.Errorf("invalid login token format")
	}
	ctx := s.ctx()
	res, err := s.queryService.Query(ctx, qGetLoginToken, int64(userID), confirmation)
	if err != nil {
		return 0, err
	}
	if len(res.Rows) == 0 {
		// (userID, confirmation) didn't match a pending row. Use the
		// atomic bump query to detect whether the user_id has any
		// pending LOGIN row at all in a single round-trip:
		//   - zero rows returned → no pending token for this user;
		//     don't burn an increment against a stranger (MAJOR 9).
		//   - one row returned → there is a pending token; the
		//     attempt counter just advanced. If it crossed the cap,
		//     expire the row so subsequent guesses can't keep
		//     probing.
		bumpRes, _ := s.queryService.Query(ctx, qIncrementLoginAttempts, int64(userID))
		if bumpRes != nil && len(bumpRes.Rows) > 0 {
			if newAttempts := int(common.AsInt32(bumpRes.Rows[0][0])); newAttempts >= MaxLoginTokenAttempts {
				_, _ = s.queryService.Query(ctx, qExpireLoginToken, int64(userID))
			}
		}
		return 0, fmt.Errorf("invalid or expired login token")
	}
	attempts := int(common.AsInt32(res.Rows[0][1]))
	if attempts >= MaxLoginTokenAttempts {
		_, _ = s.queryService.Query(ctx, qExpireLoginToken, int64(userID))
		return 0, fmt.Errorf("invalid or expired login token")
	}
	// Row exists for (userID, confirmation) and attempts is below the cap —
	// the token is valid. Consume the row and return the userID. The
	// previous implementation re-resolved by email here; that round-trip is
	// unnecessary because user_registration.user_id is FK-constrained to
	// user_account.id, and a mid-flight email change would otherwise cause
	// a stale token to resolve to whoever owns the email NOW.
	_, _ = s.queryService.Query(ctx, qDeleteLoginToken, int64(userID))
	return userID, nil
}

// parseLoginToken splits a "<userID>-<confirmation>" token string into its
// two integer halves. Rejects whitespace, sign characters, and trailing
// garbage so an attacker cannot smuggle alternate parses.
func parseLoginToken(token string) (userID, confirmation int, err error) {
	dash := strings.IndexByte(token, '-')
	if dash <= 0 || dash >= len(token)-1 {
		return 0, 0, fmt.Errorf("malformed login token")
	}
	uid, err := strconv.Atoi(token[:dash])
	if err != nil || uid <= 0 {
		return 0, 0, fmt.Errorf("malformed login token")
	}
	conf, err := strconv.Atoi(token[dash+1:])
	if err != nil || conf <= 0 {
		return 0, 0, fmt.Errorf("malformed login token")
	}
	return uid, conf, nil
}

// --- Trusted Devices ---

func (s *LocalUserService) RegisterTrustedDevice(userID int, fingerprint string, name string) error {
	_, err := s.queryService.Query(s.ctx(), qInsertTrustedDevice, userID, fingerprint, name)
	return err
}

func (s *LocalUserService) IsTrustedDevice(userID int, fingerprint string) (bool, error) {
	res, err := s.queryService.Query(s.ctx(), qCheckTrustedDevice, userID, fingerprint)
	if err != nil {
		return false, err
	}
	if len(res.Rows) > 0 {
		_, _ = s.queryService.Query(s.ctx(), qUpdateDeviceLastSeen, userID, fingerprint)
		return true, nil
	}
	return false, nil
}

func (s *LocalUserService) GetTrustedDevices(userID int) ([]TrustedDevice, error) {
	res, err := s.queryService.Query(s.ctx(), qGetTrustedDevices, userID)
	if err != nil {
		return nil, err
	}
	devices := make([]TrustedDevice, len(res.Rows))
	for i, row := range res.Rows {
		devices[i] = TrustedDevice{
			ID:          common.AsInt64(row[0]),
			Name:        common.AsString(row[1]),
			Fingerprint: common.AsString(row[2]),
			LastUsedAt:  common.AsString(row[3]),
			CreatedAt:   common.AsString(row[4]),
		}
	}
	return devices, nil
}

func (s *LocalUserService) RevokeTrustedDevice(userID int, deviceID int64) error {
	_, err := s.queryService.Query(s.ctx(), qRevokeTrustedDevice, deviceID, userID)
	if err != nil {
		return err
	}
	// Device revocation implies the user wants the stolen/lost device out.
	// Drop its refresh token too — the device_id isn't recorded on the
	// refresh_token row, so revoke all and let the user re-auth on trusted devices.
	s.revokeAllRefreshTokens(userID)
	return nil
}

// --- OTP Authentication ---

func (s *LocalUserService) GetUserByPhone(phone string) (*model.UserSession, error) {
	res, err := s.queryService.Query(s.ctx(), qUserByPhone, phone)
	if err != nil || len(res.Rows) == 0 {
		return nil, fmt.Errorf("user not found")
	}
	row := res.Rows[0]
	session := s.newSession(
		int(common.AsInt64(row[0])),
		common.AsString(row[1]),
		common.AsString(row[2]),
		common.AsString(row[3]),
		common.AsString(row[6]),
		"local",
	)
	session.PhoneNumber = common.AsString(row[4])
	session.Language = common.AsString(row[5])
	session.PartnerId = common.AsInt64(row[7])
	return session, nil
}

func (s *LocalUserService) GenerateOTP(userId int, purpose string) (string, error) {
	code, _ := crand.Int(crand.Reader, big.NewInt(900000))
	otp := fmt.Sprintf("%06d", code.Int64()+100000)
	_, err := s.queryService.Query(s.ctx(), qGenerateOTP, userId, otp, purpose)
	if err != nil {
		return "", err
	}
	return otp, nil
}

// VerifyOTP validates a 6-digit OTP. Three correctness invariants:
//   - Comparison is constant-time (subtle.ConstantTimeCompare) so the
//     6-digit space cannot be enumerated via response timing.
//   - On mismatch, the per-OTP attempts counter is incremented inline so
//     a forgetful caller cannot bypass the attempt cap by skipping
//     IncrementOTPAttempts.
//   - On match, the OTP row is consumed (DELETE) so a single code can
//     never be reused. Callers that previously relied on a follow-up
//     ClearOTP are unaffected — the second clear is a no-op.
func (s *LocalUserService) VerifyOTP(userId int, code string) error {
	ctx := s.ctx()
	res, err := s.queryService.Query(ctx, qVerifyOTP, userId)
	if err != nil || len(res.Rows) == 0 {
		return fmt.Errorf("no active OTP")
	}
	storedCode := common.AsString(res.Rows[0][1])
	attempts := int(common.AsInt32(res.Rows[0][2]))
	cap := s.passwordPolicy.MaxAttempts
	if cap <= 0 {
		cap = 5
	}
	if attempts >= cap {
		return fmt.Errorf("max attempts exceeded")
	}
	if subtle.ConstantTimeCompare([]byte(storedCode), []byte(code)) != 1 {
		_, _ = s.queryService.Query(ctx, qIncrementOTP, userId, userId)
		return fmt.Errorf("invalid OTP")
	}
	// Single-use: delete the OTP on success so it cannot be replayed.
	_, _ = s.queryService.Query(ctx, qClearOTP, userId)
	return nil
}

func (s *LocalUserService) IncrementOTPAttempts(userId int) error {
	_, err := s.queryService.Query(s.ctx(), qIncrementOTP, userId, userId)
	return err
}

func (s *LocalUserService) ClearOTP(userId int) error {
	_, err := s.queryService.Query(s.ctx(), qClearOTP, userId)
	return err
}

// newSession builds a UserSession with Issuer/IssuedAt/ExpiresAt consistently
// populated so CreateJWT downstream emits a well-formed token.
func (s *LocalUserService) newSession(id int, firstName, lastName, email, status, provider string) *model.UserSession {
	now := time.Now()
	return &model.UserSession{
		Id:        id,
		Subject:   firstName + " " + lastName,
		Issuer:    s.Issuer,
		FirstName: firstName,
		LastName:  lastName,
		Email:     email,
		Status:    status,
		Provider:  provider,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Duration(s.sSessionTimeout)).Unix(),
	}
}

// --- Social Login ---

func (s *LocalUserService) getUserBySocialProvider(provider, providerID string) (*model.UserSession, error) {
	res, err := s.queryService.Query(s.ctx(), qUserBySocial, provider, providerID)
	if err != nil || len(res.Rows) == 0 {
		return nil, fmt.Errorf("user not found")
	}
	row := res.Rows[0]
	session := s.newSession(
		int(common.AsInt64(row[0])),
		common.AsString(row[1]),
		common.AsString(row[2]),
		common.AsString(row[3]),
		common.AsString(row[6]),
		provider,
	)
	session.PhoneNumber = common.AsString(row[4])
	session.Language = common.AsString(row[5])
	session.PartnerId = common.AsInt64(row[7])
	return session, nil
}

func (s *LocalUserService) createUserFromSocial(email, firstName, lastName, phone, provider, providerID string) (*model.UserSession, error) {
	ctx := s.ctx()
	username := email
	if username == "" {
		username = provider + "-" + providerID
	}

	tx, err := s.database.BeginTx(ctx, LocalUserQueries)
	if err != nil {
		return nil, err
	}
	userId, err := s.insertUserAccount(ctx, tx, firstName, lastName, email, phone, username)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	if _, err := tx.Query(ctx, qLinkSocialProvider, userId, provider, providerID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	s.AddUserHistory(userId, 0, "", UserActivityCreate, "A", "social:"+provider)
	session := s.newSession(userId, firstName, lastName, email, UserStatusActive, provider)
	session.PhoneNumber = phone
	return session, nil
}

// insertUserAccount runs qCreateSocialUser on the given tx and returns the
// new user_account.id. Shared by createUserFromSocial and createUserByPhone
// so both flows write the same INSERT shape (passtext=NULL, status='A').
//
// Empty email and empty phone are bound as SQL NULL so any future UNIQUE
// index on those columns will not collide on the second account that
// happens to lack the value. Email is lowercased defensively in case a
// caller bypasses GetOrCreateUserFromSocial's entry-point normalization.
func (s *LocalUserService) insertUserAccount(ctx context.Context, tx data.TxQueryService, firstName, lastName, email, phone, username string) (int, error) {
	id := tx.GenID()
	var emailArg, phoneArg any = normalizeEmail(email), phone
	if emailArg == "" {
		emailArg = nil
	}
	if phoneArg == "" {
		phoneArg = nil
	}
	if _, err := tx.Query(ctx, qCreateSocialUser, id, firstName, lastName, emailArg, phoneArg, username); err != nil {
		return 0, classifyUniqueViolation(err)
	}
	return int(id), nil
}

// createUserByPhone INSERTs a new user_account row with phone set and no
// social-provider row. Username defaults to "phone-<e164>" so it's unique
// and recognizable. Caller must pass an already-normalized (E.164) phone.
func (s *LocalUserService) createUserByPhone(phone string) (*model.UserSession, error) {
	ctx := s.ctx()
	tx, err := s.database.BeginTx(ctx, LocalUserQueries)
	if err != nil {
		return nil, err
	}
	userId, err := s.insertUserAccount(ctx, tx, "", "", "", phone, "phone-"+phone)
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.AddUserHistory(userId, 0, "", UserActivityCreate, "A", "phone")
	session := s.newSession(userId, "", "", "", UserStatusActive, "phone")
	session.PhoneNumber = phone
	return session, nil
}

// GetOrCreateUserByPhone is the first-class phone-auth entry point. Caller
// passes the raw user input plus a default region (e.g. "CA"); the method
// normalizes to E.164 before lookup or insert. Returns (session, created, err).
// When ConsentService is registered and signupConsent is non-nil with at
// least one consent, records those events against the newly-created user.
func (s *LocalUserService) GetOrCreateUserByPhone(phone, defaultRegion string, signupConsent *SignupConsent) (*model.UserSession, bool, error) {
	normalized, err := normalizePhone(phone, defaultRegion)
	if err != nil {
		return nil, false, fmt.Errorf("phone: %w", err)
	}
	if existing, lookupErr := s.GetUserByPhone(normalized); lookupErr == nil {
		s.AddUserHistory(existing.Id, 0, "", UserActivityLogin, "A", "phone")
		return existing, false, nil
	}
	fresh, createErr := s.createUserByPhone(normalized)
	if createErr != nil {
		return nil, false, createErr
	}
	if s.ConsentService != nil && signupConsent != nil && len(signupConsent.Consents) > 0 {
		if consentErr := s.recordSignupConsent(fresh.Id, "", signupConsent); consentErr != nil {
			return fresh, true, fmt.Errorf("user created but consent recording failed: %w", consentErr)
		}
	}
	return fresh, true, nil
}

// NormalizePhone is the port.UserService entry point for phone
// normalization; thin wrapper over the package-private helper.
func (s *LocalUserService) NormalizePhone(input, defaultRegion string) (string, error) {
	return normalizePhone(input, defaultRegion)
}

// normalizeEmail trims whitespace and lowercases the email so equivalent
// addresses (e.g. "Foo@Gmail.com" vs "foo@gmail.com") collapse to a single
// canonical form. Applied at every service-boundary that reads or writes
// user_email so password-signup and social-signup paths can never disagree
// on case and silently create duplicate accounts. Empty input passes through
// unchanged so callers can still pass "" to mean "no email".
func normalizeEmail(email string) string {
	trimmed := strings.TrimSpace(email)
	if trimmed == "" {
		return ""
	}
	return strings.ToLower(trimmed)
}

// normalizePhone converts a raw user-entered phone into E.164 using the
// given region as a default for local-format numbers (e.g. "(416) 555-1234"
// with region "CA" → "+14165551234"). Returns error on unparseable or
// invalid numbers. Empty region defaults to "US".
func normalizePhone(input, defaultRegion string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", fmt.Errorf("phone is required")
	}
	region := strings.ToUpper(strings.TrimSpace(defaultRegion))
	if region == "" {
		region = "US"
	}
	num, err := phonenumbers.Parse(trimmed, region)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	if !phonenumbers.IsValidNumber(num) {
		return "", fmt.Errorf("invalid phone number")
	}
	return phonenumbers.Format(num, phonenumbers.E164), nil
}

// GetOrCreateUserFromSocial implements the standard social-login ladder:
// 1) existing social link → return that session,
// 2) existing account by verified email → link new social provider to it,
// 3) otherwise create a fresh user + social-provider row atomically.
// emailVerified gates branch 2 to prevent account takeover via an unverified
// provider-asserted email.
//
// Hard-rejects provider == "phone" — phone OTP flows must go through
// GetOrCreateUserByPhone, not through the social pseudo-provider shim.
//
// When s.ConsentService is set and signupConsent is non-nil, consents are
// recorded after the create branch fires. A consent-recording failure
// returns a non-nil session alongside the error so the caller sees both
// "user was created" and "consent did not land".
func (s *LocalUserService) GetOrCreateUserFromSocial(
	email, firstName, lastName, phone, provider, providerID string,
	emailVerified bool,
	signupConsent *SignupConsent,
) (session *model.UserSession, created bool, err error) {
	if provider == "phone" {
		return nil, false, fmt.Errorf("social: provider %q is reserved; use GetOrCreateUserByPhone for phone-OTP flows", provider)
	}
	email = normalizeEmail(email)
	if existing, lookupErr := s.getUserBySocialProvider(provider, providerID); lookupErr == nil {
		s.AddUserHistory(existing.Id, 0, "", UserActivityLogin, "A", "social:"+provider)
		return existing, false, nil
	}
	// Email-link branch. Skipped when the provider has not verified the email
	// (account-takeover guard) or when the address is an Apple "Hide My Email"
	// relay — those addresses are stable per app but never match a password
	// account's email, so linking on them would always be wrong.
	if emailVerified && email != "" && !strings.HasSuffix(strings.ToLower(email), "@privaterelay.appleid.com") {
		if existing, lookupErr := s.GetUserByEmail(email); lookupErr == nil {
			if _, linkErr := s.queryService.Query(s.ctx(), qLinkSocialProvider, existing.Id, provider, providerID); linkErr != nil {
				return nil, false, linkErr
			}
			existing.Provider = provider
			return existing, false, nil
		}
	}
	fresh, createErr := s.createUserFromSocial(email, firstName, lastName, phone, provider, providerID)
	if createErr != nil {
		return nil, false, createErr
	}
	if s.ConsentService != nil && signupConsent != nil && len(signupConsent.Consents) > 0 {
		if consentErr := s.recordSignupConsent(fresh.Id, email, signupConsent); consentErr != nil {
			return fresh, true, fmt.Errorf("user created but consent recording failed: %w", consentErr)
		}
	}
	return fresh, true, nil
}

// recordSignupConsent is the private bridge between signup flows and
// the optional ConsentService. It translates a SignupConsent into the
// ConsentRequest meta shape RecordSignupConsents expects.
func (s *LocalUserService) recordSignupConsent(userID int, email string, sc *SignupConsent) error {
	meta := ConsentRequest{
		PolicyType:      sc.PolicyType,
		PolicyVersion:   sc.PolicyVersion,
		PolicyRegion:    sc.PolicyRegion,
		PolicyLanguage:  sc.PolicyLanguage,
		Region:          sc.Region,
		ClientIP:        sc.ClientIP,
		ClientUserAgent: sc.ClientUserAgent,
		EventRef:        sc.EventRef,
	}
	return s.ConsentService.RecordSignupConsents(s.ctx(), userID, email, sc.Consents, meta)
}

// --- Account Deletion (M-3) ---

// DeleteAccount anonymizes the user_account row in place (preserving FK
// integrity for historical rows — ride history, invoices, payment records,
// etc. — that legal retention requires), revokes all refresh tokens,
// deletes trusted devices, and deletes social-provider links. Records a
// UserActivityDelete history entry with the supplied reason.
//
// NOT a hard DELETE. Consumers that own domain tables cascading off user_id
// should wrap this method and run their own anonymization in the same flow.
func (s *LocalUserService) DeleteAccount(userID int, reason string) error {
	if userID <= 0 {
		return fmt.Errorf("delete: user id is required")
	}
	ctx := s.ctx()
	anonEmail := fmt.Sprintf("deleted+%d@local.invalid", userID)
	anonUsername := fmt.Sprintf("deleted-%d", userID)

	tx, err := s.database.BeginTx(ctx, LocalUserQueries)
	if err != nil {
		return err
	}
	if _, err := tx.Query(ctx, qAnonymizeUserAccount, anonEmail, anonUsername, userID); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("delete: anonymize user_account: %w", err)
	}
	if _, err := tx.Query(ctx, qDeleteSocialLinks, userID); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("delete: remove social links: %w", err)
	}
	if _, err := tx.Query(ctx, qDeleteTrustedDevices, userID); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("delete: remove trusted devices: %w", err)
	}
	if _, err := tx.Query(ctx, qDeactivateDeviceTokensForUser, userID); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("delete: deactivate device tokens: %w", err)
	}
	if _, err := tx.Query(ctx, qRevokeAllRefreshTokensForID, userID); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("delete: revoke refresh tokens: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("delete: commit: %w", err)
	}
	return s.AddUserHistory(userID, 0, "", UserActivityDelete, UserStatusDeleted, reason)
}

// --- Helpers ---

// generateRandomToken returns a hex-encoded random byte string of the
// given length. Returns an error when the OS entropy source rejects
// the read — rare but possible on a misconfigured kernel — so callers
// never silently fall back to all-zero bytes.
func generateRandomToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := crand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// generateRandomCode returns a length-character code drawn from a
// 32-symbol alphabet (no I/O/0/1 to avoid lookalike-character
// confusion). Same crand-error contract as generateRandomToken.
func generateRandomCode(length int) (string, error) {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, length)
	if _, err := crand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b), nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// hashBackupCode produces a "<saltHex>:<hashHex>" string for a single
// 2FA backup code. The salt is 16 random bytes per code so rainbow-
// table precomputation across users is impossible; SHA-256 of the
// salt-prefixed code makes the verify path microsecond-cheap rather
// than the ~250ms / cost-12 bcrypt verify it replaced (v0.4.3 perf).
//
// Security argument vs bcrypt:
//   - Backup codes are 8 chars from a 32-symbol alphabet (~40 bits).
//     Even bcrypt-12 only buys ~2^17× resistance — so a DB-compromise
//     attacker with a single GPU recovers all codes in hours either
//     way. The realistic threat model for backup codes is online
//     guessing, which is gated by the 5-attempt-then-lock policy on
//     login_attempts. SHA-256+salt loses ~minutes of offline
//     hardness per code in exchange for ~250× faster Setup2FA and
//     a 10× faster worst-case VerifyBackupCode.
//   - Per-code random salt closes the rainbow-table vector that a
//     plain SHA-256 would leave open.
//
// Format: each code stored as `<32-hex-char-salt>:<64-hex-char-hash>`.
// The 16+32-byte raw form is hex-encoded so the bytes survive
// transit through any byte-unsafe column type the consumer might use.
func hashBackupCode(code string) (string, error) {
	salt := make([]byte, 16)
	if _, err := crand.Read(salt); err != nil {
		return "", fmt.Errorf("hash backup code: %w", err)
	}
	h := sha256.Sum256(append(append([]byte{}, salt...), []byte(code)...))
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(h[:]), nil
}

// verifyBackupCodeHash compares a candidate code against a stored
// "<saltHex>:<hashHex>" entry in constant time. Returns false on any
// shape mismatch (malformed entry, wrong-length pieces) without
// revealing where the parse failed.
func verifyBackupCodeHash(stored, candidate string) bool {
	colon := strings.IndexByte(stored, ':')
	if colon <= 0 || colon == len(stored)-1 {
		return false
	}
	salt, err := hex.DecodeString(stored[:colon])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(stored[colon+1:])
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := sha256.Sum256(append(append([]byte{}, salt...), []byte(candidate)...))
	return subtle.ConstantTimeCompare(want, got[:]) == 1
}
