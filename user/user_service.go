package user

import (
	"github.com/nauticana/keel/model"
)

// TrustedDevice is a row in user_trusted_device exposed via the security
// API. The raw device secret is never returned — the DB stores only its
// SHA256, and the secret leaves the server exactly once (set as an
// HttpOnly cookie immediately after RegisterTrustedDevice).
type TrustedDevice struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	LastUsedAt string `json:"last_used_at"`
	CreatedAt  string `json:"created_at"`
}

type UserService interface {
	// Core auth
	AddUserHistory(id int, byId int, clientaddress, actionType string, status string, objectName string) error
	GetUserById(userId int) (*model.UserSession, error)
	GetUserByLogin(username string, password string) (*model.UserSession, error)
	GetUserByUsername(username string) (*model.UserSession, error)
	GetUserByEmail(email string) (*model.UserSession, error)
	SetPassword(userid int, password string) error
	GetUserMenu(userid int) ([]model.UserMenu, error)

	// Self-service profile editing (session-scoped). UpdateProfile writes
	// name/locale immediately; email/phone change via verify-before-apply —
	// CreateContactChange returns a code bound to (user, new value) for the
	// caller to deliver, ConfirmContactChange validates and applies it.
	// channel is "email" or "phone".
	UpdateProfile(userID int, firstName, lastName, locale string) error
	CreateContactChange(userID int, channel, newValue string) (code int, err error)
	ConfirmContactChange(userID int, channel, newValue string, code int) error
	CreateJWT(u *model.UserSession) (string, error)
	ParseJWT(tokenString string) (*model.UserSession, error)

	// VerifyPasswordByID checks a password against the hash stored
	// for userID. Used by handler.requireRecentAuth so phone-OTP /
	// social-login signups (whose session.Subject is "First Last"
	// rather than user_name) can re-authenticate via password
	// without going through the user_name-keyed GetUserByLogin path.
	// Increments the shared login_attempts counter on mismatch and
	// flips the account to self-locked once the policy ceiling is
	// crossed.
	VerifyPasswordByID(userID int, password string) (bool, error)

	// Refresh tokens
	CreateRefreshToken(userID int) (string, error)
	ValidateRefreshToken(token string) (*model.UserSession, error)
	RevokeRefreshToken(token string) error
	// LogoutEverywhere revokes every active refresh token for a user — the
	// "log out of all devices" button. Also invoked automatically by
	// SetPassword / Setup2FA / Disable2FA / RevokeTrustedDevice as a
	// security-posture defense.
	LogoutEverywhere(userID int) error

	// Device push tokens (P-2). Idempotent register on re-login, explicit
	// revoke on logout. ListActive is used by PushProvider implementations
	// to fan notifications out across a user's devices.
	RegisterDeviceToken(userID int, platform, token, appVersion, deviceModel string) error
	RevokeDeviceToken(userID int, token string) error
	ListActiveDeviceTokens(userID int) ([]model.DeviceToken, error)

	// SetSingleDevicePolicy flips the per-user single_device_session bit.
	// When on, a new refresh-token issue revokes all priors — the user ends
	// up signed in on exactly one device at a time. Consumer-owned
	SetSingleDevicePolicy(userID int, on bool) error

	// DeleteAccount soft-deletes: anonymizes the user_account row in place,
	// revokes tokens, deletes trusted devices and social links. Preserves
	// referential integrity for history/audit rows. Consumers that own
	// domain tables keyed on user_id should wrap this method and add their
	// own cascade; the keel version alone is enough for App Store / Play
	// Store compliance.
	DeleteAccount(userID int, reason string) error

	// 2FA (TOTP)
	Setup2FA(userID int) (secret string, qrURI string, backupCodes []string, err error)
	Verify2FA(userID int, code string) (bool, error)
	Disable2FA(userID int) error
	VerifyBackupCode(userID int, code string) (bool, error)

	// Login token (short-lived, for 2FA flow)
	CreateLoginToken(userID int) (string, error)
	ValidateLoginToken(token string) (int, error)

	// Trusted devices
	// RegisterTrustedDevice mints a random 32-byte secret, stores its hex
	// SHA256 against userID, and returns the raw secret for the caller to
	// place in an HttpOnly cookie. Callers MUST treat the returned string
	// as sensitive — it is the bearer credential for 2FA bypass.
	RegisterTrustedDevice(userID int, name string) (secret string, err error)
	// IsTrustedDevice hashes secret and looks for a matching active row.
	// secret is the raw cookie value; empty secret always returns false.
	IsTrustedDevice(userID int, secret string) (bool, error)
	GetTrustedDevices(userID int) ([]TrustedDevice, error)
	RevokeTrustedDevice(userID int, deviceID int64) error

	// OTP-based authentication
	GetUserByPhone(phone string) (*model.UserSession, error)
	GenerateOTP(userId int, purpose string) (string, error)
	VerifyOTP(userId int, code string) error
	IncrementOTPAttempts(userId int) error
	ClearOTP(userId int) error

	// Social login — single entry point for OAuth / external-identity flow.
	// signupConsent is optional; when the service has a ConsentService
	// registered and signupConsent is non-nil, consents are recorded after
	// user creation. A non-nil error alongside a non-nil session indicates
	// the user was created but consent recording failed — caller decides
	// whether to treat that as a hard failure.
	GetOrCreateUserFromSocial(email, firstName, lastName, phone, provider, providerID string, emailVerified bool, signupConsent *SignupConsent) (session *model.UserSession, created bool, err error)

	// Phone as first-class. Raw phone is normalized to E.164 using
	// defaultRegion (e.g. "CA", "US") as a hint for local-format input.
	// The optional `email` parameter records a user-supplied email
	// alongside the phone — empty means phone-only signup; a collision
	// on user_email silently drops the secondary email so the signup
	// still goes through. Same consent semantics as the other
	// GetOrCreate* methods.
	GetOrCreateUserByPhone(phone, defaultRegion, email string, signupConsent *SignupConsent) (session *model.UserSession, created bool, err error)

	// NormalizePhone converts a raw user-entered phone into E.164. Exposed
	// on the port so handlers can normalize before lookup paths that don't
	// create users (e.g. OTP send on "login" purpose).
	NormalizePhone(input, defaultRegion string) (string, error)

	// Email as first-class — twin of GetOrCreateUserByPhone for the
	// email-OTP authentication flow. The email is lowercased + trimmed
	// before lookup or insert. The optional `phone` parameter records
	// a user-supplied phone alongside the email (unverified — phone
	// verification belongs in a later flow); empty phone means email-
	// only signup. Same consent semantics as the other GetOrCreate*
	// methods. Returns (session, created, err) — created is true when
	// a new user_account row was inserted.
	GetOrCreateUserByEmail(email, phone string, signupConsent *SignupConsent) (session *model.UserSession, created bool, err error)
}
