package user

import (
	"github.com/nauticana/keel/model"
)

type TrustedDevice struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	LastUsedAt  string `json:"last_used_at"`
	CreatedAt   string `json:"created_at"`
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
	RegisterTrustedDevice(userID int, fingerprint string, name string) error
	IsTrustedDevice(userID int, fingerprint string) (bool, error)
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
	// Same consent semantics as GetOrCreateUserFromSocial.
	GetOrCreateUserByPhone(phone, defaultRegion string, signupConsent *SignupConsent) (session *model.UserSession, created bool, err error)

	// NormalizePhone converts a raw user-entered phone into E.164. Exposed
	// on the port so handlers can normalize before lookup paths that don't
	// create users (e.g. OTP send on "login" purpose).
	NormalizePhone(input, defaultRegion string) (string, error)
}
