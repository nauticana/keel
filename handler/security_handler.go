package handler

import (
	"net/http"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
)

// MaxVerify2FAPerIP caps the number of /public/2fa/verify attempts per
// caller IP in MaxVerify2FAWindow. Layered on top of the per-token
// 5-attempt cap on user_registration.attempts so an attacker who cycles
// through fresh login tokens (each new token resets the per-token
// counter) cannot keep guessing 2FA codes from the same IP unboundedly.
const (
	MaxVerify2FAPerIP   = 20
	MaxVerify2FAWindow  = 10 * time.Minute
)

// requireRecentAuth confirms the JWT-bearing caller can still produce a
// password (or current 2FA code, on accounts with TOTP enabled). It is
// the gate placed in front of security-sensitive mutations — Setup2FA,
// Disable2FA, DeleteAccount, LogoutEverywhere — so a stolen JWT alone
// cannot rotate the seed, delete the account, or force every other
// device to re-authenticate.
//
// Password verification routes through VerifyPasswordByID, NOT
// GetUserByLogin. The previous implementation used session.Subject as
// the user_name lookup key; for phone-OTP and social-login signups
// Subject is "First Last", not the canonical user_name, so the
// password branch was silently broken for those users (BLOCKER 3).
// VerifyPasswordByID keys off the JWT-bound user id directly, which
// is stable across signup paths.
//
// On success returns ok=true and leaves the response untouched. On
// failure writes a 401 and returns false; the caller should early-return.
func (h *SecurityHandler) requireRecentAuth(w http.ResponseWriter, session *model.UserSession, password, twoFactorCode string) bool {
	if password == "" && twoFactorCode == "" {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "password or current 2FA code is required")
		return false
	}
	if password != "" {
		ok, err := h.UserService.VerifyPasswordByID(session.Id, password)
		if err != nil || !ok {
			h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "re-authentication failed")
			return false
		}
		return true
	}
	valid, err := h.UserService.Verify2FA(session.Id, twoFactorCode)
	if err != nil || !valid {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "re-authentication failed")
		return false
	}
	return true
}

type SecurityHandler struct {
	AbstractHandler

	// Cache, when non-nil, gates /public/2fa/verify with a per-caller-IP
	// rate limit. Wire the keel-shipped CacheService (Valkey/Redis or
	// the NoOp fallback). When nil the per-IP cap is silently disabled —
	// existing single-tenant deployments continue to operate unchanged.
	Cache cache.CacheService
}

// rateLimitVerify2FA returns true when the caller IP has exceeded the
// per-window verify budget. Returns false (allow) when no Cache is
// wired so existing deployments without a cache backend keep working.
func (h *SecurityHandler) rateLimitVerify2FA(r *http.Request) bool {
	if h.Cache == nil {
		return false
	}
	key := "2fa_verify_ip:" + TrustedClientIP(r)
	count, _ := h.Cache.Increment(r.Context(), key)
	if count == 1 {
		_ = h.Cache.Set(r.Context(), key, "1", MaxVerify2FAWindow)
	}
	return count > MaxVerify2FAPerIP
}

// GetPublicRoutes returns public (unauthenticated) security routes for login-time 2FA verification.
func (h *SecurityHandler) GetPublicRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.PublicPrefix + "/2fa/verify":        h.Verify2FA,
		common.PublicPrefix + "/2fa/backup-verify": h.VerifyBackupCode,
	}
}

// GetAuthRoutes returns authenticated security routes (require JWT via SSO middleware).
func (h *SecurityHandler) GetAuthRoutes() map[string]func(w http.ResponseWriter, r *http.Request) {
	return map[string]func(w http.ResponseWriter, r *http.Request){
		common.RestPrefix + "/user/2fa/setup":             h.Setup2FA,
		common.RestPrefix + "/user/2fa/verify":            h.Verify2FA,
		common.RestPrefix + "/user/2fa/disable":           h.Disable2FA,
		common.RestPrefix + "/user/trusted-device/list":   h.ListTrustedDevices,
		common.RestPrefix + "/user/trusted-device/revoke": h.RevokeTrustedDevice,
		common.RestPrefix + "/user/logout-everywhere":     h.LogoutEverywhere,
		common.RestPrefix + "/user/account":               h.DeleteAccount,
	}
}

// Setup2FA issues a fresh TOTP seed and backup codes. Gated by
// requireRecentAuth so a stolen JWT cannot silently displace a legitimate
// authenticator's seed.
//
// POST /api/user/2fa/setup  { "password": "<current password>" }
//   or { "twoFactorCode": "<current TOTP, when re-rotating>" }
func (h *SecurityHandler) Setup2FA(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Password      string `json:"password"`
		TwoFactorCode string `json:"twoFactorCode"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if !h.requireRecentAuth(w, session, req.Password, req.TwoFactorCode) {
		return
	}

	secret, qrURI, backupCodes, err := h.UserService.Setup2FA(session.Id)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to set up 2FA")
		return
	}

	common.WriteJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"qrUri":       qrURI,
		"backupCodes": backupCodes,
	})
}

// Verify2FA is mounted at both /public/2fa/verify (login-time, loginToken
// present) and /api/user/2fa/verify (setup confirmation, JWT present).
// The handler dispatches by the presence of LoginToken in the body. Both
// paths use the canonical body cap via ReadRequest.
func (h *SecurityHandler) Verify2FA(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}

	var req struct {
		Code              string `json:"code"`
		LoginToken        string `json:"loginToken"`
		TrustDevice       bool   `json:"trustDevice"`
		DeviceFingerprint string `json:"deviceFingerprint"`
		DeviceName        string `json:"deviceName"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.Code == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "code is required")
		return
	}

	// Per-IP cap on the unauthenticated login-time path (loginToken
	// present). Layered on top of the per-token attempts counter so an
	// attacker cycling through fresh login tokens (each new token resets
	// its own attempts row) cannot keep guessing 2FA codes from one IP.
	// The authenticated /api/user/2fa/verify path is JWT-gated and not
	// rate-limited here.
	if req.LoginToken != "" && h.rateLimitVerify2FA(r) {
		h.WriteError(w, http.StatusTooManyRequests, "Too Many Requests", "too many 2FA attempts, try again later")
		return
	}

	// Login-time verification (loginToken present)
	if req.LoginToken != "" {
		userID, err := h.UserService.ValidateLoginToken(req.LoginToken)
		if err != nil {
			h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid or expired login token")
			return
		}

		valid, err := h.UserService.Verify2FA(userID, req.Code)
		if err != nil || !valid {
			h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid 2FA code")
			return
		}

		if req.TrustDevice && req.DeviceFingerprint != "" {
			_ = h.UserService.RegisterTrustedDevice(userID, req.DeviceFingerprint, req.DeviceName)
		}

		session, err := h.UserService.GetUserById(userID)
		if err != nil {
			h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to load session")
			return
		}

		menu, err := h.UserService.GetUserMenu(userID)
		if err != nil {
			h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to load menu")
			return
		}

		token, err := h.UserService.CreateJWT(session)
		if err != nil {
			h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to issue token")
			return
		}

		common.WriteJSON(w, http.StatusOK, map[string]any{
			"valid":     true,
			"token":     token,
			"userId":    session.Id,
			"partnerId": session.PartnerId,
			"menu":      menu,
		})
		return
	}

	// Setup confirmation: caller is authenticated via JWT.
	userID, ok := h.RequireUser(w, r)
	if !ok {
		return
	}
	valid, err := h.UserService.Verify2FA(userID, req.Code)
	if err != nil || !valid {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid 2FA code")
		return
	}

	common.WriteJSON(w, http.StatusOK, map[string]any{
		"valid": true,
	})
}

// POST /public/2fa/backup-verify — single-use backup code path.
func (h *SecurityHandler) VerifyBackupCode(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}

	var req struct {
		Code       string `json:"code"`
		LoginToken string `json:"loginToken"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.Code == "" || req.LoginToken == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "code and loginToken are required")
		return
	}

	userID, err := h.UserService.ValidateLoginToken(req.LoginToken)
	if err != nil {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid or expired login token")
		return
	}

	valid, err := h.UserService.VerifyBackupCode(userID, req.Code)
	if err != nil || !valid {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid backup code")
		return
	}

	session, err := h.UserService.GetUserById(userID)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to load session")
		return
	}

	menu, err := h.UserService.GetUserMenu(userID)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to load menu")
		return
	}

	token, err := h.UserService.CreateJWT(session)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to issue token")
		return
	}

	common.WriteJSON(w, http.StatusOK, map[string]any{
		"valid":     true,
		"token":     token,
		"userId":    session.Id,
		"partnerId": session.PartnerId,
		"menu":      menu,
	})
}

// Disable2FA removes the user's TOTP seed and backup codes. Gated by
// requireRecentAuth: caller must present BOTH the current password and
// the current 2FA code, since either alone is too weak — losing 2FA is
// the security-impactful operation, not gaining it.
//
// POST /api/user/2fa/disable
//
//	{ "password": "<current>", "code": "<current TOTP>" }
func (h *SecurityHandler) Disable2FA(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if req.Password == "" || req.Code == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "password and code are required")
		return
	}
	// Validate both factors. We deliberately call requireRecentAuth twice —
	// once with each factor — so removing 2FA always requires the union.
	if !h.requireRecentAuth(w, session, req.Password, "") {
		return
	}
	if !h.requireRecentAuth(w, session, "", req.Code) {
		return
	}

	if err := h.UserService.Disable2FA(session.Id); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to disable 2FA")
		return
	}

	common.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "2FA disabled",
	})
}

// GET /api/user/trusted-device/list
func (h *SecurityHandler) ListTrustedDevices(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodGet) {
		return
	}
	userID, ok := h.RequireUser(w, r)
	if !ok {
		return
	}

	devices, err := h.UserService.GetTrustedDevices(userID)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to list devices")
		return
	}

	common.WriteJSON(w, http.StatusOK, devices)
}

// RevokeTrustedDevice deactivates a single trusted-device row owned by
// the authenticated caller. Ownership is enforced at the handler boundary
// AND inside the service query (DELETE WHERE id=? AND user_id=?), so a
// stolen JWT for user A cannot revoke user B's devices even if the
// service layer is misused.
//
// POST /api/user/trusted-device/revoke  { "deviceId": <int64> }
func (h *SecurityHandler) RevokeTrustedDevice(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		DeviceID int64 `json:"deviceId"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if req.DeviceID <= 0 {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "deviceId is required")
		return
	}

	// Defense-in-depth ownership check: confirm the device row belongs to
	// the authenticated user before issuing the revoke. The service query
	// already includes user_id in its WHERE clause, but we don't want to
	// rely on the service implementation alone.
	owns, err := h.userOwnsDevice(session.Id, req.DeviceID)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to verify device")
		return
	}
	if !owns {
		// Same response shape as a successful revoke for an unknown device,
		// to avoid leaking which device IDs exist for other users.
		h.WriteError(w, http.StatusNotFound, "Not Found", "device not found")
		return
	}

	if err := h.UserService.RevokeTrustedDevice(session.Id, req.DeviceID); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to revoke device")
		return
	}

	common.WriteJSON(w, http.StatusOK, map[string]string{
		"message": "Device revoked",
	})
}

// userOwnsDevice scans the caller's trusted devices and reports whether
// the requested device id is one of them. Cheap because GetTrustedDevices
// returns only active rows and a typical user has < 10.
func (h *SecurityHandler) userOwnsDevice(userID int, deviceID int64) (bool, error) {
	devices, err := h.UserService.GetTrustedDevices(userID)
	if err != nil {
		return false, err
	}
	for _, d := range devices {
		if d.ID == deviceID {
			return true, nil
		}
	}
	return false, nil
}

// LogoutEverywhere revokes every active refresh token for the caller.
// Gated by requireRecentAuth so a stolen JWT cannot drop legitimate
// sessions on every other device the user owns.
//
// POST /api/user/logout-everywhere
//
//	{ "password": "<current>" }   or   { "twoFactorCode": "<TOTP>" }
func (h *SecurityHandler) LogoutEverywhere(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Password      string `json:"password"`
		TwoFactorCode string `json:"twoFactorCode"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if !h.requireRecentAuth(w, session, req.Password, req.TwoFactorCode) {
		return
	}
	if err := h.UserService.LogoutEverywhere(session.Id); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to revoke sessions")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"message": "All sessions revoked"})
}

// DeleteAccount soft-deletes the caller's account: anonymizes user_account,
// revokes all tokens, drops trusted devices and social links. Gated by
// requireRecentAuth — account deletion is irreversible, so a stolen JWT
// alone must never be sufficient.
//
// DELETE /api/user/account
//
//	{ "password": "<current>", "reason": "..." }
//	  or { "twoFactorCode": "<TOTP>", "reason": "..." }
//
// Consumers that own domain tables keyed on user_id should wrap this
// method with their own cascade before calling it.
func (h *SecurityHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodDelete) {
		return
	}
	var req struct {
		Reason        string `json:"reason"`
		Password      string `json:"password"`
		TwoFactorCode string `json:"twoFactorCode"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if !h.requireRecentAuth(w, session, req.Password, req.TwoFactorCode) {
		return
	}
	if err := h.UserService.DeleteAccount(session.Id, req.Reason); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to delete account")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
