package handler

import (
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// OTPHandler handles OTP-based authentication (phone/email verification).
//
// The handler now returns a server-issued opaque `otpToken` from SendOTP
// instead of leaking the user's raw `user_account.id`. The token is the
// only field that resolves to a userID on Verify/Resend; brute-forcing
// a userID alone gets nowhere because the cache lookup fails. Tokens
// are 32-byte base64-URL-encoded strings (~256 bits) keyed in the cache
// for OTPTokenTTL.
type OTPHandler struct {
	AbstractHandler
	NotificationSvc port.NotificationService
	Cache           cache.CacheService
}

// OTPTokenTTL caps how long a SendOTP-issued token may be presented for
// Verify or Resend. Slightly longer than the OTP code's own 2-minute
// expiry so a legitimate user typing slowly can still use the token to
// resend without re-entering their phone.
const OTPTokenTTL = 5 * time.Minute

// otpTokenPrefix is the cache-key namespace for SendOTP-issued tokens.
const otpTokenPrefix = "otp_token:"

// mintOTPToken generates a fresh opaque token, stores it in the cache
// keyed to the userID, and returns the token string. Callers send the
// token to the client; clients echo it back on Verify / Resend. A
// brute-forcer who guesses arbitrary userIDs cannot get into Verify
// because the cache lookup fails — only token-holders can verify.
func (h *OTPHandler) mintOTPToken(r *http.Request, userID int) (string, error) {
	if h.Cache == nil {
		return "", fmt.Errorf("OTPHandler: Cache must be set")
	}
	var raw [32]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("otp: rng: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	if err := h.Cache.Set(r.Context(), otpTokenPrefix+token, strconv.Itoa(userID), OTPTokenTTL); err != nil {
		return "", fmt.Errorf("otp: cache set: %w", err)
	}
	return token, nil
}

// resolveOTPToken returns the userID bound to an opaque token, or 0
// when the token is missing/expired/never-issued. Returns the same
// "zero" result for every failure mode so the caller cannot
// distinguish them — preserves the anti-enumeration property.
func (h *OTPHandler) resolveOTPToken(r *http.Request, token string) int {
	if h.Cache == nil || token == "" {
		return 0
	}
	v, err := h.Cache.Get(r.Context(), otpTokenPrefix+token)
	if err != nil || v == "" {
		return 0
	}
	id, err := strconv.Atoi(v)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

// consumeOTPToken deletes a token after a successful verify so the
// same token cannot be replayed. Best-effort: a delete failure is not
// fatal because the underlying user_otp row is already consumed.
func (h *OTPHandler) consumeOTPToken(r *http.Request, token string) {
	if h.Cache == nil || token == "" {
		return
	}
	_ = h.Cache.Delete(r.Context(), otpTokenPrefix+token)
}

// otpSendRequest is the JSON body accepted by SendOTP. Consent fields
// are optional; they're recorded only when purpose="register" creates
// a new user AND the service has a ConsentService registered.
type otpSendRequest struct {
	Contact        string          `json:"contact"`                 // phone number (raw user input)
	Purpose        string          `json:"purpose"`                 // login | register | verify
	DefaultRegion  string          `json:"defaultRegion,omitempty"` // ISO region for E.164 parse (default "US")
	PolicyType     string          `json:"policyType,omitempty"`
	PolicyVersion  string          `json:"policyVersion,omitempty"`
	PolicyRegion   string          `json:"policyRegion,omitempty"`
	PolicyLanguage string          `json:"policyLanguage,omitempty"`
	Region         string          `json:"region,omitempty"`
	Consents       map[string]bool `json:"consents,omitempty"`
}

// buildOTPSignupConsent mirrors buildSignupConsent for the OTP register
// path. Returns nil when no consent payload was sent — signals skip.
func buildOTPSignupConsent(r *http.Request, req *otpSendRequest) *user.SignupConsent {
	if len(req.Consents) == 0 && req.PolicyVersion == "" {
		return nil
	}
	return &user.SignupConsent{
		PolicyType:      req.PolicyType,
		PolicyVersion:   req.PolicyVersion,
		PolicyRegion:    req.PolicyRegion,
		PolicyLanguage:  req.PolicyLanguage,
		Region:          req.Region,
		ClientIP:        TrustedClientIP(r),
		ClientUserAgent: r.UserAgent(),
		Consents:        req.Consents,
	}
}

// SendOTP generates and sends an OTP to the user's phone or email.
// On purpose="register" a new user_account row is created with passtext=NULL;
// the E.164-normalized phone (using defaultRegion as a hint) is stored.
// Optional consent fields are recorded against the new user when a
// ConsentService is registered on the underlying UserService.
func (h *OTPHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req otpSendRequest
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.Contact == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "contact is required")
		return
	}
	if req.Purpose == "" {
		req.Purpose = "login"
	}
	if req.DefaultRegion == "" {
		req.DefaultRegion = "US"
	}

	normalized, err := h.UserService.NormalizePhone(req.Contact, req.DefaultRegion)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid phone number")
		return
	}

	// Per-contact rate limit: max 3 OTPs per E.164 number per 10 minutes.
	// Normalized key so "(416) 555-1234" and "+14165551234" share the quota.
	contactKey := "otp_rate:" + normalized
	count, _ := h.Cache.Increment(r.Context(), contactKey)
	if count == 1 {
		h.Cache.Set(r.Context(), contactKey, "1", 10*time.Minute)
	}
	if count > 3 {
		h.WriteError(w, http.StatusTooManyRequests, "Too Many Requests", "too many OTP requests, try again later")
		return
	}

	// Per-IP rate limit: max 10 OTPs per caller IP per 10 minutes.
	// Prevents SMS-pumping attacks that enumerate phone numbers (each under
	// the per-contact limit) from a single origin.
	ipKey := "otp_rate_ip:" + TrustedClientIP(r)
	ipCount, _ := h.Cache.Increment(r.Context(), ipKey)
	if ipCount == 1 {
		h.Cache.Set(r.Context(), ipKey, "1", 10*time.Minute)
	}
	if ipCount > 10 {
		h.WriteError(w, http.StatusTooManyRequests, "Too Many Requests", "too many OTP requests from this IP, try again later")
		return
	}

	// Lookup-or-create based on purpose. To avoid leaking which phone
	// numbers are registered, the LOGIN path responds with the same
	// shape on success-and-not-found: a fresh opaque token with no
	// SMS dispatch. An attacker probing arbitrary numbers can no
	// longer distinguish 200(known) from 404(unknown).
	var session *model.UserSession
	if req.Purpose == "register" {
		var created bool
		var orcreateErr error
		consent := buildOTPSignupConsent(r, &req)
		session, created, orcreateErr = h.UserService.GetOrCreateUserByPhone(normalized, req.DefaultRegion, consent)
		_ = created
		if orcreateErr != nil {
			if session != nil {
				h.WriteError(w, http.StatusFailedDependency, "Consent Not Recorded", orcreateErr.Error())
				return
			}
			h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to create user")
			return
		}
	} else {
		session, _ = h.UserService.GetUserByPhone(normalized)
		// Login path: do NOT 404 on unknown phone. Fall through and
		// return a fresh opaque token bound to no user. Verify will
		// fail with the same generic message as a wrong code, so the
		// attacker cannot tell which phone numbers are registered.
		if session == nil {
			fakeToken, _ := h.mintFakeOTPToken(r)
			common.WriteJSON(w, http.StatusOK, map[string]any{"otpToken": fakeToken})
			return
		}
	}

	otp, err := h.UserService.GenerateOTP(session.Id, req.Purpose)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to generate OTP")
		return
	}

	token, err := h.mintOTPToken(r, session.Id)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to issue OTP token")
		return
	}

	if h.NotificationSvc != nil {
		_ = h.NotificationSvc.Send(r.Context(), port.NotificationRequest{
			UserID:  session.Id,
			Type:    "S",
			Channel: "S", // SMS
			Title:   "Verification Code",
			Body:    "Your verification code is: " + otp,
		})
	}

	// Note: `isNewUser` and `sessionId` are deliberately NOT in the
	// response — both leak information an unauthenticated caller
	// shouldn't have ("does this phone exist?", "what's the user
	// id?"). Clients that need a flow-branch on first-time-user
	// detect it after Verify by inspecting the returned session.
	common.WriteJSON(w, http.StatusOK, map[string]any{"otpToken": token})
}

// mintFakeOTPToken returns a server-issued token that resolves to
// userID=0 in the cache — Verify() will treat it as "wrong code" but
// the caller cannot distinguish it from a real token. Used on the
// login fall-through where the phone isn't registered: we still
// respond with a 200 + token to keep the shape identical and prevent
// enumeration.
func (h *OTPHandler) mintFakeOTPToken(r *http.Request) (string, error) {
	var raw [32]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	// userID=0 is intentional: VerifyOTP rejects it.
	if h.Cache != nil {
		_ = h.Cache.Set(r.Context(), otpTokenPrefix+token, "0", OTPTokenTTL)
	}
	return token, nil
}

// VerifyOTP verifies the OTP code and returns a JWT token on success.
//
// Accepts the opaque `otpToken` from SendOTP — NOT a raw user_id. The
// token resolves through the cache to a userID; an attacker who guessed
// arbitrary userIDs has no way past this binding. The pre-v0.5 API
// accepted `sessionId` (= raw user_id) directly, which made user-id
// brute-forcing the only barrier between an attacker and 5 OTP-attempt
// windows per victim.
func (h *OTPHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		OTPToken string `json:"otpToken"`
		Code     string `json:"code"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.OTPToken == "" || req.Code == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "otpToken and code are required")
		return
	}

	userID := h.resolveOTPToken(r, req.OTPToken)
	if userID <= 0 {
		// Either the token never existed, or it's a fake-token from
		// the login fall-through (userID=0). Generic 401 — same shape
		// as a wrong code so the caller can't distinguish.
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid or expired code")
		return
	}

	// VerifyOTP now atomically increments attempts on mismatch and consumes
	// the row on match — callers no longer need to bracket it with explicit
	// IncrementOTPAttempts / ClearOTP calls. We still keep the response
	// detail generic to avoid distinguishing "wrong code" from "expired"
	// from "max attempts exceeded".
	if err := h.UserService.VerifyOTP(userID, req.Code); err != nil {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid or expired code")
		return
	}

	// Consume the token after a successful verify so a stolen token
	// can't be replayed even within its TTL.
	h.consumeOTPToken(r, req.OTPToken)

	session, err := h.UserService.GetUserById(userID)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to load user")
		return
	}

	token, err := h.UserService.CreateJWT(session)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to create token")
		return
	}

	common.WriteJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"userId":    session.Id,
		"partnerId": session.PartnerId,
	})
}

// ResendOTP regenerates the OTP for an existing send-flow.
//
// Like VerifyOTP, the request is keyed on the opaque otpToken from
// SendOTP. The token's lifetime is reset on resend so the user gets
// the full Verify window after a slow-typing retry.
func (h *OTPHandler) ResendOTP(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		OTPToken string `json:"otpToken"`
		Purpose  string `json:"purpose"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.OTPToken == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "otpToken is required")
		return
	}
	if req.Purpose == "" {
		req.Purpose = "login"
	}

	userID := h.resolveOTPToken(r, req.OTPToken)
	if userID <= 0 {
		// Same anti-enumeration shape as the login fall-through:
		// pretend success without dispatching.
		common.WriteJSON(w, http.StatusOK, map[string]string{"status": "otp_sent"})
		return
	}

	_ = h.UserService.ClearOTP(userID)

	otp, err := h.UserService.GenerateOTP(userID, req.Purpose)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to generate OTP")
		return
	}

	// Refresh the token TTL so the legitimate user has the full
	// Verify window after a resend.
	if h.Cache != nil {
		_ = h.Cache.Set(r.Context(), otpTokenPrefix+req.OTPToken, strconv.Itoa(userID), OTPTokenTTL)
	}

	if h.NotificationSvc != nil {
		_ = h.NotificationSvc.Send(r.Context(), port.NotificationRequest{
			UserID:  userID,
			Type:    "S",
			Channel: "S",
			Title:   "Verification Code",
			Body:    "Your verification code is: " + otp,
		})
	}

	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "otp_sent"})
}
