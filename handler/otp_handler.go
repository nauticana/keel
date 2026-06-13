package handler

import (
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/dispatcher"
	"github.com/nauticana/keel/logger"
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
	// Mail is the synchronous email-send transport used when a SendOTP
	// request specifies contactType="email". Optional — when nil, the
	// email path falls back to NotificationSvc.Send with Channel="E"
	// (which goes through the consumer's async dispatch pipeline). Most
	// consumers should set Mail directly: OTP timing matters and the
	// async-Pub/Sub round-trip adds avoidable latency to a security
	// flow the user is actively waiting on.
	Mail *dispatcher.MailClient
	// Journal receives dispatch-side errors (mail/SMS send failures)
	// that the handler intentionally doesn't surface to the client. nil
	// is fine — failures fall through to log.Println so they always
	// reach stdout/journald.
	Journal logger.ApplicationLogger
}

// otpChannelPhone / otpChannelEmail are the two contactType values the
// OTP API accepts. Stored alongside the userID in the cache so Resend
// can dispatch on the same channel SendOTP used.
const (
	otpChannelPhone = "phone"
	otpChannelEmail = "email"
)

// OTPTokenTTL caps how long a SendOTP-issued token may be presented for
// Verify or Resend. Sized to match the OTP code's own lifetime
// (--otp_ttl_seconds, default 300s) so a legitimate user can use the
// token for the full window the code is valid. Raising the flag above
// this constant would let the code outlive its token — see the warning
// on common.OTPTTLSeconds.
const OTPTokenTTL = 5 * time.Minute

// otpSendResponse mirrors what clients deserialize. resendCountdownSec
// echoes the server's --otp_ttl_seconds so the OTP-input keypad's
// resend timer can match the code's actual lifetime instead of using
// a client-side fallback.
type otpSendResponse struct {
	OtpToken            string `json:"otpToken"`
	ResendCountdownSec  int    `json:"resendCountdownSec"`
}

func makeOtpSendResponse(token string) otpSendResponse {
	return otpSendResponse{OtpToken: token, ResendCountdownSec: *common.OTPTTLSeconds}
}

// otpTokenPrefix is the cache-key namespace for SendOTP-issued tokens.
const otpTokenPrefix = "otp_token:"

// mintOTPToken generates a fresh opaque token, stores it in the cache
// keyed to the userID + channel, and returns the token string. Callers
// send the token to the client; clients echo it back on Verify / Resend.
// A brute-forcer who guesses arbitrary userIDs cannot get into Verify
// because the cache lookup fails — only token-holders can verify.
//
// The cache value is "<userID>:<channel>" so Resend can dispatch on the
// same channel SendOTP used. Older single-int values are still parsed
// as legacy phone-OTP for backward compatibility with in-flight tokens
// minted before the email-OTP feature shipped.
func (h *OTPHandler) mintOTPToken(r *http.Request, userID int, channel string) (string, error) {
	if h.Cache == nil {
		return "", fmt.Errorf("OTPHandler: Cache must be set")
	}
	var raw [32]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("otp: rng: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	value := strconv.Itoa(userID) + ":" + channel
	if err := h.Cache.Set(r.Context(), otpTokenPrefix+token, value, OTPTokenTTL); err != nil {
		return "", fmt.Errorf("otp: cache set: %w", err)
	}
	return token, nil
}

// resolveOTPToken returns (userID, channel) bound to an opaque token,
// or (0, "") when the token is missing/expired/never-issued. Returns the
// same "zero" result for every failure mode so the caller cannot
// distinguish them — preserves the anti-enumeration property.
//
// Legacy values without a ":channel" suffix (minted before email-OTP
// support) are interpreted as phone-channel so in-flight tokens
// continue working through the rolling deploy window.
func (h *OTPHandler) resolveOTPToken(r *http.Request, token string) (int, string) {
	if h.Cache == nil || token == "" {
		return 0, ""
	}
	v, err := h.Cache.Get(r.Context(), otpTokenPrefix+token)
	if err != nil || v == "" {
		return 0, ""
	}
	idStr, channel := v, otpChannelPhone
	if idx := strings.Index(v, ":"); idx >= 0 {
		idStr = v[:idx]
		channel = v[idx+1:]
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		return 0, ""
	}
	if channel != otpChannelPhone && channel != otpChannelEmail {
		channel = otpChannelPhone
	}
	return id, channel
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
//
// ContactType selects the dispatch channel: "phone" (default — Contact
// is a phone number, normalized to E.164 via DefaultRegion) or "email"
// (Contact is an email address, lowercased + trimmed). Older clients
// that omit ContactType continue to hit the phone path.
type otpSendRequest struct {
	Contact        string          `json:"contact"`                 // phone number or email (raw user input)
	ContactType    string          `json:"contactType,omitempty"`   // "phone" (default) | "email"
	Purpose        string          `json:"purpose"`                 // login | register | verify
	DefaultRegion  string          `json:"defaultRegion,omitempty"` // ISO region for E.164 parse (default "US"); ignored for email
	// SecondaryContact is the user's claim for the OTHER channel:
	// when ContactType=email, this is the phone the user typed at
	// signup. Stored on the new user_account row so they have both
	// channels on file even though only one was OTP-verified at this
	// step. Phone verification can happen later (e.g. first booking).
	// Ignored on the phone path today — symmetric support is a TODO.
	SecondaryContact string          `json:"secondaryContact,omitempty"`
	PolicyType       string          `json:"policyType,omitempty"`
	PolicyVersion    string          `json:"policyVersion,omitempty"`
	PolicyRegion     string          `json:"policyRegion,omitempty"`
	PolicyLanguage   string          `json:"policyLanguage,omitempty"`
	Region           string          `json:"region,omitempty"`
	Consents         map[string]bool `json:"consents,omitempty"`
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
	if req.ContactType == "" {
		req.ContactType = otpChannelPhone
	}
	if req.DefaultRegion == "" {
		req.DefaultRegion = "US"
	}

	switch req.ContactType {
	case otpChannelPhone:
		h.sendOTPPhone(w, r, &req)
	case otpChannelEmail:
		h.sendOTPEmail(w, r, &req)
	default:
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "contactType must be 'phone' or 'email'")
	}
}

// rateLimitOTP enforces per-contact + per-IP caps shared by both
// channels. Returns true when the request should proceed; false means
// an error response has already been written.
func (h *OTPHandler) rateLimitOTP(w http.ResponseWriter, r *http.Request, contactKeySuffix string) bool {
	contactKey := "otp_rate:" + contactKeySuffix
	count, _ := h.Cache.Increment(r.Context(), contactKey)
	if count == 1 {
		h.Cache.Set(r.Context(), contactKey, "1", 10*time.Minute)
	}
	if count > 3 {
		h.WriteError(w, http.StatusTooManyRequests, "Too Many Requests", "too many OTP requests, try again later")
		return false
	}
	// Per-IP cap prevents pumping attacks that enumerate contacts
	// (each under the per-contact limit) from a single origin.
	ipKey := "otp_rate_ip:" + TrustedClientIP(r)
	ipCount, _ := h.Cache.Increment(r.Context(), ipKey)
	if ipCount == 1 {
		h.Cache.Set(r.Context(), ipKey, "1", 10*time.Minute)
	}
	if ipCount > 10 {
		h.WriteError(w, http.StatusTooManyRequests, "Too Many Requests", "too many OTP requests from this IP, try again later")
		return false
	}
	return true
}

// sendOTPPhone is the original SMS-channel path, factored out so
// SendOTP can branch on contactType cleanly.
func (h *OTPHandler) sendOTPPhone(w http.ResponseWriter, r *http.Request, req *otpSendRequest) {
	normalized, err := h.UserService.NormalizePhone(req.Contact, req.DefaultRegion)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid phone number")
		return
	}
	if !h.rateLimitOTP(w, r, normalized) {
		return
	}

	// Lookup-or-create based on purpose. To avoid leaking which phone
	// numbers are registered, the LOGIN path responds with the same
	// shape on success-and-not-found: a fresh opaque token with no
	// SMS dispatch. An attacker probing arbitrary numbers can no
	// longer distinguish 200(known) from 404(unknown).
	var session *model.UserSession
	if req.Purpose == "register" {
		var orcreateErr error
		consent := buildOTPSignupConsent(r, req)
		// SecondaryContact carries the email the user typed alongside
		// the phone on the signup form. The user-service handles
		// normalization (lowercase + trim) and silently drops the
		// email on collision with another user's account so the
		// phone-OTP signup still completes.
		session, _, orcreateErr = h.UserService.GetOrCreateUserByPhone(normalized, req.DefaultRegion, req.SecondaryContact, consent)
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
		if session == nil {
			fakeToken, _ := h.mintFakeOTPToken(r, otpChannelPhone)
			common.WriteJSON(w, http.StatusOK, makeOtpSendResponse(fakeToken))
			return
		}
	}

	otp, err := h.UserService.GenerateOTP(session.Id, req.Purpose)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to generate OTP")
		return
	}
	token, err := h.mintOTPToken(r, session.Id, otpChannelPhone)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to issue OTP token")
		return
	}
	h.dispatchOTPSMS(r, session.Id, otp)

	common.WriteJSON(w, http.StatusOK, makeOtpSendResponse(token))
}

// sendOTPEmail is the email-channel twin of sendOTPPhone. Mirrors the
// rate-limit, lookup-or-create, and anti-enumeration semantics; only
// the dispatch transport differs.
func (h *OTPHandler) sendOTPEmail(w http.ResponseWriter, r *http.Request, req *otpSendRequest) {
	email := strings.ToLower(strings.TrimSpace(req.Contact))
	if email == "" || !strings.Contains(email, "@") || strings.ContainsAny(email, " \t\n\r") {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid email address")
		return
	}
	if !h.rateLimitOTP(w, r, email) {
		return
	}

	var session *model.UserSession
	if req.Purpose == "register" {
		var orcreateErr error
		consent := buildOTPSignupConsent(r, req)
		// SecondaryContact carries the phone the user typed on the
		// signup form (alongside the email). Normalize to E.164 so
		// phone columns stay consistent across phone-OTP and email-
		// OTP signup paths — a phone-OTP user is stored as
		// "+14165551234", and an email-OTP user with the same number
		// must be stored the same way for future lookups to match.
		// On invalid format we silently drop it: the email is what's
		// being verified, and a typo'd secondary phone shouldn't
		// fail the whole signup. The user can fix it later.
		secondaryPhone := ""
		if raw := strings.TrimSpace(req.SecondaryContact); raw != "" {
			if e164, err := h.UserService.NormalizePhone(raw, req.DefaultRegion); err == nil {
				secondaryPhone = e164
			}
		}
		session, _, orcreateErr = h.UserService.GetOrCreateUserByEmail(email, secondaryPhone, consent)
		if orcreateErr != nil {
			if session != nil {
				h.WriteError(w, http.StatusFailedDependency, "Consent Not Recorded", orcreateErr.Error())
				return
			}
			h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to create user")
			return
		}
	} else {
		session, _ = h.UserService.GetUserByEmail(email)
		if session == nil {
			// Same anti-enumeration shape as the phone fall-through.
			fakeToken, _ := h.mintFakeOTPToken(r, otpChannelEmail)
			common.WriteJSON(w, http.StatusOK, makeOtpSendResponse(fakeToken))
			return
		}
	}

	otp, err := h.UserService.GenerateOTP(session.Id, req.Purpose)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to generate OTP")
		return
	}
	token, err := h.mintOTPToken(r, session.Id, otpChannelEmail)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to issue OTP token")
		return
	}
	h.dispatchOTPEmail(r, session.Id, email, otp)

	common.WriteJSON(w, http.StatusOK, makeOtpSendResponse(token))
}

// dispatchOTPSMS pushes the SMS code through the consumer's notification
// service. The error doesn't propagate to the client — the OTP row
// already exists in user_otp so the user can resend — but it IS logged
// so a silently-failing Twilio config surfaces in the journal.
func (h *OTPHandler) dispatchOTPSMS(r *http.Request, userID int, otp string) {
	if h.NotificationSvc == nil {
		return
	}
	if err := h.NotificationSvc.Send(r.Context(), port.NotificationRequest{
		UserID:  userID,
		Type:    "S",
		Channel: "S", // SMS
		Title:   "Verification Code",
		Body:    "Your verification code is: " + otp,
	}); err != nil {
		h.logDispatchFailure("otp-sms", userID, err)
	}
}

// dispatchOTPEmail prefers the synchronous MailClient path because OTP
// timing matters and the user is actively waiting. Falls back to the
// async NotificationSvc with Channel="E" when MailClient isn't wired.
//
// Errors are NOT propagated to the caller — the OTP row already exists
// in user_otp so the user can resend, and a 5xx here would leak
// dispatch-internal failure modes. But we DO log them via the
// AbstractHandler.Journal (when wired by the consumer) so a "200 OK
// but nothing arrived" mystery surfaces in the logs instead of silence.
func (h *OTPHandler) dispatchOTPEmail(r *http.Request, userID int, email, otp string) {
	body := "Your Trvoo verification code is: " + otp + "\n\nThe code expires in a few minutes. If you didn't request it, you can ignore this message."
	if h.Mail != nil {
		if err := h.Mail.SendEmail(r.Context(), "Verification Code", body, []string{email}); err != nil {
			h.logDispatchFailure("otp-email", userID, err)
		}
		return
	}
	if h.NotificationSvc != nil {
		if err := h.NotificationSvc.Send(r.Context(), port.NotificationRequest{
			UserID:  userID,
			Type:    "S",
			Channel: "E", // Email
			Title:   "Verification Code",
			Body:    body,
		}); err != nil {
			h.logDispatchFailure("otp-email-async", userID, err)
		}
	}
}

// logDispatchFailure routes a dispatch error to the consumer-provided
// Journal so silent mail/SMS failures don't disappear. AbstractHandler.
// Journal is optional; nil journals fall back to log.Printf so the
// message is at least in stdout/journald.
func (h *OTPHandler) logDispatchFailure(channel string, userID int, err error) {
	msg := fmt.Sprintf("otp dispatch failed (channel=%s userID=%d): %v", channel, userID, err)
	if h.Journal != nil {
		h.Journal.Error(msg)
		return
	}
	log.Println(msg)
}

// mintFakeOTPToken returns a server-issued token that resolves to
// userID=0 in the cache — Verify() will treat it as "wrong code" but
// the caller cannot distinguish it from a real token. Used on the
// login fall-through where the contact isn't registered: we still
// respond with a 200 + token to keep the shape identical and prevent
// enumeration. The channel suffix matches the legitimate code path so
// a Resend on a fake token produces the same cache-shape as a real one.
func (h *OTPHandler) mintFakeOTPToken(r *http.Request, channel string) (string, error) {
	var raw [32]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	if h.Cache != nil {
		// userID=0 is intentional: VerifyOTP rejects it.
		_ = h.Cache.Set(r.Context(), otpTokenPrefix+token, "0:"+channel, OTPTokenTTL)
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

	userID, _ := h.resolveOTPToken(r, req.OTPToken)
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

	userID, channel := h.resolveOTPToken(r, req.OTPToken)
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

	// Refresh the token TTL (preserving the channel suffix) so the
	// legitimate user has the full Verify window after a resend.
	if h.Cache != nil {
		_ = h.Cache.Set(r.Context(), otpTokenPrefix+req.OTPToken, strconv.Itoa(userID)+":"+channel, OTPTokenTTL)
	}

	// Resend on the same channel SendOTP used. Channel was stored
	// alongside the userID at mint-time, so a phone-OTP user retries
	// over SMS and an email-OTP user over email — never a silent
	// channel-switch.
	if channel == otpChannelEmail {
		// Look up the email from the user's session record so we know
		// where to send. Failures fall through silently (consistent
		// with the SMS path's "best-effort, the user can retry" stance).
		if session, err := h.UserService.GetUserById(userID); err == nil && session != nil && session.Email != "" {
			h.dispatchOTPEmail(r, userID, session.Email, otp)
		}
	} else {
		h.dispatchOTPSMS(r, userID, otp)
	}

	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "otp_sent"})
}
