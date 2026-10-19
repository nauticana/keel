package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
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
// for the otp_token_ttl config window.
type OTPHandler struct {
	AbstractHandler
	NotificationSvc port.NotificationService
	Cache           cache.CacheService
	// Mail is the synchronous email-send transport used when a SendOTP
	// request specifies contactType="email". Optional — when nil, the
	// email path falls back to NotificationSvc.Send on dispatcher.EmailChannel
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
	// Brand is the product name shown in OTP messages; empty = brand-less.
	// A 10DLC campaign must register the exact SMS body this sends.
	Brand string
	// Optional body overrides ("{code}" → the OTP). Empty uses brand-aware
	// defaults; the SMS default carries STOP/HELP opt-out language for 10DLC.
	OTPSMSTemplate   string
	OTPEmailTemplate string
	OTPEmailSubject  string
	// Human, when set, checks the challengeToken of a register send before any
	// code is sent; nil skips the check.
	Human port.HumanVerifier
}

// otpSMSBody: OTPSMSTemplate with {code} filled, else the brand-aware default.
func (h *OTPHandler) otpSMSBody(otp string) string {
	if h.OTPSMSTemplate != "" {
		return strings.ReplaceAll(h.OTPSMSTemplate, "{code}", otp)
	}
	brand := h.Brand
	if brand != "" {
		brand += " "
	}
	return fmt.Sprintf("Your %sverification code is %s. Reply STOP to opt out, HELP for help.", brand, otp)
}

// otpEmailBody: OTPEmailTemplate with {code} filled, else the brand-aware default.
func (h *OTPHandler) otpEmailBody(otp string) string {
	if h.OTPEmailTemplate != "" {
		return strings.ReplaceAll(h.OTPEmailTemplate, "{code}", otp)
	}
	brand := h.Brand
	if brand != "" {
		brand += " "
	}
	return fmt.Sprintf("Your %sverification code is: %s\n\nThe code expires in a few minutes. If you didn't request it, you can ignore this message.", brand, otp)
}

func (h *OTPHandler) otpEmailSubject() string {
	if h.OTPEmailSubject != "" {
		return h.OTPEmailSubject
	}
	return "Verification Code"
}

// otpChannelPhone / otpChannelEmail are the two contactType values the
// OTP API accepts. Stored alongside the userID in the cache so Resend
// can dispatch on the same channel SendOTP used.
const (
	otpChannelPhone = "phone"
	otpChannelEmail = "email"
)

// otpSendResponse mirrors what clients deserialize. resendCountdownSec
// echoes the server's otp_ttl_seconds so the OTP-input keypad's
// resend timer can match the code's actual lifetime instead of using
// a client-side fallback.
type otpSendResponse struct {
	OtpToken           string `json:"otpToken"`
	ResendCountdownSec int    `json:"resendCountdownSec"`
}

func makeOtpSendResponse(token string) otpSendResponse {
	return otpSendResponse{OtpToken: token, ResendCountdownSec: config.Config().OTPTTLSeconds}
}

// otpTokenPrefix is the cache-key namespace for SendOTP-issued tokens.
const otpTokenPrefix = "otp_token:"

// mintOTPToken stores a fresh opaque token bound to "<userID>:<channel>:<purpose>"
// and returns it; only a token holder reaches Verify and Resend.
func (h *OTPHandler) mintOTPToken(r *http.Request, userID int, channel, purpose string) (string, error) {
	if h.Cache == nil {
		return "", fmt.Errorf("OTPHandler: Cache must be set")
	}
	token, err := newOTPToken()
	if err != nil {
		return "", err
	}
	value := strconv.Itoa(userID) + ":" + channel + ":" + purpose
	if err := h.Cache.Set(r.Context(), otpTokenPrefix+token, value, config.Config().OTPTokenTTL); err != nil {
		return "", fmt.Errorf("otp: cache set: %w", err)
	}
	return token, nil
}

// resolveOTPToken returns the user, channel and purpose bound to a token, or
// zero for a missing, expired or fake token so the failure modes look alike.
// A value without a channel or purpose is read as phone and "any purpose".
func (h *OTPHandler) resolveOTPToken(r *http.Request, token string) (userID int, channel, purpose string) {
	if h.Cache == nil || token == "" {
		return 0, "", ""
	}
	v, err := h.Cache.Get(r.Context(), otpTokenPrefix+token)
	if err != nil || v == "" {
		return 0, "", ""
	}
	parts := strings.SplitN(v, ":", 3)
	idStr, ch, pp := parts[0], otpChannelPhone, ""
	if len(parts) >= 2 {
		ch = parts[1]
	}
	if len(parts) >= 3 {
		pp = parts[2]
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		return 0, "", ""
	}
	if ch != otpChannelPhone && ch != otpChannelEmail {
		ch = otpChannelPhone
	}
	return id, ch, pp
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
	Contact       string `json:"contact"`                 // phone number or email (raw user input)
	ContactType   string `json:"contactType,omitempty"`   // "phone" (default) | "email"
	Purpose       string `json:"purpose"`                 // login | register | verify
	DefaultRegion string `json:"defaultRegion,omitempty"` // ISO region for E.164 parse (default "US"); ignored for email
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
	// ChallengeToken is the human verifier's token; required on register
	// sends when the handler has a Human verifier.
	ChallengeToken string `json:"challengeToken,omitempty"`
}

// buildOTPSignupConsent mirrors buildSignupConsent for the OTP register
// path. Returns nil when no consent payload was sent — signals skip.
func buildOTPSignupConsent(r *http.Request, req *otpSendRequest) *user.SignupConsent {
	if len(req.Consents) == 0 && req.PolicyVersion == "" {
		return nil
	}
	// The phone is the OTP contact on the phone path, the secondary on the email
	// path — either way, stamp it so an SMS consent is provably tied to the number.
	phone := req.SecondaryContact
	if req.ContactType == otpChannelPhone {
		phone = req.Contact
	}
	return &user.SignupConsent{
		PolicyType:      req.PolicyType,
		PolicyVersion:   req.PolicyVersion,
		PolicyRegion:    req.PolicyRegion,
		PolicyLanguage:  req.PolicyLanguage,
		Region:          req.Region,
		ClientIP:        common.TrustedClientIP(r),
		ClientUserAgent: r.UserAgent(),
		Phone:           phone,
		Consents:        req.Consents,
	}
}

// SendOTP generates and sends an OTP to the user's phone or email. On
// purpose="register" an unknown contact is held as a pending signup behind
// the token and the account, with its consent, is created when VerifyOTP
// proves the contact.
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
// Send is the one rate-limited path with no database-backed backstop: OTP
// verify, password login, and 2FA verify all bump a persisted attempt counter
// and lock the account, but nothing bounds *dispatch*. A swallowed cache error
// therefore removed the only cap standing between an attacker and unbounded
// SMS/email spend, so a counter that cannot be read fails closed.
func (h *OTPHandler) rateLimitOTP(w http.ResponseWriter, r *http.Request, contactKeySuffix string) bool {
	cfg := config.Config()
	if h.overOTPCap(w, r, "otp_rate:"+contactKeySuffix, "per-contact", cfg.OTPSendPerContact, cfg.OTPSendWindow,
		"too many OTP requests, try again later") {
		return false
	}
	// Per-IP cap prevents pumping attacks that enumerate contacts
	// (each under the per-contact limit) from a single origin.
	if h.overOTPCap(w, r, "otp_rate_ip:"+common.TrustedClientIP(r), "per-IP", cfg.OTPSendPerIP, cfg.OTPSendWindow,
		"too many OTP requests from this IP, try again later") {
		return false
	}
	return true
}

// overOTPCap counts one send against key and reports whether the request was
// refused (response already written). A zero limit disables the cap.
func (h *OTPHandler) overOTPCap(w http.ResponseWriter, r *http.Request, key, scope string, limit int, window time.Duration, refusal string) bool {
	if limit == 0 {
		if h.Journal != nil {
			h.Journal.Warning("otp " + scope + " send rate limit is disabled")
		}
		return false
	}
	count, err := h.Cache.IncrementWithTTL(r.Context(), key, window)
	if err != nil {
		h.rateLimitUnavailable(w, r, scope+" OTP counter", err)
		return true
	}
	if count > int64(limit) {
		h.WriteError(w, http.StatusTooManyRequests, "Too Many Requests", refusal)
		return true
	}
	return false
}

// rateLimitUnavailable refuses the send and records the cause. The client gets
// a retryable 503 with no detail; the operator gets the backend error, which a
// discarded error left invisible until the provider invoice arrived.
func (h *OTPHandler) rateLimitUnavailable(w http.ResponseWriter, r *http.Request, which string, err error) bool {
	if h.Journal != nil {
		h.Journal.Error(fmt.Sprintf("otp rate limit unavailable (%s): %v", which, err))
	}
	h.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable",
		"rate limiting is temporarily unavailable, try again later")
	return false
}

func (h *OTPHandler) sendOTPPhone(w http.ResponseWriter, r *http.Request, req *otpSendRequest) {
	normalized, err := h.UserService.NormalizePhone(req.Contact, req.DefaultRegion)
	if err != nil {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid phone number")
		return
	}
	if !h.rateLimitOTP(w, r, normalized) {
		return
	}
	if req.Purpose == "register" {
		h.sendOTPRegister(w, r, req, otpChannelPhone, normalized)
		return
	}
	h.sendOTPLogin(w, r, req, otpChannelPhone, normalized)
}

func (h *OTPHandler) sendOTPEmail(w http.ResponseWriter, r *http.Request, req *otpSendRequest) {
	email := strings.ToLower(strings.TrimSpace(req.Contact))
	if email == "" || !strings.Contains(email, "@") || strings.ContainsAny(email, " \t\n\r") {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid email address")
		return
	}
	if !h.rateLimitOTP(w, r, email) {
		return
	}
	if req.Purpose == "register" {
		h.sendOTPRegister(w, r, req, otpChannelEmail, email)
		return
	}
	h.sendOTPLogin(w, r, req, otpChannelEmail, email)
}

// lookupContact finds the account behind a contact; none is (nil, nil).
func (h *OTPHandler) lookupContact(channel, contact string) (*model.UserSession, error) {
	var session *model.UserSession
	var err error
	if channel == otpChannelEmail {
		session, err = h.UserService.GetUserByEmail(contact)
	} else {
		session, err = h.UserService.GetUserByPhone(contact)
	}
	if errors.Is(err, user.ErrNoAccount) {
		return nil, nil
	}
	return session, err
}

// sendOTPLogin answers an unknown contact with the same shape as a known one,
// without a dispatch, so contacts cannot be enumerated.
func (h *OTPHandler) sendOTPLogin(w http.ResponseWriter, r *http.Request, req *otpSendRequest, channel, contact string) {
	session, err := h.lookupContact(channel, contact)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to look up user")
		return
	}
	if session == nil {
		fakeToken, _ := h.mintFakeOTPToken(r, channel)
		common.WriteJSON(w, http.StatusOK, makeOtpSendResponse(fakeToken))
		return
	}
	h.sendOTPUser(w, r, session, channel, req.Purpose, contact)
}

// sendOTPUser issues a code to an existing account over channel.
func (h *OTPHandler) sendOTPUser(w http.ResponseWriter, r *http.Request, session *model.UserSession, channel, purpose, contact string) {
	otp, err := h.UserService.GenerateOTP(session.Id, purpose)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to generate OTP")
		return
	}
	token, err := h.mintOTPToken(r, session.Id, channel, purpose)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to issue OTP token")
		return
	}
	h.dispatchOTP(r, session.Id, channel, contact, otp)
	common.WriteJSON(w, http.StatusOK, makeOtpSendResponse(token))
}

// sendOTPRegister runs the human check, then either codes an existing account
// (a registration of a known contact is a sign-in) or holds the signup as
// pending until the code proves the contact.
func (h *OTPHandler) sendOTPRegister(w http.ResponseWriter, r *http.Request, req *otpSendRequest, channel, contact string) {
	if !h.requireHuman(w, r, h.Human, req.ChallengeToken) {
		return
	}
	consent := buildOTPSignupConsent(r, req)
	// The other channel's contact is the user's unverified claim. A phone typed
	// beside an email is normalized so both signup paths store the same form;
	// an unparseable one is dropped rather than failing the signup.
	secondary := strings.TrimSpace(req.SecondaryContact)
	if channel == otpChannelEmail && secondary != "" {
		if e164, err := h.UserService.NormalizePhone(secondary, req.DefaultRegion); err == nil {
			secondary = e164
		} else {
			secondary = ""
		}
	}
	existing, err := h.lookupContact(channel, contact)
	if existing != nil {
		if channel == otpChannelEmail {
			existing, _, err = h.UserService.GetOrCreateUserByEmail(contact, secondary, consent)
		} else {
			existing, _, err = h.UserService.GetOrCreateUserByPhone(contact, req.DefaultRegion, secondary, consent)
		}
	}
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to look up user")
		return
	}
	if existing != nil {
		h.sendOTPUser(w, r, existing, channel, req.Purpose, contact)
		return
	}
	pending := &otpPendingSignup{Channel: channel, Contact: contact, SecondaryContact: secondary, DefaultRegion: req.DefaultRegion, Consent: consent}
	otp, err := user.NewOTPCode()
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to generate OTP")
		return
	}
	pending.setCode(otp)
	token, err := newOTPToken()
	if err == nil {
		err = h.storePending(r, token, pending)
	}
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to issue OTP token")
		return
	}
	h.dispatchOTP(r, 0, channel, contact, otp)
	common.WriteJSON(w, http.StatusOK, makeOtpSendResponse(token))
}

// dispatchOTP sends the code over channel. userID 0 is a pending signup with
// no account yet, so the address is given to the notification service directly.
func (h *OTPHandler) dispatchOTP(r *http.Request, userID int, channel, contact, otp string) {
	if channel == otpChannelEmail {
		h.dispatchOTPEmail(r, userID, contact, otp)
		return
	}
	h.dispatchOTPSMS(r, userID, contact, otp)
}

// dispatchOTPSMS pushes the SMS code through the consumer's notification
// service. The error doesn't propagate to the client — the OTP row
// already exists in user_otp so the user can resend — but it IS logged
// so a silently-failing SMS config surfaces in the journal.
func (h *OTPHandler) dispatchOTPSMS(r *http.Request, userID int, phone, otp string) {
	if h.NotificationSvc == nil {
		return
	}
	req := port.NotificationRequest{
		UserID:  userID,
		Type:    port.NotificationTypeOTP,
		Channel: dispatcher.SMSChannel,
		Title:   "Verification Code",
		Body:    h.otpSMSBody(otp),
	}
	if userID == 0 {
		req.To = phone
	}
	if err := h.NotificationSvc.Send(r.Context(), req); err != nil {
		h.logDispatchFailure("otp-sms", userID, err)
	}
}

// dispatchOTPEmail prefers the synchronous MailClient path because OTP
// timing matters and the user is actively waiting. Falls back to the
// async NotificationSvc on dispatcher.EmailChannel when MailClient isn't wired.
//
// Errors are NOT propagated to the caller — the OTP row already exists
// in user_otp so the user can resend, and a 5xx here would leak
// dispatch-internal failure modes. But we DO log them via the
// AbstractHandler.Journal (when wired by the consumer) so a "200 OK
// but nothing arrived" mystery surfaces in the logs instead of silence.
func (h *OTPHandler) dispatchOTPEmail(r *http.Request, userID int, email, otp string) {
	body := h.otpEmailBody(otp)
	subject := h.otpEmailSubject()
	if h.Mail != nil {
		if err := h.Mail.SendEmail(r.Context(), subject, body, []string{email}, nil); err != nil {
			h.logDispatchFailure("otp-email", userID, err)
		}
		return
	}
	if h.NotificationSvc != nil {
		req := port.NotificationRequest{
			UserID:  userID,
			Type:    port.NotificationTypeOTP,
			Channel: dispatcher.EmailChannel,
			Title:   subject,
			Body:    body,
		}
		if userID == 0 {
			req.To = email
		}
		if err := h.NotificationSvc.Send(r.Context(), req); err != nil {
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
	token, err := newOTPToken()
	if err != nil {
		return "", err
	}
	if h.Cache != nil {
		// userID=0 is intentional: VerifyOTP rejects it.
		_ = h.Cache.Set(r.Context(), otpTokenPrefix+token, "0:"+channel, config.Config().OTPTokenTTL)
	}
	return token, nil
}

// VerifyOTP checks the code behind an otpToken and answers with the session
// tokens: for an account through user_otp, for a pending signup by creating
// the account.
func (h *OTPHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		OTPToken string `json:"otpToken"`
		Code     string `json:"code"`
		SessionLimit
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.OTPToken == "" || req.Code == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "otpToken and code are required")
		return
	}
	maxAge, err := req.MaxAge()
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}

	userID, channel, purpose := h.resolveOTPToken(r, req.OTPToken)
	if userID <= 0 {
		if pending, raw := h.loadPending(r, req.OTPToken); pending != nil {
			h.verifyPendingSignup(w, r, req.OTPToken, raw, pending, req.Code, maxAge)
			return
		}
		// An unknown token and the login fall-through's fake token answer like
		// a wrong code, so a caller cannot tell them apart.
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid or expired code")
		return
	}

	// The service claims the attempt under the cap and consumes the row on a
	// match; the refusal stays generic across wrong, expired and exhausted.
	if err := h.UserService.VerifyOTP(userID, purpose, req.Code); err != nil {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid or expired code")
		return
	}
	h.consumeOTPToken(r, req.OTPToken)
	h.finishOTPSignIn(w, r, userID, channel, false, maxAge)
}

// verifyPendingSignup checks the code of a pending registration and creates
// the account on a match.
func (h *OTPHandler) verifyPendingSignup(w http.ResponseWriter, r *http.Request, token, raw string, pending *otpPendingSignup, code string, maxAge time.Duration) {
	if !h.claimPendingAttempt(r, token) || !pending.matches(code) || !h.consumePending(r, token, raw) {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid or expired code")
		return
	}
	session, ok := h.createPendingUser(w, pending)
	if !ok {
		h.restorePending(r, token, raw, pending)
		return
	}
	h.finishOTPSignIn(w, r, session.Id, pending.Channel, true, maxAge)
}

// finishOTPSignIn records the proven channel and answers with the session tokens.
func (h *OTPHandler) finishOTPSignIn(w http.ResponseWriter, r *http.Request, userID int, channel string, isNewUser bool, maxAge time.Duration) {
	if channel == otpChannelEmail {
		if err := h.UserService.MarkEmailVerified(userID, user.EmailVerifiedByCode); err != nil {
			h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to record verification")
			return
		}
	}
	session, err := h.UserService.GetUserById(userID)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to load user")
		return
	}
	if err := h.UserService.CheckSignInMethod(session.Id, user.SignInOTP); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	session.SignInMethod = user.SignInOTP
	session.SessionMaxAge = maxAge
	resp, err := h.SessionTokens(w, r, session)
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	resp["isNewUser"] = isNewUser
	common.WriteJSON(w, http.StatusOK, resp)
}

// ResendOTP regenerates the code behind an otpToken and sends it over the
// channel SendOTP used. The token's lifetime restarts so the user has the full
// window after a retry. Resends count against the send caps.
func (h *OTPHandler) ResendOTP(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		OTPToken string `json:"otpToken"`
	}
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.OTPToken == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "otpToken is required")
		return
	}
	userID, channel, purpose := h.resolveOTPToken(r, req.OTPToken)
	if userID <= 0 {
		if pending, _ := h.loadPending(r, req.OTPToken); pending != nil {
			h.resendPendingSignup(w, r, req.OTPToken, pending)
			return
		}
		// Same anti-enumeration shape as the login fall-through: pretend
		// success without dispatching.
		common.WriteJSON(w, http.StatusOK, map[string]string{"status": "otp_sent"})
		return
	}
	if purpose == "" {
		purpose = "login"
	}

	session, err := h.UserService.GetUserById(userID)
	if err != nil || session == nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to load user")
		return
	}
	contact := session.PhoneNumber
	if channel == otpChannelEmail {
		contact = session.Email
	}
	if contact == "" {
		contact = "user:" + strconv.Itoa(userID)
	}
	if !h.rateLimitOTP(w, r, contact) {
		return
	}

	if err := h.UserService.ClearOTP(userID); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to reset OTP")
		return
	}
	otp, err := h.UserService.GenerateOTP(userID, purpose)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to generate OTP")
		return
	}
	if h.Cache != nil {
		_ = h.Cache.Set(r.Context(), otpTokenPrefix+req.OTPToken, strconv.Itoa(userID)+":"+channel+":"+purpose, config.Config().OTPTokenTTL)
	}
	if channel == otpChannelEmail {
		if session.Email != "" {
			h.dispatchOTPEmail(r, userID, session.Email, otp)
		}
	} else {
		h.dispatchOTPSMS(r, userID, session.PhoneNumber, otp)
	}
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "otp_sent"})
}

// resendPendingSignup issues a fresh code for a pending registration.
func (h *OTPHandler) resendPendingSignup(w http.ResponseWriter, r *http.Request, token string, pending *otpPendingSignup) {
	if !h.rateLimitOTP(w, r, pending.Contact) {
		return
	}
	otp, err := user.NewOTPCode()
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to generate OTP")
		return
	}
	pending.setCode(otp)
	if err := h.storePending(r, token, pending); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to issue OTP token")
		return
	}
	h.dispatchOTP(r, 0, pending.Channel, pending.Contact, otp)
	common.WriteJSON(w, http.StatusOK, map[string]string{"status": "otp_sent"})
}
