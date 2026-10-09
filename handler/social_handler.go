package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/oauth/oidc"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

const socialNonceKey = "social_nonce:"

func init() {
	RegisterErrorCode(user.ErrIdentityNotLinked, http.StatusConflict, "identity_not_linked")
	RegisterErrorCode(user.ErrIdentityLinked, http.StatusConflict, "identity_linked")
	RegisterErrorCode(user.ErrAccountUnavailable, http.StatusForbidden, "account_unavailable")
	RegisterErrorCode(user.ErrSSORequired, http.StatusForbidden, "sso_required")
	RegisterErrorCode(oidc.ErrProviderDisabled, http.StatusBadRequest, "provider_not_enabled")
}

// SocialLoginHandler handles OAuth/social login (Google, Apple).
type SocialLoginHandler struct {
	AbstractHandler
	// NonceCache, when set, turns on single-use nonce binding: a GET issues,
	// the POST login requires + consumes. Nil = nonce check off.
	NonceCache cache.CacheService
	// Verifier checks Google and Apple ID tokens; nil uses their published keys.
	Verifier *oidc.SocialVerifier
	// Apple, when set, requires an Apple sign-in or link to carry the
	// authorization code and keeps the grant it redeems, so account deletion
	// can revoke it.
	Apple *oidc.AppleGrants
}

// LoginSocial verifies a social provider ID token (POST). A GET on the same
// route issues the single-use nonce that token must carry — reusing the one
// route so no extra application signature has to be registered downstream.
func (h *SocialLoginHandler) LoginSocial(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.issueSocialNonce(w, r)
		return
	}
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req socialLoginRequest
	if !h.ReadRequest(w, r, &req) {
		return
	}
	if req.Provider == "" || req.Token == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "provider and token are required")
		return
	}
	maxAge, err := req.MaxAge()
	if err != nil {
		h.WriteServiceError(w, r, err)
		return
	}

	identity, nonce, err := h.verifySocialToken(r.Context(), req.Provider, req.Token)
	if errors.Is(err, oidc.ErrProviderDisabled) {
		h.WriteServiceError(w, r, oidc.ErrProviderDisabled)
		return
	}
	if err != nil {
		// Don't echo the verifier's diagnostic — leaking "kid not found"
		// vs "exp expired" gives an attacker a usable signal.
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid social token")
		return
	}
	// Replay/impersonation guard: the id_token must carry a nonce we issued
	// and have not yet seen. Same opaque 401 on failure as a bad signature.
	if h.NonceCache != nil && !h.consumeSocialNonce(r.Context(), nonce) {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid social token")
		return
	}
	if !h.redeemAppleGrant(w, r, &identity, req.Code) {
		return
	}

	signupConsent := buildSignupConsent(r, &req)
	session, isNewUser, err := h.UserService.GetOrCreateUserFromSocial(identity, signupConsent)
	if err != nil {
		if mapped := socialSignInError(err); mapped != nil {
			h.WriteServiceError(w, r, mapped)
			return
		}
		// A non-nil session with a non-nil error signals the user WAS created
		// but consent recording failed — surface a specific status so the
		// caller can re-submit consent rather than re-creating the account.
		if session != nil {
			h.WriteError(w, http.StatusFailedDependency, "Consent Not Recorded", err.Error())
			return
		}
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to create user")
		return
	}

	if !h.admitExternalSignIn(w, r, session, identity) {
		return
	}
	session.SessionMaxAge = maxAge
	resp, err := h.SessionTokens(session)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to create token")
		return
	}
	resp["isNewUser"] = isNewUser
	common.WriteJSON(w, http.StatusOK, resp)
}

// LinkSocial links a provider identity to the signed-in account (POST). The
// caller re-enters a password or current 2FA code and presents a fresh ID
// token carrying a nonce from GET on LoginSocial's route.
func (h *SocialLoginHandler) LinkSocial(w http.ResponseWriter, r *http.Request) {
	if !h.RequireMethod(w, r, http.MethodPost) {
		return
	}
	var req struct {
		Provider string `json:"provider"`
		Token    string `json:"token"`
		Code     string `json:"code,omitempty"`
		RecentAuth
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if !h.RequireFields(w, map[string]string{"provider": req.Provider, "token": req.Token}) {
		return
	}
	if !h.requireRecentAuth(w, r, session, req.RecentAuth) {
		return
	}
	identity, nonce, err := h.verifySocialToken(r.Context(), req.Provider, req.Token)
	if err != nil || (h.NonceCache != nil && !h.consumeSocialNonce(r.Context(), nonce)) {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid social token")
		return
	}
	if !h.redeemAppleGrant(w, r, &identity, req.Code) {
		return
	}
	if err := h.UserService.LinkExternalIdentity(session.Id, identity); err != nil {
		h.WriteServiceError(w, r, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"linked": identity.Provider})
}

// issueSocialNonce returns a single-use nonce the client feeds to the provider
// SDK; the POST login then requires it back inside the signed id_token — the
// state-parameter equivalent for the id_token flow. Nil cache ⇒ empty ⇒ off.
func (h *SocialLoginHandler) issueSocialNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store") // single-use — never let an edge cache it
	if h.NonceCache == nil {
		common.WriteJSON(w, http.StatusOK, map[string]any{"nonce": ""})
		return
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to generate nonce")
		return
	}
	nonce := hex.EncodeToString(b)
	// Store -1 so the first consume's INCR yields exactly 0; a never-issued nonce
	// starts absent (INCR → 1) and can never reach 0, closing the replay/guess gap.
	if err := h.NonceCache.Set(r.Context(), socialNonceKey+nonce, "-1", config.Config().SocialNonceTTL); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to store nonce")
		return
	}
	// Google echoes the raw nonce in the id_token, Apple its SHA-256 — store
	// both keys so LoginSocial matches whichever the provider returns.
	sum := sha256.Sum256([]byte(nonce))
	if err := h.NonceCache.Set(r.Context(), socialNonceKey+hex.EncodeToString(sum[:]), "-1", config.Config().SocialNonceTTL); err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to store nonce")
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{"nonce": nonce})
}

// consumeSocialNonce atomically claims a previously-issued nonce, returning true
// only for the first caller. The issued key holds -1, so the first INCR yields 0
// (valid) and every later INCR is ≥1 (replay); a never-issued nonce starts absent
// (INCR → 1) and never yields 0. The atomic increment closes the check-then-delete
// race and the second-submission-of-an-unknown-nonce bypass.
func (h *SocialLoginHandler) consumeSocialNonce(ctx context.Context, nonce string) bool {
	if nonce == "" {
		return false
	}
	n, err := h.NonceCache.IncrementWithTTL(ctx, socialNonceKey+nonce, config.Config().SocialNonceTTL)
	return err == nil && n == 0
}

// socialLoginRequest is the JSON body accepted by LoginSocial. Consent
// fields are optional; when the server has a ConsentService registered and
// `consents` is non-empty, the new-user branch records each entry in
// consent_event. `consents` is ignored on re-auth of an existing user.
type socialLoginRequest struct {
	Provider       string          `json:"provider"`       // google, apple
	Token          string          `json:"token"`          // ID token from the provider
	Code           string          `json:"code,omitempty"` // Apple authorization code
	PolicyType     string          `json:"policyType,omitempty"`
	PolicyVersion  string          `json:"policyVersion,omitempty"`
	PolicyRegion   string          `json:"policyRegion,omitempty"`
	PolicyLanguage string          `json:"policyLanguage,omitempty"`
	Region         string          `json:"region,omitempty"`
	Consents       map[string]bool `json:"consents,omitempty"`
	SessionLimit
}

// buildSignupConsent turns the optional consent fields on the request plus
// the HTTP request's client metadata (IP, user-agent) into a SignupConsent
// the service layer can pass to a registered ConsentService. Returns nil
// when the caller sent no consent fields — signals "skip consent capture".
func buildSignupConsent(r *http.Request, req *socialLoginRequest) *user.SignupConsent {
	if len(req.Consents) == 0 && req.PolicyVersion == "" {
		return nil
	}
	return &user.SignupConsent{
		PolicyType:      req.PolicyType,
		PolicyVersion:   req.PolicyVersion,
		PolicyRegion:    req.PolicyRegion,
		PolicyLanguage:  req.PolicyLanguage,
		Region:          req.Region,
		ClientIP:        common.TrustedClientIP(r),
		ClientUserAgent: r.UserAgent(),
		Consents:        req.Consents,
	}
}

// verifySocialToken verifies a Google or Apple ID token and returns the
// identity and the token's nonce.
func (h *SocialLoginHandler) verifySocialToken(ctx context.Context, provider, token string) (user.ExternalIdentity, string, error) {
	verifier := h.Verifier
	if verifier == nil {
		verifier = &oidc.SocialVerifier{}
	}
	a, nonce, err := verifier.Verify(ctx, provider, token)
	if err != nil {
		return user.ExternalIdentity{}, "", err
	}
	return socialIdentity(provider, a), nonce, nil
}

// redeemAppleGrant attaches the sealed grant of an Apple identity's code when
// Apple is set; it writes the refusal and returns false otherwise.
func (h *SocialLoginHandler) redeemAppleGrant(w http.ResponseWriter, r *http.Request, identity *user.ExternalIdentity, code string) bool {
	if h.Apple == nil || identity.Provider != oidc.ProviderApple {
		return true
	}
	if code == "" {
		h.WriteError(w, http.StatusBadRequest, "Bad Request", "code is required for apple")
		return false
	}
	sealed, err := h.Apple.Redeem(r.Context(), code, identity.Subject)
	var refused *oidc.TokenError
	if errors.As(err, &refused) || errors.Is(err, oidc.ErrInvalidResponse) {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid social token")
		return false
	}
	if err != nil {
		h.WriteServiceError(w, r, err)
		return false
	}
	identity.Grant = sealed
	return true
}

// socialIdentity maps a first-party assertion; only Google carries names and
// a hosted domain in its token.
func socialIdentity(provider string, a *port.IdentityAssertion) user.ExternalIdentity {
	id := user.ExternalIdentity{Provider: provider, Issuer: a.Issuer, Subject: a.Subject, Email: a.Email, EmailVerified: a.EmailVerified}
	if provider == oidc.ProviderGoogle {
		id.FirstName, id.LastName, id.HostedDomain = a.GivenName, a.FamilyName, a.HostedDomain
	}
	return id
}

// socialSignInError keeps the sign-in refusals a client can act on; other
// failures stay internal.
func socialSignInError(err error) error {
	for _, sentinel := range []error{user.ErrIdentityNotLinked, user.ErrAccountUnavailable, user.ErrIdentityLinked} {
		if errors.Is(err, sentinel) {
			return sentinel
		}
	}
	return nil
}
