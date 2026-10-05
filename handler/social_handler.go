package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/crypto"
	"github.com/nauticana/keel/user"
)

// JWKs cache lifetimes for Google and Apple. Keys rotate on the order of
// weeks; an hour is a comfortable refresh cadence. Both providers
// publish a discovery URL whose contents are stable byte-for-byte
// between rotations, so refreshing more often is just wasted bandwidth.
const (
	googleJWKsURL = "https://www.googleapis.com/oauth2/v3/certs"
	appleJWKsURL  = "https://appleid.apple.com/auth/keys"
	googleIssuer1 = user.GoogleIssuer
	googleIssuer2 = "accounts.google.com"
	appleIssuer   = user.AppleIssuer

	socialNonceKey = "social_nonce:"
)

// Lazy package-scoped JWKs providers. Constructed on first use so the
// fixed http.Client timeout doesn't fight with test setups that swap
// http.DefaultClient.
var (
	googleJWKsOnce sync.Once
	googleJWKs     *jwksProvider
	appleJWKsOnce  sync.Once
	appleJWKs      *jwksProvider
)

func getGoogleJWKs() *jwksProvider {
	googleJWKsOnce.Do(func() {
		googleJWKs = newJWKsProvider(googleJWKsURL, config.Config().SocialJWKSCacheTTL, common.HTTPClient())
	})
	return googleJWKs
}

func getAppleJWKs() *jwksProvider {
	appleJWKsOnce.Do(func() {
		appleJWKs = newJWKsProvider(appleJWKsURL, config.Config().SocialJWKSCacheTTL, common.HTTPClient())
	})
	return appleJWKs
}

func init() {
	RegisterErrorCode(user.ErrIdentityNotLinked, http.StatusConflict, "identity_not_linked")
	RegisterErrorCode(user.ErrIdentityLinked, http.StatusConflict, "identity_linked")
	RegisterErrorCode(user.ErrAccountUnavailable, http.StatusForbidden, "account_unavailable")
	RegisterErrorCode(user.ErrSSORequired, http.StatusForbidden, "sso_required")
	RegisterErrorCode(errProviderDisabled, http.StatusBadRequest, "provider_not_enabled")
}

// SocialLoginHandler handles OAuth/social login (Google, Apple).
type SocialLoginHandler struct {
	AbstractHandler
	// NonceCache, when set, turns on single-use nonce binding: a GET issues,
	// the POST login requires + consumes. Nil = nonce check off.
	NonceCache cache.CacheService
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

	// Verify token signature against the provider's JWKs and extract
	// claims. Both providers issue RS256 ID tokens; keel pins that
	// algorithm and rejects everything else.
	identity, nonce, err := verifySocialToken(r.Context(), req.Provider, req.Token)
	if errors.Is(err, errProviderDisabled) {
		h.WriteServiceError(w, r, errProviderDisabled)
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
		Provider      string `json:"provider"`
		Token         string `json:"token"`
		Password      string `json:"password"`
		TwoFactorCode string `json:"twoFactorCode"`
	}
	session, ok := h.ReadAuthRequest(w, r, &req)
	if !ok {
		return
	}
	if !h.RequireFields(w, map[string]string{"provider": req.Provider, "token": req.Token}) {
		return
	}
	if !h.requireRecentAuth(w, session, req.Password, req.TwoFactorCode) {
		return
	}
	identity, nonce, err := verifySocialToken(r.Context(), req.Provider, req.Token)
	if err != nil || (h.NonceCache != nil && !h.consumeSocialNonce(r.Context(), nonce)) {
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid social token")
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
	Provider       string          `json:"provider"` // google, apple
	Token          string          `json:"token"`    // ID token from the provider
	PolicyType     string          `json:"policyType,omitempty"`
	PolicyVersion  string          `json:"policyVersion,omitempty"`
	PolicyRegion   string          `json:"policyRegion,omitempty"`
	PolicyLanguage string          `json:"policyLanguage,omitempty"`
	Region         string          `json:"region,omitempty"`
	Consents       map[string]bool `json:"consents,omitempty"`
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

// errProviderDisabled: the provider has no client id configured. A provider
// is enabled by setting google_client_id or apple_client_id, application-wide
// or per node.
var errProviderDisabled = errors.New("sign-in provider is not enabled")

// verifySocialToken validates the provider's RS256 ID token against its JWKs,
// asserts iss/aud/exp, and returns the identity and the token's nonce.
func verifySocialToken(ctx context.Context, provider, token string) (user.ExternalIdentity, string, error) {
	switch provider {
	case "google":
		return verifyGoogleToken(ctx, token)
	case "apple":
		return verifyAppleToken(ctx, token)
	default:
		return user.ExternalIdentity{}, "", errProviderDisabled
	}
}

// verifyGoogleToken accepts either published Google issuer form and the
// configured google_client_id audience.
func verifyGoogleToken(ctx context.Context, token string) (user.ExternalIdentity, string, error) {
	aud := config.Config().GoogleClientID
	if aud == "" {
		return user.ExternalIdentity{}, "", errProviderDisabled
	}
	claims, err := crypto.VerifyRS256(ctx, getGoogleJWKs(), token, aud, "")
	if err != nil {
		return user.ExternalIdentity{}, "", err
	}
	iss, _ := claims["iss"].(string)
	if iss != googleIssuer1 && iss != googleIssuer2 {
		return user.ExternalIdentity{}, "", fmt.Errorf("google: unexpected issuer %q", iss)
	}
	id := identityFromClaims("google", googleIssuer1, claims)
	if id.Subject == "" {
		return user.ExternalIdentity{}, "", fmt.Errorf("google: missing sub")
	}
	id.FirstName, _ = claims["given_name"].(string)
	id.LastName, _ = claims["family_name"].(string)
	id.HostedDomain, _ = claims["hd"].(string)
	nonce, _ := claims["nonce"].(string)
	return id, nonce, nil
}

// verifyAppleToken requires the Apple issuer and apple_client_id audience.
// Apple sends names only on the first sign-in, and never in the token.
func verifyAppleToken(ctx context.Context, token string) (user.ExternalIdentity, string, error) {
	aud := config.Config().AppleClientID
	if aud == "" {
		return user.ExternalIdentity{}, "", errProviderDisabled
	}
	claims, err := crypto.VerifyRS256(ctx, getAppleJWKs(), token, aud, appleIssuer)
	if err != nil {
		return user.ExternalIdentity{}, "", err
	}
	id := identityFromClaims("apple", appleIssuer, claims)
	if id.Subject == "" {
		return user.ExternalIdentity{}, "", fmt.Errorf("apple: missing sub")
	}
	nonce, _ := claims["nonce"].(string)
	return id, nonce, nil
}

// identityFromClaims reads sub, email and email_verified, which providers send
// as a JSON bool or string.
func identityFromClaims(provider, issuer string, claims map[string]any) user.ExternalIdentity {
	id := user.ExternalIdentity{Provider: provider, Issuer: issuer}
	id.Subject, _ = claims["sub"].(string)
	id.Email, _ = claims["email"].(string)
	switch v := claims["email_verified"].(type) {
	case bool:
		id.EmailVerified = v
	case string:
		id.EmailVerified = v == "true"
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
