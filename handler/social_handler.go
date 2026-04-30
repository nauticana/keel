package handler

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/user"
)

// JWKs cache lifetimes for Google and Apple. Keys rotate on the order of
// weeks; an hour is a comfortable refresh cadence. Both providers
// publish a discovery URL whose contents are stable byte-for-byte
// between rotations, so refreshing more often is just wasted bandwidth.
const (
	googleJWKsURL = "https://www.googleapis.com/oauth2/v3/certs"
	appleJWKsURL  = "https://appleid.apple.com/auth/keys"
	jwksCacheTTL  = time.Hour
	googleIssuer1 = "https://accounts.google.com"
	googleIssuer2 = "accounts.google.com"
	appleIssuer   = "https://appleid.apple.com"
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
		googleJWKs = newJWKsProvider(googleJWKsURL, jwksCacheTTL, common.HTTPClient())
	})
	return googleJWKs
}

func getAppleJWKs() *jwksProvider {
	appleJWKsOnce.Do(func() {
		appleJWKs = newJWKsProvider(appleJWKsURL, jwksCacheTTL, common.HTTPClient())
	})
	return appleJWKs
}

// SocialLoginHandler handles OAuth/social login (Google, Apple).
type SocialLoginHandler struct {
	AbstractHandler
}

// LoginSocial authenticates a user via a social provider ID token.
func (h *SocialLoginHandler) LoginSocial(w http.ResponseWriter, r *http.Request) {
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
	email, firstName, lastName, emailVerified, providerID, err := verifySocialToken(r.Context(), req.Provider, req.Token)
	if err != nil {
		// Don't echo the verifier's diagnostic — leaking "kid not found"
		// vs "exp expired" gives an attacker a usable signal.
		h.WriteError(w, http.StatusUnauthorized, "Unauthorized", "invalid social token")
		return
	}

	signupConsent := buildSignupConsent(r, &req)
	session, isNewUser, err := h.UserService.GetOrCreateUserFromSocial(email, firstName, lastName, "", req.Provider, providerID, emailVerified, signupConsent)
	if err != nil {
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

	token, err := h.UserService.CreateJWT(session)
	if err != nil {
		h.WriteError(w, http.StatusInternalServerError, "Internal Server Error", "failed to create token")
		return
	}

	common.WriteJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"userId":    session.Id,
		"partnerId": session.PartnerId,
		"isNewUser": isNewUser,
	})
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
		ClientIP:        TrustedClientIP(r),
		ClientUserAgent: r.UserAgent(),
		Consents:        req.Consents,
	}
}

// TrustedClientIP returns the caller's source IP, honoring
// X-Forwarded-For and X-Real-IP only when the inbound socket address
// is in the configured trusted-proxy CIDR set (--trusted_proxy_cidr).
// Without that gate, any client could spoof its own IP for rate-
// limiting and consent-audit purposes by setting either header. Empty
// CIDR config = trust nothing = always return RemoteAddr's host part.
//
// Exported so downstream consumers (consent capture, rate-limit keys,
// security event logs) can share keel's gated implementation instead
// of re-implementing a header-trusting clientIP and silently
// reintroducing the spoof vector. Use this helper anywhere you would
// otherwise reach for r.RemoteAddr / r.Header.Get("X-Forwarded-For").
//
// CIDR list is parsed once on first call and cached; subsequent calls
// are O(N) over the (typically very small) set of trusted ranges.
func TrustedClientIP(r *http.Request) string {
	remote := remoteHost(r.RemoteAddr)
	if !isTrustedProxy(remote) {
		return remote
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// XFF semantics: leftmost entry is the original client; right-
		// most is the closest proxy (= our peer). Prefer leftmost.
		if comma := strings.IndexByte(xff, ','); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	if real := r.Header.Get("X-Real-IP"); real != "" {
		return strings.TrimSpace(real)
	}
	return remote
}

// RequireTrustedProxyCIDR returns nil when --trusted_proxy_cidr is set
// to a CSV containing at least one parseable CIDR entry, and an error
// otherwise. Call it from main() after flag.Parse() in any deployment
// that mounts public, IP-attributing endpoints (keel's social-login,
// OTP, and register paths all write client_ip into consent_event).
//
// Without a populated CIDR list, every audit row attributes traffic
// to the LB / proxy peer IP; the spoof-gated TrustedClientIP refuses
// to promote XFF because nothing's trusted to forward, so it returns
// the peer. The empty-config default is intentionally retained at
// the library layer so unit tests, single-binary localhost
// deployments, and consumers that do not record IPs can still run
// unmodified — this helper is the production-required opt-in that
// turns the safe default into a deploy-time failure.
//
// Validation also rejects configs that look populated but parse to
// zero nets (typo'd entries, empty fields after splitting), since
// that's behaviorally identical to "empty" at runtime.
func RequireTrustedProxyCIDR() error {
	cfg := strings.TrimSpace(*common.TrustedProxyCIDR)
	if cfg == "" {
		return fmt.Errorf("--trusted_proxy_cidr must be set when mounting public IP-attributing endpoints; received empty value")
	}
	if len(getTrustedProxyNets(cfg)) == 0 {
		return fmt.Errorf("--trusted_proxy_cidr=%q parsed to zero valid CIDR entries", cfg)
	}
	return nil
}

// MustRequireTrustedProxyCIDR is the log.Fatalf-on-error wrapper
// around RequireTrustedProxyCIDR. Intended for direct use in main()
// right after flag.Parse() so a misconfigured production binary
// fails to start instead of silently mis-attributing every audit row.
func MustRequireTrustedProxyCIDR() {
	if err := RequireTrustedProxyCIDR(); err != nil {
		log.Fatalf("trusted-proxy config: %v", err)
	}
}

// remoteHost strips the port off a "host:port" RemoteAddr so callers
// see a bare IP. IPv6 addresses arrive with brackets ("[::1]:54321")
// which net.SplitHostPort handles transparently.
func remoteHost(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// trustedProxyState is a process-scoped cache of the parsed CIDR list.
// Re-parsed lazily when --trusted_proxy_cidr changes (rare; usually
// only at startup, but tests do swap flag values).
var (
	trustedProxyMu   sync.Mutex
	trustedProxyKey  string
	trustedProxyNets []*net.IPNet
)

// isTrustedProxy reports whether ipStr falls inside any configured
// trusted-proxy CIDR. Empty config returns false unconditionally.
func isTrustedProxy(ipStr string) bool {
	if ipStr == "" {
		return false
	}
	cfg := *common.TrustedProxyCIDR
	if cfg == "" {
		return false
	}
	nets := getTrustedProxyNets(cfg)
	if len(nets) == 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// getTrustedProxyNets returns the parsed CIDR set, re-parsing only when
// the flag value changes.
func getTrustedProxyNets(cfg string) []*net.IPNet {
	trustedProxyMu.Lock()
	defer trustedProxyMu.Unlock()
	if cfg == trustedProxyKey {
		return trustedProxyNets
	}
	var nets []*net.IPNet
	for _, raw := range strings.Split(cfg, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(raw); err == nil && n != nil {
			nets = append(nets, n)
		}
	}
	trustedProxyKey = cfg
	trustedProxyNets = nets
	return nets
}

// verifySocialToken validates the provider's ID token signature against
// the provider's published JWKs, asserts iss/aud/exp, and extracts the
// claims callers need. Returns email, given/family names, the verified
// flag, and the stable subject (sub claim) used as the provider id.
//
// Both Google and Apple emit RS256 ID tokens. We pin that algorithm and
// reject any other (notably "none") at verifyJWKsToken's parser level.
//
// Callers MUST honor emailVerified — linking on an unverified
// provider-asserted email is the standard account-takeover vector for
// misconfigured OAuth clients.
func verifySocialToken(ctx context.Context, provider, token string) (email, firstName, lastName string, emailVerified bool, providerID string, err error) {
	switch provider {
	case "google":
		return verifyGoogleToken(ctx, token)
	case "apple":
		return verifyAppleToken(ctx, token)
	default:
		return "", "", "", false, "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

// verifyGoogleToken verifies a Google-issued ID token against Google's
// JWKs (`https://www.googleapis.com/oauth2/v3/certs`), enforces aud =
// configured GoogleClientID and iss = "accounts.google.com" or
// "https://accounts.google.com" (Google publishes both forms).
//
// Google's email_verified claim arrives as either a JSON bool or a
// JSON string; both shapes are accepted.
func verifyGoogleToken(ctx context.Context, token string) (email, firstName, lastName string, emailVerified bool, providerID string, err error) {
	aud := *common.GoogleClientID
	if aud == "" {
		return "", "", "", false, "", fmt.Errorf("google_client_id is not configured")
	}
	claims, err := verifyJWKsToken(ctx, getGoogleJWKs(), token, aud, "")
	if err != nil {
		return "", "", "", false, "", err
	}
	iss, _ := claims["iss"].(string)
	if iss != googleIssuer1 && iss != googleIssuer2 {
		return "", "", "", false, "", fmt.Errorf("google: unexpected issuer %q", iss)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", "", "", false, "", fmt.Errorf("google: missing sub")
	}
	emailStr, _ := claims["email"].(string)
	firstName, _ = claims["given_name"].(string)
	lastName, _ = claims["family_name"].(string)
	switch v := claims["email_verified"].(type) {
	case bool:
		emailVerified = v
	case string:
		emailVerified = v == "true"
	}
	return emailStr, firstName, lastName, emailVerified, sub, nil
}

// verifyAppleToken verifies an Apple-issued ID token against Apple's
// JWKs (`https://appleid.apple.com/auth/keys`), enforces iss =
// "https://appleid.apple.com" and aud = configured AppleClientID. Apple
// omits given/family name claims entirely after the first sign-in, so
// firstName/lastName are returned empty when absent.
//
// For "Hide My Email" relay addresses (*@privaterelay.appleid.com)
// Apple still sets email_verified=true, but those addresses must not be
// used to link to existing password-account emails. That policy lives
// in GetOrCreateUserFromSocial.
func verifyAppleToken(ctx context.Context, token string) (email, firstName, lastName string, emailVerified bool, providerID string, err error) {
	aud := *common.AppleClientID
	if aud == "" {
		return "", "", "", false, "", fmt.Errorf("apple_client_id is not configured")
	}
	claims, err := verifyJWKsToken(ctx, getAppleJWKs(), token, aud, appleIssuer)
	if err != nil {
		return "", "", "", false, "", err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", "", "", false, "", fmt.Errorf("apple: missing sub")
	}
	emailStr, _ := claims["email"].(string)
	switch v := claims["email_verified"].(type) {
	case bool:
		emailVerified = v
	case string:
		emailVerified = v == "true"
	}
	return emailStr, "", "", emailVerified, sub, nil
}
