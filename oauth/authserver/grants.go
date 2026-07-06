package authserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/nauticana/keel/oauth/claims"
	"github.com/nauticana/keel/port"
)

// oauthIssuer mints RS256 access tokens (and, when asked, a rotating refresh
// token) — shared by the grant handlers.
type oauthIssuer struct {
	signer          port.TokenSigner
	tokens          port.OAuthTokenStore
	issuer          string
	defaultAud      string
	supportedScopes []string // AS-advertised scopes; the hard upper bound on any grant
	resources       []string // valid RFC 8707 resource indicators (token audiences)
	accessTTL       time.Duration
	refreshTTL      time.Duration
}

// clientGrantable is the client's effective scope ceiling: its registered scopes
// clamped to the AS-supported set (or, when it registered none, the AS-supported
// set). Always ⊆ AS-supported when the AS declares any — so a client that
// registered an unsupported scope (e.g. admin) can never have it granted.
func (i *oauthIssuer) clientGrantable(clientScopes []string) []string {
	if len(clientScopes) == 0 {
		return i.supportedScopes
	}
	if len(i.supportedScopes) == 0 {
		return clientScopes
	}
	return intersect(clientScopes, i.supportedScopes)
}

// boundScopes returns the granted scopes or an error. An omitted request
// defaults to the client's grantable ceiling (already clamped to AS-supported);
// an explicit request must be a subset of that ceiling.
func (i *oauthIssuer) boundScopes(requested, clientScopes []string) ([]string, error) {
	grantable := i.clientGrantable(clientScopes)
	if len(requested) == 0 {
		return grantable, nil
	}
	if !isSubset(requested, grantable) {
		return nil, ErrOAuthInvalidScope
	}
	return requested, nil
}

// issue mints an access token and optionally a refresh token. familyID empty
// starts a new rotation family; a non-empty familyID continues one (refresh).
func (i *oauthIssuer) issue(ctx context.Context, sub string, userID, partnerID int64, clientID string, scopes []string, resource, familyID, rotateFromHash string, withRefresh bool) (*port.TokenResponse, error) {
	now := time.Now()
	if resource != "" && !slices.Contains(i.resources, resource) {
		return nil, ErrOAuthInvalidTarget
	}
	aud := resource
	if aud == "" {
		aud = i.defaultAud
	}
	claimSet := map[string]any{
		"iss":       i.issuer,
		"sub":       sub,
		"aud":       aud,
		"iat":       now.Unix(),
		"exp":       now.Add(i.accessTTL).Unix(),
		"scope":     strings.Join(scopes, " "),
		"client_id": clientID,
	}
	if partnerID > 0 {
		claimSet["partner_id"] = partnerID
	}
	access, err := i.signer.Sign(ctx, claimSet)
	if err != nil {
		return nil, err
	}
	resp := &port.TokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(i.accessTTL.Seconds()),
		Scope:       strings.Join(scopes, " "),
	}
	if withRefresh {
		raw, err := randToken()
		if err != nil {
			return nil, err
		}
		fam := familyID
		if fam == "" {
			fam, err = randToken()
			if err != nil {
				return nil, err
			}
		}
		rt := &port.RefreshToken{
			TokenHash: hashToken(raw),
			FamilyID:  fam,
			ClientID:  clientID,
			UserID:    userID,
			PartnerID: partnerID,
			Scopes:    scopes,
			Resource:  resource,
			ExpiresAt: now.Add(i.refreshTTL),
		}
		if rotateFromHash != "" {
			if err := i.tokens.Rotate(ctx, rotateFromHash, rt); err != nil {
				return nil, err
			}
		} else if err := i.tokens.SaveRefreshToken(ctx, rt); err != nil {
			return nil, err
		}
		resp.RefreshToken = raw
	}
	return resp, nil
}

// verifyPKCE checks an RFC 7636 S256 challenge. OAuth 2.1 forbids "plain".
func verifyPKCE(verifier, challenge, method string) bool {
	if method != "S256" || verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

// authorizationCodeGrant — RFC 6749 §4.1 with mandatory PKCE.
type authorizationCodeGrant struct {
	clients port.OAuthClientStore
	codes   port.AuthCodeStore
	issuer  *oauthIssuer
}

func (g *authorizationCodeGrant) GrantType() string { return "authorization_code" }

func (g *authorizationCodeGrant) Handle(ctx context.Context, req port.TokenRequest, client *port.OAuthClient) (*port.TokenResponse, error) {
	if req.Code == "" || req.CodeVerifier == "" {
		return nil, ErrOAuthInvalidRequest
	}
	code, err := g.codes.ConsumeCode(ctx, req.Code)
	if err != nil {
		return nil, err
	}
	if code == nil || code.ClientID != client.ClientID {
		return nil, ErrOAuthInvalidGrant
	}
	if code.RedirectURI != req.RedirectURI {
		return nil, ErrOAuthInvalidGrant
	}
	if !verifyPKCE(req.CodeVerifier, code.CodeChallenge, code.CodeChallengeMethod) {
		return nil, ErrOAuthInvalidGrant
	}
	sub := subjectForUser(code.UserID)
	// Only mint a refresh token if the client registered the refresh_token grant.
	withRefresh := slices.Contains(client.GrantTypes, "refresh_token")
	return g.issuer.issue(ctx, sub, code.UserID, code.PartnerID, client.ClientID, code.Scopes, code.Resource, "", "", withRefresh)
}

// refreshTokenGrant — RFC 6749 §6 with rotation + reuse-detection.
type refreshTokenGrant struct {
	tokens port.OAuthTokenStore
	issuer *oauthIssuer
}

func (g *refreshTokenGrant) GrantType() string { return "refresh_token" }

func (g *refreshTokenGrant) Handle(ctx context.Context, req port.TokenRequest, client *port.OAuthClient) (*port.TokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, ErrOAuthInvalidRequest
	}
	stored, err := g.tokens.GetRefreshToken(ctx, hashToken(req.RefreshToken))
	if err != nil {
		return nil, err
	}
	if stored == nil || stored.ClientID != client.ClientID {
		return nil, ErrOAuthInvalidGrant
	}
	// Replay of an already-rotated token → revoke the whole family. A failed revoke
	// leaves the stolen chain valid, so surface it rather than swallow it.
	if stored.RevokedAt != nil {
		if err := g.tokens.RevokeFamily(ctx, stored.FamilyID); err != nil {
			return nil, err
		}
		return nil, ErrOAuthInvalidGrant
	}
	if time.Now().After(stored.ExpiresAt) {
		return nil, ErrOAuthInvalidGrant
	}
	scopes := stored.Scopes
	if len(req.Scopes) > 0 { // narrowing only
		if !isSubset(req.Scopes, stored.Scopes) {
			return nil, ErrOAuthInvalidScope
		}
		scopes = req.Scopes
	}
	// Atomic rotate: the consume inside Rotate is the single-use gate. If it
	// finds no active row we lost the race (concurrent refresh or replay) →
	// treat as reuse and kill the whole family.
	resp, err := g.issuer.issue(ctx, subjectForUser(stored.UserID), stored.UserID, stored.PartnerID, client.ClientID, scopes, stored.Resource, stored.FamilyID, stored.TokenHash, true)
	if errors.Is(err, errRefreshConsumed) {
		// Lost the rotation race → reuse: kill the family, surfacing a failed revoke
		// rather than swallowing it (a stale chain must not stay valid).
		if rerr := g.tokens.RevokeFamily(ctx, stored.FamilyID); rerr != nil {
			return nil, rerr
		}
		return nil, ErrOAuthInvalidGrant
	}
	return resp, err
}

// clientCredentialsGrant — RFC 6749 §4.4. Confidential clients only, no user,
// no refresh token (per spec).
type clientCredentialsGrant struct {
	issuer *oauthIssuer
}

func (g *clientCredentialsGrant) GrantType() string { return "client_credentials" }

func (g *clientCredentialsGrant) Handle(ctx context.Context, req port.TokenRequest, client *port.OAuthClient) (*port.TokenResponse, error) {
	if client.TokenAuthMethod == "none" {
		return nil, ErrOAuthInvalidClient // public clients can't use this grant
	}
	// A machine token carries no user consent, so — unlike the interactive
	// grants — it must NOT fall back to the full AS-supported set when the
	// client registered no scopes. Bound strictly to the client's registered
	// scopes (∩ AS-supported); a scopeless client gets a scopeless token.
	grantable := client.Scopes
	if len(g.issuer.supportedScopes) > 0 {
		grantable = intersect(client.Scopes, g.issuer.supportedScopes)
	}
	requested := req.Scopes
	if len(requested) == 0 {
		requested = grantable
	}
	if !isSubset(requested, grantable) {
		return nil, ErrOAuthInvalidScope
	}
	return g.issuer.issue(ctx, "client:"+client.ClientID, 0, 0, client.ClientID, requested, req.Resource, "", "", false)
}

// tokenExchangeGrant — RFC 8693, restricted to exchanging an access token this
// AS issued for a (possibly narrowed) token at another resource. No refresh.
type tokenExchangeGrant struct {
	validator port.TokenValidator
	issuer    *oauthIssuer
}

func (g *tokenExchangeGrant) GrantType() string {
	return "urn:ietf:params:oauth:grant-type:token-exchange"
}

// tokenTypeAccessToken is the only subject_token_type this grant exchanges (RFC 8693).
const tokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

func (g *tokenExchangeGrant) Handle(ctx context.Context, req port.TokenRequest, client *port.OAuthClient) (*port.TokenResponse, error) {
	if req.SubjectToken == "" || req.SubjectTokenType != tokenTypeAccessToken {
		return nil, ErrOAuthInvalidRequest
	}
	principal, err := g.validator.Validate(ctx, req.SubjectToken)
	if err != nil {
		return nil, ErrOAuthInvalidGrant
	}
	requested := req.Scopes
	if len(requested) == 0 {
		requested = principal.Scopes
	}
	// Bound by BOTH the subject token (no amplification) and the exchanging
	// client's own ceiling (registered scopes ∩ AS-supported) — a low-scope
	// client holding a high-scope subject token can't exchange up.
	if !isSubset(requested, principal.Scopes) || !isSubset(requested, g.issuer.clientGrantable(client.Scopes)) {
		return nil, ErrOAuthInvalidScope
	}
	partnerID := claims.Int64(principal.Claims["partner_id"])
	return g.issuer.issue(ctx, principal.Subject, 0, partnerID, client.ClientID, requested, req.Resource, "", "", false)
}

func isSubset(want, have []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}

// intersect returns the elements of a that also appear in b (order of a).
func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	var out []string
	for _, s := range a {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return out
}
