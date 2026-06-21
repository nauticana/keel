package oauth

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/port"
)

// OAuth AS endpoint paths (advertised in RFC 8414 metadata, mounted by the HTTP layer).
const (
	OAuthASMetadataPath = "/.well-known/oauth-authorization-server" // RFC 8414
	OAuthAuthorizePath  = "/oauth/authorize"
	OAuthTokenPath      = "/oauth/token"
	OAuthRegisterPath   = "/oauth/register"
	OAuthRevokePath     = "/oauth/revoke"
	OAuthIntrospectPath = "/oauth/introspect"
	OAuthJWKSPath       = "/oauth/jwks"
)

// OAuth error sentinels; Error() is the RFC 6749 error code the endpoints return.
type oauthErr string

func (e oauthErr) Error() string { return string(e) }

const (
	ErrOAuthInvalidRequest     = oauthErr("invalid_request")
	ErrOAuthInvalidClient      = oauthErr("invalid_client")
	ErrOAuthInvalidGrant       = oauthErr("invalid_grant")
	ErrOAuthUnsupportedGrant   = oauthErr("unsupported_grant_type")
	ErrOAuthUnauthorizedClient = oauthErr("unauthorized_client")
	ErrOAuthInvalidScope       = oauthErr("invalid_scope")
	ErrOAuthInvalidTarget      = oauthErr("invalid_target")
	ErrOAuthAccessDenied       = oauthErr("access_denied")
)

func subjectForUser(userID int64) string { return "user:" + strconv.FormatInt(userID, 10) }

// OAuthASConfig holds the local AS's non-secret settings.
type OAuthASConfig struct {
	Issuer          string // public base URL of this AS (also the token iss)
	DefaultAudience string
	Scopes          []string // AS-supported scopes; the upper bound on any grant
	Resources       []string // extra valid RFC 8707 resource indicators (DefaultAudience is always valid)
	AccessTTL       time.Duration
	RefreshTTL      time.Duration
	CodeTTL         time.Duration
}

// AuthorizationServerLocal is keel's local OAuth 2.1 authorization server.
type AuthorizationServerLocal struct {
	clients   port.OAuthClientStore
	codes     port.AuthCodeStore
	tokens    port.OAuthTokenStore
	signer    port.TokenSigner
	validator port.TokenValidator
	issuer    *oauthIssuer
	grants    map[string]port.GrantHandler
	cfg       OAuthASConfig
}

var _ port.AuthorizationServer = (*AuthorizationServerLocal)(nil)

func NewAuthorizationServerLocal(signer *RS256Signer, clients port.OAuthClientStore, codes port.AuthCodeStore, tokens port.OAuthTokenStore, cfg OAuthASConfig) *AuthorizationServerLocal {
	resources := []string{cfg.DefaultAudience}
	for _, r := range cfg.Resources {
		if r != "" && !contains(resources, r) {
			resources = append(resources, r)
		}
	}
	iss := &oauthIssuer{
		signer:          signer,
		tokens:          tokens,
		issuer:          cfg.Issuer,
		defaultAud:      cfg.DefaultAudience,
		supportedScopes: cfg.Scopes,
		resources:       resources,
		accessTTL:       cfg.AccessTTL,
		refreshTTL:      cfg.RefreshTTL,
	}
	// AS-internal validator accepts a token minted for ANY configured resource,
	// so introspection and token-exchange work across all of them (not just the
	// default audience).
	internal := NewLocalJWTValidatorMulti(signer, cfg.Issuer, resources)
	as := &AuthorizationServerLocal{
		clients: clients, codes: codes, tokens: tokens, signer: signer,
		validator: internal, issuer: iss, cfg: cfg,
		grants: map[string]port.GrantHandler{},
	}
	for _, g := range []port.GrantHandler{
		&authorizationCodeGrant{clients: clients, codes: codes, issuer: iss},
		&refreshTokenGrant{tokens: tokens, issuer: iss},
		&clientCredentialsGrant{issuer: iss},
		&tokenExchangeGrant{validator: internal, issuer: iss},
	} {
		as.grants[g.GrantType()] = g
	}
	return as
}

func (a *AuthorizationServerLocal) Metadata() port.AuthServerMetadata {
	base := strings.TrimRight(a.cfg.Issuer, "/")
	grants := make([]string, 0, len(a.grants))
	for gt := range a.grants {
		grants = append(grants, gt)
	}
	return port.AuthServerMetadata{
		Issuer:                            base,
		AuthorizationEndpoint:             base + OAuthAuthorizePath,
		TokenEndpoint:                     base + OAuthTokenPath,
		RegistrationEndpoint:              base + OAuthRegisterPath,
		RevocationEndpoint:                base + OAuthRevokePath,
		IntrospectionEndpoint:             base + OAuthIntrospectPath,
		JWKSURI:                           base + OAuthJWKSPath,
		ScopesSupported:                   a.cfg.Scopes,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               grants,
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_basic", "client_secret_post"},
	}
}

func (a *AuthorizationServerLocal) JWKS() port.JWKS { return a.signer.JWKS() }

func (a *AuthorizationServerLocal) Register(ctx context.Context, req port.ClientRegistration) (*port.OAuthClient, error) {
	if len(req.RedirectURIs) == 0 {
		return nil, ErrOAuthInvalidRequest
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			return nil, ErrOAuthInvalidRequest
		}
	}
	grants := req.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code", "refresh_token"}
	}
	for _, gt := range grants {
		if _, ok := a.grants[gt]; !ok {
			return nil, ErrOAuthInvalidRequest // don't persist a grant keel can't honor
		}
	}
	method := req.TokenAuthMethod
	if method == "" {
		method = "none"
	}
	switch method {
	case "none", "client_secret_basic", "client_secret_post":
	default:
		return nil, ErrOAuthInvalidRequest
	}
	// Don't persist scopes the AS doesn't support (defense-in-depth with the
	// issuance-time clamp): a client can't even register `admin`.
	if len(a.issuer.supportedScopes) > 0 && !isSubset(req.Scopes, a.issuer.supportedScopes) {
		return nil, ErrOAuthInvalidScope
	}
	cid, err := oauthRandToken()
	if err != nil {
		return nil, err
	}
	c := &port.OAuthClient{
		ClientID:        "oc_" + cid[:32],
		RedirectURIs:    req.RedirectURIs,
		GrantTypes:      grants,
		Scopes:          req.Scopes,
		TokenAuthMethod: method,
		Name:            req.Name,
	}
	if method != "none" {
		secret, err := oauthRandToken()
		if err != nil {
			return nil, err
		}
		c.SecretHash = oauthHash(secret)
		c.Secret = secret // returned once to the registrant
	}
	if err := a.clients.CreateClient(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (a *AuthorizationServerLocal) ValidateAuthorizeRequest(ctx context.Context, req port.AuthorizeRequest) (*port.OAuthClient, []string, error) {
	client, err := a.clients.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, ErrOAuthInvalidClient
	}
	if !contains(client.RedirectURIs, req.RedirectURI) {
		return nil, nil, ErrOAuthInvalidRequest
	}
	if req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return nil, nil, ErrOAuthInvalidRequest
	}
	if req.Resource != "" && !contains(a.issuer.resources, req.Resource) {
		return nil, nil, ErrOAuthInvalidTarget
	}
	scopes, err := a.issuer.boundScopes(req.Scopes, client.Scopes)
	if err != nil {
		return nil, nil, err
	}
	return client, scopes, nil
}

func (a *AuthorizationServerLocal) Authorize(ctx context.Context, req port.AuthorizeRequest) (*port.AuthorizeResult, error) {
	if req.User == nil || !req.ConsentGranted {
		return nil, ErrOAuthAccessDenied
	}
	client, scopes, err := a.ValidateAuthorizeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	code, err := oauthRandToken()
	if err != nil {
		return nil, err
	}
	ac := &port.AuthCode{
		Code:                code,
		ClientID:            client.ClientID,
		UserID:              req.User.UserID,
		PartnerID:           req.User.PartnerID,
		Scopes:              scopes,
		RedirectURI:         req.RedirectURI,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Resource:            req.Resource,
	}
	if err := a.codes.SaveCode(ctx, ac, a.cfg.CodeTTL); err != nil {
		return nil, err
	}
	return &port.AuthorizeResult{Code: code, State: req.State}, nil
}

func (a *AuthorizationServerLocal) Token(ctx context.Context, req port.TokenRequest) (*port.TokenResponse, error) {
	g, ok := a.grants[req.GrantType]
	if !ok {
		return nil, ErrOAuthUnsupportedGrant
	}
	client, err := a.authenticateClient(ctx, req.Client)
	if err != nil {
		return nil, err
	}
	if !contains(client.GrantTypes, req.GrantType) {
		return nil, ErrOAuthUnauthorizedClient
	}
	return g.Handle(ctx, req, client)
}

func (a *AuthorizationServerLocal) Revoke(ctx context.Context, token, hint string, clientAuth port.ClientAuth) error {
	// RFC 7009: authenticate the client; an unknown or other-client token is a
	// 200 no-op. Access tokens are stateless and expire via TTL — we revoke the
	// refresh token's whole rotation family.
	client, err := a.authenticateClient(ctx, clientAuth)
	if err != nil {
		return err
	}
	stored, err := a.tokens.GetRefreshToken(ctx, oauthHash(token))
	if err != nil || stored == nil || stored.ClientID != client.ClientID {
		return nil
	}
	return a.tokens.RevokeFamily(ctx, stored.FamilyID)
}

func (a *AuthorizationServerLocal) Introspect(ctx context.Context, token string, clientAuth port.ClientAuth) (*port.Introspection, error) {
	// RFC 7662: authenticate the caller, and only reveal a token to the client
	// that owns it — otherwise active:false rather than leak another client's token.
	client, err := a.authenticateClient(ctx, clientAuth)
	if err != nil {
		return nil, err
	}
	principal, err := a.validator.Validate(ctx, token)
	if err != nil {
		return &port.Introspection{Active: false}, nil
	}
	if oauthStr(principal.Claims["client_id"]) != client.ClientID {
		return &port.Introspection{Active: false}, nil
	}
	return &port.Introspection{
		Active:   true,
		Scope:    strings.Join(principal.Scopes, " "),
		ClientID: oauthStr(principal.Claims["client_id"]),
		Sub:      principal.Subject,
		Aud:      strings.Join(principal.Audience, " "),
		Exp:      claimInt64(principal.Claims["exp"]),
	}, nil
}

// authenticateClient resolves the client and, for confidential clients, checks
// the secret. Public clients (token_auth_method=none) are protected by PKCE.
func (a *AuthorizationServerLocal) authenticateClient(ctx context.Context, auth port.ClientAuth) (*port.OAuthClient, error) {
	if auth.ClientID == "" {
		return nil, ErrOAuthInvalidClient
	}
	client, err := a.clients.GetClient(ctx, auth.ClientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, ErrOAuthInvalidClient
	}
	if client.TokenAuthMethod != "none" {
		// The credential must arrive via the registered method (basic vs post)
		// and match the stored secret.
		if auth.Method != client.TokenAuthMethod {
			return nil, ErrOAuthInvalidClient
		}
		if auth.ClientSecret == "" || oauthHash(auth.ClientSecret) != client.SecretHash {
			return nil, ErrOAuthInvalidClient
		}
	}
	return client, nil
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	// Reject userinfo ("user:pass@host"): it lets a registered URI read as one
	// host while routing to another — an open-redirect / code-leak vector.
	if err != nil || !u.IsAbs() || u.Fragment != "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
