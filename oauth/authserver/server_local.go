package authserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"maps"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/oauth/claims"
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

	OAuthPathPrefix         = "/oauth"
	OAuthSessionPath        = "/oauth/session"         // redeems a hand-off code for an AS cookie session
	OAuthSessionHandoffPath = "/oauth/session/handoff" // mints a hand-off code for a bearer-authenticated user
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
	// RFC 7591 registration errors.
	ErrOAuthInvalidClientMetadata = oauthErr("invalid_client_metadata")
	ErrOAuthInvalidRedirectURI    = oauthErr("invalid_redirect_uri")
	// ErrOAuthClientLimit refuses a registration while ClientStoreDB.MaxPending
	// unauthorized clients exist.
	ErrOAuthClientLimit = oauthErr("temporarily_unavailable")
)

// describedErr is a protocol error with an error_description for the client.
type describedErr struct {
	code oauthErr
	desc string
}

func (e describedErr) Error() string { return string(e.code) + ": " + e.desc }
func (e describedErr) Unwrap() error { return e.code }

// ProtocolErrorDescription reports the client-safe error_description of a
// protocol error, or "" when it has none.
func ProtocolErrorDescription(err error) string {
	var de describedErr
	if errors.As(err, &de) {
		return de.desc
	}
	return ""
}

// ProtocolErrorCode reports the RFC 6749 error code for a client-facing AS error.
// Anything else is internal (DB/signer/rand) — the caller logs it and returns a
// generic server_error rather than leaking detail.
func ProtocolErrorCode(err error) (string, bool) {
	var oe oauthErr
	if errors.As(err, &oe) {
		return string(oe), true
	}
	return "", false
}

const subjectPrefix = "user:"

func subjectForUser(userID int64) string { return subjectPrefix + strconv.FormatInt(userID, 10) }

// UserIDFromSubject parses the sub claim of a token this AS issued.
func UserIDFromSubject(sub string) (int64, bool) {
	if !strings.HasPrefix(sub, subjectPrefix) {
		return 0, false
	}
	id, err := strconv.ParseInt(sub[len(subjectPrefix):], 10, 64)
	return id, err == nil && id > 0
}

// Config holds the local AS's non-secret settings.
type Config struct {
	Issuer          string // public base URL of this AS (also the token iss)
	DefaultAudience string
	Scopes          []string // AS-supported scopes; the upper bound on any grant
	Resources       []string // extra valid RFC 8707 resource indicators (DefaultAudience is always valid)
	AccessTTL       time.Duration
	RefreshTTL      time.Duration
	CodeTTL         time.Duration
}

// registrationGrants are the grants open registration records: the interactive
// ones, which act only with a user's consent. Other grants need Provision.
var registrationGrants = []string{"authorization_code", "refresh_token"}

// Local is keel's local OAuth 2.1 authorization server.
type Local struct {
	clients   port.OAuthClientStore
	codes     port.AuthCodeStore
	tokens    port.OAuthTokenStore
	signer    port.TokenSigner
	validator port.TokenValidator
	issuer    *oauthIssuer
	grants    map[string]port.GrantHandler
	cfg       Config
}

var _ port.AuthorizationServer = (*Local)(nil)

func NewLocal(signer *RS256Signer, clients port.OAuthClientStore, codes port.AuthCodeStore, tokens port.OAuthTokenStore, cfg Config) *Local {
	resources := []string{cfg.DefaultAudience}
	for _, r := range cfg.Resources {
		if r != "" && !slices.Contains(resources, r) {
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
	internal := NewLocalValidatorMulti(signer, cfg.Issuer, resources)
	as := &Local{
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

func (a *Local) Metadata() port.AuthServerMetadata {
	base := strings.TrimRight(a.cfg.Issuer, "/")
	grants := slices.Sorted(maps.Keys(a.grants))
	authMethods := []string{"none", "client_secret_basic", "client_secret_post"}
	return port.AuthServerMetadata{
		Issuer:                                     base,
		AuthorizationEndpoint:                      base + OAuthAuthorizePath,
		TokenEndpoint:                              base + OAuthTokenPath,
		RegistrationEndpoint:                       base + OAuthRegisterPath,
		RevocationEndpoint:                         base + OAuthRevokePath,
		IntrospectionEndpoint:                      base + OAuthIntrospectPath,
		JWKSURI:                                    base + OAuthJWKSPath,
		ScopesSupported:                            a.cfg.Scopes,
		ResponseTypesSupported:                     []string{"code"},
		GrantTypesSupported:                        grants,
		CodeChallengeMethodsSupported:              []string{"S256"},
		TokenEndpointAuthMethodsSupported:          authMethods,
		ResponseModesSupported:                     []string{"query"},
		RevocationEndpointAuthMethodsSupported:     authMethods,
		IntrospectionEndpointAuthMethodsSupported:  authMethods,
		AuthorizationResponseIssParameterSupported: true,
	}
}

func (a *Local) JWKS() port.JWKS { return a.signer.JWKS() }

// Register admits an open (RFC 7591) registration. Every registered client
// gets authorization_code and refresh_token, so each one the pending bound and
// the purge cover; a request for any other grant is refused.
func (a *Local) Register(ctx context.Context, req port.ClientRegistration) (*port.OAuthClient, error) {
	for _, gt := range req.GrantTypes {
		if !slices.Contains(registrationGrants, gt) {
			return nil, describedErr{ErrOAuthInvalidClientMetadata, "grant_types: registration admits only authorization_code and refresh_token"}
		}
	}
	return a.createClient(ctx, req, registrationGrants, true)
}

// Provision creates an operator-managed client with any grant this AS serves.
// It is never exposed over HTTP, and the purge never deletes its clients.
func (a *Local) Provision(ctx context.Context, req port.ClientRegistration) (*port.OAuthClient, error) {
	if len(req.GrantTypes) == 0 {
		return nil, describedErr{ErrOAuthInvalidClientMetadata, "grant_types: required"}
	}
	for _, gt := range req.GrantTypes {
		if _, ok := a.grants[gt]; !ok {
			return nil, describedErr{ErrOAuthInvalidClientMetadata, "grant_types: unsupported " + gt}
		}
	}
	return a.createClient(ctx, req, req.GrantTypes, false)
}

func (a *Local) createClient(ctx context.Context, req port.ClientRegistration, grants []string, registered bool) (*port.OAuthClient, error) {
	if len(req.RedirectURIs) == 0 && slices.Contains(grants, "authorization_code") {
		return nil, describedErr{ErrOAuthInvalidRedirectURI, "redirect_uris: required"}
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			return nil, describedErr{ErrOAuthInvalidRedirectURI, "redirect_uris: must be https, or http on a loopback address, without userinfo or fragment"}
		}
	}
	method := req.TokenAuthMethod
	if method == "" {
		method = "none"
	}
	switch method {
	case "none", "client_secret_basic", "client_secret_post":
	default:
		return nil, describedErr{ErrOAuthInvalidClientMetadata, "token_endpoint_auth_method: unsupported " + method}
	}
	// Don't persist scopes the AS doesn't support (defense-in-depth with the
	// issuance-time clamp): a client can't even register `admin`.
	if len(a.issuer.supportedScopes) > 0 && !isSubset(req.Scopes, a.issuer.supportedScopes) {
		return nil, describedErr{ErrOAuthInvalidClientMetadata, "scope: not supported by this server"}
	}
	cid, err := randToken()
	if err != nil {
		return nil, err
	}
	c := &port.OAuthClient{
		ClientID:        "oc_" + cid[:32],
		RedirectURIs:    req.RedirectURIs,
		GrantTypes:      slices.Clone(grants),
		Scopes:          req.Scopes,
		TokenAuthMethod: method,
		Name:            req.Name,
		Registered:      registered,
		CreatedAt:       time.Now(),
	}
	if method != "none" {
		secret, err := randToken()
		if err != nil {
			return nil, err
		}
		c.SecretHash = hashToken(secret)
		c.Secret = secret // returned once to the registrant
	}
	if err := a.clients.CreateClient(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (a *Local) ValidateAuthorizeRequest(ctx context.Context, req port.AuthorizeRequest) (*port.OAuthClient, []string, error) {
	client, err := a.clients.GetClient(ctx, req.ClientID)
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, ErrOAuthInvalidClient
	}
	if !slices.Contains(client.RedirectURIs, req.RedirectURI) {
		return nil, nil, ErrOAuthInvalidRequest
	}
	if req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return client, nil, ErrOAuthInvalidRequest
	}
	if req.Resource != "" && !slices.Contains(a.issuer.resources, req.Resource) {
		return client, nil, ErrOAuthInvalidTarget
	}
	scopes, err := a.issuer.boundScopes(req.Scopes, client.Scopes)
	if err != nil {
		return client, nil, err
	}
	return client, scopes, nil
}

func (a *Local) Authorize(ctx context.Context, req port.AuthorizeRequest) (*port.AuthorizeResult, error) {
	if req.User == nil || !req.ConsentGranted {
		return nil, ErrOAuthAccessDenied
	}
	client, scopes, err := a.ValidateAuthorizeRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	code, err := randToken()
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

func (a *Local) Token(ctx context.Context, req port.TokenRequest) (*port.TokenResponse, error) {
	g, ok := a.grants[req.GrantType]
	if !ok {
		return nil, ErrOAuthUnsupportedGrant
	}
	client, err := a.authenticateClient(ctx, req.Client)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(client.GrantTypes, req.GrantType) {
		return nil, ErrOAuthUnauthorizedClient
	}
	return g.Handle(ctx, req, client)
}

func (a *Local) Revoke(ctx context.Context, token, hint string, clientAuth port.ClientAuth) error {
	// RFC 7009: authenticate the client; an unknown or other-client token is a
	// 200 no-op.
	client, err := a.authenticateClient(ctx, clientAuth)
	if err != nil {
		return err
	}
	if token == "" {
		return ErrOAuthInvalidRequest
	}
	stored, err := a.tokens.GetRefreshToken(ctx, hashToken(token))
	if err != nil {
		return err // DB failure — never report success while the token is still valid
	}
	if stored != nil {
		if stored.ClientID != client.ClientID {
			return nil
		}
		return a.tokens.RevokeFamily(ctx, stored.FamilyID)
	}
	// An access token is stateless: revoking it ends the grant it came from,
	// which introspection and GrantService.Active then report.
	userID, ok := a.ownAccessToken(ctx, token, client.ClientID)
	if !ok {
		return nil
	}
	return a.tokens.RevokeGrant(ctx, userID, client.ClientID)
}

// ownAccessToken returns the user of a valid access token issued to clientID.
func (a *Local) ownAccessToken(ctx context.Context, token, clientID string) (int64, bool) {
	principal, err := a.validator.Validate(ctx, token)
	if err != nil || common.AsString(principal.Claims["client_id"]) != clientID {
		return 0, false
	}
	return UserIDFromSubject(principal.Subject)
}

func (a *Local) Introspect(ctx context.Context, token string, clientAuth port.ClientAuth) (*port.Introspection, error) {
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
	if common.AsString(principal.Claims["client_id"]) != client.ClientID {
		return &port.Introspection{Active: false}, nil
	}
	// A client holding refresh tokens has a revocable grant; once it ends,
	// its access tokens are reported inactive.
	if userID, ok := UserIDFromSubject(principal.Subject); ok && slices.Contains(client.GrantTypes, "refresh_token") {
		live, err := a.tokens.GrantActive(ctx, userID, client.ClientID)
		if err != nil {
			return nil, err
		}
		if !live {
			return &port.Introspection{Active: false}, nil
		}
	}
	return &port.Introspection{
		Active:   true,
		Scope:    strings.Join(principal.Scopes, " "),
		ClientID: common.AsString(principal.Claims["client_id"]),
		Sub:      principal.Subject,
		Aud:      strings.Join(principal.Audience, " "),
		Exp:      claims.Int64(principal.Claims["exp"]),
	}, nil
}

// authenticateClient resolves the client and, for confidential clients, checks
// the secret. Public clients (token_auth_method=none) are protected by PKCE.
func (a *Local) authenticateClient(ctx context.Context, auth port.ClientAuth) (*port.OAuthClient, error) {
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
		if auth.ClientSecret == "" || subtle.ConstantTimeCompare([]byte(hashToken(auth.ClientSecret)), []byte(client.SecretHash)) != 1 {
			return nil, ErrOAuthInvalidClient
		}
	}
	return client, nil
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	// Reject userinfo ("user:pass@host"): it lets a registered URI read as one
	// host while routing to another — an open-redirect / code-leak vector.
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())
}
