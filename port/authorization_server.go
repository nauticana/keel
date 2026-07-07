package port

import (
	"context"
	"time"
)

// AuthorizationServer is keel's local OAuth 2.1 authorization-server contract.
// The HTTP layer drives it; storage, signing, and per-grant logic are injected
// via the interfaces below, so a deployment can swap DB for cache/KMS without
// touching the AS. When oauth_as_mode=external the AS is absent and keel acts
// only as the resource server (see TokenValidator).
type AuthorizationServer interface {
	Metadata() AuthServerMetadata                                               // RFC 8414
	JWKS() JWKS                                                                 // token-signing public keys
	Register(ctx context.Context, req ClientRegistration) (*OAuthClient, error) // RFC 7591 DCR
	// ValidateAuthorizeRequest checks client_id + redirect_uri + PKCE before any
	// user interaction (so the consent UI shows only for a legitimate client and
	// errors never redirect to an unregistered URI), and returns the effective
	// granted scopes so the consent page shows exactly what will be granted.
	ValidateAuthorizeRequest(ctx context.Context, req AuthorizeRequest) (*OAuthClient, []string, error)
	Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResult, error)           // issue code after auth+consent
	Token(ctx context.Context, req TokenRequest) (*TokenResponse, error)                     // dispatched by grant_type
	Revoke(ctx context.Context, token, hint string, client ClientAuth) error                 // RFC 7009
	Introspect(ctx context.Context, token string, client ClientAuth) (*Introspection, error) // RFC 7662
}

// GrantHandler implements one grant_type at /token. The AS holds a registry
// keyed by GrantType(); new grants (token-exchange, client_credentials, …) plug
// in at composition without changing the AS — the Full-AS polymorphism point.
type GrantHandler interface {
	GrantType() string
	Handle(ctx context.Context, req TokenRequest, client *OAuthClient) (*TokenResponse, error)
}

// OAuthClientStore persists DCR-registered clients.
type OAuthClientStore interface {
	CreateClient(ctx context.Context, c *OAuthClient) error
	GetClient(ctx context.Context, clientID string) (*OAuthClient, error)
	UpdateClient(ctx context.Context, c *OAuthClient) error
	DeleteClient(ctx context.Context, clientID string) error
}

// AuthCodeStore holds single-use authorization codes. Back it with the cache
// (codes are short-lived and hot) to spare the small DB pool. ConsumeCode must
// atomically fetch-and-delete so a code is redeemable at most once.
type AuthCodeStore interface {
	SaveCode(ctx context.Context, c *AuthCode, ttl time.Duration) error
	ConsumeCode(ctx context.Context, code string) (*AuthCode, error)
}

// OAuthTokenStore persists refresh tokens (hashed) with rotation. RevokeFamily
// kills a rotated chain on replay (reuse-detection); RevokeForUser backs
// logout-all and GDPR erasure.
type OAuthTokenStore interface {
	SaveRefreshToken(ctx context.Context, t *RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	RevokeFamily(ctx context.Context, familyID string) error
	RevokeForUser(ctx context.Context, userID int64) error
	// Rotate atomically revokes oldHash and inserts t, so a crash can't leave a
	// gap where both the old and new refresh token are usable (or neither).
	Rotate(ctx context.Context, oldHash string, t *RefreshToken) error
}

// TokenSigner mints RS256 access tokens and exposes their verification keys.
// The local impl holds an RSA key from the keystore; a KMS impl can replace it.
type TokenSigner interface {
	Sign(ctx context.Context, claims map[string]any) (string, error)
	JWKS() JWKS
	KeyID() string
}

// AuthServerMetadata is the RFC 8414 authorization-server metadata document.
type AuthServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// OAuthClient is a registered client (RFC 7591). SecretHash is set only for
// confidential clients; public clients (e.g. ChatGPT) have none and use PKCE.
type OAuthClient struct {
	ClientID        string
	SecretHash      string
	RedirectURIs    []string
	GrantTypes      []string
	Scopes          []string
	TokenAuthMethod string // none | client_secret_basic | client_secret_post
	Name            string
	CreatedAt       time.Time
	Secret          string // plaintext, set only on the registration response — never persisted
}

// ClientRegistration is an inbound RFC 7591 registration request.
type ClientRegistration struct {
	RedirectURIs    []string
	GrantTypes      []string
	Scopes          []string
	TokenAuthMethod string
	Name            string
}

// ClientAuth carries credentials presented at /token, /revoke, /introspect.
// Method is how they were presented (none | client_secret_basic |
// client_secret_post) so the AS can enforce the client's registered method.
type ClientAuth struct {
	ClientID     string
	ClientSecret string // empty for public clients
	Method       string
}

// AuthorizeRequest is a parsed /authorize request. The HTTP layer authenticates
// the user (reusing keel login) and collects consent first, then sets User and
// ConsentGranted — the AS itself stays free of HTTP/login concerns.
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string // must be "S256"
	Resource            string // RFC 8707 — binds the issued token's audience
	User                *UserRef
	ConsentGranted      bool
}

// AuthorizeResult is returned once consent is granted.
type AuthorizeResult struct {
	Code  string
	State string
}

// AuthCode is the stored single-use authorization code.
type AuthCode struct {
	Code                string
	ClientID            string
	UserID              int64
	PartnerID           int64
	Scopes              []string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	ExpiresAt           time.Time
}

// TokenRequest is a parsed /token request; which fields apply depends on GrantType.
type TokenRequest struct {
	GrantType        string
	Code             string
	RedirectURI      string
	CodeVerifier     string // PKCE
	RefreshToken     string
	Scopes           []string
	Resource         string
	Client           ClientAuth
	SubjectToken     string // RFC 8693 token-exchange
	SubjectTokenType string
}

// TokenResponse is the /token success body.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` // "Bearer"
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// RefreshToken is the persisted (hashed) refresh token plus its rotation family.
type RefreshToken struct {
	TokenHash string
	FamilyID  string
	ClientID  string
	UserID    int64
	PartnerID int64
	Scopes    []string
	Resource  string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Introspection is the RFC 7662 response.
type Introspection struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Sub      string `json:"sub,omitempty"`
	Aud      string `json:"aud,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
}

// JWKS is a JSON Web Key Set of public keys.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// UserRef is the authenticated user the AS issues a code for — the bridge from
// keel's login (model.UserSession) that keeps port a leaf (no model import).
type UserRef struct {
	UserID    int64
	PartnerID int64
	Subject   string
	Email     string
}
