package port

import (
	"context"
	"net/url"
)

// IdentityProvider turns one sign-in protocol's evidence into a neutral
// assertion. It decides nothing about accounts, tenants, or roles; the sign-in
// service does. One implementation per protocol, each reading its own settings
// for the connection.
type IdentityProvider interface {
	Protocol() string
	Begin(ctx context.Context, conn IdentityConnection, req IdentityBegin) (*IdentityRedirect, error)
	// Complete fails unless the callback answers this connection's Begin with
	// the same state and pending value.
	Complete(ctx context.Context, conn IdentityConnection, cb IdentityCallback) (*IdentityAssertion, error)
}

// IdentityConnection is the protocol-neutral part of a tenant's IdP connection.
type IdentityConnection struct {
	ID           int64
	PartnerID    int64
	Protocol     string
	Issuer       string
	SubjectClaim string
	EmailClaim   string
	RequireMFA   bool
}

// IdentityBegin starts a sign-in. Scopes are requested in addition to the
// connection's own, for example to obtain a domain-proof token.
type IdentityBegin struct {
	State       string
	RedirectURI string
	LoginHint   string
	Scopes      []string
}

// IdentityRedirect sends the browser to the IdP. Pending carries protocol state
// (nonce, PKCE verifier, request id) that the caller stores server-side and
// returns unchanged in IdentityCallback.
type IdentityRedirect struct {
	URL     string
	Pending string
}

// IdentityCallback is the IdP's answer: query parameters, or the posted form
// of a SAML binding.
type IdentityCallback struct {
	RedirectURI string
	Params      url.Values
	Pending     string
}

// IdentityAssertion is a verified identity. Claims holds multi-valued claims
// usable by role mapping; Overage names claims the IdP truncated, which grant
// nothing. AccessToken is set only when IdentityBegin asked for extra scopes
// and is never persisted.
type IdentityAssertion struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	GivenName     string
	FamilyName    string
	HostedDomain  string
	AuthMethods   []string
	Claims        map[string][]string
	Overage       []string
	AccessToken   string
}
