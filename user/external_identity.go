package user

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrIdentityNotLinked means the asserted email belongs to an account and
	// the issuer is not trusted to link by email; the owner links explicitly.
	ErrIdentityNotLinked = errors.New("user: the email belongs to an account this identity is not linked to")
	// ErrIdentityLinked means the identity belongs to another account, or the
	// account already has an identity from this issuer.
	ErrIdentityLinked = errors.New("user: identity is already linked")
	// ErrNoAccount: no account is linked to the identity or owns its email.
	ErrNoAccount = errors.New("user: no account for this identity")
	// ErrAccountUnavailable: the account is locked, expired or deleted.
	ErrAccountUnavailable = errors.New("user: account is locked or expired")
)

// ExternalIdentity is an identity from a token the caller verified. Links are
// keyed only on Issuer and Subject; Provider selects the adapter and UI label.
type ExternalIdentity struct {
	Provider      string // google, apple
	Issuer        string // exact verified iss claim
	Subject       string // stable sub claim within Issuer
	Email         string
	EmailVerified bool
	HostedDomain  string // Google Workspace hd claim
	FirstName     string
	LastName      string
	Phone         string
}

// Canonical issuers stored for Google and Apple identities.
const (
	GoogleIssuer = "https://accounts.google.com"
	AppleIssuer  = "https://appleid.apple.com"
)

func (id ExternalIdentity) validate() error {
	if strings.TrimSpace(id.Provider) == "" || strings.TrimSpace(id.Issuer) == "" || strings.TrimSpace(id.Subject) == "" {
		return fmt.Errorf("user: identity provider, issuer and subject are required")
	}
	if id.Provider == "phone" {
		return fmt.Errorf("user: provider %q is reserved; use GetOrCreateUserByPhone", id.Provider)
	}
	return nil
}

// emailTrusted reports whether the email was verified by Google or Apple.
// Only such an email is stored on a new account.
func (id ExternalIdentity) emailTrusted() bool {
	if !id.EmailVerified || normalizeEmail(id.Email) == "" {
		return false
	}
	return (id.Provider == "google" && id.Issuer == GoogleIssuer) || (id.Provider == "apple" && id.Issuer == AppleIssuer)
}

// linksByEmail reports whether the email may select an existing account. An
// Apple relay address never belongs to another account.
func (id ExternalIdentity) linksByEmail() bool {
	return id.emailTrusted() && !strings.HasSuffix(normalizeEmail(id.Email), "@privaterelay.appleid.com")
}
