package domain

import (
	"context"
	"errors"
)

// ErrDomainNotProven is a verifier's negative verdict: the evidence was read
// and does not prove the domain. Any other verifier error is transient and is
// not a verdict.
var ErrDomainNotProven = errors.New("domain verification: evidence does not prove the domain")

// DomainVerifier checks one domain verification method. Implementations make
// no decision about partners or exclusivity; the domain verification service
// records the outcome.
type DomainVerifier interface {
	Method() string
	// Verify returns a provider evidence reference (empty when the method has
	// none) when proof establishes the domain, ErrDomainNotProven on a
	// negative verdict, or another error when the check could not complete.
	Verify(ctx context.Context, proof DomainProof) (evidenceRef string, err error)
}

// DomainProof is the evidence a verifier inspects. Domain, PartnerID and
// TokenHash are set by the service; the identity fields must come from a
// verified session or token, never from a request body.
type DomainProof struct {
	PartnerID int64
	Domain    string // normalized domain name
	TokenHash string // SHA-256 hex of the issued challenge token or code
	Response  string // code the user entered, for code-based methods
	// Email is the acting user's address, and EmailVerified whether the
	// account system or the identity provider verified it.
	Email         string
	EmailVerified bool
	HostedDomain  string // verified Google ID-token hd claim
	AccessToken   string // acting user's provider grant, for provider-attested methods
}
