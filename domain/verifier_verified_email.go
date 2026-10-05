package domain

import (
	"context"
)

// VerifiedEmailVerifier proves a mailbox on the domain (VE) from the acting
// user's verified email: its domain shares the domain's registrable domain.
type VerifiedEmailVerifier struct{}

var _ DomainVerifier = VerifiedEmailVerifier{}

func (VerifiedEmailVerifier) Method() string { return MethodVerifiedEmail }

func (VerifiedEmailVerifier) Verify(_ context.Context, proof DomainProof) (string, error) {
	if !emailOnDomain(proof) {
		return "", ErrDomainNotProven
	}
	return "", nil
}

func emailOnDomain(proof DomainProof) bool {
	at := DomainFromEmail(proof.Email)
	return proof.EmailVerified && at != "" && !IsPublicDomain(at) && DomainsMatch(at, proof.Domain)
}
