package domain

import (
	"context"
)

// EmailCodeVerifier proves a mailbox on the domain (EC): the user enters the
// code that was emailed to an address on it.
type EmailCodeVerifier struct{}

var _ DomainVerifier = EmailCodeVerifier{}

func (EmailCodeVerifier) Method() string { return MethodEmailCode }

func (EmailCodeVerifier) Verify(_ context.Context, proof DomainProof) (string, error) {
	if !tokenMatches(proof.Response, proof.TokenHash) {
		return "", ErrDomainNotProven
	}
	return "", nil
}
