package domain

import (
	"context"
	"strings"
)

// GoogleHDVerifier proves membership in the Google organization that owns the
// domain (GH): the verified ID token's hd claim is the domain or a parent of it.
type GoogleHDVerifier struct{}

var _ DomainVerifier = GoogleHDVerifier{}

func (GoogleHDVerifier) Method() string { return MethodGoogleHD }

func (GoogleHDVerifier) Verify(_ context.Context, proof DomainProof) (string, error) {
	hd := strings.ToLower(strings.TrimSpace(proof.HostedDomain))
	if !CoveredBy(proof.Domain, hd) {
		return "", ErrDomainNotProven
	}
	return hd, nil
}
