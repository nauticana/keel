package domain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// MXResolver is the DNS lookup GoogleMXVerifier needs; *net.Resolver satisfies it.
type MXResolver interface {
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// GoogleMXVerifier proves a Google mailbox on the domain (GM): the acting
// user signed in with Google on a verified address whose domain shares the
// domain's registrable domain and receives mail at Google. Use it only for
// Google sign-ins.
type GoogleMXVerifier struct {
	Resolver MXResolver // nil uses net.DefaultResolver
}

var _ DomainVerifier = (*GoogleMXVerifier)(nil)

func (v *GoogleMXVerifier) Method() string { return MethodGoogleMX }

func (v *GoogleMXVerifier) Verify(ctx context.Context, proof DomainProof) (string, error) {
	if !emailOnDomain(proof) {
		return "", ErrDomainNotProven
	}
	var resolver MXResolver = net.DefaultResolver
	if v.Resolver != nil {
		resolver = v.Resolver
	}
	mailDomain := DomainFromEmail(proof.Email)
	mxs, err := resolver.LookupMX(ctx, mailDomain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", fmt.Errorf("%w: %s has no MX records", ErrDomainNotProven, mailDomain)
		}
		return "", fmt.Errorf("domain verification: MX lookup of %s: %w", mailDomain, err)
	}
	for _, mx := range mxs {
		host := strings.TrimSuffix(strings.ToLower(mx.Host), ".")
		if CoveredBy(host, "google.com") || CoveredBy(host, "googlemail.com") {
			return mailDomain, nil
		}
	}
	return "", fmt.Errorf("%w: %s does not receive mail at Google", ErrDomainNotProven, mailDomain)
}
