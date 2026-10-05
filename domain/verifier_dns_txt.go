package domain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/nauticana/keel/config"
)

// TXTResolver is the DNS lookup DNSTXTVerifier needs; *net.Resolver satisfies it.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DNSTXTVerifier proves DNS control (DT): the domain publishes TXTValue of
// the issued token.
type DNSTXTVerifier struct {
	Resolver TXTResolver // nil uses net.DefaultResolver
}

var _ DomainVerifier = (*DNSTXTVerifier)(nil)

func (v *DNSTXTVerifier) Method() string { return MethodDNSTXT }

func (v *DNSTXTVerifier) Verify(ctx context.Context, proof DomainProof) (string, error) {
	if proof.Domain == "" || proof.TokenHash == "" {
		return "", ErrDomainNotProven
	}
	var resolver TXTResolver = net.DefaultResolver
	if v.Resolver != nil {
		resolver = v.Resolver
	}
	records, err := resolver.LookupTXT(ctx, proof.Domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", fmt.Errorf("%w: %s has no TXT records", ErrDomainNotProven, proof.Domain)
		}
		return "", fmt.Errorf("domain verification: TXT lookup of %s: %w", proof.Domain, err)
	}
	prefix := config.Config().DomainVerificationLabel + "="
	for _, record := range records {
		if token, ok := strings.CutPrefix(strings.TrimSpace(record), prefix); ok && tokenMatches(token, proof.TokenHash) {
			return "", nil
		}
	}
	return "", fmt.Errorf("%w: %s does not publish the token", ErrDomainNotProven, proof.Domain)
}
