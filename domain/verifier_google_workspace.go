package domain

import (
	"context"
	"fmt"
)

// GoogleWorkspaceDomainsURL lists the administered organization's domains
// (Admin SDK Directory API, scope admin.directory.domain.readonly).
const GoogleWorkspaceDomainsURL = "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/domains"

// GoogleWorkspaceVerifier proves the acting user administers the Google
// organization that verified the domain (GW). Only administrators may call
// the Directory API; anyone else gets a 403, a negative verdict.
type GoogleWorkspaceVerifier struct {
	DomainsURL string // empty uses GoogleWorkspaceDomainsURL
}

var _ DomainVerifier = (*GoogleWorkspaceVerifier)(nil)

func (v *GoogleWorkspaceVerifier) Method() string { return MethodGoogleWorkspace }

func (v *GoogleWorkspaceVerifier) Verify(ctx context.Context, proof DomainProof) (string, error) {
	endpoint := v.DomainsURL
	if endpoint == "" {
		endpoint = GoogleWorkspaceDomainsURL
	}
	var page struct {
		Domains []struct {
			DomainName string `json:"domainName"`
			Verified   bool   `json:"verified"`
			Aliases    []struct {
				DomainAliasName string `json:"domainAliasName"`
				Verified        bool   `json:"verified"`
			} `json:"domainAliases"`
		} `json:"domains"`
	}
	if err := getProviderJSON(ctx, endpoint, proof.AccessToken, &page); err != nil {
		return "", err
	}
	for _, d := range page.Domains {
		if d.Verified && coveredBy(proof.Domain, d.DomainName) {
			return d.DomainName, nil
		}
		for _, a := range d.Aliases {
			if a.Verified && coveredBy(proof.Domain, a.DomainAliasName) {
				return a.DomainAliasName, nil
			}
		}
	}
	return "", fmt.Errorf("%w: %s is not a verified domain of the organization", ErrDomainNotProven, proof.Domain)
}
