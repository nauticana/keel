package domain

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

const (
	EntraDomainsURL = "https://graph.microsoft.com/v1.0/domains"
	// The OData cast needs $count and the ConsistencyLevel header; transitive
	// membership includes roles assigned through a group.
	EntraRolesURL = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.directoryRole?$count=true"
	// Directory role templates allowed to prove a domain: Global
	// Administrator and Domain Name Administrator.
	EntraGlobalAdministrator     = "62e90394-69f5-4237-9190-012177145e10"
	EntraDomainNameAdministrator = "8329153b-31d0-4727-b945-745eb3bc5f31"
)

// MicrosoftEntraVerifier proves the acting user administers the Entra tenant
// that verified the domain (ME): the user holds an AdminRoles directory role
// and the tenant lists the domain as verified. Reading domains alone is not
// enough, since every member may read them. The grant needs Domain.Read.All
// and a directory read permission that exposes role template ids.
type MicrosoftEntraVerifier struct {
	DomainsURL string   // empty uses EntraDomainsURL
	RolesURL   string   // empty uses EntraRolesURL
	AdminRoles []string // role template ids; empty uses the two administrators above
}

var _ DomainVerifier = (*MicrosoftEntraVerifier)(nil)

func (v *MicrosoftEntraVerifier) Method() string { return MethodMicrosoftEntra }

func (v *MicrosoftEntraVerifier) Verify(ctx context.Context, proof DomainProof) (string, error) {
	roles := []string{EntraGlobalAdministrator, EntraDomainNameAdministrator}
	if len(v.AdminRoles) > 0 {
		roles = roles[:0]
		for _, r := range v.AdminRoles {
			roles = append(roles, strings.ToLower(r))
		}
	}
	admin := false
	err := graphPages(ctx, orDefault(v.RolesURL, EntraRolesURL), proof.AccessToken, func(raw []byte) (bool, error) {
		var page struct {
			Value []struct {
				RoleTemplateID string `json:"roleTemplateId"`
			} `json:"value"`
		}
		if err := unmarshal(raw, &page); err != nil {
			return false, err
		}
		for _, r := range page.Value {
			if r.RoleTemplateID == "" {
				return false, fmt.Errorf("domain verification: the grant cannot read directory role details")
			}
			if slices.Contains(roles, strings.ToLower(r.RoleTemplateID)) {
				admin = true
				return true, nil
			}
		}
		return false, nil
	}, "ConsistencyLevel", "eventual")
	if err != nil {
		return "", err
	}
	if !admin {
		return "", fmt.Errorf("%w: user holds no domain administrator role", ErrDomainNotProven)
	}
	ref := ""
	err = graphPages(ctx, orDefault(v.DomainsURL, EntraDomainsURL), proof.AccessToken, func(raw []byte) (bool, error) {
		var page struct {
			Value []struct {
				ID         string `json:"id"`
				IsVerified bool   `json:"isVerified"`
			} `json:"value"`
		}
		if err := unmarshal(raw, &page); err != nil {
			return false, err
		}
		for _, d := range page.Value {
			if d.IsVerified && CoveredBy(proof.Domain, d.ID) {
				ref = strings.ToLower(d.ID)
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return "", err
	}
	if ref == "" {
		return "", fmt.Errorf("%w: %s is not a verified domain of the tenant", ErrDomainNotProven, proof.Domain)
	}
	return ref, nil
}

// graphPages follows @odata.nextLink on the first page's host until visit
// returns true or maxProviderPages pages were read.
func graphPages(ctx context.Context, first, accessToken string, visit func([]byte) (bool, error), headers ...string) error {
	start, err := url.Parse(first)
	if err != nil {
		return err
	}
	next := first
	for range maxProviderPages {
		var page struct {
			NextLink string `json:"@odata.nextLink"`
		}
		var raw rawJSON
		if err := getProviderJSON(ctx, next, accessToken, &raw, headers...); err != nil {
			return err
		}
		done, err := visit(raw)
		if err != nil || done {
			return err
		}
		if err := unmarshal(raw, &page); err != nil {
			return err
		}
		if page.NextLink == "" {
			return nil
		}
		u, err := url.Parse(page.NextLink)
		if err != nil || u.Scheme != start.Scheme || u.Host != start.Host {
			return fmt.Errorf("domain verification: unexpected next page %q", page.NextLink)
		}
		next = page.NextLink
	}
	return errTooManyPages
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
