package domain

import (
	"context"
	"fmt"
)

// GoogleSiteResourcesURL lists the web resources the acting user owns (Site
// Verification API, scope siteverification).
const GoogleSiteResourcesURL = "https://www.googleapis.com/siteVerification/v1/webResource"

// GoogleSiteVerifier proves the acting Google account owns the domain property
// (GS): a DNS-verified INET_DOMAIN resource for the domain or a parent of it.
// Many accounts, delegated owners included, can own one property.
type GoogleSiteVerifier struct {
	ResourcesURL string // empty uses GoogleSiteResourcesURL
}

var _ DomainVerifier = (*GoogleSiteVerifier)(nil)

func (v *GoogleSiteVerifier) Method() string { return MethodGoogleSite }

func (v *GoogleSiteVerifier) Verify(ctx context.Context, proof DomainProof) (string, error) {
	var page struct {
		Items []struct {
			ID   string `json:"id"`
			Site struct {
				Type       string `json:"type"`
				Identifier string `json:"identifier"`
			} `json:"site"`
		} `json:"items"`
	}
	if err := getProviderJSON(ctx, orDefault(v.ResourcesURL, GoogleSiteResourcesURL), proof.AccessToken, &page); err != nil {
		return "", err
	}
	for _, item := range page.Items {
		if item.Site.Type == "INET_DOMAIN" && coveredBy(proof.Domain, item.Site.Identifier) {
			return item.ID, nil
		}
	}
	return "", fmt.Errorf("%w: the account owns no domain property for %s", ErrDomainNotProven, proof.Domain)
}
