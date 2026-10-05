package domain

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

const (
	GoogleBusinessAccountsURL  = "https://mybusinessaccountmanagement.googleapis.com/v1/accounts"
	GoogleBusinessLocationsURL = "https://mybusinessbusinessinformation.googleapis.com/v1"
	maxBusinessAccounts        = 20
)

// GoogleBusinessVerifier proves the acting user manages a Google-verified
// business listing whose website is the domain (GB). The website field is
// set by the listing's manager, so this is weak evidence.
type GoogleBusinessVerifier struct {
	AccountsURL  string // empty uses GoogleBusinessAccountsURL
	LocationsURL string // base of {account}/locations; empty uses GoogleBusinessLocationsURL
}

var _ DomainVerifier = (*GoogleBusinessVerifier)(nil)

func (v *GoogleBusinessVerifier) Method() string { return MethodGoogleBusiness }

func (v *GoogleBusinessVerifier) Verify(ctx context.Context, proof DomainProof) (string, error) {
	accounts, err := v.accounts(ctx, proof.AccessToken)
	if err != nil {
		return "", err
	}
	for _, account := range accounts {
		ref, err := v.matchingLocation(ctx, account, proof)
		if err != nil || ref != "" {
			return ref, err
		}
	}
	return "", fmt.Errorf("%w: no verified listing names %s as its website", ErrDomainNotProven, proof.Domain)
}

func (v *GoogleBusinessVerifier) accounts(ctx context.Context, accessToken string) ([]string, error) {
	var out []string
	token := ""
	for range maxProviderPages {
		next, err := withPageToken(orDefault(v.AccountsURL, GoogleBusinessAccountsURL), token)
		if err != nil {
			return nil, err
		}
		var page struct {
			Accounts []struct {
				Name string `json:"name"`
			} `json:"accounts"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := getProviderJSON(ctx, next, accessToken, &page); err != nil {
			return nil, err
		}
		for _, a := range page.Accounts {
			if strings.HasPrefix(a.Name, "accounts/") && len(out) < maxBusinessAccounts {
				out = append(out, a.Name)
			}
		}
		if page.NextPageToken == "" || len(out) >= maxBusinessAccounts {
			break
		}
		token = page.NextPageToken
	}
	return out, nil
}

func (v *GoogleBusinessVerifier) matchingLocation(ctx context.Context, account string, proof DomainProof) (string, error) {
	base := strings.TrimSuffix(orDefault(v.LocationsURL, GoogleBusinessLocationsURL), "/") + "/" + account +
		"/locations?" + url.Values{"readMask": {"name,websiteUri,metadata"}, "pageSize": {"100"}}.Encode()
	token := ""
	for range maxProviderPages {
		next, err := withPageToken(base, token)
		if err != nil {
			return "", err
		}
		var page struct {
			Locations []struct {
				Name       string `json:"name"`
				WebsiteURI string `json:"websiteUri"`
				Metadata   struct {
					HasVoiceOfMerchant bool `json:"hasVoiceOfMerchant"`
				} `json:"metadata"`
			} `json:"locations"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := getProviderJSON(ctx, next, proof.AccessToken, &page); err != nil {
			return "", err
		}
		for _, loc := range page.Locations {
			site, ok := DomainName(loc.WebsiteURI)
			if ok && site == proof.Domain && loc.Metadata.HasVoiceOfMerchant {
				return loc.Name, nil
			}
		}
		if page.NextPageToken == "" {
			return "", nil
		}
		token = page.NextPageToken
	}
	return "", nil
}
