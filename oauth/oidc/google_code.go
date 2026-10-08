package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

const (
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// GoogleCode redeems a Google authorization code obtained by a first-party
// client (redirect URI "postmessage" for the JavaScript popup flow) and reads
// the account from userinfo. Empty endpoints use Google's.
type GoogleCode struct {
	TokenURL    string
	UserInfoURL string
	HTTP        *http.Client // nil = common.HTTPClient()
}

// Identity returns the Google account with the canonical Google issuer. A
// refused code is *TokenError; an unverified email is ErrEmailNotVerified.
func (g *GoogleCode) Identity(ctx context.Context, clientID, clientSecret, code, redirectURI string) (*port.IdentityAssertion, error) {
	if clientID == "" {
		return nil, ErrProviderDisabled
	}
	httpc := g.HTTP
	if httpc == nil {
		httpc = common.HTTPClient()
	}
	tokenURL, userInfoURL := g.TokenURL, g.UserInfoURL
	if tokenURL == "" {
		tokenURL = googleTokenURL
	}
	if userInfoURL == "" {
		userInfoURL = googleUserInfoURL
	}
	form := url.Values{"code": {code}, "redirect_uri": {redirectURI}, "grant_type": {"authorization_code"}}
	set, err := exchangeCode(ctx, httpc, tokenURL, clientID, ClientCredential{Method: AuthSecretPost, Secret: clientSecret}, form)
	if err != nil {
		return nil, err
	}
	if set.AccessToken == "" {
		return nil, &TokenError{}
	}
	var info struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		HostedDomain  string `json:"hd"`
	}
	body, _, err := common.RequestJSONWith(ctx, httpc, http.MethodGet, userInfoURL, map[string]string{"Authorization": "Bearer " + set.AccessToken}, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: google userinfo: %w", err)
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("%w: google userinfo: %v", ErrInvalidResponse, err)
	}
	if info.ID == "" {
		return nil, fmt.Errorf("%w: google userinfo without id", ErrInvalidResponse)
	}
	if !info.VerifiedEmail {
		return nil, ErrEmailNotVerified
	}
	return &port.IdentityAssertion{
		Issuer: GoogleIssuer, Subject: info.ID, Email: info.Email, EmailVerified: true,
		GivenName: info.GivenName, FamilyName: info.FamilyName, HostedDomain: info.HostedDomain,
	}, nil
}
