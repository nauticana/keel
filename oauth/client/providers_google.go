package client

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/nauticana/keel/common"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// googleAuthCodeOptions forces offline access + a consent prompt so Google
// always returns a refresh token (it omits one on silent re-consent).
var googleAuthCodeOptions = []oauth2.AuthCodeOption{oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent")}

// NewGoogleProvider builds the standard Google offline-access provider for any
// Google API (Search Console, Analytics, YouTube, Business Profile, …). The
// mechanism is identical across Google products; the caller supplies the scopes,
// OAuth client (clientID + secretName), and apiEndpoint for its own use case.
// Returns the concrete *BaseProvider so callers can attach hooks if needed.
func NewGoogleProvider(svc CredentialStore, name, callbackURL, clientID, secretName string, scopes []string, apiEndpoint string) *BaseProvider {
	return &BaseProvider{
		Service:         svc,
		CallbackURL:     callbackURL,
		ProviderName:    name,
		ClientID:        clientID,
		SecretName:      secretName,
		Endpoint:        google.Endpoint,
		Scopes:          scopes,
		AuthCodeOptions: googleAuthCodeOptions,
		RequireRefresh:  true,
		APIEndpoint:     apiEndpoint,
	}
}

// NewGBPProvider builds a Google Business Profile provider: a Google provider
// (caller supplies the scopes, e.g. business.manage) plus two GBP behaviors —
// discover + cache the account name in api_endpoint, and persist the refresh
// token (GBP reuses it for other Google APIs) via SaveRefreshToken.
func NewGBPProvider(svc CredentialStore, name, callbackURL, clientID, secretName string, scopes []string) *BaseProvider {
	b := NewGoogleProvider(svc, name, callbackURL, clientID, secretName, scopes, "")
	b.DeriveAPIEndpoint = func(ctx context.Context, accessToken string) string {
		return DiscoverGBPAccountName(ctx, accessToken)
	}
	b.PostCallback = func(ctx context.Context, partnerID int64, t *oauth2.Token) error {
		return svc.SaveRefreshToken(ctx, partnerID, name, t.RefreshToken)
	}
	return b
}

// DiscoverGBPAccountName returns the first GBP account resource name (e.g.
// "accounts/123"), or "" on failure so callers can fall back to on-demand
// discovery.
func DiscoverGBPAccountName(ctx context.Context, accessToken string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://mybusinessaccountmanagement.googleapis.com/v1/accounts", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := common.HTTPClient().Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return ""
	}
	var body struct {
		Accounts []struct {
			Name string `json:"name"`
		} `json:"accounts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || len(body.Accounts) == 0 {
		return ""
	}
	return body.Accounts[0].Name
}
