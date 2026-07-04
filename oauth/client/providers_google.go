package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
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
// (caller supplies the scopes, e.g. business.manage) that also discovers + caches
// the account name in api_endpoint. The refresh token is stored in cred_ref by the
// default flow.
func NewGBPProvider(svc CredentialStore, name, callbackURL, clientID, secretName string, scopes []string) *BaseProvider {
	b := NewGoogleProvider(svc, name, callbackURL, clientID, secretName, scopes, "")
	b.DeriveAPIEndpoint = func(ctx context.Context, accessToken string) string {
		return DiscoverGBPAccountName(ctx, accessToken, b.Journal)
	}
	return b
}

const gbpAccountsURL = "https://mybusinessaccountmanagement.googleapis.com/v1/accounts"

// DiscoverGBPAccountName returns the first GBP account resource name, or "" so
// callers fall back to on-demand discovery. Failures are logged (the 4xx/5xx
// branch with status + body, e.g. 429 quota / 403 scope) so "" is never silent.
func DiscoverGBPAccountName(ctx context.Context, accessToken string, journal logger.ApplicationLogger) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gbpAccountsURL, nil)
	if err != nil {
		gbpDiscoveryLog(journal, "build request failed: %v", err)
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := common.HTTPClient().Do(req)
	if err != nil {
		gbpDiscoveryLog(journal, "request to %s failed: %v", gbpAccountsURL, err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		gbpDiscoveryLog(journal, "%s returned %d: %s", gbpAccountsURL, resp.StatusCode, strings.TrimSpace(string(body)))
		return ""
	}
	var parsed struct {
		Accounts []struct {
			Name string `json:"name"`
		} `json:"accounts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		gbpDiscoveryLog(journal, "decode response failed: %v", err)
		return ""
	}
	if len(parsed.Accounts) == 0 {
		gbpDiscoveryLog(journal, "no accounts returned for token")
		return ""
	}
	return parsed.Accounts[0].Name
}

func gbpDiscoveryLog(journal logger.ApplicationLogger, format string, args ...any) {
	if journal != nil {
		journal.Error("gbp account discovery: " + fmt.Sprintf(format, args...))
	}
}
