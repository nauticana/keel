package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/nauticana/keel/common"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// NewMetaProvider builds a Facebook-Graph provider (Meta or Instagram). The
// caller supplies the scopes + app credentials for its use case; two Facebook
// behaviors are wired in — the short-lived token the exchange returns is swapped
// for a long-lived (60-day) one we persist (DeriveCredential), and Test hits /me
// with the token in the query string since Graph rejects the Bearer header on
// that endpoint (TestHealthcheck).
func NewMetaProvider(svc CredentialStore, name, callbackURL, appID, appSecretName string, scopes []string) *BaseProvider {
	b := &BaseProvider{
		Service:      svc,
		CallbackURL:  callbackURL,
		ProviderName: name,
		ClientID:     appID,
		SecretName:   appSecretName,
		Endpoint:     facebook.Endpoint,
		Scopes:       scopes,
		APIEndpoint:  "https://graph.facebook.com/v21.0/me",
		// The persisted credential is a long-lived (60-day) token, not a refreshable
		// one — Test exercises it directly rather than forcing a refresh.
		SkipRefreshOnTest: true,
	}
	b.DeriveCredential = func(ctx context.Context, t *oauth2.Token) (string, error) {
		appSecret, err := svc.GetSecret(ctx, appSecretName)
		if err != nil {
			return "", fmt.Errorf("get %s: %w", appSecretName, err)
		}
		longLived, err := exchangeMetaLongLivedToken(ctx, appID, appSecret, t.AccessToken)
		if err != nil {
			return "", fmt.Errorf("long-lived token exchange: %w", err)
		}
		return longLived, nil
	}
	b.TestHealthcheck = func(ctx context.Context, _ CredentialStore, partnerID int64, accessToken, _ string) error {
		testURL := fmt.Sprintf("https://graph.facebook.com/v21.0/me?access_token=%s", url.QueryEscape(accessToken))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			return err
		}
		return b.runHealthcheck(ctx, partnerID, req)
	}
	return b
}

// exchangeMetaLongLivedToken swaps a short-lived Meta/Facebook token for a
// long-lived (60-day) one. The caller supplies the app id + secret.
func exchangeMetaLongLivedToken(ctx context.Context, appID, appSecret, shortLivedToken string) (string, error) {
	u := fmt.Sprintf("https://graph.facebook.com/v21.0/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s",
		url.QueryEscape(appID), url.QueryEscape(appSecret), url.QueryEscape(shortLivedToken))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := common.HTTPClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("meta token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("meta token exchange HTTP %d: %s", resp.StatusCode, string(body))
	}
	var r struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("parse meta token exchange: %w", err)
	}
	if r.AccessToken == "" {
		return "", fmt.Errorf("empty access token in meta exchange response")
	}
	return r.AccessToken, nil
}
