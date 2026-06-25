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
)

// RefreshAccessToken mints a fresh access token from a stored oauth2-library
// refresh token (Google and any standard provider). Apps typically back
// CredentialStore.RefreshAccessToken with this.
func RefreshAccessToken(ctx context.Context, clientID, clientSecret string, endpoint oauth2.Endpoint, refreshToken string) (string, error) {
	cfg := &oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: endpoint}
	tok, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return "", fmt.Errorf("token refresh: %w", err)
	}
	return tok.AccessToken, nil
}

// ExchangeMetaLongLivedToken swaps a short-lived Meta/Facebook token for a
// long-lived (60-day) one. The caller supplies the app id + secret.
func ExchangeMetaLongLivedToken(ctx context.Context, appID, appSecret, shortLivedToken string) (string, error) {
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
