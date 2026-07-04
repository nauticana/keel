package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nauticana/keel/common"
	"golang.org/x/oauth2"
)

// TokenResponse is the subset of an OAuth2 token endpoint reply the manual
// (non-oauth2-library) providers read.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// ManualTokenExchange POSTs a form-encoded token request and parses the JSON
// reply — for providers whose exchange doesn't fit the oauth2 library (Shopify,
// PKCE flows). Only 2xx is accepted; the body is capped at 1 MiB.
func ManualTokenExchange(ctx context.Context, tokenURL string, form url.Values) (TokenResponse, error) {
	var tr TokenResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tr, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := common.HTTPClient().Do(req)
	if err != nil {
		return tr, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tr, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return tr, fmt.Errorf("token exchange HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return tr, fmt.Errorf("parse token response: %w", err)
	}
	return tr, nil
}

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
