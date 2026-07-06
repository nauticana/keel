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

// ExchangeOption mutates the token request before it's sent (e.g. HTTP Basic auth).
type ExchangeOption func(*http.Request)

// WithBasicAuth authenticates the client via HTTP Basic (Twitter/X, Reddit).
func WithBasicAuth(username, password string) ExchangeOption {
	return func(req *http.Request) { req.SetBasicAuth(username, password) }
}

// ManualTokenExchange POSTs a form-encoded token request and parses the JSON
// reply — for providers whose exchange doesn't fit the oauth2 library (Shopify,
// PKCE flows). Only 2xx is accepted; the body is capped at 1 MiB. Pass opts
// (e.g. WithBasicAuth) for header-based client auth.
func ManualTokenExchange(ctx context.Context, tokenURL string, form url.Values, opts ...ExchangeOption) (TokenResponse, error) {
	var tr TokenResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tr, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for _, opt := range opts {
		opt(req)
	}
	// Never follow redirects on the token POST: it carries the client_secret in
	// its body (and possibly a Basic-auth header), which Go would resend to the
	// redirect target — a redirecting/hostile endpoint could capture it.
	noRedirect := *common.HTTPClient()
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
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

// RefreshOAuth2Token mints a fresh token from a stored oauth2-library refresh
// token, returning the whole token so callers can persist a rotated refresh
// token. The oauth2 library backfills the prior refresh token when the server
// doesn't rotate, so RefreshToken is always populated.
func RefreshOAuth2Token(ctx context.Context, clientID, clientSecret string, endpoint oauth2.Endpoint, refreshToken string) (*oauth2.Token, error) {
	cfg := &oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: endpoint}
	tok, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}
	return tok, nil
}

// RefreshAccessToken mints a fresh access token from a stored oauth2-library
// refresh token (Google and any standard provider). Apps typically back
// CredentialStore.RefreshAccessToken with this.
func RefreshAccessToken(ctx context.Context, clientID, clientSecret string, endpoint oauth2.Endpoint, refreshToken string) (string, error) {
	tok, err := RefreshOAuth2Token(ctx, clientID, clientSecret, endpoint, refreshToken)
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}
