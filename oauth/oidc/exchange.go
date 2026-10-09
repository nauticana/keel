package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
)

// TokenSet is the part of a token endpoint answer the relying party reads.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

type tokenErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// exchangeCode redeems an authorization code. Redirects are refused so a
// credential is never sent to another host; an OAuth error answer is a
// *TokenError.
func exchangeCode(ctx context.Context, httpc *http.Client, tokenEndpoint, clientID string, cred ClientCredential, form url.Values) (*TokenSet, error) {
	header := http.Header{}
	if err := cred.apply(form, header, clientID, tokenEndpoint, time.Now()); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = header
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	noRedirect := *httpc
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noRedirect.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: token exchange: %w", err)
	}
	defer resp.Body.Close()
	limit := config.Config().OutboundMaxResponseSize
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("oidc: read token response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("oidc: token response: %w", common.ErrResponseTooLarge)
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("oidc: token exchange: http status %d", resp.StatusCode)
	}
	var failure tokenErrorBody
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(body, &failure)
		return nil, &TokenError{Code: failure.Error, Description: failure.ErrorDescription}
	}
	var set TokenSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("%w: token response: %v", ErrInvalidResponse, err)
	}
	return &set, nil
}
