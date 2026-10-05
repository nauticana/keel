package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/nauticana/keel/common"
)

const maxProviderPages = 10

// errTooManyPages is not a verdict: the answer may be on an unread page.
var errTooManyPages = errors.New("domain verification: provider listing exceeds the page limit")

// getProviderJSON reads one provider API page with the acting user's grant.
// HTTP failures are operational or credential errors, not proof verdicts:
// providers also use 403 for missing scopes, quota and disabled APIs.
func getProviderJSON(ctx context.Context, rawURL, accessToken string, out any, headers ...string) error {
	if accessToken == "" {
		return fmt.Errorf("domain verification: provider access token required")
	}
	h := map[string]string{"Authorization": "Bearer " + accessToken}
	for i := 0; i+1 < len(headers); i += 2 {
		h[headers[i]] = headers[i+1]
	}
	body, _, err := common.RequestJSON(ctx, http.MethodGet, rawURL, h, nil)
	if err != nil {
		var requestErr *url.Error
		if errors.As(err, &requestErr) {
			return fmt.Errorf("domain verification: provider request: %w", requestErr.Err)
		}
		return fmt.Errorf("domain verification: provider request: %w", err)
	}
	return unmarshal(body, out)
}

type rawJSON = json.RawMessage

func unmarshal(raw []byte, out any) error {
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("domain verification: provider response: %w", err)
	}
	return nil
}

// withPageToken appends pageToken to a Google list URL.
func withPageToken(rawURL, token string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if token != "" {
		q := u.Query()
		q.Set("pageToken", token)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}
