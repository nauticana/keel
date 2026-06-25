package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/nauticana/keel/common"
)

// bearerHealthcheck GETs testURL with a bearer token and records the connection
// status from the result.
func bearerHealthcheck(ctx context.Context, svc CredentialStore, partnerID int64, provider, connType, testURL, accessToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return fmt.Errorf("build healthcheck request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return runHealthcheck(ctx, svc, partnerID, provider, connType, req)
}

// runHealthcheck executes req and maps the outcome to a connection status
// (Active on 2xx/3xx, Error otherwise or on transport failure).
func runHealthcheck(ctx context.Context, svc CredentialStore, partnerID int64, provider, connType string, req *http.Request) error {
	resp, err := common.HTTPClient().Do(req)
	if err != nil {
		_ = svc.UpdateConnectionStatus(ctx, partnerID, provider, connType, ConnStatusError)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		_ = svc.UpdateConnectionStatus(ctx, partnerID, provider, connType, ConnStatusError)
		return fmt.Errorf("%s API returned HTTP %d", provider, resp.StatusCode)
	}
	return svc.UpdateConnectionStatus(ctx, partnerID, provider, connType, ConnStatusActive)
}
