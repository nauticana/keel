package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

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
	}
	b.DeriveCredential = func(ctx context.Context, t *oauth2.Token) (string, error) {
		appSecret, err := svc.GetSecret(ctx, appSecretName)
		if err != nil {
			return "", fmt.Errorf("get %s: %w", appSecretName, err)
		}
		longLived, err := ExchangeMetaLongLivedToken(ctx, appID, appSecret, t.AccessToken)
		if err != nil {
			return "", fmt.Errorf("long-lived token exchange: %w", err)
		}
		return longLived, nil
	}
	b.TestHealthcheck = func(ctx context.Context, s CredentialStore, partnerID int64, _, _ string) error {
		credRef, _, err := s.GetConnectionCredentials(ctx, partnerID, name)
		if err != nil {
			return err
		}
		testURL := fmt.Sprintf("https://graph.facebook.com/v21.0/me?access_token=%s", url.QueryEscape(credRef))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			return err
		}
		return runHealthcheck(ctx, s, partnerID, name, ConnTypeOAuth, req)
	}
	return b
}
