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

const DefaultMetaGraphVersion = "v23.0"

// MetaProvider is a Facebook-Graph provider (Meta or Instagram). GraphVersion
// is read at each call, so a consumer can move it without a keel release.
type MetaProvider struct {
	BaseProvider
	GraphVersion string
}

var _ Provider = (*MetaProvider)(nil)

// NewMetaProvider builds a Facebook-Graph provider. The caller supplies the
// scopes + app credentials for its use case; two Facebook behaviors are wired
// in — the short-lived token the exchange returns is swapped for a long-lived
// (60-day) one we persist (DeriveCredential), and Test hits /me with the token
// in the query string since Graph rejects the Bearer header on that endpoint
// (TestHealthcheck).
func NewMetaProvider(svc CredentialStore, name, callbackURL, appID, appSecretName string, scopes []string) *MetaProvider {
	p := &MetaProvider{
		BaseProvider: BaseProvider{
			Service:      svc,
			CallbackURL:  callbackURL,
			ProviderName: name,
			ClientID:     appID,
			SecretName:   appSecretName,
			Scopes:       scopes,
			// The persisted credential is a long-lived (60-day) token, not a refreshable
			// one — Test exercises it directly rather than forcing a refresh.
			SkipRefreshOnTest: true,
			NoImpliedScopes:   true,
		},
		GraphVersion: DefaultMetaGraphVersion,
	}
	p.DeriveEndpoint = func() oauth2.Endpoint {
		return oauth2.Endpoint{
			AuthURL:  "https://www.facebook.com/" + p.GraphVersion + "/dialog/oauth",
			TokenURL: p.graphBase() + "/oauth/access_token",
		}
	}
	p.DeriveAPIEndpoint = func(context.Context, string) string { return p.graphBase() + "/me" }
	p.DeriveCredential = func(ctx context.Context, t *oauth2.Token) (string, error) {
		appSecret, err := svc.GetSecret(ctx, appSecretName)
		if err != nil {
			return "", fmt.Errorf("get %s: %w", appSecretName, err)
		}
		longLived, err := exchangeMetaLongLivedToken(ctx, p.graphBase(), appID, appSecret, t.AccessToken)
		if err != nil {
			return "", fmt.Errorf("long-lived token exchange: %w", err)
		}
		return longLived, nil
	}
	p.TestHealthcheck = func(ctx context.Context, _ CredentialStore, partnerID int64, accessToken, _ string) error {
		testURL := p.graphBase() + "/me?access_token=" + url.QueryEscape(accessToken)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
		if err != nil {
			return err
		}
		return p.runHealthcheck(ctx, partnerID, req)
	}
	return p
}

func (p *MetaProvider) graphBase() string {
	return "https://graph.facebook.com/" + p.GraphVersion
}

// exchangeMetaLongLivedToken swaps a short-lived Meta/Facebook token for a
// long-lived (60-day) one. The caller supplies the app id + secret.
func exchangeMetaLongLivedToken(ctx context.Context, graphBase, appID, appSecret, shortLivedToken string) (string, error) {
	u := fmt.Sprintf("%s/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s", graphBase,
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
