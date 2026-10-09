package client

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// TikTokEndpoint is TikTok's OAuth endpoint. TikTok names the client id
// client_key and exchanges codes through a plain form POST.
var TikTokEndpoint = oauth2.Endpoint{
	AuthURL:  "https://www.tiktok.com/v2/auth/authorize/",
	TokenURL: "https://open.tiktokapis.com/v2/oauth/token/",
}

const tiktokAPIBase = "https://open.tiktokapis.com/v2"

// TikTokProvider connects a TikTok account. ClientID holds the client key.
type TikTokProvider struct {
	BaseProvider
}

var _ Provider = (*TikTokProvider)(nil)

// NewTikTokProvider builds a TikTok provider that stores the refresh token.
// Test checks the token against /user/info.
func NewTikTokProvider(svc CredentialStore, name, callbackURL, clientKey, secretName string, scopes []string) *TikTokProvider {
	return &TikTokProvider{BaseProvider{
		Service:      svc,
		ProviderName: name,
		CallbackURL:  callbackURL,
		ClientID:     clientKey,
		SecretName:   secretName,
		Endpoint:     TikTokEndpoint,
		Scopes:       scopes,
		APIEndpoint:  tiktokAPIBase,
		TestEndpoint: tiktokAPIBase + "/user/info/?fields=open_id",
	}}
}

func (p *TikTokProvider) AuthURL(ctx context.Context, partnerID int64, params map[string]string) (string, error) {
	if p.ClientID == "" || p.SecretName == "" {
		return "", fmt.Errorf("%s: missing ClientID or SecretName", p.ProviderName)
	}
	scopes := mergeScopes(p.Scopes, params[ParamExtraScopes])
	state, err := p.Service.CreateOAuthState(ctx, partnerID, p.ProviderName, stateExtras(params, scopes))
	if err != nil {
		return "", err
	}
	q := url.Values{
		"client_key":    {p.ClientID},
		"scope":         {strings.Join(scopes, ",")},
		"response_type": {"code"},
		"redirect_uri":  {p.CallbackURL},
		"state":         {state},
	}
	return p.Endpoint.AuthURL + "?" + q.Encode(), nil
}

// Callback consumes the state before the exchange, so a flow bound to another
// initiator is refused before the code is spent.
func (p *TikTokProvider) Callback(ctx context.Context, code, state string) error {
	partnerID, extra, err := p.Service.ConsumeOAuthState(ctx, state, p.ProviderName)
	if err != nil {
		return err
	}
	secret, err := p.Service.GetSecret(ctx, p.SecretName)
	if err != nil {
		return fmt.Errorf("get %s: %w", p.SecretName, err)
	}
	tok, err := ManualTokenExchange(ctx, p.Endpoint.TokenURL, url.Values{
		"client_key":    {p.ClientID},
		"client_secret": {secret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {p.CallbackURL},
	})
	if err != nil {
		return err
	}
	granted := ParseScopes(tok.Scope)
	if len(granted) == 0 {
		granted = ParseScopes(extra[stateRequestedScopesKey])
	}
	if missing := MissingScopes(granted, p.RequiredScopes); len(missing) > 0 {
		return &MissingScopeError{Provider: p.ProviderName, Missing: missing}
	}
	if tok.RefreshToken == "" {
		return fmt.Errorf("%s: no refresh token", p.ProviderName)
	}
	return p.Service.UpsertConnection(WithEntity(ctx, entityFromExtra(extra)), partnerID, Connection{
		Provider:      p.ProviderName,
		ConnType:      p.connType(),
		CredRef:       tok.RefreshToken,
		APIEndpoint:   p.APIEndpoint,
		GrantedScopes: granted,
	})
}
