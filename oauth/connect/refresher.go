package connect

import (
	"context"
	"fmt"
	"net/url"

	"github.com/nauticana/keel/oauth/client"
	"github.com/nauticana/keel/secret"
	"golang.org/x/oauth2"
)

// RefreshStyle selects how NewRefresher mints a fresh access token.
type RefreshStyle int

const (
	RefreshOAuth2Lib   RefreshStyle = iota // oauth2 library against Endpoint (Google et al.)
	RefreshForm                            // POST a form-encoded refresh_token grant to TokenURL
	RefreshPassthrough                     // stored token used as-is (long-lived: Meta, Shopify)
	RefreshJSON                            // POST a JSON {client_id, refresh_token} grant to TokenURL (Clover v2 et al.)
)

// RefreshSpec describes how to refresh one provider's token.
type RefreshSpec struct {
	ClientID      string          // OAuth client id (or client key)
	SecretName    string          // keystore key holding the client secret
	Endpoint      oauth2.Endpoint // RefreshOAuth2Lib
	TokenURL      string          // RefreshForm / RefreshJSON: the refresh POST target
	Style         RefreshStyle
	ClientIDParam string // RefreshForm client-id field; "" defaults to "client_id" (TikTok: "client_key")
}

// NewRefresher builds a provider-aware Refresher from a spec registry. Unknown
// providers error; passthrough providers return the stored token unchanged.
func NewRefresher(secrets secret.SecretProvider, specs map[string]RefreshSpec) Refresher {
	return func(ctx context.Context, provider, refreshToken string) (RefreshResult, error) {
		spec, ok := specs[provider]
		if !ok {
			return RefreshResult{}, fmt.Errorf("unsupported provider: %s", provider)
		}
		if spec.Style == RefreshPassthrough {
			return RefreshResult{AccessToken: refreshToken}, nil
		}
		clientSecret, err := secrets.GetSecret(ctx, spec.SecretName)
		if err != nil {
			return RefreshResult{}, fmt.Errorf("get %s: %w", spec.SecretName, err)
		}
		switch spec.Style {
		case RefreshOAuth2Lib:
			tok, err := client.RefreshOAuth2Token(ctx, spec.ClientID, clientSecret, spec.Endpoint, refreshToken)
			if err != nil {
				return RefreshResult{}, err
			}
			res := RefreshResult{AccessToken: tok.AccessToken}
			if tok.RefreshToken != "" && tok.RefreshToken != refreshToken {
				res.RefreshToken = tok.RefreshToken // server rotated the refresh token; persist it
			}
			return res, nil
		case RefreshForm:
			idParam := spec.ClientIDParam
			if idParam == "" {
				idParam = "client_id"
			}
			tr, err := client.ManualTokenExchange(ctx, spec.TokenURL, url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
				idParam:         {spec.ClientID},
				"client_secret": {clientSecret},
			})
			if err != nil {
				return RefreshResult{}, err
			}
			if tr.AccessToken == "" {
				return RefreshResult{}, fmt.Errorf("%s: empty access token", provider)
			}
			res := RefreshResult{AccessToken: tr.AccessToken}
			if tr.RefreshToken != "" && tr.RefreshToken != refreshToken {
				res.RefreshToken = tr.RefreshToken // server rotated the refresh token; persist it
			}
			return res, nil
		case RefreshJSON:
			idParam := spec.ClientIDParam
			if idParam == "" {
				idParam = "client_id"
			}
			// Clover v2 authenticates the refresh by client_id + refresh_token; the
			// client_secret is not part of the JSON refresh body.
			tr, err := client.ManualTokenExchangeJSON(ctx, spec.TokenURL, map[string]string{
				idParam:         spec.ClientID,
				"refresh_token": refreshToken,
			})
			if err != nil {
				return RefreshResult{}, err
			}
			if tr.AccessToken == "" {
				return RefreshResult{}, fmt.Errorf("%s: empty access token", provider)
			}
			res := RefreshResult{AccessToken: tr.AccessToken}
			if tr.RefreshToken != "" && tr.RefreshToken != refreshToken {
				res.RefreshToken = tr.RefreshToken // server rotated the refresh token; persist it
			}
			return res, nil
		}
		return RefreshResult{}, fmt.Errorf("%s: unsupported refresh style", provider)
	}
}
