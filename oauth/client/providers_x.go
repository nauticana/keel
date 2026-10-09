package client

import "golang.org/x/oauth2"

// XEndpoint is X's OAuth 2.0 endpoint; confidential clients authenticate with
// HTTP Basic.
var XEndpoint = oauth2.Endpoint{
	AuthURL:   "https://x.com/i/oauth2/authorize",
	TokenURL:  "https://api.x.com/2/oauth2/token",
	AuthStyle: oauth2.AuthStyleInHeader,
}

const xAPIBase = "https://api.x.com/2"

// NewXProvider builds an X (Twitter) provider. PKCE is mandatory on X, and
// offline.access is always requested because the connection keeps a refresh
// token. Test checks the token against /users/me.
func NewXProvider(svc CredentialStore, name, callbackURL, clientID, secretName string, scopes []string) *BaseProvider {
	return &BaseProvider{
		Service:        svc,
		ProviderName:   name,
		CallbackURL:    callbackURL,
		ClientID:       clientID,
		SecretName:     secretName,
		Endpoint:       XEndpoint,
		Scopes:         mergeScopes(scopes, "offline.access"),
		UsePKCE:        true,
		RequireRefresh: true,
		APIEndpoint:    xAPIBase,
		TestEndpoint:   xAPIBase + "/users/me",
	}
}
