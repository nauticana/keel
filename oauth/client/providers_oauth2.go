package client

import "golang.org/x/oauth2"

// NewOAuth2Provider builds a provider for any standards-compliant OAuth2
// authorization-code service (Amazon, LinkedIn, Slack, GitHub, …). Set
// requireRefresh when the provider must return a refresh token; set UsePKCE on
// the result for PKCE.
func NewOAuth2Provider(svc CredentialStore, name, callbackURL, clientID, secretName string, endpoint oauth2.Endpoint, scopes []string, apiEndpoint string, requireRefresh bool) *BaseProvider {
	return &BaseProvider{
		Service:        svc,
		ProviderName:   name,
		CallbackURL:    callbackURL,
		ClientID:       clientID,
		SecretName:     secretName,
		Endpoint:       endpoint,
		Scopes:         scopes,
		APIEndpoint:    apiEndpoint,
		RequireRefresh: requireRefresh,
	}
}
