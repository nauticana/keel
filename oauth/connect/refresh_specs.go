package connect

import "github.com/nauticana/keel/oauth/client"

// XRefreshSpec refreshes an X connection; X rotates the refresh token on use.
func XRefreshSpec(clientID, secretName string) RefreshSpec {
	return RefreshSpec{ClientID: clientID, SecretName: secretName, Endpoint: client.XEndpoint, Style: RefreshOAuth2Lib}
}

// TikTokRefreshSpec refreshes a TikTok connection with its client key.
func TikTokRefreshSpec(clientKey, secretName string) RefreshSpec {
	return RefreshSpec{ClientID: clientKey, SecretName: secretName, TokenURL: client.TikTokEndpoint.TokenURL, Style: RefreshForm, ClientIDParam: "client_key"}
}
