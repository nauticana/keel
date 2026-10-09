package authserver

import (
	"context"
	"errors"
	"testing"

	"github.com/nauticana/keel/port"
)

func redeem(as *Local, code, verifier, resource string, client *port.OAuthClient) (*port.TokenResponse, error) {
	return as.Token(context.Background(), port.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: "https://app.example/cb",
		CodeVerifier: verifier, Resource: resource, Client: port.ClientAuth{ClientID: client.ClientID},
	})
}

func TestCodeReplayRevokesItsGrant(t *testing.T) {
	as, _ := newTestAS(t)
	verifier := "v-1234567890-1234567890-1234567890-abcd"
	code, client := authCodeFor(t, as, pkce(verifier))
	tok, err := redeem(as, code, verifier, "", client)
	if err != nil {
		t.Fatal(err)
	}
	other, err := as.Provision(context.Background(), port.ClientRegistration{
		RedirectURIs: []string{"https://app.example/cb"}, GrantTypes: []string{"authorization_code"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := redeem(as, code, verifier, "", other); !errors.Is(err, ErrOAuthInvalidGrant) {
		t.Fatalf("replay by another client err = %v", err)
	}
	if live, _ := as.tokens.GrantActive(context.Background(), 7, client.ClientID); !live {
		t.Fatal("another client must not revoke the code owner's grant")
	}
	if _, err := redeem(as, code, verifier, "", client); !errors.Is(err, ErrOAuthInvalidGrant) {
		t.Fatalf("replay err = %v", err)
	}
	if live, _ := as.tokens.GrantActive(context.Background(), 7, client.ClientID); live {
		t.Fatal("a replayed code must revoke the grant it issued")
	}
	if _, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "refresh_token", RefreshToken: tok.RefreshToken, Client: port.ClientAuth{ClientID: client.ClientID},
	}); !errors.Is(err, ErrOAuthInvalidGrant) {
		t.Fatalf("refresh after replay err = %v", err)
	}
}

func TestTokenRequestResourceMustMatchGrant(t *testing.T) {
	as, _ := newTestAS(t)
	verifier := "v-1234567890-1234567890-1234567890-abcd"
	code, client := authCodeFor(t, as, pkce(verifier))
	if _, err := redeem(as, code, verifier, "https://other.example", client); !errors.Is(err, ErrOAuthInvalidTarget) {
		t.Fatalf("other resource err = %v", err)
	}
	code, client = authCodeFor(t, as, pkce(verifier))
	tok, err := redeem(as, code, verifier, "https://rs.example", client)
	if err != nil {
		t.Fatalf("granted resource err = %v", err)
	}
	if _, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "refresh_token", RefreshToken: tok.RefreshToken, Resource: "https://other.example",
		Client: port.ClientAuth{ClientID: client.ClientID},
	}); !errors.Is(err, ErrOAuthInvalidTarget) {
		t.Fatalf("refresh to another resource err = %v", err)
	}
}

func TestRevokingAnAccessTokenEndsItsGrant(t *testing.T) {
	as, _ := newTestAS(t)
	access, client := mintToken(t, as, []string{"read"}, "https://rs.example")
	auth := port.ClientAuth{ClientID: client.ClientID}
	if res, err := as.Introspect(context.Background(), access, auth); err != nil || !res.Active {
		t.Fatalf("before revoke: %+v %v", res, err)
	}
	if err := as.Revoke(context.Background(), "", "", auth); !errors.Is(err, ErrOAuthInvalidRequest) {
		t.Fatalf("missing token err = %v", err)
	}
	if err := as.Revoke(context.Background(), access, "access_token", auth); err != nil {
		t.Fatal(err)
	}
	if res, err := as.Introspect(context.Background(), access, auth); err != nil || res.Active {
		t.Fatalf("after revoke: %+v %v", res, err)
	}
}

func TestTokenExchangeReportsIssuedTokenType(t *testing.T) {
	as, _ := newTestAS(t)
	subject, _ := mintToken(t, as, []string{"read"}, "https://rs.example")
	ex, err := as.Provision(context.Background(), port.ClientRegistration{
		Scopes: []string{"read"}, TokenAuthMethod: "client_secret_basic",
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := as.Token(context.Background(), port.TokenRequest{
		GrantType: "urn:ietf:params:oauth:grant-type:token-exchange", SubjectToken: subject,
		SubjectTokenType: tokenTypeAccessToken,
		Client:           port.ClientAuth{ClientID: ex.ClientID, ClientSecret: ex.Secret, Method: "client_secret_basic"},
	})
	if err != nil || resp.IssuedTokenType != tokenTypeAccessToken {
		t.Fatalf("resp %+v err %v", resp, err)
	}
}
