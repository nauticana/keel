package authserver

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nauticana/keel/guard"
	"github.com/nauticana/keel/port"
)

func TestClientStoreBoundsPendingClients(t *testing.T) {
	ctx := context.Background()
	repo := &grantRepo{rows: map[string][][]any{oauthPendingCount: {{int64(2)}}}}
	store := &ClientStoreDB{DB: repo, MaxPending: 2}
	store.Init(ctx)
	public := &port.OAuthClient{ClientID: "oc_1", TokenAuthMethod: "none", GrantTypes: registrationGrants, Registered: true}

	if err := store.CreateClient(ctx, public); !errors.Is(err, ErrOAuthClientLimit) {
		t.Fatalf("err = %v", err)
	}
	if slices.Contains(repo.calls, oauthInsertClient) || repo.commits != 0 {
		t.Fatalf("a refused client must not be inserted: %v", repo.calls)
	}
	if lock, count := slices.Index(repo.calls, guard.QueryLock), slices.Index(repo.calls, oauthPendingCount); lock < 0 || count < lock {
		t.Fatalf("the count must run under the lock: %v", repo.calls)
	}
	rollbackErr := errors.New("rollback failed")
	repo.rollbackErr = rollbackErr
	if err := store.CreateClient(ctx, public); !errors.Is(err, ErrOAuthClientLimit) || !errors.Is(err, rollbackErr) {
		t.Fatalf("limit and rollback errors must both be reported: %v", err)
	}
	repo.rollbackErr = nil

	repo.rows[oauthPendingCount] = [][]any{{int64(1)}}
	if err := store.CreateClient(ctx, public); err != nil || repo.commits != 1 {
		t.Fatalf("err %v commits %d", err, repo.commits)
	}

	repo.rows[oauthPendingCount] = [][]any{{int64(2)}}
	confidential := &port.OAuthClient{ClientID: "oc_2", TokenAuthMethod: "client_secret_post", GrantTypes: registrationGrants, Registered: true}
	if err := store.CreateClient(ctx, confidential); !errors.Is(err, ErrOAuthClientLimit) {
		t.Fatalf("a registered confidential client counts toward the bound: %v", err)
	}

	repo.calls = nil
	provisioned := &port.OAuthClient{ClientID: "oc_3", TokenAuthMethod: "client_secret_basic", GrantTypes: registrationGrants}
	if err := store.CreateClient(ctx, provisioned); err != nil || slices.Contains(repo.calls, oauthPendingCount) {
		t.Fatalf("a provisioned client is not counted: %v %v", err, repo.calls)
	}

	for _, rows := range [][][]any{nil, {{}}, {{"two"}}} {
		repo.rows[oauthPendingCount] = rows
		if err := store.CreateClient(ctx, public); err == nil {
			t.Fatalf("malformed count %v must fail closed", rows)
		}
	}
}

func TestRegistrationPolicy(t *testing.T) {
	as, _ := newTestAS(t)
	ctx := context.Background()
	cb := []string{"https://app.example/cb"}
	for _, req := range []port.ClientRegistration{
		{RedirectURIs: cb, TokenAuthMethod: "client_secret_post", GrantTypes: []string{"authorization_code", "refresh_token"}},
		{RedirectURIs: cb},
		{RedirectURIs: cb, GrantTypes: []string{"authorization_code"}},
	} {
		c, err := as.Register(ctx, req)
		if err != nil {
			t.Fatalf("%+v: %v", req, err)
		}
		if !c.Registered || !slices.Equal(c.GrantTypes, registrationGrants) || (c.TokenAuthMethod != "none") != (c.Secret != "") {
			t.Fatalf("%+v registered as %+v", req, c)
		}
	}
	for _, gt := range []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange", "password"} {
		req := port.ClientRegistration{RedirectURIs: cb, TokenAuthMethod: "client_secret_basic", GrantTypes: []string{"authorization_code", gt}}
		if _, err := as.Register(ctx, req); !errors.Is(err, ErrOAuthInvalidClientMetadata) || ProtocolErrorDescription(err) == "" {
			t.Fatalf("%s: err = %v", gt, err)
		}
	}
	if _, err := as.Register(ctx, port.ClientRegistration{}); !errors.Is(err, ErrOAuthInvalidRedirectURI) {
		t.Fatalf("no redirect_uris: err = %v", err)
	}

	md := as.Metadata()
	if !slices.Equal(md.TokenEndpointAuthMethodsSupported, []string{"none", "client_secret_basic", "client_secret_post"}) {
		t.Fatalf("auth methods = %v", md.TokenEndpointAuthMethodsSupported)
	}
	if !slices.IsSorted(md.GrantTypesSupported) || !slices.Contains(md.GrantTypesSupported, "authorization_code") {
		t.Fatalf("grant types = %v", md.GrantTypesSupported)
	}
	if !slices.Equal(md.ResponseModesSupported, []string{"query"}) || !md.AuthorizationResponseIssParameterSupported ||
		!slices.Contains(md.RevocationEndpointAuthMethodsSupported, "none") || !slices.Contains(md.IntrospectionEndpointAuthMethodsSupported, "none") {
		t.Fatalf("metadata = %+v", md)
	}
}

func TestUserIDFromSubject(t *testing.T) {
	if id, ok := UserIDFromSubject(subjectForUser(42)); !ok || id != 42 {
		t.Fatalf("round trip = %d, %v", id, ok)
	}
	for _, sub := range []string{"", "42", "user:", "user:0", "user:-1", "user:x", "client:42"} {
		if _, ok := UserIDFromSubject(sub); ok {
			t.Fatalf("%q must not parse", sub)
		}
	}
}
