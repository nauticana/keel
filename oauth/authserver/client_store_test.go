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
	public := &port.OAuthClient{ClientID: "oc_1", TokenAuthMethod: "none", GrantTypes: []string{"authorization_code", "refresh_token"}}

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

	repo.calls = nil
	confidential := &port.OAuthClient{ClientID: "oc_2", TokenAuthMethod: "client_secret_basic", GrantTypes: []string{"client_credentials"}}
	if err := store.CreateClient(ctx, confidential); err != nil || slices.Contains(repo.calls, oauthPendingCount) {
		t.Fatalf("a client the purge does not cover is not counted: %v %v", err, repo.calls)
	}

	for _, rows := range [][][]any{nil, {{}}, {{"two"}}} {
		repo.rows[oauthPendingCount] = rows
		if err := store.CreateClient(ctx, public); err == nil {
			t.Fatalf("malformed count %v must fail closed", rows)
		}
	}
}

func TestPublicClientsOnly(t *testing.T) {
	as, _ := newTestAS(t)
	as.cfg.PublicClientsOnly = true
	ctx := context.Background()
	for _, req := range []port.ClientRegistration{
		{RedirectURIs: []string{"https://app.example/cb"}, TokenAuthMethod: "client_secret_basic"},
		{RedirectURIs: []string{"https://app.example/cb"}, GrantTypes: []string{"authorization_code"}},
	} {
		if _, err := as.Register(ctx, req); !errors.Is(err, ErrOAuthInvalidRequest) {
			t.Fatalf("%+v: err = %v", req, err)
		}
	}
	if _, err := as.Register(ctx, port.ClientRegistration{RedirectURIs: []string{"https://app.example/cb"}}); err != nil {
		t.Fatal(err)
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
