package authserver

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nauticana/keel/guard"
	"github.com/nauticana/keel/model"
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

// Registration deletes abandoned registrations first, under the lock and
// before the count when bounded, so they never hold pending slots.
func TestClientStorePurgesOnRegistration(t *testing.T) {
	ctx := context.Background()
	public := &port.OAuthClient{ClientID: "oc_1", TokenAuthMethod: "none", GrantTypes: registrationGrants, Registered: true}
	for _, max := range []int{0, 2} {
		repo := &grantRepo{rows: map[string][][]any{oauthPendingCount: {{int64(1)}}}}
		store := &ClientStoreDB{DB: repo, MaxPending: max, PurgeAge: time.Hour}
		store.Init(ctx)
		if err := store.CreateClient(ctx, public); err != nil {
			t.Fatal(err)
		}
		purge, insert := slices.Index(repo.calls, oauthClientPurge), slices.Index(repo.calls, oauthInsertClient)
		if purge < 0 || insert < purge || repo.args[oauthClientPurge][0] != 3600 || repo.args[oauthClientPurge][1] != purgeBatch {
			t.Fatalf("max %d: calls %v args %v", max, repo.calls, repo.args[oauthClientPurge])
		}
		if max > 0 && (slices.Index(repo.calls, guard.QueryLock) > purge || slices.Index(repo.calls, oauthPendingCount) < purge) {
			t.Fatalf("purge must run under the lock and before the count: %v", repo.calls)
		}
	}

	repo := &grantRepo{}
	store := &ClientStoreDB{DB: repo}
	store.Init(ctx)
	if err := store.CreateClient(ctx, public); err != nil || slices.Contains(repo.calls, oauthClientPurge) {
		t.Fatalf("zero PurgeAge keeps registrations: %v %v", err, repo.calls)
	}
	repo.calls = nil
	if err := store.CreateClient(ctx, &port.OAuthClient{ClientID: "oc_2", GrantTypes: []string{"client_credentials"}}); err != nil || len(repo.calls) != 1 {
		t.Fatalf("a provisioned client purges nothing: %v %v", err, repo.calls)
	}

	failing := &grantRepo{err: errors.New("db down")}
	store = &ClientStoreDB{DB: failing, PurgeAge: time.Hour}
	store.Init(ctx)
	if err := store.CreateClient(ctx, public); err == nil || slices.Contains(failing.calls, oauthInsertClient) {
		t.Fatalf("a failed purge must refuse: %v %v", err, failing.calls)
	}
}

func TestSaveCodePurgesFirst(t *testing.T) {
	ctx := context.Background()
	repo := &grantRepo{}
	codes := &CodeStoreDB{DB: repo}
	codes.Init(ctx)
	if err := codes.SaveCode(ctx, &port.AuthCode{Code: "c"}, time.Minute); err != nil ||
		!slices.Equal(repo.calls, []string{oauthPurgeCodes, oauthInsertCode}) || repo.args[oauthPurgeCodes][0] != purgeBatch {
		t.Fatalf("err %v calls %v args %v", err, repo.calls, repo.args[oauthPurgeCodes])
	}
}

// PurgeExpired repeats full batches until a short one.
func TestPurgeExpiredRepeatsBatches(t *testing.T) {
	ctx := context.Background()
	repo := &batchRepo{sizes: []int{purgeBatch, purgeBatch, 1}}
	codes := &CodeStoreDB{DB: repo}
	codes.Init(ctx)
	if err := codes.PurgeExpired(ctx); err != nil || repo.calls != 3 {
		t.Fatalf("err %v calls %d", err, repo.calls)
	}
	repo = &batchRepo{grantRepo: grantRepo{err: errors.New("db down")}}
	codes = &CodeStoreDB{DB: repo}
	codes.Init(ctx)
	if err := codes.PurgeExpired(ctx); err == nil || repo.calls != 1 {
		t.Fatalf("err %v calls %d", err, repo.calls)
	}
}

// batchRepo answers each query with the next batch size.
type batchRepo struct {
	grantRepo
	sizes []int
	calls int
}

func (r *batchRepo) GetQueryService(context.Context, map[string]string) port.QueryService { return r }
func (r *batchRepo) Query(context.Context, string, ...any) (*model.QueryResult, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	n := r.sizes[0]
	r.sizes = r.sizes[1:]
	return &model.QueryResult{Rows: make([][]any, n)}, nil
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
