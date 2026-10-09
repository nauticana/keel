package authserver

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nauticana/keel/guard"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type grantRepo struct {
	port.DatabaseRepository
	rows        map[string][][]any
	args        map[string][]any
	calls       []string
	commits     int
	err         error
	rollbackErr error
}

func (r *grantRepo) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return r, nil
}
func (r *grantRepo) Commit(context.Context) error   { r.commits++; return nil }
func (r *grantRepo) Rollback(context.Context) error { return r.rollbackErr }

func (r *grantRepo) GetQueryService(context.Context, map[string]string) port.QueryService { return r }
func (r *grantRepo) GenID() int64                                                         { return 0 }
func (r *grantRepo) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	if r.args == nil {
		r.args = map[string][]any{}
	}
	r.args[name] = args
	r.calls = append(r.calls, name)
	return &model.QueryResult{Rows: r.rows[name]}, r.err
}

func TestGrantService(t *testing.T) {
	ctx := context.Background()
	first := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	repo := &grantRepo{rows: map[string][][]any{
		oauthGrantList: {{"client-a", "Assistant", "write read read", first, first.Add(time.Hour)}},
	}}
	svc := &GrantService{DB: repo}

	grants, err := svc.List(ctx, 7)
	if err != nil || len(grants) != 1 {
		t.Fatalf("List = %v, %v", grants, err)
	}
	g := grants[0]
	if g.ClientID != "client-a" || g.ClientName != "Assistant" || strings.Join(g.Scopes, " ") != "read write" || !g.AuthorizedAt.Equal(first) {
		t.Fatalf("grant = %+v", g)
	}
	if none, err := svc.List(ctx, 0); err != nil || none != nil {
		t.Fatalf("no user = %v, %v", none, err)
	}

	if active, _ := svc.Active(ctx, 7, "client-a"); active {
		t.Fatal("no live refresh token means no grant")
	}
	repo.rows[oauthGrantActive] = [][]any{{1}}
	if active, err := svc.Active(ctx, 7, "client-a"); err != nil || !active {
		t.Fatalf("Active = %v, %v", active, err)
	}
	if active, _ := svc.Active(ctx, 0, "client-a"); active {
		t.Fatal("a missing user is never active")
	}

	if err := svc.Revoke(ctx, 7, "client-a"); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("nothing to revoke: %v", err)
	}
	repo.rows[oauthGrantRevoke] = [][]any{{int64(1)}, {int64(2)}}
	if err := svc.Revoke(ctx, 7, "client-a"); err != nil {
		t.Fatal(err)
	}
	if got := repo.args[oauthGrantRevoke]; got[0] != int64(7) || got[1] != "client-a" {
		t.Fatalf("revoke is scoped to the user and client: %v", got)
	}

	repo.rows[oauthClientPurge] = [][]any{{"stale-1"}, {"stale-2"}}
	if n, err := svc.PurgeUnauthorizedClients(ctx, 24*time.Hour); err != nil || n != 2 {
		t.Fatalf("purge = %d, %v", n, err)
	}
	if got := repo.args[oauthClientPurge]; got[0] != 86400 || got[1] != purgeBatch {
		t.Fatalf("purge args = %v", got)
	}
	if _, err := svc.PurgeUnauthorizedClients(ctx, time.Second); err == nil {
		t.Fatal("a tiny age would delete clients mid-registration")
	}

	repo.err = errors.New("database down")
	if active, err := svc.Active(ctx, 7, "client-a"); err == nil || active {
		t.Fatalf("a failed lookup must not report an active grant: %v, %v", active, err)
	}
}

// The statements must keep their safety predicates.
func TestGrantQueriesStayScoped(t *testing.T) {
	for name, wants := range map[string][]string{
		oauthGrantRevoke: {"user_id = ?", "client_id = ?"},
		oauthGrantActive: {"user_id = ?", "client_id = ?", "revoked_at IS NULL", "expires_at > CURRENT_TIMESTAMP"},
		oauthClientPurge: {"registered = TRUE", "refresh_token", "NOT EXISTS (SELECT 1 FROM oauth_refresh_token", "NOT EXISTS (SELECT 1 FROM oauth_authorization_code", "LIMIT ?"},
	} {
		for _, want := range wants {
			if !strings.Contains(oauthGrantQueries[name], want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}
}

// A revocation and a concurrent refresh rotation take the same lock, so the
// rotation cannot slip a replacement token past the revocation.
func TestGrantRevokeIsSerializedWithRotation(t *testing.T) {
	ctx := context.Background()
	repo := &grantRepo{rows: map[string][][]any{
		oauthGrantRevoke:    {{int64(1)}},
		oauthConsumeRefresh: {{"old"}},
	}}
	if err := (&GrantService{DB: repo}).Revoke(ctx, 7, "client-a"); err != nil {
		t.Fatal(err)
	}
	if len(repo.calls) != 2 || repo.calls[0] != guard.QueryLock || repo.calls[1] != oauthGrantRevoke || repo.commits != 1 {
		t.Fatalf("revoke calls = %v, commits = %d", repo.calls, repo.commits)
	}
	revokeLock := repo.args[guard.QueryLock][0]

	repo.calls = nil
	store := &TokenStoreDB{DB: repo}
	err := store.Rotate(ctx, "old", &port.RefreshToken{TokenHash: "new", FamilyID: "f", ClientID: "client-a", UserID: 7})
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.calls) != 3 || repo.calls[0] != guard.QueryLock || repo.calls[1] != oauthConsumeRefresh || repo.calls[2] != oauthInsertRefresh {
		t.Fatalf("rotate calls = %v", repo.calls)
	}
	if got := repo.args[guard.QueryLock][0]; got != revokeLock {
		t.Fatalf("rotation locks %v, revocation locks %v", got, revokeLock)
	}
	if grantLockKey(7, "client-a") == grantLockKey(7, "client-b") || grantLockKey(7, "client-a") == grantLockKey(8, "client-a") {
		t.Fatal("the lock must be per user and client")
	}

	// A token already revoked by the grant revocation cannot be rotated.
	repo.rows[oauthConsumeRefresh] = nil
	if err := store.Rotate(ctx, "old", &port.RefreshToken{TokenHash: "new2", ClientID: "client-a", UserID: 7}); !errors.Is(err, errRefreshConsumed) {
		t.Fatalf("rotation after revocation: %v", err)
	}
}
