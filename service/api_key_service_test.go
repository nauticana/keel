package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/guard"
)

func newAPIKeys(t *testing.T) (*APIKeyService, *quotaFakeQS) {
	t.Helper()
	qs := newQuotaFakeQS()
	qs.rows[insertAPIKey] = [][]any{{int64(1)}}
	qs.rows[insertUserAPIKey] = [][]any{{int64(1)}}
	qs.rows[countActiveKeys] = [][]any{{int64(0)}}
	svc := &APIKeyService{DB: &quotaFakeRepo{qs: qs, tx: &quotaFakeTx{quotaFakeQS: qs}}, KeyPrefix: "t_"}
	svc.Init(context.Background())
	return svc, qs
}

func TestLookupKeyCarriesUser(t *testing.T) {
	svc, qs := newAPIKeys(t)
	ctx := context.Background()
	qs.rows[validateAPIKey] = [][]any{{int64(5), int64(7), "query", time.Time{}, int64(11), nil}}
	entry, err := svc.LookupKey(ctx, "h1")
	if err != nil || entry == nil || entry.UserID != 11 || entry.PartnerID != 7 || entry.KeyID != 5 {
		t.Fatalf("entry = %+v, %v", entry, err)
	}
	qs.rows[validateAPIKey] = [][]any{{int64(6), int64(7), "query", time.Time{}, nil, nil}}
	if entry, err = svc.LookupKey(ctx, "h2"); err != nil || entry.UserID != 0 {
		t.Fatalf("partner-only key = %+v, %v", entry, err)
	}
}

func TestAPIKeyMiddlewareBindsUser(t *testing.T) {
	svc, qs := newAPIKeys(t)
	qs.rows[validateAPIKey] = [][]any{{int64(5), int64(7), "query", time.Time{}, int64(11), nil}}
	var got common.CallerSession
	h := APIKeyAuthMiddleware(svc, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = common.CallerSessionFromContext(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("X-API-Key", "t_abc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || got.UserID != 11 || got.PartnerID != 7 || got.APIKeyID != 5 {
		t.Fatalf("status %d session %+v", rec.Code, got)
	}
}

func TestInsertKeyAppliesScopePolicy(t *testing.T) {
	svc, qs := newAPIKeys(t)
	ctx := context.Background()
	svc.ScopePolicy = func(scopes string) error {
		if scopes != "query" {
			return errors.New("only query")
		}
		return nil
	}
	if _, _, err := svc.InsertKey(ctx, 7, 11, "k", "admin", ""); !errors.Is(err, ErrInvalidScopes) {
		t.Fatalf("err = %v", err)
	}
	if qs.callIndex(insertUserAPIKey) >= 0 {
		t.Fatal("a refused scope must not be stored")
	}
	if key, _, err := svc.InsertKey(ctx, 7, 11, "k", "query", ""); err != nil || key[:2] != "t_" {
		t.Fatalf("key %q, %v", key, err)
	}
	// A rolled key keeps scopes the policy no longer admits.
	qs.rows[rotateAPIKey] = [][]any{{"old", "k", "admin", nil, "10.0.0.0/8"}}
	if key, _, err := svc.RotateKey(ctx, 5, 7); err != nil || key == "" {
		t.Fatalf("roll = %q, %v", key, err)
	}
	if args := qs.calls[len(qs.calls)-1].args; args[4] != "admin" || args[5] != "10.0.0.0/8" {
		t.Fatalf("rolled key args = %v", args)
	}
}

func TestInsertKeyWithoutUserUsesPartnerKey(t *testing.T) {
	svc, qs := newAPIKeys(t)
	if _, _, err := svc.InsertKey(context.Background(), 7, 0, "k", "query", ""); err != nil {
		t.Fatal(err)
	}
	if qs.callIndex(insertAPIKey) < 0 || qs.callIndex(insertUserAPIKey) >= 0 {
		t.Fatalf("calls = %+v", qs.calls)
	}
}

func TestInsertKeyCapPerPartner(t *testing.T) {
	svc, qs := newAPIKeys(t)
	ctx := context.Background()
	repo := svc.DB.(*quotaFakeRepo)
	qs.rows[countActiveKeys] = [][]any{{int64(config.Config().APIKeyMaxPerPartner)}}
	if _, _, err := svc.InsertKey(ctx, 7, 11, "k", "query", ""); !errors.Is(err, ErrAPIKeyLimit) {
		t.Fatalf("at the cap = %v", err)
	}
	if qs.callIndex(insertUserAPIKey) >= 0 || repo.tx.rollbacks != 1 {
		t.Fatalf("a refused key must not be stored: calls %+v", qs.calls)
	}
	if qs.calls[0].name != guard.QueryLock || qs.calls[0].args[0] != "guard:api_key:partner:7" || qs.calls[1].args[0] != int64(7) {
		t.Fatalf("count must be serialized per partner: %+v", qs.calls[:2])
	}

	qs.calls = nil
	qs.rows[countActiveKeys] = [][]any{{int64(config.Config().APIKeyMaxPerPartner - 1)}}
	if _, _, err := svc.InsertKey(ctx, 7, 11, "k", "query", ""); err != nil || repo.tx.commits != 1 {
		t.Fatalf("under the cap = %v, commits %d", err, repo.tx.commits)
	}
	// Rolling replaces a key, so it is never refused by the cap.
	qs.rows[rotateAPIKey] = [][]any{{"old", "k", "query", nil, nil}}
	qs.rows[countActiveKeys] = [][]any{{int64(1000)}}
	if key, _, err := svc.RotateKey(ctx, 5, 7); err != nil || key == "" {
		t.Fatalf("roll at the cap = %q, %v", key, err)
	}
}

func TestKeyNetworkAllowList(t *testing.T) {
	svc, qs := newAPIKeys(t)
	ctx := context.Background()
	if _, _, err := svc.InsertKey(ctx, 7, 11, "k", "query", "10.0.0.0/33"); !errors.Is(err, common.ErrInvalidCIDRList) {
		t.Fatalf("bad list = %v", err)
	}
	if _, _, err := svc.InsertKey(ctx, 7, 11, "k", "query", " 192.0.2.9 , 10.1.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if args := qs.calls[len(qs.calls)-1].args; args[5] != "192.0.2.9/32,10.1.0.0/16" {
		t.Fatalf("stored list = %v", args[5])
	}

	qs.rows[validateAPIKey] = [][]any{{int64(5), int64(7), "query", time.Time{}, nil, "192.0.2.0/24"}}
	h := APIKeyAuthMiddleware(svc, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for addr, want := range map[string]int{"192.0.2.10:1234": http.StatusOK, "198.51.100.1:1234": http.StatusForbidden} {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.RemoteAddr = addr
		r.Header.Set("X-API-Key", "t_net")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != want {
			t.Errorf("%s: status %d, want %d", addr, rec.Code, want)
		}
	}
}

func TestRestrictKey(t *testing.T) {
	svc, qs := newAPIKeys(t)
	ctx := context.Background()
	qs.rows[validateAPIKey] = [][]any{{int64(5), int64(7), "query", time.Time{}, nil, nil}}
	if _, err := svc.LookupKey(ctx, "h5"); err != nil {
		t.Fatal(err)
	}
	qs.rows[restrictAPIKey] = [][]any{{"h5"}}
	if found, err := svc.RestrictKey(ctx, 5, 7, "2001:db8::/32"); err != nil || !found {
		t.Fatalf("restrict = %v, %v", found, err)
	}
	if args := qs.calls[len(qs.calls)-1].args; args[0] != "2001:db8::/32" || args[1] != int64(5) || args[2] != int64(7) {
		t.Fatalf("restrict args = %v", args)
	}
	qs.rows[validateAPIKey] = [][]any{{int64(5), int64(7), "query", time.Time{}, nil, "2001:db8::/32"}}
	if entry, _ := svc.LookupKey(ctx, "h5"); entry == nil || common.CIDRListAllows(entry.AllowedNets, "192.0.2.1") {
		t.Fatal("the cached entry must be dropped so the new list applies at once")
	}
	if found, err := svc.RestrictKey(ctx, 5, 7, ""); err != nil || !found || qs.calls[len(qs.calls)-1].args[0] != nil {
		t.Fatalf("clearing = %v, %v", found, err)
	}
	qs.rows[restrictAPIKey] = nil
	if found, err := svc.RestrictKey(ctx, 5, 8, ""); err != nil || found {
		t.Fatalf("another partner's key = %v, %v", found, err)
	}
	if _, err := svc.RestrictKey(ctx, 5, 7, "nope"); !errors.Is(err, common.ErrInvalidCIDRList) {
		t.Fatalf("bad list = %v", err)
	}
}
