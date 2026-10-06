package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauticana/keel/common"
)

func newAPIKeys(t *testing.T) (*APIKeyService, *quotaFakeQS) {
	t.Helper()
	qs := newQuotaFakeQS()
	qs.rows[insertAPIKey] = [][]any{{int64(1)}}
	qs.rows[insertUserAPIKey] = [][]any{{int64(1)}}
	svc := &APIKeyService{DB: &quotaFakeRepo{qs: qs}, KeyPrefix: "t_"}
	svc.Init(context.Background())
	return svc, qs
}

func TestLookupKeyCarriesUser(t *testing.T) {
	svc, qs := newAPIKeys(t)
	ctx := context.Background()
	qs.rows[validateAPIKey] = [][]any{{int64(5), int64(7), "query", time.Time{}, int64(11)}}
	entry, err := svc.LookupKey(ctx, "h1")
	if err != nil || entry == nil || entry.UserID != 11 || entry.PartnerID != 7 || entry.KeyID != 5 {
		t.Fatalf("entry = %+v, %v", entry, err)
	}
	qs.rows[validateAPIKey] = [][]any{{int64(6), int64(7), "query", time.Time{}, nil}}
	if entry, err = svc.LookupKey(ctx, "h2"); err != nil || entry.UserID != 0 {
		t.Fatalf("partner-only key = %+v, %v", entry, err)
	}
}

func TestAPIKeyMiddlewareBindsUser(t *testing.T) {
	svc, qs := newAPIKeys(t)
	qs.rows[validateAPIKey] = [][]any{{int64(5), int64(7), "query", time.Time{}, int64(11)}}
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
	if _, _, err := svc.InsertKey(ctx, 7, 11, "k", "admin"); !errors.Is(err, ErrInvalidScopes) {
		t.Fatalf("err = %v", err)
	}
	if qs.callIndex(insertUserAPIKey) >= 0 {
		t.Fatal("a refused scope must not be stored")
	}
	if key, _, err := svc.InsertKey(ctx, 7, 11, "k", "query"); err != nil || key[:2] != "t_" {
		t.Fatalf("key %q, %v", key, err)
	}
	// A rolled key keeps scopes the policy no longer admits.
	qs.rows[rotateAPIKey] = [][]any{{"old", "k", "admin", nil}}
	if key, _, err := svc.RotateKey(ctx, 5, 7); err != nil || key == "" {
		t.Fatalf("roll = %q, %v", key, err)
	}
	if args := qs.calls[len(qs.calls)-1].args; args[4] != "admin" {
		t.Fatalf("rolled key args = %v", args)
	}
}
