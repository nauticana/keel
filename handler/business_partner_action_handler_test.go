package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

// partnerRepo answers every query with id 42 and keeps the arguments.
type partnerRepo struct {
	actionGrantDB
	args    map[string][]any
	commits int
}

func (p *partnerRepo) Query(_ context.Context, name string, args ...any) (*model.QueryResult, error) {
	p.args[name] = args
	return &model.QueryResult{Rows: [][]any{{int64(42)}}}, nil
}
func (p *partnerRepo) GenID() int64                   { return 0 }
func (p *partnerRepo) Commit(context.Context) error   { p.commits++; return nil }
func (p *partnerRepo) Rollback(context.Context) error { return nil }
func (p *partnerRepo) GetQueryService(context.Context, map[string]string) port.QueryService {
	return p
}
func (p *partnerRepo) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return p, nil
}

func TestBusinessPartnerCreate(t *testing.T) {
	repo := &partnerRepo{actionGrantDB: actionGrantDB{scope: "business_partner", actions: map[string]bool{}}, args: map[string][]any{}}
	h := &BusinessPartnerActionHandler{UserService: &lockUsers{}, DB: repo, Register: &user.RegistrationService{Repo: repo}}
	call := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/business_partner/create", strings.NewReader(body))
		stashSession(r, &model.UserSession{Id: 3})
		w := httptest.NewRecorder()
		h.Routes("/api/v1")["/api/v1/business_partner/create"](w, r)
		return w
	}
	if w := call(`{"caption":"Ops"}`); w.Code != http.StatusForbidden || repo.commits != 0 {
		t.Fatalf("create without BUSINESS_PARTNER CREATE = %d", w.Code)
	}
	repo.actions["BUSINESS_PARTNER/CREATE"] = true
	w := call(`{"caption":"Ops","address":"1 Main St","city":"Fresno","latitude":36.7,"longitude":-119.8}`)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"id":"42"`) || repo.commits != 1 {
		t.Fatalf("create = %d %s, commits %d", w.Code, w.Body, repo.commits)
	}
	if a := repo.args["add_address"]; a[0] != int64(42) || a[1] != "1 Main St" || a[2] != "Fresno" || a[7] != 36.7 || a[8] != -119.8 {
		t.Fatalf("address args = %#v", a)
	}
	if w := call(`{"address":"1 Main St"}`); w.Code != http.StatusBadRequest || repo.commits != 1 {
		t.Fatalf("no caption = %d, commits %d", w.Code, repo.commits)
	}
}
