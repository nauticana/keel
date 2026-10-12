package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/authserver"
	"github.com/nauticana/keel/port"
)

// oauthGrantDB holds one live grant, of client-a to user 5.
type oauthGrantDB struct {
	port.DatabaseRepository
	args [][]any
}

func (d *oauthGrantDB) GetQueryService(context.Context, map[string]string) port.QueryService {
	return d
}
func (d *oauthGrantDB) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return d, nil
}
func (d *oauthGrantDB) GenID() int64                   { return 0 }
func (d *oauthGrantDB) Commit(context.Context) error   { return nil }
func (d *oauthGrantDB) Rollback(context.Context) error { return nil }
func (d *oauthGrantDB) Query(_ context.Context, _ string, args ...any) (*model.QueryResult, error) {
	d.args = append(d.args, args)
	if len(args) > 0 && args[0] == int64(5) && (len(args) < 2 || args[1] != "client-b") {
		return &model.QueryResult{Rows: [][]any{{"client-a", "Assistant", "read", nil, nil}}}, nil
	}
	return &model.QueryResult{}, nil
}

func TestGrantRoutes(t *testing.T) {
	db := &oauthGrantDB{}
	routes := (&GrantHandler{AbstractHandler: AbstractHandler{UserService: &sessionUsers{}}, Grants: &authserver.GrantService{DB: db}}).GetAuthRoutes()
	authed := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer t")
		rec := httptest.NewRecorder()
		routes[path](rec, req)
		return rec
	}

	rec := authed(http.MethodGet, "/api/user/oauth-grants", "")
	var out struct {
		Data []authserver.Grant `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK || len(out.Data) != 1 || out.Data[0].ClientID != "client-a" {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	if rec := authed(http.MethodPost, "/api/user/oauth-grants", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("list by POST = %d", rec.Code)
	}
	if rec := authed(http.MethodPost, "/api/user/oauth-grants/revoke", `{"clientId":"client-a"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body.String())
	}
	if last := db.args[len(db.args)-1]; last[0] != int64(5) || last[1] != "client-a" {
		t.Fatalf("revoke args = %v, want the session user's", last)
	}
	for _, body := range []string{`{"clientId":"client-b"}`, `{}`} {
		if rec := authed(http.MethodPost, "/api/user/oauth-grants/revoke", body); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "grant_not_found") {
			t.Fatalf("revoke %s = %d %s", body, rec.Code, rec.Body.String())
		}
	}
	unauthed := httptest.NewRecorder()
	routes["/api/user/oauth-grants"](unauthed, httptest.NewRequest(http.MethodGet, "/api/user/oauth-grants", nil))
	if unauthed.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d", unauthed.Code)
	}
}
