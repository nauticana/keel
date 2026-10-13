package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/oauth/authserver"
)

type fakeGrants struct{ revoked bool }

func (f *fakeGrants) List(_ context.Context, userID int64) ([]authserver.Grant, error) {
	if userID != 5 {
		return nil, nil
	}
	return []authserver.Grant{{ClientID: "client-a"}}, nil
}

func (f *fakeGrants) Revoke(_ context.Context, userID int64, clientID string) error {
	if userID != 5 || clientID != "client-a" {
		return authserver.ErrGrantNotFound
	}
	f.revoked = true
	return nil
}

func TestGrantRoutes(t *testing.T) {
	grants := &fakeGrants{}
	routes := (&GrantHandler{AbstractHandler: AbstractHandler{UserService: &sessionUsers{}}, Grants: grants}).GetAuthRoutes()
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
	if !grants.revoked {
		t.Fatal("revoke did not reach the session user's grant")
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
