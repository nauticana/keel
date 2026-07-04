package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/client"
)

func TestParseEntity(t *testing.T) {
	ok := map[string]int64{"": 0, "0": 0, "42": 42}
	for in, want := range ok {
		if got, err := parseEntity(in); err != nil || got != want {
			t.Errorf("parseEntity(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"abc", "-1", "1.5", " 3"} {
		if got, err := parseEntity(in); err == nil {
			t.Errorf("parseEntity(%q) = %d, want error", in, got)
		}
	}
}

func TestGateFailsClosed(t *testing.T) {
	h := &OAuthConnectHandler{} // no Authz, no AllowAnyPartner
	called := false
	rec := httptest.NewRecorder()
	h.gate(func(http.ResponseWriter, *http.Request) { called = true })(rec, httptest.NewRequest("GET", "/x", nil))
	if called {
		t.Fatal("inner must not run when authorization is unconfigured")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

func TestGateAllowAnyPartner(t *testing.T) {
	h := &OAuthConnectHandler{AllowAnyPartner: true}
	called := false
	h.gate(func(http.ResponseWriter, *http.Request) { called = true })(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	if !called {
		t.Fatal("AllowAnyPartner should pass through")
	}
}

func TestGateAppliesAuthz(t *testing.T) {
	wrapped := false
	h := &OAuthConnectHandler{Authz: func(inner http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { wrapped = true; inner(w, r) }
	}}
	h.gate(func(http.ResponseWriter, *http.Request) {})(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	if !wrapped {
		t.Fatal("Authz middleware should wrap the route")
	}
}

func TestRouteMethodGuards(t *testing.T) {
	h := &OAuthConnectHandler{}
	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
	}{
		{"authorize", h.authorize("x", nil), http.MethodPost}, // GET-only
		{"test", h.test("x", nil), http.MethodGet},            // POST-only
		{"apikey", h.saveAPIKey, http.MethodGet},              // POST-only
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		c.handler(rec, httptest.NewRequest(c.method, "/x", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s with %s: want 405, got %d", c.name, c.method, rec.Code)
		}
	}
}

func TestSaveAPIKeyRejectsOAuthProvider(t *testing.T) {
	h := &OAuthConnectHandler{Providers: map[string]client.Provider{"gsc": nil}}
	r := httptest.NewRequest("POST", "/api/oauth/apikey", strings.NewReader(`{"provider":"gsc","cred_ref":"x"}`))
	stashSession(r, &model.UserSession{PartnerId: 42})
	rec := httptest.NewRecorder()
	h.saveAPIKey(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("posting an OAuth provider to /apikey must be rejected, got %d", rec.Code)
	}
}
