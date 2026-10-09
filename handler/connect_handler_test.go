package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/client"
	"github.com/nauticana/keel/oauth/connect"
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

type boundProvider struct{ completed []client.Initiator }

func (p *boundProvider) AuthURL(context.Context, int64, map[string]string) (string, error) {
	return "", nil
}
func (p *boundProvider) Test(context.Context, int64) error { return nil }
func (p *boundProvider) Callback(ctx context.Context, code, state string) error {
	i, _ := client.InitiatorFrom(ctx)
	if code != "c1" || state != "s1" || i != (client.Initiator{UserID: 3, PartnerID: 42}) {
		return connect.ErrStateNotBound
	}
	p.completed = append(p.completed, i)
	return nil
}

func TestConnectCallbackCompletesOnlyForTheInitiator(t *testing.T) {
	nonce := &connect.NonceService{DB: &nonceDB{rows: map[string][2]string{}}}
	nonce.Init(context.Background())
	provider := &boundProvider{}
	h := &OAuthConnectHandler{Nonce: nonce, FrontendReturnURL: "https://app.example/connections"}

	callback := func() string {
		rec := httptest.NewRecorder()
		h.callback("gsc", provider)(rec, httptest.NewRequest(http.MethodGet, "/api/oauth/gsc/callback?code=c1&state=s1", nil))
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if rec.Code != http.StatusFound || loc.Query().Get("connect") != "gsc" || loc.Query().Get("ticket") == "" {
			t.Fatalf("callback: %d %q", rec.Code, rec.Header().Get("Location"))
		}
		if len(provider.completed) != 0 {
			t.Fatal("the callback must not connect without the signed-in user")
		}
		return loc.Query().Get("ticket")
	}
	complete := func(ticket string, session *model.UserSession) int {
		r := httptest.NewRequest(http.MethodPost, "/api/oauth/gsc/complete", strings.NewReader(`{"ticket":"`+ticket+`"}`))
		stashSession(r, session)
		rec := httptest.NewRecorder()
		h.complete("gsc", provider)(rec, r)
		return rec.Code
	}

	ticket := callback()
	if code := complete(ticket, &model.UserSession{Id: 9, PartnerId: 42}); code != http.StatusForbidden {
		t.Fatalf("another user: %d", code)
	}
	if code := complete(ticket, &model.UserSession{Id: 3, PartnerId: 42}); code != http.StatusOK || len(provider.completed) != 1 {
		t.Fatalf("initiator: %d", code)
	}
	if code := complete(ticket, &model.UserSession{Id: 3, PartnerId: 42}); code != http.StatusBadRequest {
		t.Fatalf("a ticket is single-use: %d", code)
	}
	if code := complete(`x"}{"ticket":"y`, &model.UserSession{Id: 3, PartnerId: 42}); code != http.StatusBadRequest {
		t.Fatalf("trailing JSON: %d", code)
	}
}
