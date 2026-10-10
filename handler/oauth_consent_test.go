package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nauticana/keel/oauth/authserver"
)

const consentQuery = "/oauth/authorize?response_type=code&client_id=c&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&state=s&code_challenge=x&code_challenge_method=S256"

// signedIn returns a handler whose AS session cookie belongs to user 7.
func signedIn(t *testing.T) (*OAuthASHandler, *http.ServeMux, *http.Cookie) {
	t.Helper()
	h, _, mux := newHandoffHandler(t)
	h.AS = issuerAS{endpoint: handoffAuthorize}
	u, _ := url.Parse(mintRedirect(t, mux, handoffAuthorize))
	c := sessionCookie(get(mux, u.RequestURI()))
	if c == nil {
		t.Fatal("no session cookie")
	}
	return h, mux, c
}

func TestConsentNamesTheAccountAndOffersAnother(t *testing.T) {
	_, mux, c := signedIn(t)
	rec := get(mux, consentQuery, c)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Signed in as <strong>Ada Lovelace</strong> (ada@example.com)") ||
		!strings.Contains(body, `name="switch_account"`) {
		t.Fatalf("consent = %d: %s", rec.Code, body)
	}
}

func TestSwitchAccountEndsSessionAndAsksToSignIn(t *testing.T) {
	h, mux, c := signedIn(t)
	csrf := h.csrfGuard(httptest.NewRequest(http.MethodGet, consentQuery, nil))
	issue := httptest.NewRecorder()
	token, err := csrf.Issue(issue)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"response_type": {"code"}, "client_id": {"c"}, "redirect_uri": {"https://app.example/cb"}, "state": {"s"},
		"code_challenge": {"x"}, "code_challenge_method": {"S256"}, "csrf": {token}, "switch_account": {"true"}}
	req := httptest.NewRequest(http.MethodPost, authserver.OAuthAuthorizePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(c)
	for _, ck := range issue.Result().Cookies() {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	loginRedirect(t, rec, "login")
	if ended := sessionCookie(rec); ended == nil || ended.MaxAge >= 0 {
		t.Fatalf("session cookie not cleared: %+v", ended)
	}
	rec = get(mux, consentQuery, c)
	if loc, _ := url.Parse(rec.Header().Get("Location")); rec.Code != http.StatusFound || loc.Host != "app.example.com" {
		t.Fatalf("ended session still authorizes: %d %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestPromptLoginAndSelectAccountSignInAgain(t *testing.T) {
	_, mux, c := signedIn(t)
	for _, prompt := range []string{"login", "select_account", "consent select_account"} {
		rec := get(mux, consentQuery+"&_authretry=1&prompt="+url.QueryEscape(prompt), c)
		loginRedirect(t, rec, strings.TrimPrefix(prompt, "consent "))
	}
}

func TestPromptLoginCannotBeBypassedWithPost(t *testing.T) {
	_, mux, c := signedIn(t)
	form, _ := url.ParseQuery(strings.TrimPrefix(consentQuery, authserver.OAuthAuthorizePath+"?"))
	form.Set("prompt", "login")
	form.Set("approve", "true")
	req := httptest.NewRequest(http.MethodPost, authserver.OAuthAuthorizePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	loginRedirect(t, rec, "login")
}

func TestPromptNone(t *testing.T) {
	_, mux, c := signedIn(t)
	for query, want := range map[string]string{
		consentQuery + "&prompt=none":               "error=consent_required",
		consentQuery + "&prompt=none+login":         "error=invalid_request",
		consentQuery + "&prompt=none&anonymous=yes": "error=login_required",
	} {
		var rec *httptest.ResponseRecorder
		if strings.Contains(query, "anonymous") {
			rec = get(mux, query)
		} else {
			rec = get(mux, query, c)
		}
		if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(loc, "https://app.example/cb?") || !strings.Contains(loc, want) {
			t.Fatalf("%s: %d %q", query, rec.Code, loc)
		}
	}
}

// loginRedirect checks a redirect to LoginURL carrying the prompt hint and a
// return that drops prompt and the retry counter.
func loginRedirect(t *testing.T, rec *httptest.ResponseRecorder, prompt string) {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || loc.Host != "app.example.com" || loc.Query().Get("prompt") != prompt {
		t.Fatalf("redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	ret, err := url.Parse(loc.Query().Get("return"))
	if err != nil || ret.Scheme+"://"+ret.Host+ret.Path != handoffAuthorize {
		t.Fatalf("return = %q", loc.Query().Get("return"))
	}
	if q := ret.Query(); q.Get("client_id") != "c" || q.Get("state") != "s" || q.Has("prompt") || q.Has("_authretry") || q.Has("approve") || q.Has("csrf") {
		t.Fatalf("return query = %v", q)
	}
}
