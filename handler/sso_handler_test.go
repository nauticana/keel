package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/connect"
	"github.com/nauticana/keel/sso"
	"github.com/nauticana/keel/user"
)

func newSSOHandler(t *testing.T) *SSOHandler {
	t.Helper()
	nonces := &connect.NonceService{DB: &nonceDB{rows: map[string][2]string{}}}
	nonces.Init(context.Background())
	return &SSOHandler{SSO: &sso.Service{}, Handoff: nonces, PublicBaseURL: "https://api.example/",
		FrontendReturnURL: "https://app.example/sso/return"}
}

func returned(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || u.Host != "app.example" || u.Path != "/sso/return" {
		t.Fatalf("location = %q", rec.Header().Get("Location"))
	}
	return u.Query()
}

func TestSSOStartUnknownAddressReturnsOpaqueError(t *testing.T) {
	h := newSSOHandler(t)
	for _, target := range []string{"/public/sso/start?email=ada%40acme.example", "/public/sso/start"} {
		rec := httptest.NewRecorder()
		h.Start(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if q := returned(t, rec); q.Get("error") != "sso_unavailable" || len(q) != 1 {
			t.Errorf("%s: %v", target, q)
		}
		if rec.Header().Get("Set-Cookie") != "" {
			t.Errorf("%s: no cookie may be set", target)
		}
	}
}

func TestSSOCallbackWithoutCookieFailsAndClearsIt(t *testing.T) {
	h := newSSOHandler(t)
	rec := httptest.NewRecorder()
	h.Callback(rec, httptest.NewRequest(http.MethodGet, "/public/sso/callback?code=c&state=s", nil))
	if q := returned(t, rec); q.Get("error") != "sso_failed" || q.Get("code") != "" {
		t.Fatalf("callback = %v", q)
	}
	c := rec.Result().Cookies()
	if len(c) != 1 || c[0].Name != ssoCookie || c[0].MaxAge >= 0 {
		t.Fatalf("cookie = %+v", c)
	}
}

func TestSSOCookieIsBoundAndConfined(t *testing.T) {
	h := newSSOHandler(t)
	rec := httptest.NewRecorder()
	h.toIdentityProvider(rec, httptest.NewRequest(http.MethodGet, "/public/sso/start", nil), "key-1", "https://idp.example/authorize?x=1")
	c := rec.Result().Cookies()
	if rec.Code != http.StatusFound || len(c) != 1 || c[0].Value != "key-1" || !c[0].HttpOnly || !c[0].Secure ||
		c[0].SameSite != http.SameSiteNoneMode || c[0].Path != "/public/sso" || c[0].MaxAge != config.Config().OAuthStateTTLSeconds {
		t.Fatalf("redirect %d cookie %+v", rec.Code, c)
	}
	rec = httptest.NewRecorder()
	h.toIdentityProvider(rec, httptest.NewRequest(http.MethodGet, "/public/sso/start", nil), "key-1", "http://idp.example/authorize")
	if q := returned(t, rec); q.Get("error") != "sso_failed" || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("plain-http target = %v", q)
	}
}

func TestSSOLaunchOpensOnlyItsOwnTest(t *testing.T) {
	h := newSSOHandler(t)
	payload, _ := json.Marshal(map[string]string{"k": "pending-key", "u": "https://idp.example/authorize"})
	code, err := h.Handoff.Create(context.Background(), ssoLaunchPurpose, string(payload))
	if err != nil {
		t.Fatal(err)
	}
	signIn, _ := h.Handoff.Create(context.Background(), handoffPurpose, `{"userId":1,"signInMethod":"T"}`)
	launch := func(c string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.Launch(rec, httptest.NewRequest(http.MethodGet, "/public/sso/launch?code="+url.QueryEscape(c), nil))
		return rec
	}
	if rec := launch(code); rec.Code != http.StatusFound || rec.Header().Get("Location") != "https://idp.example/authorize" || rec.Result().Cookies()[0].Value != "pending-key" {
		t.Fatalf("launch = %d %v", rec.Code, rec.Header())
	}
	for name, c := range map[string]string{"replayed": code, "sign-in handoff code": signIn, "empty": ""} {
		if q := returned(t, launch(c)); q.Get("test") != "failed" {
			t.Errorf("%s: %v", name, q)
		}
	}
}

func TestSSOHandoffSkipsSecondFactorOnlyForIdentityProvider(t *testing.T) {
	users := &handoffSignIn{twoFactor: true}
	h := newSignInHandoff(t, users)
	session := &model.UserSession{Id: 8, SignInMethod: user.SignInTenant}
	code, err := createHandoff(context.Background(), h.Handoff, session, true)
	if err != nil {
		t.Fatal(err)
	}
	if rec := exchange(h, code); !strings.Contains(rec.Body.String(), `"twoFactorRequired":false`) || len(users.refreshed) != 1 {
		t.Fatalf("identity provider sign-in: %d %s", rec.Code, rec.Body.String())
	}
	code, _ = h.HandoffCode(context.Background(), session)
	if rec := exchange(h, code); !strings.Contains(rec.Body.String(), `"twoFactorRequired":true`) {
		t.Fatalf("other handoff must keep 2FA: %s", rec.Body.String())
	}
}

func TestSSORedirectCodes(t *testing.T) {
	h := newSSOHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/public/sso/callback", nil)
	for err, want := range map[error]string{
		fmt.Errorf("%w: %w", sso.ErrSignInFailed, errors.New("nonce")): "sso_failed",
		sso.ErrMFARequired:                       "mfa_required",
		sso.ErrEmailNotAllowed:                   "sso_email_not_allowed",
		sso.ErrNoAccount:                         "sso_no_account",
		sso.ErrOtherPartner:                      "sso_other_partner",
		fmt.Errorf("x: %w", user.ErrSSORequired): "sso_required",
		errors.New("database down"):              "server_error",
	} {
		if got := h.redirectCode(r, err); got != want {
			t.Errorf("%v = %s, want %s", err, got, want)
		}
	}
}

func TestReadConfigurationJSONAndMultipart(t *testing.T) {
	body := `{"id":"12","caption":"Acme","issuer":"https://idp.acme.example","client_id":"c","client_auth":"P","client_secret":"s","require_mfa":true}`
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	cfg, err := readConfiguration(httptest.NewRecorder(), r)
	if err != nil || cfg.ID != 12 || cfg.Credential != "s" || !cfg.RequireMFA || cfg.Issuer != "https://idp.acme.example" {
		t.Fatalf("json = %+v, %v", cfg, err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range map[string]string{"caption": "Acme", "issuer": "https://idp.acme.example", "client_id": "c", "client_auth": "J", "require_mfa": "false"} {
		_ = mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("private_key", "key.pem")
	_, _ = fw.Write([]byte("-----BEGIN PRIVATE KEY-----"))
	_ = mw.Close()
	r = httptest.NewRequest(http.MethodPost, "/x", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	cfg, err = readConfiguration(httptest.NewRecorder(), r)
	if err != nil || cfg.ClientAuth != "J" || cfg.Credential != "-----BEGIN PRIVATE KEY-----" || cfg.RequireMFA {
		t.Fatalf("multipart = %+v, %v", cfg, err)
	}

	for name, bad := range map[string]string{
		"both credentials": `{"client_secret":"s","private_key":"k"}`,
		"negative id":      `{"id":"-1"}`,
		"bad mfa":          `{"require_mfa":"maybe"}`,
		"not json":         `{`,
		"trailing value":   `{"caption":"x"}{}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(bad))
		if _, err := readConfiguration(httptest.NewRecorder(), r); !errors.Is(err, sso.ErrInvalidConfiguration) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
