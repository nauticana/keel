package connect

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type fakeSecrets map[string]string

func (f fakeSecrets) GetSecret(_ context.Context, key string) (string, error) { return f[key], nil }

func TestNewRefresher_Passthrough(t *testing.T) {
	r := NewRefresher(fakeSecrets{}, map[string]RefreshSpec{"meta": {Style: RefreshPassthrough}})
	res, err := r(context.Background(), "meta", "long-lived")
	if err != nil || res.AccessToken != "long-lived" {
		t.Fatalf("got %+v err=%v, want AccessToken=long-lived", res, err)
	}
}

func TestNewRefresher_Unknown(t *testing.T) {
	r := NewRefresher(fakeSecrets{}, nil)
	if _, err := r(context.Background(), "nope", "x"); err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestNewRefresher_Form(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.Form
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"NEW"}`))
	}))
	defer srv.Close()

	r := NewRefresher(fakeSecrets{"tiktok_secret": "shh"}, map[string]RefreshSpec{
		"tiktok": {ClientID: "ck", SecretName: "tiktok_secret", TokenURL: srv.URL, Style: RefreshForm, ClientIDParam: "client_key"},
	})
	res, err := r(context.Background(), "tiktok", "RT")
	if err != nil || res.AccessToken != "NEW" {
		t.Fatalf("got %+v err=%v, want AccessToken=NEW", res, err)
	}
	if form.Get("client_key") != "ck" || form.Get("client_id") != "" {
		t.Errorf("client-id param: client_key=%q client_id=%q, want client_key only", form.Get("client_key"), form.Get("client_id"))
	}
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "RT" {
		t.Errorf("form = %v, want refresh_token grant", form)
	}
	if res.RefreshToken != "" {
		t.Errorf("RefreshToken = %q, want empty when server returns none", res.RefreshToken)
	}
}

func jsonTokenServer(t *testing.T, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
}

// A rotated refresh token from the oauth2-lib path must be surfaced for persistence.
func TestNewRefresher_LibRotation(t *testing.T) {
	srv := jsonTokenServer(t, `{"access_token":"AT","token_type":"bearer","refresh_token":"RT2","expires_in":3600}`)
	defer srv.Close()
	r := NewRefresher(fakeSecrets{"g": "shh"}, map[string]RefreshSpec{
		"google": {ClientID: "cid", SecretName: "g", Endpoint: oauth2.Endpoint{TokenURL: srv.URL}, Style: RefreshOAuth2Lib},
	})
	res, err := r(context.Background(), "google", "RT1")
	if err != nil || res.AccessToken != "AT" {
		t.Fatalf("got %+v err=%v", res, err)
	}
	if res.RefreshToken != "RT2" {
		t.Errorf("rotated refresh token = %q, want RT2 (must be persisted)", res.RefreshToken)
	}
}

// No rotation → keep the existing token (empty RefreshResult.RefreshToken), even
// though the oauth2 library backfills the prior token onto the returned token.
func TestNewRefresher_LibNoRotation(t *testing.T) {
	srv := jsonTokenServer(t, `{"access_token":"AT","token_type":"bearer","expires_in":3600}`)
	defer srv.Close()
	r := NewRefresher(fakeSecrets{"g": "shh"}, map[string]RefreshSpec{
		"google": {ClientID: "cid", SecretName: "g", Endpoint: oauth2.Endpoint{TokenURL: srv.URL}, Style: RefreshOAuth2Lib},
	})
	res, err := r(context.Background(), "google", "RT1")
	if err != nil {
		t.Fatal(err)
	}
	if res.RefreshToken != "" {
		t.Errorf("RefreshToken = %q, want empty (no rotation → keep existing)", res.RefreshToken)
	}
}

func TestNewRefresher_JSON(t *testing.T) {
	var gotCT, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","refresh_token":"RT2"}`))
	}))
	defer srv.Close()

	r := NewRefresher(fakeSecrets{"clover_secret": "shh"}, map[string]RefreshSpec{
		"clover": {ClientID: "APP", SecretName: "clover_secret", TokenURL: srv.URL, Style: RefreshJSON},
	})
	res, err := r(context.Background(), "clover", "RT1")
	if err != nil || res.AccessToken != "AT" || res.RefreshToken != "RT2" {
		t.Fatalf("got %+v err=%v, want AT/RT2 (rotated)", res, err)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	// client_id + refresh_token only; never the client_secret.
	if !strings.Contains(gotBody, `"client_id":"APP"`) || !strings.Contains(gotBody, `"refresh_token":"RT1"`) {
		t.Errorf("body = %q, want client_id + refresh_token", gotBody)
	}
	if strings.Contains(gotBody, "shh") {
		t.Errorf("body leaked client_secret: %q", gotBody)
	}
}

func TestNewRefresher_FormRotation(t *testing.T) {
	srv := jsonTokenServer(t, `{"access_token":"NEW","refresh_token":"RT2"}`)
	defer srv.Close()
	r := NewRefresher(fakeSecrets{"s": "shh"}, map[string]RefreshSpec{
		"prov": {ClientID: "id", SecretName: "s", TokenURL: srv.URL, Style: RefreshForm},
	})
	res, err := r(context.Background(), "prov", "RT1")
	if err != nil || res.AccessToken != "NEW" || res.RefreshToken != "RT2" {
		t.Fatalf("got %+v err=%v, want NEW/RT2", res, err)
	}
}
