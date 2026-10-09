package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

func tokenServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestManualTokenExchangeValidatesResponse(t *testing.T) {
	form := url.Values{"grant_type": {"authorization_code"}}
	for body, ok := range map[string]bool{
		`{"access_token":"AT","token_type":"Bearer"}`: true,
		`{"access_token":"AT","token_type":"bearer"}`: true,
		`{"access_token":"AT"}`:                       true,
		`{"access_token":"AT","token_type":"mac"}`:    false,
		`{"access_token":"AT","token_type":"DPoP"}`:   false,
		`{"access_token":"","token_type":"Bearer"}`:   false,
		`{"refresh_token":"RT"}`:                      false,
	} {
		srv := tokenServer(t, body)
		tr, err := ManualTokenExchange(context.Background(), srv.URL, form)
		if ok && (err != nil || tr.AccessToken != "AT") {
			t.Errorf("%s: %+v, %v", body, tr, err)
		}
		if !ok && (!errors.Is(err, ErrInvalidTokenResponse) || tr != (TokenResponse{})) {
			t.Errorf("%s: %+v, %v, want ErrInvalidTokenResponse", body, tr, err)
		}
		if _, jerr := ManualTokenExchangeJSON(context.Background(), srv.URL, map[string]string{"code": "c"}); (jerr == nil) != ok {
			t.Errorf("JSON %s: %v", body, jerr)
		}
	}
}

func TestWithBasicAuthFormEncodesCredentials(t *testing.T) {
	var user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT"}`))
	}))
	defer srv.Close()
	if _, err := ManualTokenExchange(context.Background(), srv.URL, url.Values{}, WithBasicAuth("id:1", "s e/c+r%t")); err != nil {
		t.Fatal(err)
	}
	if user != "id%3A1" || pass != "s+e%2Fc%2Br%25t" {
		t.Fatalf("basic auth = (%q, %q), want form-urlencoded values", user, pass)
	}
}

func TestJSONCallbackRefusesEmptyAccessToken(t *testing.T) {
	srv := tokenServer(t, `{"access_token":"","refresh_token":"RT"}`)
	store := &fakeStore{secrets: map[string]string{"s": "shh"}, state: "S"}
	b := &BaseProvider{Service: store, ProviderName: "clover", CallbackURL: "https://app/cb", ClientID: "APP", SecretName: "s",
		Endpoint: oauth2.Endpoint{TokenURL: srv.URL}, JSONTokenExchange: true}
	if err := b.Callback(context.Background(), "CODE", "S"); !errors.Is(err, ErrInvalidTokenResponse) {
		t.Fatalf("Callback = %v, want ErrInvalidTokenResponse", err)
	}
	if store.gotCred != "" {
		t.Fatalf("a connection was stored: %q", store.gotCred)
	}
}

func TestGoogleProviderUsesPKCE(t *testing.T) {
	var gotVerifier string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotVerifier = r.PostForm.Get("code_verifier")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","refresh_token":"RT","token_type":"Bearer"}`))
	}))
	defer srv.Close()
	cs := &capturingStore{fakeStore: newFake()}
	p := NewGoogleProvider(cs, "gsc", "https://app/cb", "cid", "google_secret", []string{"openid"}, "")
	p.Endpoint = oauth2.Endpoint{AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}
	raw, err := p.AuthURL(context.Background(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	verifier := cs.params[StatePKCEKey]
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") == "" || verifier == "" {
		t.Fatalf("consent URL %s with state %v lacks PKCE S256", raw, cs.params)
	}
	if err := p.Callback(context.Background(), "CODE", "STATE123"); err != nil {
		t.Fatal(err)
	}
	if gotVerifier != verifier {
		t.Fatalf("code_verifier = %q, want the verifier bound to the state", gotVerifier)
	}
}
