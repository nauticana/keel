package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestGeneratePKCE(t *testing.T) {
	v, c, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
		t.Errorf("verifier not base64url: %v", err)
	}
	sum := sha256.Sum256([]byte(v))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); c != want {
		t.Errorf("challenge = %q, want S256(verifier) %q", c, want)
	}
	if v2, _, _ := GeneratePKCE(); v2 == v {
		t.Error("two verifiers identical")
	}
}

// capturingStore records the params AuthURL stashes in the state.
type capturingStore struct {
	*fakeStore
	params map[string]string
}

func (c *capturingStore) CreateOAuthState(_ context.Context, _ int64, _ string, params map[string]string) (string, error) {
	c.params = params
	return c.fakeStore.state, nil
}

func TestAuthURL_PKCE(t *testing.T) {
	cs := &capturingStore{fakeStore: newFake()}
	p := NewOAuth2Provider(cs, "twitter", "https://app/cb", "cid", "google_secret",
		oauth2.Endpoint{AuthURL: "https://x/authorize", TokenURL: "https://x/token"},
		[]string{"tweet.read"}, "https://api", true)
	p.UsePKCE = true

	raw, err := p.AuthURL(context.Background(), 1, map[string]string{"entity_id": "9"})
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(raw)
	if q.Query().Get("code_challenge_method") != "S256" {
		t.Errorf("method = %q, want S256", q.Query().Get("code_challenge_method"))
	}
	if cs.params["entity_id"] != "9" {
		t.Errorf("caller entity_id not preserved: %v", cs.params)
	}
	verifier := cs.params[StatePKCEKey]
	if verifier == "" {
		t.Fatal("verifier not stashed in state")
	}
	sum := sha256.Sum256([]byte(verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); q.Query().Get("code_challenge") != want {
		t.Errorf("code_challenge does not match S256(stashed verifier)")
	}
}

func TestNewOAuth2Provider_AuthURL(t *testing.T) {
	p := NewOAuth2Provider(newFake(), "amazon", "https://app/cb", "amzn", "google_secret",
		oauth2.Endpoint{AuthURL: "https://amazon/ap/oa", TokenURL: "https://amazon/token"},
		[]string{"profile"}, "https://api.amazon.com", true)
	u, err := p.AuthURL(context.Background(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"https://amazon/ap/oa", "client_id=amzn", "scope=profile", "state=STATE123"} {
		if !strings.Contains(u, want) {
			t.Errorf("URL missing %q: %s", want, u)
		}
	}
}

func TestManualTokenExchange_WithBasicAuth(t *testing.T) {
	var user, pass string
	var ok bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","refresh_token":"RT"}`))
	}))
	defer srv.Close()

	tr, err := ManualTokenExchange(context.Background(), srv.URL,
		url.Values{"grant_type": {"authorization_code"}}, WithBasicAuth("id", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !ok || user != "id" || pass != "secret" {
		t.Errorf("basic auth = (%q,%q,%v), want (id,secret,true)", user, pass, ok)
	}
	if tr.AccessToken != "AT" || tr.RefreshToken != "RT" {
		t.Errorf("tokens = %+v, want AT/RT", tr)
	}
}
