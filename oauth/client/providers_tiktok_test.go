package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// stateStore keeps the extras AuthURL stored and hands them back on consume.
type stateStore struct {
	fakeStore
	extra    map[string]string
	consumed bool
	conn     Connection
	entity   int64
}

func (s *stateStore) CreateOAuthState(_ context.Context, _ int64, _ string, extra map[string]string) (string, error) {
	s.extra = extra
	return s.state, nil
}

func (s *stateStore) ConsumeOAuthState(_ context.Context, state, _ string) (int64, map[string]string, error) {
	if state != s.state {
		return 0, nil, errors.New("state bound to another initiator")
	}
	s.consumed = true
	return 7, s.extra, nil
}

func (s *stateStore) UpsertConnection(ctx context.Context, _ int64, conn Connection) error {
	s.conn, s.entity = conn, EntityFromContext(ctx)
	return nil
}

func newStateStore() *stateStore {
	return &stateStore{fakeStore: fakeStore{secrets: map[string]string{"tiktok_secret": "shh"}, state: "STATE123"}}
}

func TestTikTokAuthURLUsesClientKey(t *testing.T) {
	store := newStateStore()
	p := NewTikTokProvider(store, "tiktok", "https://app/cb", "ck", "tiktok_secret", []string{"user.info.basic", "video.list"})
	raw, err := p.AuthURL(context.Background(), 7, map[string]string{ParamExtraScopes: "video.publish", StateEntityKey: "42"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if u.Host != "www.tiktok.com" || q.Get("client_key") != "ck" || q.Has("client_id") || q.Get("state") != "STATE123" {
		t.Fatalf("consent URL %s", raw)
	}
	if q.Get("scope") != "user.info.basic,video.list,video.publish" || q.Get("redirect_uri") != "https://app/cb" {
		t.Errorf("scope %q redirect %q", q.Get("scope"), q.Get("redirect_uri"))
	}
	if store.extra[StateEntityKey] != "42" {
		t.Errorf("entity not carried in state: %v", store.extra)
	}
	if _, err := NewTikTokProvider(store, "tiktok", "https://app/cb", "", "tiktok_secret", nil).AuthURL(context.Background(), 7, nil); err == nil {
		t.Error("a missing client key must error")
	}
}

func TestTikTokCallback(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		_, _ = w.Write([]byte(`{"access_token":"AT","refresh_token":"RT","scope":"user.info.basic,video.list","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	store := newStateStore()
	p := NewTikTokProvider(store, "tiktok", "https://app/cb", "ck", "tiktok_secret", []string{"user.info.basic", "video.list"})
	p.Endpoint.TokenURL = srv.URL
	p.RequiredScopes = []string{"video.list"}
	if _, err := p.AuthURL(context.Background(), 7, map[string]string{StateEntityKey: "42"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Callback(context.Background(), "CODE", "forged"); err == nil || form != nil {
		t.Fatal("a foreign state must be refused before the code is exchanged")
	}
	if err := p.Callback(context.Background(), "CODE", "STATE123"); err != nil {
		t.Fatal(err)
	}
	if form.Get("client_key") != "ck" || form.Get("client_secret") != "shh" || form.Get("code") != "CODE" || form.Get("grant_type") != "authorization_code" {
		t.Errorf("token form %v", form)
	}
	if store.conn.CredRef != "RT" || store.conn.APIEndpoint != tiktokAPIBase || store.entity != 42 || strings.Join(store.conn.GrantedScopes, " ") != "user.info.basic video.list" {
		t.Errorf("connection %+v entity %d", store.conn, store.entity)
	}

	p.RequiredScopes = []string{"video.publish"}
	var scopeErr *MissingScopeError
	if err := p.Callback(context.Background(), "CODE", "STATE123"); !errors.As(err, &scopeErr) {
		t.Errorf("a narrower grant must fail with MissingScopeError, got %v", err)
	}
}

func TestTikTokCallbackRequiresRefreshToken(t *testing.T) {
	srv := tokenServer(t, `{"access_token":"AT","token_type":"Bearer"}`)
	store := newStateStore()
	p := NewTikTokProvider(store, "tiktok", "https://app/cb", "ck", "tiktok_secret", nil)
	p.Endpoint.TokenURL = srv.URL
	if err := p.Callback(context.Background(), "CODE", "STATE123"); err == nil || store.conn.CredRef != "" {
		t.Fatal("a grant without a refresh token must not be stored")
	}
}

func TestXProvider(t *testing.T) {
	p := NewXProvider(newFake(), "x", "https://app/cb", "cid", "google_secret", []string{"tweet.read", "users.read"})
	if !p.UsePKCE || !p.RequireRefresh || p.Endpoint != XEndpoint {
		t.Fatalf("X provider %+v", p)
	}
	raw, err := p.AuthURL(context.Background(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery(strings.SplitN(raw, "?", 2)[1])
	if q.Get("scope") != "tweet.read users.read offline.access" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Errorf("consent URL %s", raw)
	}
	if got := NewXProvider(newFake(), "x", "", "cid", "s", []string{"offline.access", "tweet.read"}).Scopes; len(got) != 2 {
		t.Errorf("offline.access duplicated: %v", got)
	}
}
