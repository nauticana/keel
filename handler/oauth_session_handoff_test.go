package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/oauth/authserver"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/user"
)

const handoffAuthorize = "https://as.example.com/oauth/authorize"

type handoffUsers struct{ user.UserService }

func (handoffUsers) ParseJWT(token string) (*model.UserSession, error) {
	if token != "good" {
		return nil, errors.New("invalid token")
	}
	return &model.UserSession{Id: 7, PartnerId: 3}, nil
}

var _ user.UserService = handoffUsers{}

type handoffRow struct {
	code           port.SessionHandoffCode
	expires        time.Time
	consumed       bool
	sessionHash    string
	sessionExpires time.Time
}

// handoffStore mirrors SessionHandoffStoreDB's predicates on a fake clock.
type handoffStore struct {
	mu   sync.Mutex
	now  time.Time
	rows map[string]*handoffRow
	err  error
}

func (s *handoffStore) advance(d time.Duration) { s.mu.Lock(); s.now = s.now.Add(d); s.mu.Unlock() }

func (s *handoffStore) SaveHandoff(_ context.Context, h *port.SessionHandoffCode, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[h.CodeHash] = &handoffRow{code: *h, expires: s.now.Add(ttl)}
	return s.err
}

func (s *handoffStore) RedeemHandoff(_ context.Context, codeHash, ret, sessionHash string, ttl time.Duration) (*port.UserRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	r := s.rows[codeHash]
	if r == nil || r.consumed || !r.expires.After(s.now) || r.code.ReturnURL != ret {
		return nil, nil
	}
	r.consumed, r.sessionHash, r.sessionExpires = true, sessionHash, s.now.Add(ttl)
	return &port.UserRef{UserID: r.code.UserID, PartnerID: r.code.PartnerID}, nil
}

func (s *handoffStore) ResolveHandoffSession(_ context.Context, sessionHash string) (*port.UserRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	for _, r := range s.rows {
		if r.sessionHash == sessionHash && r.sessionExpires.After(s.now) {
			return &port.UserRef{UserID: r.code.UserID, PartnerID: r.code.PartnerID}, nil
		}
	}
	return nil, nil
}

var _ port.SessionHandoffStore = (*handoffStore)(nil)

type handoffAS struct{ port.AuthorizationServer }

func (handoffAS) ValidateAuthorizeRequest(context.Context, port.AuthorizeRequest) (*port.OAuthClient, []string, error) {
	return &port.OAuthClient{ClientID: "c", Name: "Client"}, []string{"read"}, nil
}

func newHandoffHandler(t *testing.T) (*OAuthASHandler, *handoffStore, *http.ServeMux) {
	t.Helper()
	store := &handoffStore{now: time.Unix(1_700_000_000, 0), rows: map[string]*handoffRow{}}
	hs, err := authserver.NewSessionHandoff(store, handoffAuthorize)
	if err != nil {
		t.Fatal(err)
	}
	h := &OAuthASHandler{AS: handoffAS{}, Handoff: hs, UserService: handoffUsers{}, LoginURL: "https://app.example.com/login"}
	h.ResolveUser = HandoffSessionUser(hs, nil)
	mux := http.NewServeMux()
	for path, fn := range h.Routes() {
		mux.HandleFunc(path, fn)
	}
	return h, store, mux
}

func mint(mux *http.ServeMux, bearer, ret string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"return": ret})
	req := httptest.NewRequest(http.MethodPost, authserver.OAuthSessionHandoffPath, strings.NewReader(string(body)))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func mintRedirect(t *testing.T, mux *http.ServeMux, ret string) string {
	t.Helper()
	rec := mint(mux, "good", ret)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint status = %d: %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data struct {
			Code     string `json:"code"`
			Redirect string `json:"redirect"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil || env.Data.Redirect == "" || env.Data.Code != "" {
		t.Fatalf("mint body: %v %+v", err, env)
	}
	return env.Data.Redirect
}

func get(mux *http.ServeMux, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == OAuthSessionCookie {
			return c
		}
	}
	return nil
}

func TestHandoffRoutesNeedDependencies(t *testing.T) {
	for _, h := range []*OAuthASHandler{{}, {UserService: handoffUsers{}}, {Handoff: &authserver.SessionHandoff{}}} {
		routes := h.Routes()
		if _, ok := routes[authserver.OAuthSessionPath]; ok {
			t.Error("redeem mounted without its dependencies")
		}
		if _, ok := routes[authserver.OAuthSessionHandoffPath]; ok {
			t.Error("mint mounted without its dependencies")
		}
	}
	_, _, mux := newHandoffHandler(t)
	if _, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, authserver.OAuthSessionPath, nil)); pattern == "" {
		t.Fatal("redeem not mounted")
	}
}

func TestHandoffMintRedeemSetsCookieAndAuthenticatesAuthorize(t *testing.T) {
	_, _, mux := newHandoffHandler(t)
	ret := "/oauth/authorize?response_type=code&client_id=c&_authretry=1"
	redirect := mintRedirect(t, mux, ret)
	u, _ := url.Parse(redirect)
	if u.Scheme != "https" || u.Host != "as.example.com" || u.Path != authserver.OAuthSessionPath {
		t.Fatalf("redirect = %q", redirect)
	}

	rec := get(mux, u.RequestURI())
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("redeem status = %d: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "https://as.example.com"+ret {
		t.Fatalf("Location = %q", loc)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("redeem response is cacheable")
	}
	c := sessionCookie(rec)
	if c == nil {
		t.Fatal("no session cookie")
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/oauth" ||
		c.MaxAge != int(authserver.HandoffSessionTTL.Seconds()) || c.Domain != "" {
		t.Fatalf("cookie attributes = %+v", c)
	}

	authz := get(mux, ret, c)
	if authz.Code != http.StatusOK || !strings.Contains(authz.Body.String(), "Authorize Client") {
		t.Fatalf("authorize with hand-off cookie = %d: %s", authz.Code, authz.Body.String())
	}
}

func TestHandoffReplayAndExpiryRejected(t *testing.T) {
	_, store, mux := newHandoffHandler(t)
	u, _ := url.Parse(mintRedirect(t, mux, handoffAuthorize))
	if rec := get(mux, u.RequestURI()); rec.Code != http.StatusSeeOther {
		t.Fatalf("first redeem = %d", rec.Code)
	}
	if rec := get(mux, u.RequestURI()); rec.Code != http.StatusBadRequest || sessionCookie(rec) != nil {
		t.Fatalf("replay = %d", rec.Code)
	}

	u, _ = url.Parse(mintRedirect(t, mux, handoffAuthorize))
	store.advance(authserver.HandoffCodeTTL)
	if rec := get(mux, u.RequestURI()); rec.Code != http.StatusBadRequest || sessionCookie(rec) != nil {
		t.Fatalf("expired = %d", rec.Code)
	}
}

func TestHandoffMintRequiresBearer(t *testing.T) {
	_, _, mux := newHandoffHandler(t)
	for _, bearer := range []string{"", "forged"} {
		if rec := mint(mux, bearer, handoffAuthorize); rec.Code != http.StatusUnauthorized {
			t.Errorf("bearer %q: status = %d", bearer, rec.Code)
		}
	}
	if rec := get(mux, authserver.OAuthSessionHandoffPath); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET mint = %d", rec.Code)
	}
}

func TestHandoffOpenRedirectRejected(t *testing.T) {
	_, _, mux := newHandoffHandler(t)
	bad := []string{
		"https://evil.example/oauth/authorize",
		"http://as.example.com/oauth/authorize",
		"https://as.example.com/oauth/token",
		"https://user@as.example.com/oauth/authorize",
		"//evil.example/oauth/authorize",
		"https://as.example.com/oauth/authorize#x",
		"https://evil.example/",
	}
	code := strings.Repeat("a", 64)
	for _, ret := range bad {
		if rec := mint(mux, "good", ret); rec.Code != http.StatusBadRequest {
			t.Errorf("mint %q = %d", ret, rec.Code)
		}
		rec := get(mux, authserver.OAuthSessionPath+"?"+url.Values{"code": {code}, "return": {ret}}.Encode())
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || sessionCookie(rec) != nil {
			t.Errorf("redeem %q = %d, Location %q", ret, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestHandoffRedeemReturnMustMatchMint(t *testing.T) {
	_, _, mux := newHandoffHandler(t)
	u, _ := url.Parse(mintRedirect(t, mux, handoffAuthorize+"?state=a"))
	q := u.Query()
	q.Set("return", handoffAuthorize+"?state=b")
	if rec := get(mux, authserver.OAuthSessionPath+"?"+q.Encode()); rec.Code != http.StatusBadRequest || sessionCookie(rec) != nil {
		t.Fatalf("mismatched return = %d", rec.Code)
	}
	if rec := get(mux, u.RequestURI()); rec.Code != http.StatusSeeOther {
		t.Fatalf("bound return after mismatch = %d", rec.Code)
	}
}

func TestHandoffRedeemSanitizesStoreFailure(t *testing.T) {
	h, store, mux := newHandoffHandler(t)
	journal := &recordingJournal{}
	h.Journal = journal
	u, _ := url.Parse(mintRedirect(t, mux, handoffAuthorize))
	store.err = errors.New("pq: secret detail")
	rec := get(mux, u.RequestURI())
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("store failure = %d: %s", rec.Code, rec.Body.String())
	}
	if len(journal.errors) == 0 {
		t.Fatal("store failure not logged")
	}
	if rec := mint(mux, "good", handoffAuthorize); rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("mint store failure = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandoffSessionUserFailsClosed(t *testing.T) {
	h, store, mux := newHandoffHandler(t)
	u, _ := url.Parse(mintRedirect(t, mux, handoffAuthorize))
	c := sessionCookie(get(mux, u.RequestURI()))

	resolve := func(cookies ...*http.Cookie) *port.UserRef {
		req := httptest.NewRequest(http.MethodGet, handoffAuthorize, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		return h.ResolveUser(req)
	}
	if got := resolve(c); got == nil || got.UserID != 7 || got.PartnerID != 3 {
		t.Fatalf("valid cookie = %+v", got)
	}
	tampered := *c
	tampered.Value = strings.Repeat("0", 64)
	for _, bad := range []*http.Cookie{&tampered, {Name: OAuthSessionCookie, Value: c.Value[:63]}, {Name: "other", Value: c.Value}} {
		if got := resolve(bad); got != nil {
			t.Errorf("cookie %+v resolved to %+v", bad, got)
		}
	}
	if resolve() != nil {
		t.Error("no cookie resolved")
	}

	journal := &recordingJournal{}
	store.err = errors.New("db down")
	if got := HandoffSessionUser(h.Handoff, journal)(func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, handoffAuthorize, nil)
		r.AddCookie(c)
		return r
	}()); got != nil || len(journal.errors) == 0 {
		t.Fatalf("store error: user %+v, logged %d", got, len(journal.errors))
	}
	store.err = nil

	store.advance(authserver.HandoffSessionTTL)
	if got := resolve(c); got != nil {
		t.Fatalf("expired cookie resolved to %+v", got)
	}
	if HandoffSessionUser(nil, nil)(httptest.NewRequest(http.MethodGet, "/", nil)) != nil {
		t.Fatal("nil hand-off resolved a user")
	}
}

func TestAuthorizeLoopPointsToHandoff(t *testing.T) {
	h, _, _ := newHandoffHandler(t)
	rec := httptest.NewRecorder()
	h.redirectToLogin(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?_authretry=1000", nil))
	if rec.Code != http.StatusLoopDetected || !strings.Contains(rec.Body.String(), authserver.OAuthSessionHandoffPath) {
		t.Fatalf("loop = %d: %s", rec.Code, rec.Body.String())
	}
}
