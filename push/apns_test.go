package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/user"
)

type tokenStore struct {
	user.UserService
	devices []model.DeviceToken
	revoked []string
}

func (s *tokenStore) ListActiveDeviceTokens(int) ([]model.DeviceToken, error) { return s.devices, nil }
func (s *tokenStore) RevokeDeviceToken(_ int, token string) error {
	s.revoked = append(s.revoked, token)
	return nil
}

var _ user.UserService = (*tokenStore)(nil)

func newTestAPNs(t *testing.T, srv *httptest.Server, store *tokenStore) *APNsPushProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &APNsPushProvider{
		client: srv.Client(), host: srv.URL,
		keyID: "KEY1", teamID: "TEAM1", bundleID: "com.example.app",
		key: key, tokenTTL: 50 * time.Minute, users: store,
	}
}

func TestAPNs_DispatchSendsHeadersPayloadAndRevokesStale(t *testing.T) {
	var seen []*http.Request
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, body)
		if strings.HasSuffix(r.URL.Path, "/gone") {
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"reason":"Unregistered"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := &tokenStore{devices: []model.DeviceToken{
		{Platform: model.DevicePlatformiOS, Token: "ok"},
		{Platform: model.DevicePlatformiOS, Token: "gone"},
	}}
	p := newTestAPNs(t, srv, store)
	if err := p.Dispatch(context.Background(), 7, "Ride", "Driver arrived", map[string]string{"ride_id": "42"}); err != nil {
		t.Fatalf("stale token must not fail the dispatch: %v", err)
	}
	if len(seen) != 2 || len(store.revoked) != 1 || store.revoked[0] != "gone" {
		t.Fatalf("requests=%d revoked=%v", len(seen), store.revoked)
	}
	r := seen[0]
	if r.URL.Path != "/3/device/ok" || r.Header.Get("apns-topic") != "com.example.app" || r.Header.Get("apns-push-type") != "alert" {
		t.Fatalf("bad request: %s %v", r.URL.Path, r.Header)
	}
	tok, err := jwt.Parse(strings.TrimPrefix(r.Header.Get("authorization"), "bearer "), func(*jwt.Token) (any, error) { return &p.key.PublicKey, nil })
	if err != nil || tok.Header["kid"] != "KEY1" || tok.Claims.(jwt.MapClaims)["iss"] != "TEAM1" {
		t.Fatalf("provider token: err=%v header=%v claims=%v", err, tok.Header, tok.Claims)
	}
	aps := bodies[0]["aps"].(map[string]any)
	if aps["alert"].(map[string]any)["title"] != "Ride" || bodies[0]["ride_id"] != "42" {
		t.Fatalf("payload=%v", bodies[0])
	}
}

func TestAPNs_TransportErrorSurfacesWithoutRevoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"reason":"ServiceUnavailable"}`))
	}))
	defer srv.Close()
	store := &tokenStore{devices: []model.DeviceToken{{Platform: model.DevicePlatformiOS, Token: "t"}}}
	p := newTestAPNs(t, srv, store)
	err := p.Dispatch(context.Background(), 1, "a", "b", nil)
	if err == nil || !strings.Contains(err.Error(), "503") || len(store.revoked) != 0 {
		t.Fatalf("err=%v revoked=%v", err, store.revoked)
	}
}

func TestAPNs_ProviderTokenIsCached(t *testing.T) {
	p := newTestAPNs(t, httptest.NewServer(http.NotFoundHandler()), &tokenStore{})
	a, _ := p.providerToken()
	b, _ := p.providerToken()
	if a == "" || a != b {
		t.Fatal("provider token must be reused inside its TTL")
	}
	p.tokenTTL = 0
	if c, _ := p.providerToken(); c == a {
		t.Fatal("expired provider token must be re-minted")
	}
}

type fakeSender struct {
	got  map[string][]string
	name string
}

func (f *fakeSender) Dispatch(context.Context, int, string, string, map[string]string) error {
	return errors.New("router must not call Dispatch")
}
func (f *fakeSender) Send(_ context.Context, to, _, _ string, _ map[string]string) error {
	f.got[f.name] = append(f.got[f.name], to)
	return nil
}
func (f *fakeSender) sendTokens(_ context.Context, _ int, devices []model.DeviceToken, _, _ string, _ map[string]string) error {
	for _, d := range devices {
		f.got[f.name] = append(f.got[f.name], d.Token)
	}
	return nil
}

func TestPlatformRouter_SplitsByPlatformAndTokenShape(t *testing.T) {
	got := map[string][]string{}
	fcm, apns := &fakeSender{got: got, name: "fcm"}, &fakeSender{got: got, name: "apns"}
	store := &tokenStore{devices: []model.DeviceToken{
		{Platform: model.DevicePlatformiOS, Token: "ios1"},
		{Platform: model.DevicePlatformAndroid, Token: "and1"},
		{Platform: model.DevicePlatformWeb, Token: "web1"},
	}}
	r := NewPlatformRouter(store, fcm, apns)
	if err := r.Dispatch(context.Background(), 1, "t", "b", nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got["apns"], ",") != "ios1" || strings.Join(got["fcm"], ",") != "and1,web1" {
		t.Fatalf("got=%v", got)
	}
	hex64 := strings.Repeat("ab", 32)
	_ = r.Send(context.Background(), hex64, "t", "b", nil)
	_ = r.Send(context.Background(), "fcm:token", "t", "b", nil)
	if got["apns"][1] != hex64 || got["fcm"][2] != "fcm:token" {
		t.Fatalf("send routing got=%v", got)
	}
}
