package connect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/oauth/client"
)

func TestXRefreshSpecUsesBasicAuthAndKeepsRotation(t *testing.T) {
	var user, pass, bodySecret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ = r.BasicAuth()
		_ = r.ParseForm()
		bodySecret = r.PostForm.Get("client_secret")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","token_type":"bearer","refresh_token":"RT2","expires_in":7200}`))
	}))
	defer srv.Close()
	spec := XRefreshSpec("cid", "x_secret")
	spec.Endpoint.TokenURL = srv.URL
	res, err := NewRefresher(fakeSecrets{"x_secret": "shh"}, map[string]RefreshSpec{"x": spec})(context.Background(), "x", "RT1")
	if err != nil || res.AccessToken != "AT" || res.RefreshToken != "RT2" {
		t.Fatalf("got %+v err=%v", res, err)
	}
	if user != "cid" || pass != "shh" || bodySecret != "" {
		t.Errorf("client auth basic=%q:%q body secret=%q, want Basic only", user, pass, bodySecret)
	}
}

func TestTikTokRefreshSpec(t *testing.T) {
	spec := TikTokRefreshSpec("ck", "tiktok_secret")
	if spec.Style != RefreshForm || spec.ClientIDParam != "client_key" || spec.TokenURL != client.TikTokEndpoint.TokenURL || spec.ClientID != "ck" {
		t.Errorf("spec %+v", spec)
	}
}
