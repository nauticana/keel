package client

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// fakeStore is a minimal in-memory CredentialStore for the pure-logic tests.
type fakeStore struct {
	secrets map[string]string
	state   string
}

func (s *fakeStore) CreateOAuthState(_ context.Context, _ int64, _ string, _ map[string]string) (string, error) {
	return s.state, nil
}
func (s *fakeStore) ConsumeOAuthState(_ context.Context, _, _ string) (int64, map[string]string, error) {
	return 1, nil, nil
}
func (s *fakeStore) UpsertConnection(_ context.Context, _ int64, _, _, _, _ string) error { return nil }
func (s *fakeStore) UpdateConnectionStatus(_ context.Context, _ int64, _, _, _ string) error {
	return nil
}
func (s *fakeStore) GetConnectionCredentials(_ context.Context, _ int64, _ string) (string, string, error) {
	return "", "", nil
}
func (s *fakeStore) RefreshAccessToken(_ context.Context, _ int64, _ string) (string, error) {
	return "access", nil
}
func (s *fakeStore) GetSecret(_ context.Context, key string) (string, error) {
	return s.secrets[key], nil
}

func newFake() *fakeStore {
	return &fakeStore{secrets: map[string]string{"google_secret": "shh"}, state: "STATE123"}
}

func TestGoogleProvider_AuthURL(t *testing.T) {
	p := NewGoogleProvider(newFake(), "gsc", "https://app/cb", "cid", "google_secret",
		[]string{"https://www.googleapis.com/auth/webmasters.readonly"}, "https://searchconsole.googleapis.com")
	u, err := p.AuthURL(context.Background(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"state=STATE123", "access_type=offline", "prompt=consent", "client_id=cid", "webmasters.readonly"} {
		if !strings.Contains(u, want) {
			t.Errorf("consent URL missing %q: %s", want, u)
		}
	}
}

func TestGoogleProvider_MissingConfig(t *testing.T) {
	p := NewGoogleProvider(newFake(), "gsc", "https://app/cb", "", "google_secret", nil, "")
	if _, err := p.AuthURL(context.Background(), 1, nil); err == nil {
		t.Error("expected error for empty ClientID")
	}
}

func TestGBPProvider_Config(t *testing.T) {
	b := NewGBPProvider(newFake(), "gbp", "https://app/cb", "cid", "google_secret",
		[]string{"https://www.googleapis.com/auth/business.manage"})
	if b.Endpoint != google.Endpoint {
		t.Error("GBP must use google.Endpoint")
	}
	if len(b.Scopes) != 1 || b.Scopes[0] != "https://www.googleapis.com/auth/business.manage" {
		t.Errorf("GBP scopes (caller-supplied) not preserved: %v", b.Scopes)
	}
	if b.DeriveAPIEndpoint == nil {
		t.Error("GBP must set the DeriveAPIEndpoint hook")
	}
}

func TestMetaProvider_Config(t *testing.T) {
	b := NewMetaProvider(newFake(), "meta", "https://app/cb", "appid", "meta_secret",
		[]string{"pages_show_list", "business_management"})
	if b.DeriveCredential == nil || b.TestHealthcheck == nil {
		t.Error("Meta must set DeriveCredential (long-lived swap) + TestHealthcheck")
	}
	if b.RequireRefresh {
		t.Error("Meta has no refresh token; RequireRefresh must be false")
	}
}

func TestBaseProvider_connType(t *testing.T) {
	if (&BaseProvider{}).connType() != ConnTypeOAuth {
		t.Error("empty ConnType must default to ConnTypeOAuth")
	}
	if (&BaseProvider{ConnType: "X"}).connType() != "X" {
		t.Error("explicit ConnType must be preserved")
	}
}

func TestBaseProvider_deriveCredential(t *testing.T) {
	b := &BaseProvider{}
	if got, _ := b.deriveCredential(context.Background(), &oauth2.Token{RefreshToken: "r", AccessToken: "a"}); got != "r" {
		t.Errorf("refresh token should win: %q", got)
	}
	if got, _ := b.deriveCredential(context.Background(), &oauth2.Token{AccessToken: "a"}); got != "a" {
		t.Errorf("access token fallback: %q", got)
	}
	b.DeriveCredential = func(context.Context, *oauth2.Token) (string, error) { return "custom", nil }
	if got, _ := b.deriveCredential(context.Background(), &oauth2.Token{RefreshToken: "r"}); got != "custom" {
		t.Errorf("hook should override: %q", got)
	}
}
