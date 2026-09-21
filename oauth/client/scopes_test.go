package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestParseScopes(t *testing.T) {
	cases := map[string][]string{
		"":                        {},
		"read_products":           {"read_products"},
		"read_products,write_seo": {"read_products", "write_seo"}, // shopify commas
		"a b  a":                  {"a", "b"},                     // RFC 6749 spaces, repeats dropped
		" a,\nb ":                 {"a", "b"},
	}
	for in, want := range cases {
		if got := ParseScopes(in); !reflect.DeepEqual(got, want) {
			t.Errorf("ParseScopes(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestMissingScopes(t *testing.T) {
	granted := []string{"webmasters.readonly", "openid"}
	if got := MissingScopes(granted, []string{"openid"}); len(got) != 0 {
		t.Errorf("nothing should be missing, got %v", got)
	}
	want := []string{"webmasters", "analytics"}
	if got := MissingScopes(granted, []string{"webmasters", "openid", "analytics"}); !reflect.DeepEqual(got, want) {
		t.Errorf("MissingScopes = %v, want %v in required order", got, want)
	}
}

// Extra scopes widen the consent URL and must not be stashed in the state —
// the state is replayed at Callback, where the requested set is irrelevant.
func TestAuthURL_ExtraScopesWidenConsentOnly(t *testing.T) {
	cs := &capturingStore{fakeStore: newFake()}
	p := NewOAuth2Provider(cs, "gsc", "https://app/cb", "cid", "google_secret",
		oauth2.Endpoint{AuthURL: "https://g/auth", TokenURL: "https://g/token"},
		[]string{"webmasters.readonly"}, "https://api", false)

	u, err := p.AuthURL(context.Background(), 1, map[string]string{
		StateEntityKey:   "9",
		ParamExtraScopes: "webmasters",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, "scope=webmasters.readonly+webmasters") {
		t.Errorf("consent URL should request both scopes: %s", u)
	}
	if _, ok := cs.params[ParamExtraScopes]; ok {
		t.Errorf("extra scopes must not ride the state: %v", cs.params)
	}
	if cs.params[stateRequestedScopesKey] != "webmasters.readonly webmasters" {
		t.Errorf("requested grant must ride the state: %v", cs.params)
	}
	if cs.params[StateEntityKey] != "9" {
		t.Errorf("entity must still ride the state: %v", cs.params)
	}
}

func TestBaseProviderCallbackRecordsGrantedScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","refresh_token":"RT","scope":"webmasters.readonly openid"}`))
	}))
	defer srv.Close()

	store := &fakeStore{secrets: map[string]string{"s": "shh"}, state: "S"}
	b := &BaseProvider{
		Service: store, ProviderName: "gsc", CallbackURL: "https://app/cb",
		ClientID: "cid", SecretName: "s",
		Endpoint: oauth2.Endpoint{TokenURL: srv.URL},
	}
	if err := b.Callback(context.Background(), "CODE", "S"); err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if want := []string{"webmasters.readonly", "openid"}; !reflect.DeepEqual(store.gotScopes, want) {
		t.Errorf("granted scopes = %v, want %v", store.gotScopes, want)
	}
}

func TestBaseProviderCallbackInfersOmittedScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT"}`))
	}))
	defer srv.Close()

	store := &capturingStore{fakeStore: &fakeStore{secrets: map[string]string{"s": "shh"}, state: "S"}}
	b := &BaseProvider{
		Service: store, ProviderName: "gsc", CallbackURL: "https://app/cb",
		ClientID: "cid", SecretName: "s", Scopes: []string{"webmasters"},
		Endpoint: oauth2.Endpoint{AuthURL: srv.URL + "/auth", TokenURL: srv.URL}, RequiredScopes: []string{"webmasters", "inspection"},
	}
	if _, err := b.AuthURL(context.Background(), 1, map[string]string{ParamExtraScopes: "inspection"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Callback(context.Background(), "CODE", "S"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(store.gotScopes, []string{"webmasters", "inspection"}) {
		t.Fatalf("granted scopes = %v", store.gotScopes)
	}
}

// Meta omits scope even when the user declined permissions, so nothing is inferred.
func TestBaseProviderCallbackNoImpliedScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT"}`))
	}))
	defer srv.Close()

	store := &fakeStore{secrets: map[string]string{"s": "shh"}, state: "S"}
	b := &BaseProvider{
		Service: store, ProviderName: "meta", CallbackURL: "https://app/cb",
		ClientID: "cid", SecretName: "s", Scopes: []string{"pages_show_list"},
		Endpoint: oauth2.Endpoint{TokenURL: srv.URL}, NoImpliedScopes: true,
	}
	if err := b.Callback(context.Background(), "CODE", "S"); err != nil {
		t.Fatal(err)
	}
	if len(store.gotScopes) != 0 {
		t.Fatalf("granted scopes = %v, want none recorded", store.gotScopes)
	}
	if !NewMetaProvider(store, "meta", "cb", "id", "s", nil).NoImpliedScopes {
		t.Error("the Meta provider must not infer scopes")
	}
}

// A grant narrower than RequiredScopes is refused before the connection is stored.
func TestBaseProviderCallbackRefusesNarrowGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"AT","scope":"webmasters.readonly"}`))
	}))
	defer srv.Close()

	store := &fakeStore{secrets: map[string]string{"s": "shh"}, state: "S"}
	b := &BaseProvider{
		Service: store, ProviderName: "gsc", CallbackURL: "https://app/cb",
		ClientID: "cid", SecretName: "s",
		Endpoint:       oauth2.Endpoint{TokenURL: srv.URL},
		RequiredScopes: []string{"webmasters"},
	}
	err := b.Callback(context.Background(), "CODE", "S")
	var missing *MissingScopeError
	if !errors.As(err, &missing) {
		t.Fatalf("err = %v, want *MissingScopeError", err)
	}
	if !reflect.DeepEqual(missing.Missing, []string{"webmasters"}) {
		t.Errorf("missing = %v", missing.Missing)
	}
	if store.gotCred != "" {
		t.Error("a narrow grant must not be stored")
	}
}
