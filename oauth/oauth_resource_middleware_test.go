package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

type stubValidator struct {
	principal *port.Principal
	err       error
}

func (s stubValidator) Validate(context.Context, string) (*port.Principal, error) {
	return s.principal, s.err
}

func serve(mw func(http.Handler) http.Handler, next http.Handler, setup func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if setup != nil {
		setup(req)
	}
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)
	return rec
}

func ok200(http.ResponseWriter, *http.Request) {}

func TestOAuthResourceMiddleware_MissingToken(t *testing.T) {
	mw := OAuthResourceMiddleware(stubValidator{}, "https://r/"+ProtectedResourceMetadataPath, nil, nil)
	rec := serve(mw, http.HandlerFunc(ok200), nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `resource_metadata="https://r/`) {
		t.Fatalf("missing RFC 9728 challenge: %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestOAuthResourceMiddleware_InvalidToken(t *testing.T) {
	mw := OAuthResourceMiddleware(stubValidator{err: errors.New("bad")}, "https://r/m", nil, nil)
	rec := serve(mw, http.HandlerFunc(ok200), func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer nope")
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("want invalid_token challenge, got %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestOAuthResourceMiddleware_ValidInjectsContext(t *testing.T) {
	principal := &port.Principal{Subject: "sub-1", Scopes: []string{"read", "write"}}
	resolve := func(context.Context, *port.Principal) (int64, error) { return 42, nil }
	mw := OAuthResourceMiddleware(stubValidator{principal: principal}, "", nil, resolve)

	var gotPartner int64
	var gotScopes string
	var gotPrincipal *port.Principal
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPartner, _ = r.Context().Value(common.PartnerID).(int64)
		gotScopes, _ = r.Context().Value(common.Scopes).(string)
		gotPrincipal = PrincipalFromContext(r.Context())
	})
	rec := serve(mw, next, func(r *http.Request) { r.Header.Set("Authorization", "Bearer good") })

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if gotPartner != 42 {
		t.Fatalf("want partner 42, got %d", gotPartner)
	}
	if gotScopes != "read write" {
		t.Fatalf("want scopes 'read write', got %q", gotScopes)
	}
	if gotPrincipal == nil || gotPrincipal.Subject != "sub-1" {
		t.Fatalf("principal not injected: %+v", gotPrincipal)
	}
}

func TestProtectedResourceMetadataHandler(t *testing.T) {
	h := ProtectedResourceMetadataHandler(ProtectedResourceMetadata{
		Resource:             "https://r",
		AuthorizationServers: []string{"https://as"},
	})
	rec := serve(func(http.Handler) http.Handler { return h }, nil, nil)

	var got ProtectedResourceMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if got.Resource != "https://r" || len(got.AuthorizationServers) != 1 {
		t.Fatalf("bad metadata: %+v", got)
	}
	if len(got.BearerMethodsSupported) != 1 || got.BearerMethodsSupported[0] != "header" {
		t.Fatalf("want default bearer_methods_supported=[header], got %v", got.BearerMethodsSupported)
	}
}

func TestScopeClaim(t *testing.T) {
	if got := scopeClaim(map[string]any{"scope": "a b c"}); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("scope string parse: %v", got)
	}
	if got := scopeClaim(map[string]any{"scp": []any{"x", "y"}}); strings.Join(got, ",") != "x,y" {
		t.Fatalf("scp array parse: %v", got)
	}
}
