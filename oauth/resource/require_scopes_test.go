package resource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
)

func TestRequireScopes(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mw := RequireScopes("https://rs.example/.well-known/oauth-protected-resource", "read", "write")
	run := func(p *model.TokenPrincipal) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if p != nil {
			r = r.WithContext(context.WithValue(r.Context(), common.AuthPrincipal, p))
		}
		rec := httptest.NewRecorder()
		mw(ok).ServeHTTP(rec, r)
		return rec
	}
	if rec := run(nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no principal: %d", rec.Code)
	}
	rec := run(&model.TokenPrincipal{Scopes: []string{"read"}})
	challenge := rec.Header().Get("WWW-Authenticate")
	if rec.Code != http.StatusForbidden || !strings.Contains(challenge, `error="insufficient_scope"`) || !strings.Contains(challenge, `scope="read write"`) {
		t.Fatalf("missing scope: %d %q", rec.Code, challenge)
	}
	if rec := run(&model.TokenPrincipal{Scopes: []string{"write", "read"}}); rec.Code != http.StatusNoContent {
		t.Fatalf("all scopes: %d", rec.Code)
	}
}
