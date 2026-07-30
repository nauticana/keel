package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/port"
)

func TestHasScope(t *testing.T) {
	var h AbstractHandler
	req := func(ctx context.Context) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(ctx)
	}

	t.Run("oauth principal scopes", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), common.AuthPrincipal,
			&port.Principal{Scopes: []string{"read", "write"}})
		if !h.HasScope(req(ctx), "write") {
			t.Fatal("want write present")
		}
		if h.HasScope(req(ctx), "delete") {
			t.Fatal("want delete absent")
		}
	})

	t.Run("api-key comma string", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), common.Scopes, "read, write")
		if !h.HasScope(req(ctx), "write") {
			t.Fatal("want write present")
		}
	})

	t.Run("empty context and empty scope", func(t *testing.T) {
		if h.HasScope(req(context.Background()), "read") {
			t.Fatal("want absent on bare context")
		}
		ctx := context.WithValue(context.Background(), common.Scopes, "read")
		if h.HasScope(req(ctx), "") {
			t.Fatal("want false for empty scope")
		}
	})
}

func TestEnsureRequestIDPreservesOrCreatesCorrelation(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/public/webhook/stripe", nil)
	correlated := EnsureRequestID(request)
	generated := common.RequestIDFromContext(correlated.Context())
	if generated == "" {
		t.Fatal("request id was not generated")
	}
	if EnsureRequestID(correlated) != correlated {
		t.Fatal("already-correlated request must be returned unchanged")
	}

	upstream := request.WithContext(common.WithRequestID(request.Context(), "edge-request-7"))
	if got := common.RequestIDFromContext(EnsureRequestID(upstream).Context()); got != "edge-request-7" {
		t.Fatalf("request id = %q, want upstream id", got)
	}
}
