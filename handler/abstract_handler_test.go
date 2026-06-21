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
