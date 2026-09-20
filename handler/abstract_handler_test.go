package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/model"
)

func TestHasScope(t *testing.T) {
	var h AbstractHandler
	req := func(ctx context.Context) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(ctx)
	}

	t.Run("oauth principal scopes", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), common.AuthPrincipal,
			&model.TokenPrincipal{Scopes: []string{"read", "write"}})
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

func TestRequirePartnerRejectsNonPositiveIDs(t *testing.T) {
	var h AbstractHandler
	for _, tc := range []struct {
		partnerID int64
		ok        bool
	}{{-1, false}, {0, false}, {42, true}} {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		stashSession(r, &model.UserSession{Id: 1, PartnerId: tc.partnerID})
		w := httptest.NewRecorder()
		got, ok := h.RequirePartner(w, r)
		if ok != tc.ok {
			t.Fatalf("partner %d: ok=%v, want %v", tc.partnerID, ok, tc.ok)
		}
		if tc.ok && got != tc.partnerID {
			t.Fatalf("partner %d: got %d", tc.partnerID, got)
		}
		if !tc.ok && w.Code != http.StatusUnauthorized {
			t.Fatalf("partner %d: status %d, want 401", tc.partnerID, w.Code)
		}
	}
}

func TestSessionPartner(t *testing.T) {
	var h AbstractHandler
	for _, session := range []*model.UserSession{nil, {Id: 1}, {Id: 1, PartnerId: -1}} {
		_, err := h.SessionPartner(session)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
			t.Fatalf("session %+v: err = %v, want 401 APIError", session, err)
		}
	}
	if got, err := h.SessionPartner(&model.UserSession{Id: 1, PartnerId: 42}); err != nil || got != 42 {
		t.Fatalf("got %d, %v", got, err)
	}
}
