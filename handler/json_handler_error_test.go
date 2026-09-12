package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rateLimited stands in for a downstream's typed domain error: it carries retry
// advice that the status+message mapping alone would drop.
type rateLimited struct{ after string }

func (e *rateLimited) Error() string { return "rate limited" }

func (e *rateLimited) ErrorHeaders() http.Header {
	return http.Header{"Retry-After": []string{e.after}}
}

func TestJSONPublic_WritesHeadersFromAPIError(t *testing.T) {
	h := &AbstractHandler{}
	fn := func(context.Context, json.RawMessage) (any, error) {
		return nil, NewAPIError(http.StatusTooManyRequests, "slow down").WithHeader("Retry-After", "30")
	}

	rec := httptest.NewRecorder()
	h.JSONPublic("", fn)(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "30" {
		t.Errorf("Retry-After = %q, want 30", got)
	}
}

// A domain error that is not an *APIError still gets its headers written, so a
// caller does not have to re-derive them when mapping the status.
func TestJSONPublic_WritesHeadersFromWrappedDomainError(t *testing.T) {
	h := &AbstractHandler{}
	domain := &rateLimited{after: "12"}
	wrapped := func(context.Context, json.RawMessage) (any, error) {
		return nil, errors.Join(NewAPIError(http.StatusTooManyRequests, "slow down"), domain)
	}
	rec := httptest.NewRecorder()
	h.JSONPublic("", wrapped)(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if got := rec.Header().Get("Retry-After"); got != "12" {
		t.Errorf("Retry-After = %q, want 12", got)
	}
}

func TestJSONPublic_NoHeadersOnPlainError(t *testing.T) {
	h := &AbstractHandler{}
	fn := func(context.Context, json.RawMessage) (any, error) { return nil, errors.New("boom") }

	rec := httptest.NewRecorder()
	h.JSONPublic("", fn)(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "" {
		t.Errorf("unexpected Retry-After %q", got)
	}
}
