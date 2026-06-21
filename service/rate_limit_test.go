package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauticana/keel/cache"
)

func TestRateLimitMiddleware(t *testing.T) {
	c := cache.NewMemoryCacheService()
	mw := RateLimitMiddleware(c, 3, time.Minute, func(*http.Request) string { return "k1" }, nil)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	var codes []int
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		codes = append(codes, rec.Code)
	}
	for i := 0; i < 3; i++ {
		if codes[i] != http.StatusOK {
			t.Fatalf("req %d = %d, want 200", i, codes[i])
		}
	}
	if codes[3] != http.StatusTooManyRequests || codes[4] != http.StatusTooManyRequests {
		t.Fatalf("over-limit = %v, want 429s", codes[3:])
	}
}

func TestRateLimitMiddlewareFailsOpenWithoutCache(t *testing.T) {
	mw := RateLimitMiddleware(nil, 1, time.Minute, nil, nil)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("nil cache must fail open, got %d", rec.Code)
		}
	}
}
