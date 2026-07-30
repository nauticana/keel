package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauticana/keel/cache"
)

var errCacheDown = errors.New("cache: connection refused")

// brokenCache fails every counter read, standing in for a Redis outage.
type brokenCache struct {
	cache.CacheService
	increments int
}

func (c *brokenCache) Increment(context.Context, string) (int64, error) {
	c.increments++
	return 0, errCacheDown
}

func (c *brokenCache) IncrementWithTTL(context.Context, string, time.Duration) (int64, error) {
	c.increments++
	return 0, errCacheDown
}

func (c *brokenCache) Set(context.Context, string, string, time.Duration) error { return nil }

// TestRateLimitOTP_FailsClosedWhenCounterUnavailable — dispatch has no
// database-backed backstop, so a cache error must refuse the send. Discarding
// the error left `count` at 0, which passed every cap and turned a cache outage
// into an uncapped SMS/email spend path.
func TestRateLimitOTP_FailsClosedWhenCounterUnavailable(t *testing.T) {
	broken := &brokenCache{}
	h := &OTPHandler{Cache: broken}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/public/otp/send", nil)

	if h.rateLimitOTP(rec, req, "+15551234567") {
		t.Fatal("rateLimitOTP allowed the send while the counter was unavailable")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (retryable, no detail leaked)", rec.Code)
	}
	if broken.increments != 1 {
		t.Errorf("cache increments = %d, want 1 — must refuse on the first failure", broken.increments)
	}
}

// TestRateLimitVerify2FA_AllowsWhenCounterUnavailable — the opposite call, and
// deliberately so: LocalUserService.Verify2FA still locks the account at
// MaxAttempts via a persisted counter, so failing closed here would trade a
// backstopped abuse window for a total 2FA login outage on any cache hiccup.
func TestRateLimitVerify2FA_AllowsWhenCounterUnavailable(t *testing.T) {
	broken := &brokenCache{}
	h := &SecurityHandler{Cache: broken}
	req := httptest.NewRequest(http.MethodPost, "/public/2fa/verify", nil)

	if h.rateLimitVerify2FA(req) {
		t.Fatal("rateLimitVerify2FA blocked the attempt on a cache error; the DB lockout is the real bound")
	}
	if broken.increments != 1 {
		t.Errorf("cache increments = %d, want 1", broken.increments)
	}
}

// TestRateLimitVerify2FA_AllowsWithoutCache pins the documented backward-compat
// behavior: deployments that never wire a Cache keep working.
func TestRateLimitVerify2FA_AllowsWithoutCache(t *testing.T) {
	h := &SecurityHandler{}
	if h.rateLimitVerify2FA(httptest.NewRequest(http.MethodPost, "/public/2fa/verify", nil)) {
		t.Fatal("rateLimitVerify2FA must allow when no Cache is wired")
	}
}
