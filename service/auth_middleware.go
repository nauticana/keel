package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/nauticana/keel/cache"
	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// APIKeyAuthMiddleware validates the X-API-Key header, enforces expiry, touches
// last_used async, and injects partner_id / api_key_id / scopes into context.
// Quota is enforced separately by QuotaMiddleware composed after auth, so the
// same gate covers X-API-Key and OAuth callers. No path-prefix gating — the
// caller decides which routes require auth.
func APIKeyAuthMiddleware(apiKeys *APIKeyService, journal logger.ApplicationLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				http.Error(w, `{"error":"missing X-API-Key header"}`, http.StatusUnauthorized)
				return
			}
			hash := sha256.Sum256([]byte(apiKey))
			keyHash := hex.EncodeToString(hash[:])

			entry, err := apiKeys.LookupKey(r.Context(), keyHash)
			if err != nil {
				journal.Error(fmt.Sprintf("API key lookup error: %s", err.Error()))
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				return
			}
			if entry == nil {
				http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
				return
			}
			if entry.ExpiresAt.Year() > 1 && time.Now().After(entry.ExpiresAt) {
				http.Error(w, `{"error":"API key expired"}`, http.StatusUnauthorized)
				return
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := apiKeys.TouchLastUsed(ctx, entry.KeyID); err != nil && journal != nil {
					journal.Error(fmt.Sprintf("API key last-used update error for partner %d: %s", entry.PartnerID, err.Error()))
				}
			}()
			ctx := context.WithValue(r.Context(), common.PartnerID, entry.PartnerID)
			ctx = context.WithValue(ctx, common.ApiKeyID, entry.KeyID)
			ctx = context.WithValue(ctx, common.Scopes, entry.Scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// QuotaMiddleware enforces per-partner quota after authentication, reading
// partner_id from context (set by APIKeyAuthMiddleware or oauth/resource.Middleware)
// so one gate serves every auth method. Requests with no partner (anonymous
// OAuth) pass through — gate those with an IP/client limiter if needed. 429 over
// quota, 500 on quota-service error; usage is logged async on success.
func QuotaMiddleware(quota port.QuotaService, resource, caption string, journal logger.ApplicationLogger) func(http.Handler) http.Handler {
	if resource == "" {
		resource = "API_CALLS"
	}
	if caption == "" {
		caption = "public-api"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			partnerID, ok := r.Context().Value(common.PartnerID).(int64)
			if !ok || partnerID <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			allowed, err := quota.CheckQuota(r.Context(), partnerID, resource, 1)
			if err != nil {
				if journal != nil {
					journal.Error(fmt.Sprintf("Quota check error for partner %d: %s", partnerID, err.Error()))
				}
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				return
			}
			if !allowed {
				http.Error(w, `{"error":"daily API quota exceeded"}`, http.StatusTooManyRequests)
				return
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := quota.LogUsage(ctx, partnerID, resource, 1, caption); err != nil && journal != nil {
					journal.Error(fmt.Sprintf("Quota usage log error for partner %d: %s", partnerID, err.Error()))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware caps requests per keyBy(r) (e.g. client IP or client_id)
// to limit per window, returning 429 over budget. It is a backstop against
// request storms — wrap public/unauthenticated endpoints such as open Dynamic
// Client Registration. Backed by CacheService (Increment + a TTL on the first
// hit). Fails open when no cache is wired or the cache errors, so a cache outage
// can't take the route down.
func RateLimitMiddleware(c cache.CacheService, limit int64, window time.Duration, keyBy func(*http.Request) string, journal logger.ApplicationLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c == nil || limit <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			id := r.RemoteAddr
			if keyBy != nil {
				id = keyBy(r)
			}
			key := "rl:" + id
			count, err := c.IncrementWithTTL(r.Context(), key, window)
			if err != nil {
				if journal != nil {
					journal.Error(fmt.Sprintf("rate limit cache error for %s: %s", id, err.Error()))
				}
				next.ServeHTTP(w, r) // fail open — never take a route down on cache error
				return
			}
			if count > limit {
				w.Header().Set("Retry-After", strconv.Itoa(int(window.Seconds())))
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
