package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// APIKeyAuthMiddleware validates the X-API-Key header on every request, looks
// up the key, enforces expiry + quota, logs usage async, and injects
// partner_id / api_key_id / scopes into the request context. No path-prefix
// gating — the caller decides which routes require auth.
//
// Two consumers in keel:
//
//  1. HttpBackend.APIKeyMiddleware wraps this with /pubapi/* path-gating, so
//     REST callers under that prefix are authenticated. JWT-authed routes
//     bypass.
//  2. Standalone services (e.g. an MCP server exposed over Streamable HTTP)
//     wrap their entire handler with this factory directly — every request
//     to the public endpoint must present an X-API-Key.
//
// All status codes match the original inline pattern: 401 for missing/invalid/
// expired keys, 429 for over-quota, 500 for transport/DB errors.
func APIKeyAuthMiddleware(apiKeys *APIKeyService, quota port.QuotaService, journal logger.ApplicationLogger) func(http.Handler) http.Handler {
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
			allowed, err := quota.CheckQuota(r.Context(), entry.PartnerID, "API_CALLS", 1)
			if err != nil {
				journal.Error(fmt.Sprintf("Quota check error for partner %d: %s", entry.PartnerID, err.Error()))
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
				if err := apiKeys.LogUsage(ctx, entry.PartnerID, entry.KeyID); err != nil && journal != nil {
					// Async usage-log failure was previously dropped silently.
					// On a DB outage every request would silently skip the
					// usage increment and the partner could overrun their
					// quota with zero visibility. Surfacing the failure
					// lets ops correlate "quota didn't tick" with the
					// underlying transport error.
					journal.Error(fmt.Sprintf("API key usage log error for partner %d: %s", entry.PartnerID, err.Error()))
				}
			}()
			ctx := context.WithValue(r.Context(), common.PartnerID, entry.PartnerID)
			ctx = context.WithValue(ctx, common.ApiKeyID, entry.KeyID)
			ctx = context.WithValue(ctx, common.Scopes, entry.Scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
