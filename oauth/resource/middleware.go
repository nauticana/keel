package resource

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/logger"
	"github.com/nauticana/keel/port"
)

// PartnerResolver maps a validated OAuth principal to a keel partner id
// (account linking). Return 0 when the subject isn't linked to a partner.
// Optional — pass nil to inject the principal/scopes without a partner id.
type PartnerResolver func(ctx context.Context, p *port.Principal) (int64, error)

// Middleware authenticates requests with an OAuth 2.1 bearer
// access token (resource-server role). It validates the token via validator,
// injects the principal, subject, and space-delimited scopes (plus partner id
// when resolve maps one) into the request context, and challenges callers
// without a valid token using an RFC 9728 resource_metadata pointer so OAuth /
// MCP clients can discover the authorization server.
//
// Composable like APIKeyAuthMiddleware: wrap a standalone handler (e.g. an MCP
// Streamable-HTTP server) or a sub-router. 401 on missing/invalid token, 500
// if the resolver errors. It does not gate by path — the caller decides which
// routes require OAuth, leaving X-API-Key / JWT routes untouched.
func Middleware(validator port.TokenValidator, metadataURL string, journal logger.ApplicationLogger, resolve PartnerResolver) func(http.Handler) http.Handler {
	if validator == nil {
		panic("oauth: Middleware requires a non-nil TokenValidator")
	}
	challenge := "Bearer"
	if metadataURL != "" {
		challenge = fmt.Sprintf("Bearer resource_metadata=%q", metadataURL)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer := extractBearer(r)
			if bearer == "" {
				w.Header().Set("WWW-Authenticate", challenge)
				http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
				return
			}
			principal, err := validator.Validate(r.Context(), bearer)
			if err != nil {
				w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token"`)
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), common.AuthPrincipal, principal)
			ctx = context.WithValue(ctx, common.Subject, principal.Subject)
			ctx = context.WithValue(ctx, common.Scopes, strings.Join(principal.Scopes, " "))
			if resolve != nil {
				partnerID, err := resolve(ctx, principal)
				if err != nil {
					if journal != nil {
						journal.Error(fmt.Sprintf("oauth partner resolve error for sub %s: %s", principal.Subject, err.Error()))
					}
					http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
					return
				}
				if partnerID > 0 {
					ctx = context.WithValue(ctx, common.PartnerID, partnerID)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// PrincipalFromContext returns the OAuth principal injected by
// Middleware, or nil for non-OAuth requests.
func PrincipalFromContext(ctx context.Context) *port.Principal {
	p, _ := ctx.Value(common.AuthPrincipal).(*port.Principal)
	return p
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) >= 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
