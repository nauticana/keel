package resource

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// RequireScopes runs after Middleware and answers 403 with an RFC 6750
// insufficient_scope challenge unless the token carries every scope, so a
// client can ask the user for more.
func RequireScopes(metadataURL string, scopes ...string) func(http.Handler) http.Handler {
	challenge := fmt.Sprintf(`Bearer error="insufficient_scope", scope=%q`, strings.Join(scopes, " "))
	if metadataURL != "" {
		challenge += fmt.Sprintf(", resource_metadata=%q", metadataURL)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := PrincipalFromContext(r.Context())
			if principal == nil {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
				return
			}
			for _, scope := range scopes {
				if !slices.Contains(principal.Scopes, scope) {
					w.Header().Set("WWW-Authenticate", challenge)
					http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
