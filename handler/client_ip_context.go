package handler

import (
	"context"
	"net/http"
)

type clientIPCtxKey struct{}

// WithClientIPContext stashes the gated TrustedClientIP(r) in ctx. Its signature
// matches mcp-go's SSE/Streamable-HTTP context hook, but it's plain net/http and
// usable by any transport.
func WithClientIPContext(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, clientIPCtxKey{}, TrustedClientIP(r))
}

// ClientIPFromContext returns the IP placed by WithClientIPContext, or "" when
// absent (e.g. stdio transport).
func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPCtxKey{}).(string)
	return ip
}
