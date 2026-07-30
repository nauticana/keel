package common

import "context"

// RequestIDFromContext returns the request correlation id bound by HTTP
// middleware or an operator-initiated background action.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	requestID, _ := ctx.Value(RequestID).(string)
	return requestID
}

// WithRequestID binds a request correlation id when one is available.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	if requestID == "" {
		return ctx
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, RequestID, requestID)
}
