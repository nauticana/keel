package service

import (
	"bufio"
	"net"
	"net/http"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
)

// requestIDWriter carries the id to common.WriteJSON, which has no request.
type requestIDWriter struct {
	http.ResponseWriter
	id string
}

func (w *requestIDWriter) RequestID() string           { return w.id }
func (w *requestIDWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *requestIDWriter) Flush()                      { _ = w.FlushError() }
func (w *requestIDWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *requestIDWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

var (
	_ http.Flusher  = (*requestIDWriter)(nil)
	_ http.Hijacker = (*requestIDWriter)(nil)
)

// RequestIDMiddleware binds one correlation id per request into
// common.RequestID. A valid request_id_header value from a trusted proxy is
// adopted; anything else gets a fresh id. The id is echoed in that header.
func (h *HttpBackend) RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := config.Config().RequestIDHeader
		id := common.RequestIDFromContext(r.Context())
		if id == "" && header != "" && common.FromTrustedProxy(r) {
			if inbound := r.Header.Get(header); common.ValidRequestID(inbound) {
				id = inbound
			}
		}
		if id == "" {
			id = common.NewRequestID()
		}
		if header != "" {
			w.Header().Set(header, id)
		}
		next.ServeHTTP(&requestIDWriter{ResponseWriter: w, id: id}, r.WithContext(common.WithRequestID(r.Context(), id)))
	})
}
