package service

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"

	"github.com/nauticana/keel/common"
)

// startedWriter records whether the response has begun, which decides whether
// a recovered panic can still be answered.
type startedWriter struct {
	http.ResponseWriter
	started bool
}

func (w *startedWriter) WriteHeader(code int) {
	if code >= http.StatusOK || code == http.StatusSwitchingProtocols {
		w.started = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *startedWriter) Write(b []byte) (int, error) {
	w.started = true
	return w.ResponseWriter.Write(b)
}

func (w *startedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *startedWriter) FlushError() error {
	w.started = true
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *startedWriter) Flush() { _ = w.FlushError() }

func (w *startedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.started = true
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

var (
	_ http.Flusher  = (*startedWriter)(nil)
	_ http.Hijacker = (*startedWriter)(nil)
)

// RecoverMiddleware answers a handler panic with the sanitized 500 envelope
// and the request id, keeping the headers outer middleware set (CORS among
// them) and the connection. The stack is logged. A panic after the response
// began, or http.ErrAbortHandler, is re-raised: the response cannot be
// answered, so net/http aborts it.
func (h *HttpBackend) RecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &startedWriter{ResponseWriter: w}
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler || sw.started {
				panic(rec)
			}
			requestID := common.RequestIDFromContext(r.Context())
			if requestID == "" {
				requestID = common.NewRequestID()
			}
			h.logPanic(fmt.Sprintf("request_id=%s panic %s %s: %v\n%s", requestID, r.Method, r.URL.EscapedPath(), rec, debug.Stack()))
			w.Header().Del("Content-Length")
			_ = common.WriteProblem(w, common.ProblemDetail{
				Type:      "about:blank",
				Title:     http.StatusText(http.StatusInternalServerError),
				Status:    http.StatusInternalServerError,
				Detail:    common.InternalErrorDetail,
				RequestID: requestID,
			})
		}()
		next.ServeHTTP(sw, r)
	})
}

func (h *HttpBackend) logPanic(msg string) {
	if h.Journal != nil {
		h.Journal.Error(msg)
		return
	}
	log.Print(msg)
}
