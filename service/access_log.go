package service

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nauticana/keel/common"
)

const maxAccessLogHeader = 64

// accessRecorder captures the status and byte count for the access log.
// Every call is forwarded, so net/http's own diagnostics (superfluous
// WriteHeader, etc.) still fire; Unwrap keeps http.ResponseController working.
type accessRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *accessRecorder) WriteHeader(code int) {
	if r.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *accessRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *accessRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *accessRecorder) FlushError() error {
	err := http.NewResponseController(r.ResponseWriter).Flush()
	if err == nil && r.status == 0 {
		r.status = http.StatusOK
	}
	return err
}

func (r *accessRecorder) Flush() { _ = r.FlushError() }

func (r *accessRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(r.ResponseWriter).Hijack()
	if err == nil && r.status == 0 {
		r.status = http.StatusSwitchingProtocols
	}
	return conn, rw, err
}

var (
	_ http.Flusher  = (*accessRecorder)(nil)
	_ http.Hijacker = (*accessRecorder)(nil)
)

// accessLogHeaders quotes each value so a client cannot forge log fields.
func (h *HttpBackend) accessLogHeaders(r *http.Request) string {
	var b strings.Builder
	for _, name := range h.AccessLogHeaders {
		b.WriteString(" " + name + "=")
		if value := r.Header.Get(name); value != "" {
			b.WriteString(strconv.Quote(common.TruncateRunes(value, maxAccessLogHeader)))
		} else {
			b.WriteString("-")
		}
	}
	return b.String()
}

// AccessLogMiddleware writes one ApplicationLogger.Access line per request:
// method, escaped path (query excluded: confirmation links carry codes),
// status, response bytes, duration, the trusted-proxy-gated client IP and the
// request id, then each AccessLogHeaders header.
// Outermost in the chain so rejections from inner middleware are recorded;
// RecoverMiddleware answers handler panics, and a panic that still reaches
// here (one after the response began) logs 500 and re-panics. Healthy probe
// hits are skipped.
func (h *HttpBackend) AccessLogMiddleware(next http.Handler) http.Handler {
	if h.Journal == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &accessRecorder{ResponseWriter: w}
		completed := false
		defer func() {
			status := rec.status
			switch {
			case !completed:
				status = http.StatusInternalServerError
			case status == 0:
				status = http.StatusOK
			}
			if isProbePath(r.URL.Path) && status < http.StatusBadRequest {
				return
			}
			requestID := common.RequestIDFromContext(r.Context())
			if requestID == "" {
				requestID = "-"
			}
			line := fmt.Sprintf("%s %s %d %dB %dms %s %s",
				r.Method, r.URL.EscapedPath(), status, rec.bytes,
				time.Since(start).Milliseconds(), common.TrustedClientIP(r), requestID)
			h.Journal.Access(line + h.accessLogHeaders(r))
		}()
		next.ServeHTTP(rec, r)
		completed = true
	})
}
