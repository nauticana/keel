package service

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/logger"
)

type capturingLogger struct {
	logger.ApplicationLogger
	access []string
}

func (l *capturingLogger) Access(log string) { l.access = append(l.access, log) }

var _ logger.ApplicationLogger = (*capturingLogger)(nil)

func TestAccessLogMiddleware_RecordsStatusBytesAndPeerIP(t *testing.T) {
	journal := &capturingLogger{}
	h := &HttpBackend{Journal: journal}
	handler := h.AccessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/thing?token=credential", nil)
	req.RemoteAddr = "10.0.0.9:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if len(journal.access) != 1 {
		t.Fatalf("expected one access line, got %d", len(journal.access))
	}
	line := journal.access[0]
	for _, want := range []string{"POST /api/v1/thing 201 5B ", " 10.0.0.9"} {
		if !strings.Contains(line, want) {
			t.Errorf("access line %q missing %q", line, want)
		}
	}
}

func TestAccessLogMiddleware_TrustedProxyPromotesForwardedFor(t *testing.T) {
	saved := config.Config().TrustedProxyCIDR
	config.Config().TrustedProxyCIDR = "10.0.0.0/8"
	t.Cleanup(func() { config.Config().TrustedProxyCIDR = saved })

	journal := &capturingLogger{}
	h := &HttpBackend{Journal: journal}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.9:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	h.AccessLogMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)
	if !strings.HasSuffix(journal.access[0], " 203.0.113.7") {
		t.Fatalf("unexpected access line %q", journal.access[0])
	}
}

func TestAccessLogMiddleware_DefaultsTo200WithoutExplicitWriteHeader(t *testing.T) {
	journal := &capturingLogger{}
	h := &HttpBackend{Journal: journal}
	handler := h.AccessLogMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "127.0.0.1:1"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := journal.access[0]; !strings.HasPrefix(got, "GET /x 200 0B ") || !strings.HasSuffix(got, " 127.0.0.1") {
		t.Errorf("unexpected access line %q", got)
	}
}

func TestAccessLogMiddleware_ProbesLoggedOnlyOnFailure(t *testing.T) {
	journal := &capturingLogger{}
	h := &HttpBackend{Journal: journal}
	status := http.StatusOK
	handler := h.AccessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	for _, path := range []string{"/health", "/ready"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	}
	if len(journal.access) != 0 {
		t.Fatalf("healthy probes logged: %v", journal.access)
	}
	status = http.StatusServiceUnavailable
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))
	if len(journal.access) != 1 || !strings.Contains(journal.access[0], " 503 ") {
		t.Fatalf("failing probe not logged: %v", journal.access)
	}
}

func TestAccessLogMiddleware_NoLogger(t *testing.T) {
	h := &HttpBackend{}
	w := httptest.NewRecorder()
	h.AccessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 204 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestAccessLogMiddleware_PanicStillLoggedAndPropagated(t *testing.T) {
	journal := &capturingLogger{}
	h := &HttpBackend{Journal: journal}
	defer func() {
		if recover() != "boom" {
			t.Error("panic was swallowed or changed")
		}
		if len(journal.access) != 1 || !strings.Contains(journal.access[0], " 500 ") {
			t.Errorf("logs=%v", journal.access)
		}
	}()
	h.AccessLogMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
		panic("boom")
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

type headerWriter struct {
	headers http.Header
	codes   []int
}

func (w *headerWriter) Header() http.Header {
	if w.headers == nil {
		w.headers = make(http.Header)
	}
	return w.headers
}
func (w *headerWriter) WriteHeader(code int)        { w.codes = append(w.codes, code) }
func (w *headerWriter) Write(b []byte) (int, error) { return len(b), nil }

var _ http.ResponseWriter = (*headerWriter)(nil)

func TestAccessRecorder_ForwardsEveryWriteHeaderRecordsFirstFinal(t *testing.T) {
	base := &headerWriter{}
	rec := &accessRecorder{ResponseWriter: base}
	rec.WriteHeader(103)
	rec.WriteHeader(201)
	rec.WriteHeader(500)
	if rec.status != 201 || len(base.codes) != 3 {
		t.Fatalf("status=%d headers=%v", rec.status, base.codes)
	}
}

type unwrapWriter struct{ http.ResponseWriter }

func (w unwrapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestAccessRecorder_FlushThroughWrapper(t *testing.T) {
	base := httptest.NewRecorder()
	rec := &accessRecorder{ResponseWriter: unwrapWriter{base}}
	if err := http.NewResponseController(rec).Flush(); err != nil {
		t.Fatal(err)
	}
	if rec.status != 200 || !base.Flushed || base.Code != 200 {
		t.Fatalf("status=%d underlying=%d flushed=%v", rec.status, base.Code, base.Flushed)
	}
	unsupported := &accessRecorder{ResponseWriter: &headerWriter{}}
	if err := http.NewResponseController(unsupported).Flush(); !errors.Is(err, http.ErrNotSupported) {
		t.Fatalf("flush error=%v", err)
	}
}

type hijackWriter struct {
	headerWriter
	err error
}

func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, w.err }

var _ http.Hijacker = (*hijackWriter)(nil)

func TestAccessRecorder_HijackStatus(t *testing.T) {
	for _, fail := range []bool{false, true} {
		base := &hijackWriter{}
		if fail {
			base.err = errors.New("failed")
		}
		rec := &accessRecorder{ResponseWriter: unwrapWriter{base}}
		_, _, err := rec.Hijack()
		if fail {
			if err == nil || rec.status != 0 {
				t.Fatal("failed hijack recorded as success")
			}
		} else if err != nil || rec.status != 101 {
			t.Fatalf("status=%d err=%v", rec.status, err)
		}
	}
}

func TestAccessLogMiddleware_RecordsSSORejection(t *testing.T) {
	journal := &capturingLogger{}
	h := &HttpBackend{Journal: journal}
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthenticated request reached handler") })
	rec := httptest.NewRecorder()
	h.AccessLogMiddleware(h.SSOMiddleware(next)).ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/private?token=credential", nil))
	if rec.Code != 401 || len(journal.access) != 1 {
		t.Fatalf("status=%d logs=%v", rec.Code, journal.access)
	}
	if strings.Contains(journal.access[0], "credential") || strings.Contains(journal.access[0], "?") {
		t.Fatal("query string logged")
	}
}
