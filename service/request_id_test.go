package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
)

func withRequestIDConfig(t *testing.T, header, trusted string) {
	t.Helper()
	savedHeader, savedTrusted := config.Config().RequestIDHeader, config.Config().TrustedProxyCIDR
	config.Config().RequestIDHeader, config.Config().TrustedProxyCIDR = header, trusted
	t.Cleanup(func() {
		config.Config().RequestIDHeader, config.Config().TrustedProxyCIDR = savedHeader, savedTrusted
	})
}

func serveRequestID(remote, inbound string) (bound string, w *httptest.ResponseRecorder) {
	h := &HttpBackend{}
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.RemoteAddr = remote
	if inbound != "" {
		req.Header.Set("X-Request-Id", inbound)
	}
	w = httptest.NewRecorder()
	h.RequestIDMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		bound = common.RequestIDFromContext(r.Context())
	})).ServeHTTP(w, req)
	return bound, w
}

func TestRequestIDMiddlewareBindsAndEchoes(t *testing.T) {
	withRequestIDConfig(t, "X-Request-Id", "")
	bound, w := serveRequestID("198.51.100.4:1", "")
	if bound == "" || w.Header().Get("X-Request-Id") != bound {
		t.Fatalf("bound %q, response header %q", bound, w.Header().Get("X-Request-Id"))
	}
}

func TestRequestIDMiddlewareAdoptsOnlyTrustedValidIDs(t *testing.T) {
	withRequestIDConfig(t, "X-Request-Id", "10.0.0.0/8")
	if bound, _ := serveRequestID("10.0.0.9:1", "edge-7.a:b_c"); bound != "edge-7.a:b_c" {
		t.Errorf("trusted proxy id not adopted: %q", bound)
	}
	if bound, _ := serveRequestID("198.51.100.4:1", "spoofed"); bound == "spoofed" {
		t.Error("an untrusted peer chose its request id")
	}
	for _, bad := range []string{"has space", "line\nbreak", strings.Repeat("a", 129)} {
		if bound, _ := serveRequestID("10.0.0.9:1", bad); bound == bad || bound == "" {
			t.Errorf("invalid inbound id %q gave %q", bad, bound)
		}
	}
}

func TestRequestIDMiddlewareWithoutHeader(t *testing.T) {
	withRequestIDConfig(t, "", "10.0.0.0/8")
	h := &HttpBackend{}
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.RemoteAddr = "10.0.0.9:1"
	req.Header.Set("X-Request-Id", "edge-7")
	w := httptest.NewRecorder()
	bound := ""
	h.RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bound = common.RequestIDFromContext(r.Context())
		common.WriteJSON(w, http.StatusOK, "ok")
	})).ServeHTTP(w, req)
	var body common.APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if bound == "" || bound == "edge-7" || w.Header().Get("X-Request-Id") != "" {
		t.Fatalf("bound %q, headers %v", bound, w.Header())
	}
	if body.Meta.RequestID != bound {
		t.Fatalf("envelope request id %q, want bound id %q", body.Meta.RequestID, bound)
	}
}

func TestRequestIDReachesAccessLog(t *testing.T) {
	withRequestIDConfig(t, "X-Request-Id", "")
	journal := &capturingLogger{}
	h := &HttpBackend{Journal: journal}
	w := httptest.NewRecorder()
	h.RequestIDMiddleware(h.AccessLogMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))).
		ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if id := w.Header().Get("X-Request-Id"); id == "" || !strings.HasSuffix(journal.access[0], " "+id) {
		t.Fatalf("access line %q lacks request id %q", journal.access[0], id)
	}
}

func TestRequestIDMiddlewarePreservesFlush(t *testing.T) {
	withRequestIDConfig(t, "X-Request-Id", "")
	w := httptest.NewRecorder()
	(&HttpBackend{}).RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
	})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stream", nil))
	if !w.Flushed {
		t.Fatal("request id middleware did not forward flush")
	}
}
