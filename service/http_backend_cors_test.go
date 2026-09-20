package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func corsResponse(h *HttpBackend, origin string) http.Header {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.CORSMiddleware(next).ServeHTTP(rec, req)
	return rec.Header()
}

func TestCORSExposeHeaders(t *testing.T) {
	const app = "https://app.example.com"
	tests := []struct {
		name    string
		backend *HttpBackend
		origin  string
		want    string
	}{
		{"allowed origin", &HttpBackend{Origin: app, ExposeHeaders: []string{"X-Data-Source-Status", "X-Data-Source"}}, app, "X-Data-Source-Status, X-Data-Source"},
		{"wildcard origin", &HttpBackend{Origin: "*", ExposeHeaders: []string{"X-Data-Source"}}, app, "X-Data-Source"},
		{"credentialed origin", &HttpBackend{Origin: app, AllowCredentials: true, ExposeHeaders: []string{"X-Data-Source"}}, app, "X-Data-Source"},
		{"rejected origin", &HttpBackend{Origin: app, ExposeHeaders: []string{"X-Data-Source"}}, "https://evil.example.com", ""},
		{"unset", &HttpBackend{Origin: app}, app, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := corsResponse(tt.backend, tt.origin)
			if v := got.Get("Access-Control-Expose-Headers"); v != tt.want {
				t.Errorf("Access-Control-Expose-Headers = %q, want %q", v, tt.want)
			}
			if _, present := got["Access-Control-Expose-Headers"]; present && tt.want == "" {
				t.Error("Access-Control-Expose-Headers emitted but should be absent")
			}
		})
	}
}
