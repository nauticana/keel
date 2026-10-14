package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nauticana/keel/common"
)

func serveTimeZone(header string) *time.Location {
	var bound *time.Location
	req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	if header != "" {
		req.Header.Set(common.TimeZoneHeader, header)
	}
	(&HttpBackend{}).TimeZoneMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		bound = common.LocationFromContext(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), req)
	return bound
}

func TestTimeZoneMiddleware(t *testing.T) {
	if got := serveTimeZone("Europe/Istanbul"); got.String() != "Europe/Istanbul" {
		t.Fatalf("valid zone not bound: %v", got)
	}
	if got := serveTimeZone(""); got != time.UTC {
		t.Fatalf("no header must read UTC: %v", got)
	}
	if got := serveTimeZone("Nowhere/Town"); got != time.UTC {
		t.Fatalf("unknown zone must read UTC: %v", got)
	}
}
