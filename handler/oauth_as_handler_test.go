package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/oauth/authserver"
)

func TestOAuthClientLimitIsServiceUnavailable(t *testing.T) {
	rec := httptest.NewRecorder()
	(&OAuthASHandler{}).writeOAuthError(rec, fmt.Errorf("register: %w", authserver.ErrOAuthClientLimit))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"error":"temporarily_unavailable"`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}
