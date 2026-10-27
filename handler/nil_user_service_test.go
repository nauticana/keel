package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A handler built without a UserService fails closed on session reads
// instead of panicking, and logs the misconfiguration once.
func TestNilUserServiceAnswers401(t *testing.T) {
	nilUserServiceLogged.Store(false)
	journal := &recordingJournal{}
	h := &AbstractHandler{Journal: journal}
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		if _, ok := h.RequireSession(rec, req); ok || rec.Code != http.StatusUnauthorized {
			t.Fatalf("ok=%v status=%d", ok, rec.Code)
		}
		if h.GetUser(req) != -1 {
			t.Fatal("GetUser found a user without a UserService")
		}
	}
	if len(journal.errors) != 1 {
		t.Fatalf("errors = %q, want one", journal.errors)
	}

	ws := &WebSocketHandler{Journal: journal}
	rec := httptest.NewRecorder()
	ws.Connect(rec, httptest.NewRequest(http.MethodGet, "/public/ws?token=abc", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("websocket token without UserService: %d", rec.Code)
	}

	var zero AbstractHandler
	if zero.ParseSession(httptest.NewRequest(http.MethodGet, "/api/x", nil)) != nil {
		t.Fatal("zero-value handler returned a session")
	}
}
