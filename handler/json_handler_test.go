package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
)

func TestAPIErrorMapsToStatus(t *testing.T) {
	h := &AbstractHandler{}
	fn := func(ctx context.Context, body json.RawMessage) (any, error) {
		return nil, NewAPIError(http.StatusConflict, "duplicate")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	h.JSONPublic("POST", fn)(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
}

func TestGenericErrorMapsTo500(t *testing.T) {
	h := &AbstractHandler{}
	fn := func(ctx context.Context, body json.RawMessage) (any, error) {
		return nil, errAny{}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	h.JSONPublic("POST", fn)(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestWrongMethodRejected(t *testing.T) {
	h := &AbstractHandler{}
	called := false
	fn := func(ctx context.Context, body json.RawMessage) (any, error) {
		called = true
		return "x", nil
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	h.JSONPublic("POST", fn)(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
	if called {
		t.Fatal("fn should not be called on wrong method")
	}
}

func TestInvalidJSONBodyRejected(t *testing.T) {
	h := &AbstractHandler{}
	fn := func(ctx context.Context, body json.RawMessage) (any, error) { return "x", nil }
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader("not json"))
	r.ContentLength = 8
	h.JSONPublic("POST", fn)(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestJSONPublicSuccess(t *testing.T) {
	h := &AbstractHandler{}
	fn := func(ctx context.Context, body json.RawMessage) (any, error) {
		return map[string]string{"k": "v"}, nil
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"x":1}`))
	h.JSONPublic("POST", fn)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"k":"v"`) {
		t.Fatalf("body missing payload: %s", w.Body.String())
	}
}

// Sanity: JSON (auth-required) wires through RequireSession — verify it 401s
// when no session is present rather than dispatching the business fn.
func TestJSONRequiresSession(t *testing.T) {
	h := &AbstractHandler{}
	called := false
	fn := func(ctx context.Context, s *model.UserSession, body json.RawMessage) (any, error) {
		called = true
		return nil, nil
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", nil)
	h.JSON("POST", fn)(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if called {
		t.Fatal("fn should not be called without a session")
	}
}

type errAny struct{}

func (errAny) Error() string { return "boom" }
