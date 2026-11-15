package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/service"
	"github.com/nauticana/keel/user"
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

func TestJSONBindsCallerAndMapsServiceErrors(t *testing.T) {
	h := &AbstractHandler{UserService: stubSessionUsers{session: &model.UserSession{Id: 5, PartnerId: 9}}}
	var caller common.CallerSession
	fn := func(ctx context.Context, _ *model.UserSession, _ json.RawMessage) (any, error) {
		caller, _ = common.CallerSessionFromContext(ctx)
		return nil, fmt.Errorf("lookup: %w", service.ErrNotFound)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer token")
	h.JSON("POST", fn)(w, r)
	if caller.UserID != 5 || caller.PartnerID != 9 {
		t.Fatalf("caller = %+v, want user 5 of partner 9", caller)
	}
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "lookup") {
		t.Fatalf("status %d body %s, want a 404 without the internal cause", w.Code, w.Body.String())
	}
}

func TestJSONBodyBoundedAndGetQueryAsObject(t *testing.T) {
	h := &AbstractHandler{}
	var got json.RawMessage
	fn := func(_ context.Context, body json.RawMessage) (any, error) { got = body; return "ok", nil }

	w := httptest.NewRecorder()
	big := `{"x":"` + strings.Repeat("a", int(config.Config().MaxRequestSize)) + `"}`
	h.JSONPublic("POST", fn)(w, httptest.NewRequest("POST", "/", strings.NewReader(big)))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: status %d, want 413", w.Code)
	}

	w = httptest.NewRecorder()
	h.JSONPublic("POST", fn)(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"role":"user","role":"admin"}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate member names: status %d, want 400", w.Code)
	}

	w = httptest.NewRecorder()
	h.JSONPublic("GET", fn)(w, httptest.NewRequest("GET", "/?q=ann&tag=a&tag=b", nil))
	if w.Code != http.StatusOK || string(got) != `{"q":"ann","tag":["a","b"]}` {
		t.Fatalf("GET body = %s (status %d)", got, w.Code)
	}
}

type stubSessionUsers struct {
	user.UserService
	session *model.UserSession
}

func (u stubSessionUsers) ParseJWT(string) (*model.UserSession, error) { return u.session, nil }
