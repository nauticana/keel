package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
	"github.com/nauticana/keel/sso"
)

// tokenDB knows no tokens.
type tokenDB struct {
	port.DatabaseRepository
	valid bool
}

func (d *tokenDB) GetQueryService(context.Context, map[string]string) port.QueryService { return d }
func (d *tokenDB) GenID() int64                                                         { return 0 }
func (d *tokenDB) Query(context.Context, string, ...any) (*model.QueryResult, error) {
	if d.valid {
		return &model.QueryResult{Rows: [][]any{{int64(1), int64(11)}}}, nil
	}
	return &model.QueryResult{}, nil
}

func scimServe(h *SCIMHandler, method, path, auth, body string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	for p, fn := range h.PublicRoutes() {
		mux.HandleFunc(p, fn)
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestSCIMRefusesWithoutValidToken(t *testing.T) {
	h := &SCIMHandler{Provisioning: &sso.Provisioning{DB: &tokenDB{}}, PublicBaseURL: "https://api.example"}
	for _, auth := range []string{"", "Basic abc", "Bearer scim_unknown", "Bearer not-a-scim-token"} {
		w := scimServe(h, http.MethodGet, "/public/scim/v2/Users", auth, "")
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != http.StatusUnauthorized || body["status"] != "401" || w.Header().Get("Content-Type") != scimContentType {
			t.Errorf("%q = %d %v", auth, w.Code, body)
		}
	}
}

func TestSCIMDiscoveryEndpointsArePublic(t *testing.T) {
	h := &SCIMHandler{Provisioning: &sso.Provisioning{DB: &tokenDB{}}}
	for _, p := range []string{"/public/scim/v2/ServiceProviderConfig", "/public/scim/v2/ResourceTypes", "/public/scim/v2/Schemas"} {
		if w := scimServe(h, http.MethodGet, p, "", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "schemas") {
			t.Errorf("%s = %d", p, w.Code)
		}
		if w := scimServe(h, http.MethodPost, p, "", ""); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d", p, w.Code)
		}
	}
}

func TestSCIMParsesAuthorizationAndInputStrictly(t *testing.T) {
	h := &SCIMHandler{Provisioning: &sso.Provisioning{DB: &tokenDB{valid: true}}}
	w := scimServe(h, http.MethodPost, "/public/scim/v2/Users", "bEaReR scim_token", `{} {}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "malformed JSON") {
		t.Fatalf("mixed-case bearer and trailing JSON = %d %s", w.Code, w.Body.String())
	}
	for _, target := range []string{
		"/public/scim/v2/Users?startIndex=-1",
		"/public/scim/v2/Users?count=many",
	} {
		w = scimServe(h, http.MethodGet, target, "Bearer scim_token", "")
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", target, w.Code, w.Body.String())
		}
	}
}

func TestSCIMErrorMapping(t *testing.T) {
	h := &SCIMHandler{}
	r := httptest.NewRequest(http.MethodPost, "/public/scim/v2/Users", nil)
	for err, want := range map[error][2]string{
		sso.ErrSCIMConflict:      {"409", "uniqueness"},
		sso.ErrSCIMInvalidFilter: {"400", "invalidFilter"},
		sso.ErrSCIMNotFound:      {"404", ""},
		context.Canceled:         {"500", ""},
	} {
		w := httptest.NewRecorder()
		h.scimError(w, r, err)
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if body["status"] != want[0] || (want[1] != "" && body["scimType"] != want[1]) {
			t.Errorf("%v = %v", err, body)
		}
		if want[0] == "500" && body["detail"] != "internal error" {
			t.Errorf("a 500 must not leak its cause: %v", body)
		}
	}
}
