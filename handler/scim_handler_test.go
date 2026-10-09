package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/config"
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
		if w.Code != http.StatusUnauthorized || body["status"] != "401" || w.Header().Get("Content-Type") != scimContentType ||
			w.Header().Get("WWW-Authenticate") != "Bearer" {
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
		"/public/scim/v2/Users?count=many",
		"/public/scim/v2/Users?startIndex=1.5",
	} {
		w = scimServe(h, http.MethodGet, target, "Bearer scim_token", "")
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", target, w.Code, w.Body.String())
		}
	}
}

func TestSCIMClampsPaging(t *testing.T) {
	h := &SCIMHandler{Provisioning: &sso.Provisioning{DB: &tokenDB{valid: true}}}
	for _, target := range []string{
		"/public/scim/v2/Users?startIndex=-1&count=-5",
		"/public/scim/v2/Groups?startIndex=0&count=0",
	} {
		w := scimServe(h, http.MethodGet, target, "Bearer scim_token", "")
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != http.StatusOK || body["startIndex"] != float64(1) || body["totalResults"] != float64(1) || body["itemsPerPage"] != float64(0) {
			t.Errorf("%s = %d %s", target, w.Code, w.Body.String())
		}
	}
}

func TestSCIMListQuery(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, `/x?filter=userName+eq+"a"&startIndex=3`, nil)
	q, err := listQuery(r)
	if err != nil || q.Filter != `userName eq "a"` || q.StartIndex != 3 || q.Count != nil {
		t.Fatalf("omitted count must stay nil: %+v %v", q, err)
	}
	r = httptest.NewRequest(http.MethodGet, "/x?count=0", nil)
	if q, err = listQuery(r); err != nil || q.Count == nil || *q.Count != 0 {
		t.Fatalf("count=0 = %+v %v", q, err)
	}
}

func TestSCIMCreatedCarriesLocationAndProjects(t *testing.T) {
	h := &SCIMHandler{PublicBaseURL: "https://api.example/"}
	r := httptest.NewRequest(http.MethodPost, "/public/scim/v2/Users?attributes=userName", nil)
	w := httptest.NewRecorder()
	h.userResult(w, r, http.StatusCreated, &sso.SCIMUser{Schemas: []string{sso.SchemaUser}, ID: "7", UserName: "ada", Meta: &sso.SCIMMeta{ResourceType: "User"}}, nil)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusCreated || w.Header().Get("Location") != "https://api.example/public/scim/v2/Users/7" {
		t.Fatalf("created = %d %v", w.Code, w.Header())
	}
	if len(body) != 3 || body["userName"] != "ada" || body["id"] != "7" || body["schemas"] == nil {
		t.Fatalf("attributes=userName = %v", body)
	}
	r = httptest.NewRequest(http.MethodGet, "/public/scim/v2/Groups/9?excludedAttributes=members", nil)
	w = httptest.NewRecorder()
	h.groupResult(w, r, http.StatusOK, &sso.SCIMGroup{ID: "9", DisplayName: "G", Members: []sso.SCIMRef{{Value: "1"}}, Meta: &sso.SCIMMeta{ResourceType: "Group"}}, nil)
	if w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "members") || !strings.Contains(w.Body.String(), `"location":"https://api.example/public/scim/v2/Groups/9"`) {
		t.Fatalf("get group = %v %s", w.Header(), w.Body.String())
	}
}

func TestSCIMDiscoveryResources(t *testing.T) {
	h := &SCIMHandler{Provisioning: &sso.Provisioning{DB: &tokenDB{}}, PublicBaseURL: "https://api.example"}
	get := func(path string) (int, map[string]any) {
		w := scimServe(h, http.MethodGet, path, "", "")
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body
	}
	meta := func(body map[string]any) map[string]any {
		m, _ := body["meta"].(map[string]any)
		return m
	}
	for path, resourceType := range map[string]string{
		"/public/scim/v2/ServiceProviderConfig":      "ServiceProviderConfig",
		"/public/scim/v2/ResourceTypes/User":         "ResourceType",
		"/public/scim/v2/ResourceTypes/Group":        "ResourceType",
		"/public/scim/v2/Schemas/" + sso.SchemaUser:  "Schema",
		"/public/scim/v2/Schemas/" + sso.SchemaGroup: "Schema",
	} {
		code, body := get(path)
		if code != http.StatusOK || meta(body)["resourceType"] != resourceType || meta(body)["location"] != "https://api.example"+path {
			t.Errorf("%s = %d %v", path, code, body)
		}
	}
	_, list := get("/public/scim/v2/Schemas")
	resources, _ := list["Resources"].([]any)
	for _, r := range resources {
		s, _ := r.(map[string]any)
		if schemas, _ := s["schemas"].([]any); len(schemas) != 1 || schemas[0] != sso.SchemaSchema || meta(s)["resourceType"] != "Schema" {
			t.Errorf("schema resource = %v", s)
		}
	}
	for _, path := range []string{"/public/scim/v2/ResourceTypes/Device", "/public/scim/v2/Schemas/urn:x"} {
		if code, _ := get(path); code != http.StatusNotFound {
			t.Errorf("%s = %d", path, code)
		}
	}
	if code, body := get("/public/scim/v2/Me"); code != http.StatusNotImplemented || body["status"] != "501" {
		t.Errorf("/Me = %d %v", code, body)
	}
}

func TestSCIMRejectsOversizedBodyWith413(t *testing.T) {
	saved := config.Config().MaxRequestSize
	config.Config().MaxRequestSize = 16
	t.Cleanup(func() { config.Config().MaxRequestSize = saved })
	h := &SCIMHandler{Provisioning: &sso.Provisioning{DB: &tokenDB{valid: true}}}
	w := scimServe(h, http.MethodPost, "/public/scim/v2/Users", "Bearer scim_token", `{"userName":"`+strings.Repeat("a", 64)+`"}`)
	if w.Code != http.StatusRequestEntityTooLarge || strings.Contains(w.Body.String(), "scimType") {
		t.Fatalf("oversized body = %d %s", w.Code, w.Body.String())
	}
}

func TestSCIMErrorMapping(t *testing.T) {
	h := &SCIMHandler{}
	r := httptest.NewRequest(http.MethodPost, "/public/scim/v2/Users", nil)
	for err, want := range map[error][2]string{
		sso.ErrSCIMConflict:      {"409", "uniqueness"},
		sso.ErrSCIMInvalidFilter: {"400", "invalidFilter"},
		sso.ErrSCIMNotFound:      {"404", ""},
		sso.ErrSCIMNoTarget:      {"400", "noTarget"},
		sso.ErrSCIMMutability:    {"400", "mutability"},
		sso.ErrSCIMTooMany:       {"400", "invalidValue"},
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
