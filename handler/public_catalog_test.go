package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/geo"
)

func serveCatalog(db *catalogDB, method, path string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	for route, fn := range (&PublicHandler{Catalog: &geo.Catalog{DB: db}}).GetPublicRoutes() {
		mux.HandleFunc(route, fn)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestPublicCatalogRoutes(t *testing.T) {
	cases := []struct {
		path   string
		status int
		body   string
	}{
		{"/public/countries", http.StatusOK, `[{"code":"TR","caption":"Turkey"},{"code":"US","caption":"United States"}]`},
		{"/public/countries/US/states", http.StatusOK, `[{"code":"AL","caption":"Alabama"}]`},
		{"/public/countries/TR/states", http.StatusOK, `[]`},
		{"/public/countries/XX/states", http.StatusNotFound, ""},
		{"/public/currencies", http.StatusOK, `[{"code":"USD","caption":"US Dollar","exponent":2}]`},
	}
	for _, c := range cases {
		rec := serveCatalog(&catalogDB{}, http.MethodGet, c.path)
		if rec.Code != c.status {
			t.Errorf("%s = %d, want %d: %s", c.path, rec.Code, c.status, rec.Body)
			continue
		}
		if c.body != "" {
			var envelope struct {
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil || string(envelope.Data) != c.body {
				got := string(envelope.Data)
				t.Errorf("%s body = %s, want %s", c.path, got, c.body)
			}
			if rec.Header().Get("Cache-Control") != "public, max-age=3600" {
				t.Errorf("%s is not cacheable", c.path)
			}
		}
	}
}

func TestPublicCatalogRefusesWritesAndHidesFailures(t *testing.T) {
	if rec := serveCatalog(&catalogDB{}, http.MethodPost, "/public/currencies"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d", rec.Code)
	}
	rec := serveCatalog(&catalogDB{fail: true}, http.MethodGet, "/public/countries")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "pq:") {
		t.Errorf("failure = %d %s", rec.Code, rec.Body)
	}
}

func TestPublicCatalogRoutesNeedACatalog(t *testing.T) {
	if _, ok := (&PublicHandler{}).GetPublicRoutes()["/public/currencies"]; ok {
		t.Error("catalog routes mounted without a Catalog")
	}
}
