package reference

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/common"
)

type staticSecrets map[string]string

func (s staticSecrets) GetSecret(_ context.Context, name string) (string, error) {
	v, ok := s[name]
	if !ok {
		return "", errors.New("secret not found")
	}
	return v, nil
}

var testKey = APIKey{Secrets: staticSecrets{"google_key": "k-123", "blank": ""}, SecretName: "google_key"}

func TestAPIKey(t *testing.T) {
	ctx := context.Background()
	for name, key := range map[string]APIKey{
		"unnamed":     {Secrets: testKey.Secrets},
		"no provider": {SecretName: "google_key"},
		"blank value": {Secrets: testKey.Secrets, SecretName: "blank"},
	} {
		if _, err := key.headers(ctx); !errors.Is(err, ErrNoAPIKey) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := (APIKey{Secrets: testKey.Secrets, SecretName: "absent"}).headers(ctx); err == nil || errors.Is(err, ErrNoAPIKey) {
		t.Errorf("provider failure must surface, got %v", err)
	}
}

func TestCrUXRecordForURLFallsBackToOrigin(t *testing.T) {
	var asked []map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(googleAPIKeyHeader) != "k-123" || strings.Contains(r.URL.RawQuery, "key=") {
			t.Errorf("key must travel in the header only: %s", r.URL)
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		asked = append(asked, body)
		if body["url"] != "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(`{"record":{"key":{"origin":"https://shop.example"},"metrics":{
			"largest_contentful_paint":{"percentiles":{"p75":"2400"}},
			"cumulative_layout_shift":{"percentiles":{"p75":0.12}},
			"time_to_first_byte":{"percentiles":{"p75":"800"}}}}}`))
	}))
	defer srv.Close()

	c := &CrUXClient{APIKey: testKey, Endpoint: srv.URL}
	rec, err := c.RecordForURL(context.Background(), "https://shop.example/p/1?x=1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 2 || asked[1]["origin"] != "https://shop.example" || asked[1]["formFactor"] != "PHONE" {
		t.Fatalf("requests = %v", asked)
	}
	if rec.HasURLLevelData || rec.URL != "https://shop.example/p/1?x=1" || rec.FormFactor != CrUXFormFactorPhone ||
		rec.LCP != 2400 || rec.CLS != 0.12 || rec.TTFB != 800 || rec.INP != CrUXNoValue || rec.FCP != CrUXNoValue {
		t.Fatalf("record = %+v", rec)
	}
}

func TestCrUXErrors(t *testing.T) {
	status := http.StatusNotFound
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	defer srv.Close()
	c := &CrUXClient{APIKey: testKey, Endpoint: srv.URL}
	if _, err := c.RecordForURL(context.Background(), "https://quiet.example/", CrUXFormFactorDesktop); !errors.Is(err, ErrCrUXNoData) {
		t.Errorf("404 on both levels: err = %v", err)
	}
	status = http.StatusTooManyRequests
	if _, err := c.RecordForOrigin(context.Background(), "https://quiet.example", ""); common.HTTPStatus(err) != http.StatusTooManyRequests {
		t.Errorf("429: err = %v", err)
	}
	if _, err := (&CrUXClient{}).RecordForOrigin(context.Background(), "https://quiet.example", ""); !errors.Is(err, ErrNoAPIKey) {
		t.Errorf("no key: err = %v", err)
	}
}

func TestOriginOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://www.example.com/a/b?q=1": "https://www.example.com",
		"http://example.com:8080":         "http://example.com:8080",
		"example.com":                     "example.com",
	} {
		if got := originOf(in); got != want {
			t.Errorf("originOf(%q) = %q", in, got)
		}
	}
}

func TestKGFindEntity(t *testing.T) {
	response := `{"itemListElement":[{"resultScore":812.5,"result":{"@id":"kg:/m/0k8z","name":"Apple Inc.",
		"@type":["Thing","Corporation"],"url":"https://apple.com","detailedDescription":{"articleBody":"Maker of things."}}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("query") != "Apple" || len(q["types"]) != 2 || q.Has("key") || r.Header.Get(googleAPIKeyHeader) != "k-123" {
			t.Errorf("request = %s", r.URL)
		}
		w.Write([]byte(response))
	}))
	defer srv.Close()
	c := &KGClient{APIKey: testKey, Endpoint: srv.URL}
	got, err := c.FindEntity(context.Background(), " Apple ", []string{"Organization", "Corporation"})
	if err != nil {
		t.Fatal(err)
	}
	if got.MID != "/m/0k8z" || got.Name != "Apple Inc." || got.Description != "Maker of things." || got.Score != 812.5 || len(got.Types) != 2 {
		t.Fatalf("match = %+v", got)
	}
	response = `{"itemListElement":[]}`
	if got, err := (&KGClient{APIKey: testKey, Endpoint: srv.URL}).FindEntity(context.Background(), "Apple", []string{"Organization", "Corporation"}); err != nil || got.MID != "" {
		t.Errorf("no match: %+v %v", got, err)
	}
	if got, err := c.FindEntity(context.Background(), "  ", nil); err != nil || got.MID != "" {
		t.Errorf("blank query: %+v %v", got, err)
	}
}

func TestWikidataFindEntity(t *testing.T) {
	response := `{"search":[{"id":"Q312","label":"Apple Inc.","description":"technology company","concepturi":"http://www.wikidata.org/entity/Q312"},{"id":"Q89"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "App/1.0 (ops@app.example)" || r.URL.Query().Get("action") != "wbsearchentities" {
			t.Errorf("request = %s UA=%q", r.URL, r.Header.Get("User-Agent"))
		}
		w.Write([]byte(response))
	}))
	defer srv.Close()
	c := &WikidataClient{UserAgent: "App/1.0 (ops@app.example)", Endpoint: srv.URL}
	got, err := c.FindEntity(context.Background(), "Apple")
	if err != nil {
		t.Fatal(err)
	}
	if got.QID != "Q312" || got.Label != "Apple Inc." || got.Confidence != 0.5 || got.URL == "" {
		t.Fatalf("match = %+v", got)
	}
	response = `{"error":{"code":"ratelimited","info":"slow down"}}`
	if _, err := c.FindEntity(context.Background(), "Apple"); err == nil || !strings.Contains(err.Error(), "ratelimited") {
		t.Errorf("api error in 200 body: err = %v", err)
	}
	if _, err := (&WikidataClient{}).FindEntity(context.Background(), "Apple"); !errors.Is(err, ErrNoUserAgent) {
		t.Errorf("no UA: err = %v", err)
	}
}
