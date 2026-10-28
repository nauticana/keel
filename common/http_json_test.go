package common

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nauticana/keel/config"
)

func withResponseCap(t *testing.T, n int64) {
	t.Helper()
	saved := config.Config().OutboundMaxResponseSize
	config.Config().OutboundMaxResponseSize = n
	t.Cleanup(func() { config.Config().OutboundMaxResponseSize = saved })
}

func TestRequestJSONSendsPayloadAndReturnsHeaders(t *testing.T) {
	withResponseCap(t, 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &in); err != nil || in["k"] != "v" {
			t.Errorf("payload = %q", body)
		}
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-Token") != "t" {
			t.Errorf("headers = %v", r.Header)
		}
		w.Header().Set("X-Rate-Remaining", "7")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	body, hdr, err := requestJSON(context.Background(), srv.Client(), http.MethodPost, srv.URL, map[string]string{"X-Token": "t"}, map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"ok":true}` || hdr.Get("X-Rate-Remaining") != "7" {
		t.Fatalf("body=%q hdr=%v", body, hdr)
	}
}

func TestRequestJSONOmitsContentTypeWithoutPayload(t *testing.T) {
	withResponseCap(t, 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "" {
			t.Errorf("Content-Type = %q on a bodiless request", ct)
		}
	}))
	defer srv.Close()
	if _, _, err := requestJSON(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRequestJSONStatusErrorKeepsBodyAndHeaders(t *testing.T) {
	withResponseCap(t, 1<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`slow down`))
	}))
	defer srv.Close()

	body, hdr, err := requestJSON(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, nil)
	se, ok := errors.AsType[*HTTPStatusError](err)
	if !ok {
		t.Fatalf("err = %v, want *HTTPStatusError", err)
	}
	if se.Status != 429 || se.Body != "slow down" || se.Header.Get("Retry-After") != "30" {
		t.Fatalf("status error = %+v", se)
	}
	if string(body) != "slow down" || hdr.Get("Retry-After") != "30" {
		t.Fatalf("body=%q hdr=%v", body, hdr)
	}
	if HTTPStatus(err) != 429 || HTTPStatus(errors.New("x")) != 0 {
		t.Fatal("HTTPStatus mismatch")
	}
}

func TestRequestJSONCapsResponseBody(t *testing.T) {
	withResponseCap(t, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 9)))
	}))
	defer srv.Close()
	body, _, err := requestJSON(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, nil)
	if !errors.Is(err, ErrResponseTooLarge) || string(body) != strings.Repeat("x", 8) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

func TestRequestJSONOversizedStatusRetainsClassification(t *testing.T) {
	withResponseCap(t, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("abcdef"))
	}))
	defer srv.Close()
	body, hdr, err := requestJSON(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, nil)
	statusErr, ok := errors.AsType[*HTTPStatusError](err)
	if string(body) != "abcd" || hdr.Get("Retry-After") != "5" ||
		!errors.Is(err, ErrResponseTooLarge) || !ok || !statusErr.RateLimited() {
		t.Fatalf("body=%q hdr=%v err=%v statusErr=%+v", body, hdr, err, statusErr)
	}
}

func TestRequestJSONRejectsInvalidResponseCapBeforeSending(t *testing.T) {
	withResponseCap(t, 0)
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	if _, _, err := requestJSON(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, nil); err == nil {
		t.Fatal("zero response cap accepted")
	}
	if called {
		t.Fatal("request sent with invalid response cap")
	}
}

func TestHTTPStatusErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		status                                          int
		unauthorized, rateLimited, transient, permanent bool
	}{
		{301, false, false, false, true},
		{400, false, false, false, true},
		{401, true, false, false, true},
		{403, true, false, false, true},
		{404, false, false, false, true},
		{408, false, false, true, false},
		{425, false, false, true, false},
		{429, false, true, true, false},
		{500, false, false, true, false},
		{503, false, false, true, false},
	} {
		e := &HTTPStatusError{Status: tc.status}
		if e.Unauthorized() != tc.unauthorized || e.RateLimited() != tc.rateLimited ||
			e.Transient() != tc.transient || e.Permanent() != tc.permanent {
			t.Errorf("%d: unauthorized=%v rateLimited=%v transient=%v permanent=%v",
				tc.status, e.Unauthorized(), e.RateLimited(), e.Transient(), e.Permanent())
		}
	}
}

func TestHTTPStatusErrorMessageIsBounded(t *testing.T) {
	e := &HTTPStatusError{Status: 500, Body: strings.Repeat("x", 4096)}
	if msg := e.Error(); len(msg) > statusErrorBodyPreview+64 || !strings.Contains(msg, "4096 bytes") {
		t.Fatalf("message length %d: %.80s", len(msg), msg)
	}
	if len(e.Body) != 4096 {
		t.Fatal("Body was truncated")
	}
}

func TestRequestJSONKeepsRedirectsOnTheOrigin(t *testing.T) {
	withResponseCap(t, 1<<20)
	saved := config.Config().OutboundMaxRedirects
	config.Config().OutboundMaxRedirects = 10
	t.Cleanup(func() { config.Config().OutboundMaxRedirects = saved })
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("credentials followed a redirect to another origin: %v", r.Header)
	}))
	defer foreign.Close()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, foreign.URL+"/steal", http.StatusFound)
		case "/move":
			http.Redirect(w, r, srv.URL+"/ok", http.StatusFound)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	defer srv.Close()
	auth := map[string]string{"Authorization": "Bearer tok"}
	if _, _, err := RequestJSON(context.Background(), http.MethodGet, srv.URL+"/away", auth, nil); !errors.Is(err, ErrRedirectOffOrigin) {
		t.Fatalf("cross-origin redirect: err = %v", err)
	}
	if body, _, err := RequestJSON(context.Background(), http.MethodGet, srv.URL+"/move", auth, nil); err != nil || string(body) != "{}" {
		t.Fatalf("same-origin redirect: %q, %v", body, err)
	}
}
