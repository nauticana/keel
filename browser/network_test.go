package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
)

func sent(id, url string, redirect *network.Response) *network.EventRequestWillBeSent {
	return &network.EventRequestWillBeSent{
		RequestID: network.RequestID(id), Request: &network.Request{URL: url, Method: "GET"},
		Type: network.ResourceTypeImage, RedirectResponse: redirect,
	}
}

func TestRequestLogRecordsHopsAndFailures(t *testing.T) {
	log := newRequestLog(0)
	log.observe(sent("1", "http://a/pixel", nil))
	log.observe(sent("1", "https://a/pixel", &network.Response{Status: 301}))
	log.observe(&network.EventResponseReceived{RequestID: "1", Response: &network.Response{Status: 204}})
	log.observe(sent("2", "https://b/collect", nil))
	log.observe(&network.EventLoadingFailed{RequestID: "2", ErrorText: "net::ERR_BLOCKED_BY_CLIENT"})
	log.observe(sent("3", "https://c/pending", nil))
	log.observe(&network.EventResponseReceived{RequestID: "unknown", Response: &network.Response{Status: 200}})

	got, truncated := log.snapshot()
	want := []NetworkRequest{
		{URL: "http://a/pixel", Method: "GET", Type: "Image", Status: 301},
		{URL: "https://a/pixel", Method: "GET", Type: "Image", Status: 204},
		{URL: "https://b/collect", Method: "GET", Type: "Image", Error: "net::ERR_BLOCKED_BY_CLIENT"},
		{URL: "https://c/pending", Method: "GET", Type: "Image"},
	}
	if truncated || !reflect.DeepEqual(got, want) {
		t.Fatalf("truncated=%v requests=%+v", truncated, got)
	}
}

// Past the cap nothing is recorded, a late response cannot land on the wrong
// entry, and the result says the list is incomplete.
func TestRequestLogCap(t *testing.T) {
	log := newRequestLog(1)
	log.observe(sent("1", "https://a/1", nil))
	log.observe(sent("2", "https://a/2", nil))
	log.observe(sent("1", "https://a/1-redirected", &network.Response{Status: 302}))
	log.observe(&network.EventResponseReceived{RequestID: "1", Response: &network.Response{Status: 200}})

	got, truncated := log.snapshot()
	if !truncated || len(got) != 1 || got[0].Status != 302 {
		t.Fatalf("truncated=%v requests=%+v", truncated, got)
	}
}

func TestRenderCapturesRequestsAgainstRealChrome(t *testing.T) {
	chrome := installedChrome()
	if testing.Short() || chrome == "" {
		t.Skip("needs an installed Chrome")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<html><body><img src="/missing.png"><script>
				window.addEventListener("load", () => setTimeout(() => navigator.sendBeacon("/collect?v=2", "x"), 200));
			</script></body></html>`))
		case "/collect":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	renderer := &DOMRenderer{Launcher: &Launcher{Headless: true, ExecPaths: []string{chrome}, TempDir: t.TempDir()}}
	res, err := renderer.Render(context.Background(), RenderRequest{
		URL: srv.URL, Timeout: 60 * time.Second, CaptureRequests: true, Settle: 1500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	find := func(path string) *NetworkRequest {
		for i, r := range res.Requests {
			if strings.HasPrefix(r.URL, srv.URL+path) {
				return &res.Requests[i]
			}
		}
		return nil
	}
	if doc := find("/"); doc == nil || doc.Status != 200 || doc.Type != "Document" {
		t.Errorf("document = %+v", doc)
	}
	if img := find("/missing.png"); img == nil || img.Status != 404 {
		t.Errorf("image = %+v", img)
	}
	if beacon := find("/collect"); beacon == nil || beacon.Method != http.MethodPost || beacon.Type != "Ping" || beacon.Status != 204 {
		t.Errorf("beacon = %+v (all: %+v)", beacon, res.Requests)
	}
	if res.RequestsTruncated {
		t.Error("truncated under the default cap")
	}
}
