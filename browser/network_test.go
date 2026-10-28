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

func sent(log *requestLog, id, url string, redirect *network.Response) {
	log.sent(network.EventRequestWillBeSent{
		RequestID: network.RequestID(id), Request: &network.Request{URL: url, Method: "GET"},
		Type: network.ResourceTypeImage, RedirectResponse: redirect,
	})
}

func answered(log *requestLog, id string, status int) {
	log.settle(network.RequestID(id), func(o *NetworkRequest) { o.Status = status })
}

func TestRequestLogRecordsHopsAndFailures(t *testing.T) {
	log := newRequestLog(0)
	sent(log, "1", "http://a/pixel", nil)
	sent(log, "1", "https://a/pixel", &network.Response{Status: 301})
	answered(log, "1", 204)
	sent(log, "2", "https://b/collect", nil)
	log.settle("2", func(o *NetworkRequest) { o.Error = "net::ERR_BLOCKED_BY_CLIENT" })
	sent(log, "3", "https://c/pending", nil)
	answered(log, "unknown", 200)

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

// Each event type has its own subscription, so a final response can be
// handled before the hops it ends.
func TestRequestLogOutcomeBeforeRequest(t *testing.T) {
	log := newRequestLog(0)
	answered(log, "1", 200)
	sent(log, "1", "http://a/", nil)
	sent(log, "1", "https://a/", &network.Response{Status: 301})

	got, _ := log.snapshot()
	if len(got) != 2 || got[0].Status != 301 || got[1].Status != 200 {
		t.Fatalf("requests=%+v", got)
	}
}

// Past the cap nothing is recorded, a late response cannot land on the wrong
// entry, early outcomes stay bounded, and the result says the list is incomplete.
func TestRequestLogCap(t *testing.T) {
	log := newRequestLog(1)
	sent(log, "1", "https://a/1", nil)
	sent(log, "2", "https://a/2", nil)
	sent(log, "1", "https://a/1-redirected", &network.Response{Status: 302})
	answered(log, "1", 200)
	for _, id := range []string{"x", "y", "z"} {
		answered(log, id, 200)
	}

	got, truncated := log.snapshot()
	if !truncated || len(got) != 1 || got[0].Status != 302 || len(log.outcomes) != 2 {
		t.Fatalf("truncated=%v requests=%+v outcomes=%d", truncated, got, len(log.outcomes))
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
