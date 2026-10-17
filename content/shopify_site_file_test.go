package content

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func themeReply(t *testing.T, body *string) string {
	t.Helper()
	files := []any{}
	if body != nil {
		files = append(files, map[string]any{"body": map[string]any{"content": *body}})
	}
	raw, err := json.Marshal(map[string]any{"data": map[string]any{"themes": map[string]any{"nodes": []any{
		map[string]any{"id": "gid://shopify/OnlineStoreTheme/1", "files": map[string]any{"nodes": files}},
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func ptr(s string) *string { return &s }

const (
	aiRules     = "User-agent: GPTBot\nDisallow: /\n"
	themeQueued = `{"data":{"themeFilesUpsert":{"job":{"id":"gid://shopify/Job/1"},"userErrors":[]}}}`
	jobRunning  = `{"data":{"job":{"done":false}}}`
	jobDone     = `{"data":{"job":{"done":true}}}`
)

func upserted(t *testing.T, req gqlRequest) string {
	t.Helper()
	files := req.Variables["files"].([]any)
	file := files[0].(map[string]any)
	if file["filename"] != shopifyRobotsTemplate || req.Variables["id"] != "gid://shopify/OnlineStoreTheme/1" {
		t.Fatalf("upsert = %+v", req.Variables)
	}
	return file["body"].(map[string]any)["value"].(string)
}

func TestShopifyRobotsRoundTrip(t *testing.T) {
	ctx := context.Background()
	w := fastUploader(t)

	stub := &shopifyStub{t: t, responses: []string{themeReply(t, nil)}}
	if got, err := w.ReadSiteFile(ctx, stub.serve(), "/robots.txt"); err != nil || got != "" {
		t.Fatalf("no template: %q, %v", got, err)
	}

	// A first write keeps Shopify's defaults and waits for the theme job.
	stub = &shopifyStub{t: t, responses: []string{themeReply(t, nil), themeQueued, jobRunning, jobDone}}
	if _, err := w.WriteSiteFile(ctx, stub.serve(), "/robots.txt", aiRules); err != nil {
		t.Fatal(err)
	}
	stored := upserted(t, stub.requests[1])
	if stored != shopifyRobotsDefaults+aiRules || len(stub.requests) != 4 {
		t.Fatalf("stored %q after %d requests", stored, len(stub.requests))
	}

	stub = &shopifyStub{t: t, responses: []string{themeReply(t, &stored)}}
	if got, err := w.ReadSiteFile(ctx, stub.serve(), "/robots.txt"); err != nil || got != aiRules {
		t.Fatalf("read back %q, %v", got, err)
	}

	// The theme's own template, and content that iterates the defaults itself,
	// are written as given; no job means the upsert is already done.
	for name, c := range map[string]struct {
		current       *string
		content, want string
	}{
		"own template":      {ptr("User-agent: *\n"), "User-agent: *\n" + aiRules, "User-agent: *\n" + aiRules},
		"iterates defaults": {nil, "{% for group in robots.default_groups %}{% endfor %}", "{% for group in robots.default_groups %}{% endfor %}"},
		"defaults only":     {ptr(shopifyRobotsDefaults), "", shopifyRobotsDefaults},
	} {
		reply := `{"data":{"themeFilesUpsert":{"job":null,"userErrors":[]}}}`
		stub := &shopifyStub{t: t, responses: []string{themeReply(t, c.current), reply}}
		if _, err := w.WriteSiteFile(ctx, stub.serve(), "/robots.txt", c.content); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := upserted(t, stub.requests[1]); got != c.want || len(stub.requests) != 2 {
			t.Errorf("%s: stored %q after %d requests", name, got, len(stub.requests))
		}
	}

	stub = &shopifyStub{t: t, responses: []string{`{"data":{"themes":{"nodes":[]}}}`}}
	if _, err := w.WriteSiteFile(ctx, stub.serve(), "/robots.txt", aiRules); !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("no theme: %v", err)
	}
}

func TestShopifySiteFileRejectsPaths(t *testing.T) {
	stub := &shopifyStub{t: t}
	ref := stub.serve()
	for _, path := range []string{"", "/", "robots.txt", "/a/b.txt", "/.env", "/llms.txt?x=1"} {
		if _, err := newTestWriter(t).WriteSiteFile(context.Background(), ref, path, "x"); !errors.Is(err, ErrRejected) {
			t.Errorf("%q: %v", path, err)
		}
	}
	if len(stub.requests) != 0 {
		t.Fatalf("sent %d requests", len(stub.requests))
	}
}

func TestShopifyRedirectedSiteFile(t *testing.T) {
	ctx := context.Background()
	redirects := func(target string) string {
		return `{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":false},"nodes":[{"id":"r1","path":"/llms.txt","target":"` + target + `"}]}}}`
	}
	w := fastUploader(t)
	for name, c := range map[string]struct {
		reply string
		want  string
		err   error
	}{
		"no redirect": {`{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":false},"nodes":[]}}}`, "", nil},
		"elsewhere":   {redirects("https://example.com/llms.txt"), "", ErrRejected},
		"host suffix": {redirects("https://cdn.shopify.com.evil/llms.txt"), "", ErrRejected},
	} {
		stub := &shopifyStub{t: t, responses: []string{c.reply}}
		got, err := w.ReadSiteFile(ctx, stub.serve(), "/llms.txt")
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}

	srv := &stagedUploadServer{t: t, responses: []string{
		`{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":false},"nodes":[]}}}`,
		stagedReply,
		`{"data":{"fileCreate":{"files":[{"id":"gid://shopify/GenericFile/5"}],"userErrors":[]}}}`,
		`{"data":{"node":{"fileStatus":"READY","url":"https://cdn.shopify.com/llms.txt"}}}`,
		`{"data":{"urlRedirectCreate":{"urlRedirect":{"id":"r1","path":"/llms.txt","target":"https://cdn.shopify.com/llms.txt"},"userErrors":[]}}}`,
	}}
	ref := srv.start()
	if _, err := w.WriteSiteFile(ctx, ref, "/llms.txt", "# Shop\n"); err != nil {
		t.Fatal(err)
	}
	created := srv.requests[4].Variables["r"].(map[string]any)
	if string(srv.gotFile) != "# Shop\n" || srv.gotName != "llms.txt" ||
		created["path"] != "/llms.txt" || created["target"] != "https://cdn.shopify.com/llms.txt" {
		t.Fatalf("file %q %q, redirect %+v", srv.gotFile, srv.gotName, created)
	}

	stub := &shopifyStub{t: t, responses: []string{redirects("https://cdn.shopify.com/llms.txt"), redirectGone}}
	if _, err := w.WriteSiteFile(ctx, stub.serve(), "/llms.txt", ""); err != nil || stub.requests[1].Variables["id"] != "r1" {
		t.Fatalf("remove: %v %+v", err, stub.requests)
	}
}

// cdnTransport answers for cdn.shopify.com from a local server and sends
// every other host there too, so a followed off-CDN redirect would show.
type cdnTransport struct{ srv *url.URL }

func (c cdnTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.URL.Scheme, out.URL.Host = c.srv.Scheme, c.srv.Host
	return http.DefaultTransport.RoundTrip(out)
}

func TestShopifyFetchShopFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/llms.txt":
			_, _ = w.Write([]byte("# Shop\n"))
		case "/moved":
			http.Redirect(w, r, "https://cdn.shopify.com/llms.txt", http.StatusFound)
		case "/away":
			http.Redirect(w, r, "https://example.com/llms.txt", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: cdnTransport{target}}
	w := newTestWriter(t)
	for raw, want := range map[string]string{
		"https://cdn.shopify.com/llms.txt": "# Shop\n",
		"https://CDN.SHOPIFY.COM/llms.txt": "# Shop\n",
		"https://cdn.shopify.com/moved":    "# Shop\n",
	} {
		if got, err := w.fetchShopFile(context.Background(), client, raw); err != nil || got != want {
			t.Errorf("%s: %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{
		"https://cdn.shopify.com/away",
		"https://cdn.shopify.com/gone.txt",
		"http://cdn.shopify.com/llms.txt",
		"https://cdn.shopify.com.evil/llms.txt",
		"https://cdn.shopify.com:444/llms.txt",
		"https://user@cdn.shopify.com/llms.txt",
	} {
		if _, err := w.fetchShopFile(context.Background(), client, raw); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestShopifyCreateRedirect(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		`{"data":{"urlRedirectCreate":{"urlRedirect":{"id":"r2","path":"/old","target":"/new"},"userErrors":[]}}}`,
		`{"data":{"urlRedirectCreate":{"urlRedirect":null,"userErrors":[{"field":["path"],"message":"has already been taken"}]}}}`,
	}}
	ref := stub.serve()
	w := newTestWriter(t)
	got, _, err := w.CreateRedirect(context.Background(), ref, "/old", "/new")
	if err != nil || got != (Redirect{ID: "r2", Path: "/old", Target: "/new"}) {
		t.Fatalf("%+v, %v", got, err)
	}
	if _, _, err := w.CreateRedirect(context.Background(), ref, "/old", "/new"); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "taken") {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := (Writers{"shopify": w}).SiteFileWriter("shopify"); err != nil {
		t.Fatal(err)
	}
	if _, err := (Writers{"shopify": w}).RedirectCreator("shopify"); err != nil {
		t.Fatal(err)
	}
}
