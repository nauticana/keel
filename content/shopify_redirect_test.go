package content

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func newRedirectWriter(t *testing.T) *ShopifyWriter {
	t.Helper()
	w, err := NewShopifyWriter(ShopifyFieldMap{
		ShopifyPage:       {"redirect": {Redirect: true}},
		ShopifyArticle:    {"redirect": {Redirect: true}},
		ShopifyProduct:    {"redirect": {Redirect: true}},
		ShopifyCollection: {"redirect": {Redirect: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

const (
	livePage      = `{"data":{"page":{"handle":"old","isPublished":true}}}`
	retiredPage   = `{"data":{"page":{"handle":"old","isPublished":false}}}`
	noRedirect    = `{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":false},"nodes":[{"id":"r9","path":"/pages/older","target":"/"}]}}}`
	withRedirect  = `{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":false},"nodes":[{"id":"r1","path":"/pages/old","target":"/pages/new"}]}}}`
	pageUpdated   = `{"data":{"pageUpdate":{"userErrors":[]}}}`
	redirectMade  = `{"data":{"urlRedirectCreate":{"urlRedirect":{"id":"r1"},"userErrors":[]}}}`
	redirectMoved = `{"data":{"urlRedirectUpdate":{"urlRedirect":{"id":"r1"},"userErrors":[]}}}`
	redirectGone  = `{"data":{"urlRedirectDelete":{"deletedUrlRedirectId":"r1","userErrors":[]}}}`
)

func TestShopifyRedirectRejectsUnretirableTargets(t *testing.T) {
	for name, fields := range map[string]ShopifyFieldMap{
		"with an input": {ShopifyPage: {"redirect": {Redirect: true, Input: "body"}}},
		"typed":         {ShopifyPage: {"redirect": {Redirect: true, Type: ValueBool}}},
	} {
		if _, err := NewShopifyWriter(fields); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	w := newRedirectWriter(t)
	if _, _, err := w.Create(context.Background(), ResourceRef{Kind: ShopifyPage}, map[string]string{"redirect": "/"}); !errors.Is(err, ErrUnsupportedField) {
		t.Fatalf("create with a redirect: %v", err)
	}
}

func TestShopifyReadRedirect(t *testing.T) {
	ctx := context.Background()
	w := newRedirectWriter(t)
	for name, c := range map[string]struct {
		responses []string
		want      string
	}{
		"live page ignores an inert redirect": {[]string{livePage, withRedirect}, ""},
		"retired page":                        {[]string{retiredPage, withRedirect}, "/pages/new"},
		"unpublished without redirect":        {[]string{retiredPage, noRedirect}, ""},
	} {
		stub := &shopifyStub{t: t, responses: c.responses}
		got, err := w.ReadField(ctx, refOf(stub.serve(), ShopifyPage), "redirect")
		if err != nil || got != c.want {
			t.Errorf("%s: %q, %v; want %q", name, got, err, c.want)
		}
		if q := stub.requests[1].Variables["q"]; q != `path:"/pages/old"` {
			t.Errorf("%s: redirect search = %v", name, q)
		}
	}
}

func TestShopifyRetireBehindRedirect(t *testing.T) {
	ctx := context.Background()
	w := newRedirectWriter(t)

	stub := &shopifyStub{t: t, responses: []string{livePage, noRedirect, redirectMade, pageUpdated}}
	if _, err := w.UpdateField(ctx, refOf(stub.serve(), ShopifyPage), "redirect", "/pages/new"); err != nil {
		t.Fatal(err)
	}
	created := stub.requests[2].Variables["r"].(map[string]any)
	if created["path"] != "/pages/old" || created["target"] != "/pages/new" {
		t.Fatalf("redirect = %v", created)
	}
	if in := stub.requests[3].Variables["in"].(map[string]any); in["isPublished"] != false {
		t.Fatalf("unpublish input = %v", in)
	}

	stub = &shopifyStub{t: t, responses: []string{retiredPage, withRedirect, redirectMoved}}
	if _, err := w.UpdateField(ctx, refOf(stub.serve(), ShopifyPage), "redirect", "/pages/newer"); err != nil || len(stub.requests) != 3 {
		t.Fatalf("retarget: %v after %d requests", err, len(stub.requests))
	}
	if stub.requests[2].Variables["id"] != "r1" {
		t.Fatalf("retarget did not update the existing redirect: %v", stub.requests[2].Variables)
	}

	stub = &shopifyStub{t: t, responses: []string{retiredPage, noRedirect}}
	if _, err := w.UpdateField(ctx, refOf(stub.serve(), ShopifyPage), "redirect", "/pages/new"); !errors.Is(err, ErrRejected) {
		t.Fatalf("retiring an unpublished page: %v", err)
	}
}

func TestShopifyRestoreFromRedirect(t *testing.T) {
	ctx := context.Background()
	w := newRedirectWriter(t)

	stub := &shopifyStub{t: t, responses: []string{
		`{"data":{"product":{"handle":"old","status":"ACTIVE","resourcePublications":{"nodes":[{"isPublished":false,"publication":{"id":"pub1","name":"Online Store","catalog":null}}]}}}}`,
		`{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":false},"nodes":[{"id":"r1","path":"/products/old","target":"/"}]}}}`,
		`{"data":{"publishablePublish":{"userErrors":[]}}}`,
		redirectGone,
	}}
	if _, err := w.UpdateField(ctx, refOf(stub.serve(), ShopifyProduct), "redirect", ""); err != nil {
		t.Fatal(err)
	}
	if in := stub.requests[2].Variables["input"].([]any); in[0].(map[string]any)["publicationId"] != "pub1" {
		t.Fatalf("republish input = %v", in)
	}
	if !strings.Contains(stub.requests[3].Query, "urlRedirectDelete") {
		t.Fatalf("second write = %s", stub.requests[3].Query)
	}

	stub = &shopifyStub{t: t, responses: []string{livePage, withRedirect, redirectGone}}
	if _, err := w.UpdateField(ctx, refOf(stub.serve(), ShopifyPage), "redirect", ""); err != nil || len(stub.requests) != 3 {
		t.Fatalf("clearing a live page wrote: %v after %d requests", err, len(stub.requests))
	}

	stub = &shopifyStub{t: t, responses: []string{
		`{"data":{"product":{"handle":"old","status":"DRAFT","resourcePublications":{"nodes":[{"isPublished":true,"publication":{"id":"pub1","name":"Online Store","catalog":null}}]}}}}`,
		`{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":false},"nodes":[{"id":"r1","path":"/products/old","target":"/"}]}}}`,
	}}
	if _, err := w.UpdateField(ctx, refOf(stub.serve(), ShopifyProduct), "redirect", ""); !errors.Is(err, ErrRejected) {
		t.Fatalf("restoring an independently inactive product: %v", err)
	}
}

func TestShopifyRetireCollectionFromOnlineStore(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		`{"data":{"collection":{"handle":"old","resourcePublications":{"nodes":[{"isPublished":true,"publication":{"id":"pub1","catalog":{"title":"Channel Catalog for Online Store"}}}]}}}}`,
		`{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":false},"nodes":[]}}}`,
		redirectMade,
		`{"data":{"publishableUnpublish":{"userErrors":[]}}}`,
	}}
	if _, err := newRedirectWriter(t).UpdateField(context.Background(), refOf(stub.serve(), ShopifyCollection), "redirect", "/collections/new"); err != nil {
		t.Fatal(err)
	}
	if input := stub.requests[3].Variables["input"].([]any); input[0].(map[string]any)["publicationId"] != "pub1" {
		t.Fatalf("unpublish input = %v", input)
	}
}

func TestShopifyArticlePath(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		`{"data":{"article":{"handle":"post","isPublished":false,"blog":{"handle":"news"}}}}`,
		`{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":false},"nodes":[{"id":"r1","path":"/blogs/news/post","target":"/blogs/news"}]}}}`,
	}}
	got, err := newRedirectWriter(t).ReadField(context.Background(), refOf(stub.serve(), ShopifyArticle), "redirect")
	if err != nil || got != "/blogs/news" {
		t.Fatalf("%q, %v", got, err)
	}
}

func TestShopifyListRedirectsPages(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		`{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":true,"endCursor":"c1"},"nodes":[{"id":"r1","path":"/a","target":"/b"}]}}}`,
		`{"data":{"urlRedirects":{"pageInfo":{"hasNextPage":false},"nodes":[{"id":"r2","path":"/c","target":"/d"}]}}}`,
	}}
	lister, err := Writers{"shopify": newRedirectWriter(t)}.RedirectLister("shopify")
	if err != nil {
		t.Fatal(err)
	}
	got, err := lister.ListRedirects(context.Background(), stub.serve())
	if err != nil || len(got) != 2 || got[1] != (Redirect{ID: "r2", Path: "/c", Target: "/d"}) {
		t.Fatalf("%v, %v", got, err)
	}
	if stub.requests[1].Variables["after"] != "c1" || stub.requests[0].Variables["q"] != nil {
		t.Fatalf("paging variables = %v / %v", stub.requests[0].Variables, stub.requests[1].Variables)
	}
}
