package content

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestShopifyListImagesPagesAndSkipsNonImages(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		`{"data":{"product":{"media":{"pageInfo":{"hasNextPage":true,"endCursor":"c1"},"nodes":[` +
			`{"id":"gid://shopify/MediaImage/1","alt":"","image":{"url":"https://cdn/1.png"}},{}]}}}}`,
		`{"data":{"product":{"media":{"pageInfo":{"hasNextPage":false,"endCursor":"c2"},"nodes":[` +
			`{"id":"gid://shopify/MediaImage/2","alt":"red shoe","image":null}]}}}}`,
	}}
	images, err := newTestWriter(t).ListImages(context.Background(), refOf(stub.serve(), ShopifyProduct))
	if err != nil {
		t.Fatal(err)
	}
	want := []ResourceImage{
		{ID: "gid://shopify/MediaImage/1", URL: "https://cdn/1.png"},
		{ID: "gid://shopify/MediaImage/2", Alt: "red shoe"},
	}
	if !reflect.DeepEqual(images, want) {
		t.Fatalf("images = %+v", images)
	}
	if _, ok := stub.requests[0].Variables["after"]; ok {
		t.Error("first page sent a cursor")
	}
	if got := stub.requests[1].Variables["after"]; got != "c1" {
		t.Errorf("second page cursor = %v", got)
	}
}

func TestShopifyListImagesErrors(t *testing.T) {
	w := newTestWriter(t)
	stub := &shopifyStub{t: t, responses: []string{`{"data":{"product":null}}`}}
	ref := stub.serve()
	if _, err := w.ListImages(context.Background(), refOf(ref, ShopifyProduct)); !errors.Is(err, ErrResourceNotFound) {
		t.Errorf("missing product: %v", err)
	}
	if _, err := w.ListImages(context.Background(), refOf(ref, ShopifyArticle)); !errors.Is(err, ErrUnsupportedKind) {
		t.Errorf("article: %v", err)
	}
}

const oneImagePage = `{"data":{"product":{"media":{"pageInfo":{"hasNextPage":false},"nodes":[` +
	`{"id":"gid://shopify/MediaImage/1","alt":"","image":{"url":"https://cdn/1.png"}}]}}}}`

func TestShopifySetImageAlt(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		oneImagePage,
		`{"data":{"fileUpdate":{"files":[{"id":"gid://shopify/MediaImage/1"}],"userErrors":[]}}}`,
	}}
	res, err := newTestWriter(t).SetImageAlt(context.Background(), refOf(stub.serve(), ShopifyProduct), "gid://shopify/MediaImage/1", "Red running shoe")
	if err != nil {
		t.Fatal(err)
	}
	if res.Response == "" {
		t.Error("raw response should be kept for audit")
	}
	got := stub.requests[1].Variables["files"]
	want := []any{map[string]any{"id": "gid://shopify/MediaImage/1", "alt": "Red running shoe"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("files = %v", got)
	}
}

// fileUpdate accepts any file in the shop; an image the product does not own
// must never reach it.
func TestShopifySetImageAltRefusesForeignImage(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{oneImagePage}}
	_, err := newTestWriter(t).SetImageAlt(context.Background(), refOf(stub.serve(), ShopifyProduct), "gid://shopify/MediaImage/99", "x")
	if !errors.Is(err, ErrResourceNotFound) {
		t.Fatalf("err = %v", err)
	}
	if len(stub.requests) != 1 {
		t.Fatalf("sent %d requests, want only the listing", len(stub.requests))
	}
	if _, err := newTestWriter(t).SetImageAlt(context.Background(), refOf(stub.serve(), ShopifyProduct), "", "x"); !errors.Is(err, ErrRejected) {
		t.Errorf("empty id: %v", err)
	}
}

func TestShopifySetImageAltSurfacesRefusal(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		oneImagePage,
		`{"data":{"fileUpdate":{"files":[],"userErrors":[{"field":["files","0","alt"],"message":"too long"}]}}}`,
	}}
	_, err := newTestWriter(t).SetImageAlt(context.Background(), refOf(stub.serve(), ShopifyProduct), "gid://shopify/MediaImage/1", "x")
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v", err)
	}
}
