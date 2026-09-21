package content

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestShopifyCreateMapsFieldsAndReturnsID(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		`{"data":{"pageCreate":{"page":{"id":"gid://shopify/Page/99"},"userErrors":[]}}}`,
	}}
	ref := refOf(stub.serve(), ShopifyPage)

	created, res, err := newTestWriter(t).Create(context.Background(), ref, map[string]string{
		"body":      "<p>hi</p>",
		"seo_title": "Best Widgets",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "gid://shopify/Page/99" {
		t.Fatalf("created id = %q", created.ID)
	}
	if created.Kind != ShopifyPage || created.Endpoint != ref.Endpoint {
		t.Errorf("returned ref lost its connection: %+v", created)
	}
	if res.Response == "" {
		t.Error("raw response should be kept for audit")
	}
	req := stub.requests[0]
	if !strings.Contains(req.Query, "pageCreate(page:$in)") || !strings.Contains(req.Query, "page{id}") {
		t.Fatalf("query = %s", req.Query)
	}
	in := req.Variables["in"].(map[string]any)
	if in["body"] != "<p>hi</p>" {
		t.Errorf("input body = %v", in["body"])
	}
	// A metafield target has no owner yet, so it rides the create input.
	mf := in["metafields"].([]any)[0].(map[string]any)
	if mf["key"] != "title_tag" || mf["value"] != "Best Widgets" || mf["type"] != "single_line_text_field" {
		t.Errorf("metafield = %v", mf)
	}
}

func TestShopifyCreateGroupsSEOMembers(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		`{"data":{"productCreate":{"product":{"id":"gid://shopify/Product/7"},"userErrors":[]}}}`,
	}}
	ref := refOf(stub.serve(), ShopifyProduct)

	if _, _, err := newTestWriter(t).Create(context.Background(), ref, map[string]string{
		"seo_title": "T", "seo_desc": "D", "body": "B",
	}); err != nil {
		t.Fatal(err)
	}
	in := stub.requests[0].Variables["in"].(map[string]any)
	seo := in["seo"].(map[string]any)
	if seo["title"] != "T" || seo["description"] != "D" || in["descriptionHtml"] != "B" {
		t.Fatalf("input = %v", in)
	}
}

func TestShopifyCreateRejectsUnmappedInput(t *testing.T) {
	w := newTestWriter(t)
	ref := ResourceRef{Endpoint: "https://x/admin/api/v1", Kind: ShopifyPage}

	if _, _, err := w.Create(context.Background(), ref, map[string]string{"handle": "x"}); !errors.Is(err, ErrUnsupportedField) {
		t.Errorf("unmapped field: %v", err)
	}
	if _, _, err := w.Create(context.Background(), ref, nil); !errors.Is(err, ErrRejected) {
		t.Errorf("no fields: %v", err)
	}
	if _, _, err := w.Create(context.Background(), refOf(ref, "order"), map[string]string{"body": "x"}); !errors.Is(err, ErrUnsupportedKind) {
		t.Errorf("unknown kind: %v", err)
	}
}

// A create that Shopify refuses must not report a resource that does not exist.
func TestShopifyCreateSurfacesUserErrors(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		`{"data":{"pageCreate":{"page":null,"userErrors":[{"field":["title"],"message":"can't be blank"}]}}}`,
	}}
	_, _, err := newTestWriter(t).Create(context.Background(), refOf(stub.serve(), ShopifyPage), map[string]string{"body": "x"})
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "can't be blank") {
		t.Fatalf("err = %v", err)
	}
}

func TestShopifyCreateWithoutIDIsRejected(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{`{"data":{"pageCreate":{"page":null,"userErrors":[]}}}`}}
	if _, _, err := newTestWriter(t).Create(context.Background(), refOf(stub.serve(), ShopifyPage), map[string]string{"body": "x"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
}

func TestShopifyDelete(t *testing.T) {
	// page takes the id as its own argument.
	stub := &shopifyStub{t: t, responses: []string{`{"data":{"pageDelete":{"userErrors":[]}}}`}}
	ref := refOf(stub.serve(), ShopifyPage)
	if _, err := newTestWriter(t).Delete(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if got := stub.requests[0]; !strings.Contains(got.Query, "pageDelete(id:$id)") || got.Variables["id"] != ref.ID {
		t.Fatalf("query = %s vars = %v", got.Query, got.Variables)
	}

	// product takes it inside a delete input.
	stub2 := &shopifyStub{t: t, responses: []string{`{"data":{"productDelete":{"userErrors":[]}}}`}}
	ref2 := refOf(stub2.serve(), ShopifyProduct)
	if _, err := newTestWriter(t).Delete(context.Background(), ref2); err != nil {
		t.Fatal(err)
	}
	in := stub2.requests[0].Variables["in"].(map[string]any)
	if in["id"] != ref2.ID || !strings.Contains(stub2.requests[0].Query, "ProductDeleteInput") {
		t.Fatalf("query = %s vars = %v", stub2.requests[0].Query, stub2.requests[0].Variables)
	}
}

func TestShopifyDeleteValidates(t *testing.T) {
	w := newTestWriter(t)
	ref := ResourceRef{Endpoint: "https://x/admin/api/v1", Kind: ShopifyPage}
	if _, err := w.Delete(context.Background(), ref); !errors.Is(err, ErrRejected) {
		t.Errorf("missing id: %v", err)
	}
	if _, err := w.Delete(context.Background(), refOf(ref, "order")); !errors.Is(err, ErrUnsupportedKind) {
		t.Errorf("unknown kind: %v", err)
	}
}

func TestWritersCapabilities(t *testing.T) {
	writers := Writers{"shopify": newTestWriter(t), "wordpress": readOnlyWriter{}}

	if _, err := writers.Creator("shopify"); err != nil {
		t.Errorf("shopify should create: %v", err)
	}
	if _, err := writers.Uploader("shopify"); err != nil {
		t.Errorf("shopify should upload: %v", err)
	}
	for name, err := range map[string]error{
		"create": firstErr(writers.Creator("wordpress")),
		"delete": firstErr(writers.Deleter("wordpress")),
		"upload": firstErr(writers.Uploader("wordpress")),
	} {
		if !errors.Is(err, ErrUnsupportedOperation) {
			t.Errorf("%s: err = %v, want ErrUnsupportedOperation", name, err)
		}
	}
	if _, err := writers.Creator("ghost"); !errors.Is(err, ErrUnsupportedProvider) {
		t.Errorf("unknown provider: %v", err)
	}
}

func firstErr[T any](_ T, err error) error { return err }

// readOnlyWriter is a provider that only edits — the capability accessors must
// say so rather than panicking on a type assertion at the call site.
type readOnlyWriter struct{}

func (readOnlyWriter) ReadField(context.Context, ResourceRef, string) (string, error) {
	return "", nil
}
func (readOnlyWriter) UpdateField(context.Context, ResourceRef, string, string) (WriteResult, error) {
	return WriteResult{}, nil
}
