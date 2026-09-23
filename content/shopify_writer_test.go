package content

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type gqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// shopifyStub answers each request with the next canned response and records what it received.
type shopifyStub struct {
	t         *testing.T
	status    int
	responses []string
	requests  []gqlRequest
	token     string
	path      string
}

func (s *shopifyStub) serve() ResourceRef {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req gqlRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			s.t.Errorf("request body %q: %v", body, err)
		}
		s.requests = append(s.requests, req)
		s.token, s.path = r.Header.Get("X-Shopify-Access-Token"), r.URL.Path
		if s.status != 0 {
			w.WriteHeader(s.status)
		}
		_, _ = w.Write([]byte(s.responses[len(s.requests)-1]))
	}))
	s.t.Cleanup(srv.Close)
	return ResourceRef{Endpoint: srv.URL + "/admin/api/v1/", Token: "shpat", ID: "gid://shopify/X/1"}
}

var testFields = ShopifyFieldMap{
	ShopifyPage: {
		"body":      {Input: "body"},
		"seo_title": {Metafield: &ShopifyMetafield{Namespace: "global", Key: "title_tag", Type: "single_line_text_field"}},
	},
	ShopifyProduct: {
		"body":      {Input: "descriptionHtml"},
		"seo_title": {SEO: "title"},
		"seo_desc":  {SEO: "description"},
	},
	ShopifyArticle: {
		"title":     {Input: "title"},
		"published": {Input: "isPublished", Type: ValueBool},
		"tags":      {Input: "tags", Type: ValueList},
		"author":    {Input: "author", Type: ValueJSON},
		"image":     {Input: "image", Type: ValueJSON, Selection: "{altText url}"},
	},
}

func newTestWriter(t *testing.T) *ShopifyWriter {
	t.Helper()
	w, err := NewShopifyWriter(testFields)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func refOf(ref ResourceRef, kind string) ResourceRef {
	ref.Kind = kind
	return ref
}

func TestNewShopifyWriterValidatesFieldMap(t *testing.T) {
	for name, fields := range map[string]ShopifyFieldMap{
		"unknown kind":         {"order": {"note": {Input: "note"}}},
		"no target":            {ShopifyPage: {"x": {}}},
		"two targets":          {ShopifyPage: {"x": {Input: "body", SEO: "title"}}},
		"injected selection":   {ShopifyPage: {"x": {Input: "body} shop{name"}}},
		"bad seo member":       {ShopifyProduct: {"x": {SEO: "keywords"}}},
		"partial metafield":    {ShopifyPage: {"x": {Metafield: &ShopifyMetafield{Namespace: "global"}}}},
		"empty logical field":  {ShopifyPage: {"": {Input: "body"}}},
		"typed seo member":     {ShopifyProduct: {"x": {SEO: "title", Type: ValueBool}}},
		"typed metafield":      {ShopifyPage: {"x": {Metafield: &ShopifyMetafield{Namespace: "n", Key: "k", Type: "t"}, Type: ValueList}}},
		"unknown value type":   {ShopifyPage: {"x": {Input: "body", Type: ValueType(9)}}},
		"untyped selection":    {ShopifyArticle: {"x": {Input: "image", Selection: "{url}"}}},
		"selection argument":   {ShopifyArticle: {"x": {Input: "image", Type: ValueJSON, Selection: "{url(transform:{})}"}}},
		"selection escape":     {ShopifyArticle: {"x": {Input: "image", Type: ValueJSON, Selection: "{url}} shop{name"}}},
		"unbalanced":           {ShopifyArticle: {"x": {Input: "image", Type: ValueJSON, Selection: "{url}}{"}}},
		"empty selection":      {ShopifyArticle: {"x": {Input: "image", Type: ValueJSON, Selection: "{}"}}},
		"numeric field":        {ShopifyArticle: {"x": {Input: "image", Type: ValueJSON, Selection: "{123}"}}},
		"empty nested set":     {ShopifyArticle: {"x": {Input: "image", Type: ValueJSON, Selection: "{image{}}"}}},
		"anonymous nested set": {ShopifyArticle: {"x": {Input: "image", Type: ValueJSON, Selection: "{{url}}"}}},
	} {
		if _, err := NewShopifyWriter(fields); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	fields := ShopifyFieldMap{ShopifyPage: {"body": {Input: "body"}}}
	w, err := NewShopifyWriter(fields)
	if err != nil {
		t.Fatal(err)
	}
	fields[ShopifyPage]["body"] = ShopifyTarget{Input: "body} shop{name"}
	if got := w.fields[ShopifyPage]["body"].Input; got != "body" {
		t.Fatalf("writer retained mutable field map: %q", got)
	}
}

func TestShopifyReadField(t *testing.T) {
	ctx := context.Background()
	w := newTestWriter(t)

	t.Run("input field", func(t *testing.T) {
		stub := &shopifyStub{t: t, responses: []string{`{"data":{"product":{"value":"<p>hi</p>"}}}`}}
		got, err := w.ReadField(ctx, refOf(stub.serve(), ShopifyProduct), "body")
		if err != nil || got != "<p>hi</p>" {
			t.Fatalf("got %q, %v", got, err)
		}
		if q := stub.requests[0].Query; q != "query($id:ID!){product(id:$id){value: descriptionHtml}}" {
			t.Fatalf("query = %q", q)
		}
		if stub.token != "shpat" || stub.path != "/admin/api/v1/graphql.json" {
			t.Fatalf("token=%q path=%q", stub.token, stub.path)
		}
	})

	t.Run("seo member, null reads empty", func(t *testing.T) {
		stub := &shopifyStub{t: t, responses: []string{`{"data":{"product":{"seo":{"title":null,"description":"d"}}}}`}}
		ref := refOf(stub.serve(), ShopifyProduct)
		if got, err := w.ReadField(ctx, ref, "seo_title"); err != nil || got != "" {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("metafield passes namespace and key as variables", func(t *testing.T) {
		stub := &shopifyStub{t: t, responses: []string{`{"data":{"page":{"metafield":{"value":"Title"}}}}`, `{"data":{"page":{"metafield":null}}}`}}
		ref := refOf(stub.serve(), ShopifyPage)
		if got, err := w.ReadField(ctx, ref, "seo_title"); err != nil || got != "Title" {
			t.Fatalf("got %q, %v", got, err)
		}
		vars := stub.requests[0].Variables
		if vars["ns"] != "global" || vars["key"] != "title_tag" || strings.Contains(stub.requests[0].Query, "global") {
			t.Fatalf("query=%q vars=%v", stub.requests[0].Query, vars)
		}
		if got, err := w.ReadField(ctx, ref, "seo_title"); err != nil || got != "" {
			t.Fatalf("unset metafield: got %q, %v", got, err)
		}
	})

	t.Run("missing object", func(t *testing.T) {
		stub := &shopifyStub{t: t, responses: []string{`{"data":{"page":null}}`}}
		if _, err := w.ReadField(ctx, refOf(stub.serve(), ShopifyPage), "body"); !errors.Is(err, ErrResourceNotFound) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("unmapped kind and field send nothing", func(t *testing.T) {
		stub := &shopifyStub{t: t}
		ref := stub.serve()
		if _, err := w.ReadField(ctx, refOf(ref, "order"), "body"); !errors.Is(err, ErrUnsupportedKind) {
			t.Fatalf("kind: err = %v", err)
		}
		if _, err := w.ReadField(ctx, refOf(ref, ShopifyPage), "seo_desc"); !errors.Is(err, ErrUnsupportedField) {
			t.Fatalf("field: err = %v", err)
		}
		if _, err := w.ReadField(ctx, refOf(ref, ShopifyArticle), "body"); !errors.Is(err, ErrUnsupportedField) {
			t.Fatalf("kind without mappings: err = %v", err)
		}
		if len(stub.requests) != 0 {
			t.Fatalf("sent %d requests", len(stub.requests))
		}
	})
}

func TestShopifyUpdateField(t *testing.T) {
	ctx := context.Background()
	w := newTestWriter(t)

	t.Run("id beside the input", func(t *testing.T) {
		stub := &shopifyStub{t: t, responses: []string{`{"data":{"pageUpdate":{"userErrors":[]}}}`}}
		ref := refOf(stub.serve(), ShopifyPage)
		res, err := w.UpdateField(ctx, ref, "body", "<p>new</p>")
		if err != nil || !strings.Contains(res.Response, "pageUpdate") {
			t.Fatalf("res=%+v err=%v", res, err)
		}
		req := stub.requests[0]
		if req.Query != `mutation($id:ID!,$in:PageUpdateInput!){pageUpdate(id:$id,page:$in){userErrors{field message}}}` {
			t.Fatalf("query = %q", req.Query)
		}
		want := map[string]any{"id": ref.ID, "in": map[string]any{"body": "<p>new</p>"}}
		if !reflect.DeepEqual(req.Variables, want) {
			t.Fatalf("vars = %v", req.Variables)
		}
	})

	t.Run("id inside the input", func(t *testing.T) {
		stub := &shopifyStub{t: t, responses: []string{`{"data":{"productUpdate":{"userErrors":[]}}}`}}
		ref := refOf(stub.serve(), ShopifyProduct)
		if _, err := w.UpdateField(ctx, ref, "body", "v"); err != nil {
			t.Fatal(err)
		}
		req := stub.requests[0]
		if req.Query != `mutation($in:ProductUpdateInput!){productUpdate(product:$in){userErrors{field message}}}` {
			t.Fatalf("query = %q", req.Query)
		}
		want := map[string]any{"in": map[string]any{"id": ref.ID, "descriptionHtml": "v"}}
		if !reflect.DeepEqual(req.Variables, want) {
			t.Fatalf("vars = %v", req.Variables)
		}
	})

	t.Run("seo write resends the sibling", func(t *testing.T) {
		stub := &shopifyStub{t: t, responses: []string{
			`{"data":{"product":{"seo":{"title":"old title","description":"kept"}}}}`,
			`{"data":{"productUpdate":{"userErrors":[]}}}`,
		}}
		ref := refOf(stub.serve(), ShopifyProduct)
		if _, err := w.UpdateField(ctx, ref, "seo_title", "new title"); err != nil {
			t.Fatal(err)
		}
		in := stub.requests[1].Variables["in"].(map[string]any)
		want := map[string]any{"title": "new title", "description": "kept"}
		if !reflect.DeepEqual(in["seo"], want) {
			t.Fatalf("seo = %v", in["seo"])
		}
	})

	t.Run("seo write on a missing object stops before mutating", func(t *testing.T) {
		stub := &shopifyStub{t: t, responses: []string{`{"data":{"product":null}}`}}
		if _, err := w.UpdateField(ctx, refOf(stub.serve(), ShopifyProduct), "seo_desc", "v"); !errors.Is(err, ErrResourceNotFound) {
			t.Fatalf("err = %v", err)
		}
		if len(stub.requests) != 1 {
			t.Fatalf("sent %d requests", len(stub.requests))
		}
	})

	t.Run("metafield", func(t *testing.T) {
		stub := &shopifyStub{t: t, responses: []string{`{"data":{"metafieldsSet":{"userErrors":[]}}}`}}
		ref := refOf(stub.serve(), ShopifyPage)
		if _, err := w.UpdateField(ctx, ref, "seo_title", "T"); err != nil {
			t.Fatal(err)
		}
		got := stub.requests[0].Variables["metafields"].([]any)[0]
		want := map[string]any{"ownerId": ref.ID, "namespace": "global", "key": "title_tag", "type": "single_line_text_field", "value": "T"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("metafield = %v", got)
		}
	})

	t.Run("user errors reject", func(t *testing.T) {
		stub := &shopifyStub{t: t, responses: []string{`{"data":{"pageUpdate":{"userErrors":[{"field":["page","body"],"message":"too long"}]}}}`}}
		_, err := w.UpdateField(ctx, refOf(stub.serve(), ShopifyPage), "body", "v")
		if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "page.body: too long") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestShopifyTransportErrors(t *testing.T) {
	ctx := context.Background()
	w := newTestWriter(t)

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		stub := &shopifyStub{t: t, status: status, responses: []string{`{"errors":"nope"}`}}
		if _, err := w.ReadField(ctx, refOf(stub.serve(), ShopifyPage), "body"); !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("%d: err = %v", status, err)
		}
	}

	stub := &shopifyStub{t: t, status: http.StatusBadGateway, responses: []string{`upstream`}}
	_, err := w.ReadField(ctx, refOf(stub.serve(), ShopifyPage), "body")
	if err == nil || errors.Is(err, ErrAccessDenied) || errors.Is(err, ErrRejected) {
		t.Fatalf("502: err = %v", err)
	}

	stub = &shopifyStub{t: t, responses: []string{`{"errors":[{"message":"Field 'seo' doesn't exist"}]}`}}
	if _, err := w.ReadField(ctx, refOf(stub.serve(), ShopifyPage), "body"); !errors.Is(err, ErrRejected) {
		t.Fatalf("graphql error on 200: err = %v", err)
	}

	stub = &shopifyStub{t: t, responses: []string{`{"errors":[{"message":"Access denied","extensions":{"code":"ACCESS_DENIED"}}]}`}}
	if _, err := w.ReadField(ctx, refOf(stub.serve(), ShopifyPage), "body"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("graphql access denial: err = %v", err)
	}

	stub = &shopifyStub{t: t, responses: []string{`{"errors":[{"message":"Field error"},{"message":"Access denied","extensions":{"code":"ACCESS_DENIED"}}]}`}}
	if _, err := w.ReadField(ctx, refOf(stub.serve(), ShopifyPage), "body"); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("access denial after another error: err = %v", err)
	}

	stub = &shopifyStub{t: t, responses: []string{`{"errors":[{"message":"Throttled","extensions":{"code":"THROTTLED"}}]}`}}
	if _, err := w.ReadField(ctx, refOf(stub.serve(), ShopifyPage), "body"); !errors.Is(err, ErrThrottled) || errors.Is(err, ErrRejected) {
		t.Fatalf("graphql throttle on 200: err = %v", err)
	}

	stub = &shopifyStub{t: t, status: http.StatusTooManyRequests, responses: []string{`slow down`}}
	if _, err := w.ReadField(ctx, refOf(stub.serve(), ShopifyPage), "body"); !errors.Is(err, ErrThrottled) {
		t.Fatalf("429: err = %v", err)
	}

	stub = &shopifyStub{t: t, responses: []string{`{"data":{"pageUpdate":null}}`}}
	if _, err := w.UpdateField(ctx, refOf(stub.serve(), ShopifyPage), "body", "v"); !errors.Is(err, ErrRejected) {
		t.Fatalf("null mutation result: err = %v", err)
	}
}
