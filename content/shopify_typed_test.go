package content

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestValueTypeDecode(t *testing.T) {
	for _, tc := range []struct {
		typ   ValueType
		value string
		want  any
	}{
		{ValueString, " as is ", " as is "},
		{ValueBool, "true", true},
		{ValueBool, " 0 ", false},
		{ValueList, "seo, shoes ,,", []string{"seo", "shoes"}},
		{ValueList, `["a, b","c"]`, []string{"a, b", "c"}},
		{ValueList, "", []string{}},
		{ValueJSON, `{"name":"Ada","n":12345678901234567}`, map[string]any{"name": "Ada", "n": json.Number("12345678901234567")}},
		{ValueJSON, "", nil},
	} {
		got, err := tc.typ.decode(tc.value)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("decode(%d, %q) = %#v, %v", tc.typ, tc.value, got, err)
		}
	}
	for _, tc := range []struct {
		typ   ValueType
		value string
	}{
		{ValueBool, "yes"},
		{ValueBool, ""},
		{ValueList, `["a",1]`},
		{ValueJSON, `{"a":`},
		{ValueJSON, `{} {}`},
		{ValueType(9), "x"},
	} {
		if _, err := tc.typ.decode(tc.value); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("decode(%d, %q): err = %v", tc.typ, tc.value, err)
		}
	}
}

// Every value a typed field reads back must decode into what it read.
func TestValueTypeRenderRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		typ ValueType
		raw string
	}{
		{ValueBool, "true"},
		{ValueList, `[ "a", "b" ]`},
		{ValueJSON, `{ "altText": "x", "url": "https://cdn/x.png" }`},
	} {
		rendered, err := tc.typ.render(json.RawMessage(tc.raw))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := tc.typ.decode(rendered)
		if err != nil {
			t.Fatalf("%d: %q does not decode: %v", tc.typ, rendered, err)
		}
		if again, _ := json.Marshal(decoded); string(again) != mustCompact(t, tc.raw) {
			t.Errorf("%d: round trip %s -> %s", tc.typ, tc.raw, again)
		}
	}
	if got, err := ValueJSON.render(json.RawMessage("null")); err != nil || got != "" {
		t.Errorf("null renders %q, %v", got, err)
	}
	if _, err := ValueString.render(json.RawMessage("true")); err == nil {
		t.Error("an untyped non-string field read as a string")
	}
	if _, err := ValueBool.render(json.RawMessage(`"true"`)); err == nil {
		t.Error("a boolean field accepted a JSON string")
	}
	if _, err := ValueList.render(json.RawMessage(`["a",1]`)); err == nil {
		t.Error("a string-list field accepted a non-string member")
	}
}

func mustCompact(t *testing.T, raw string) string {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(v)
	return string(out)
}

func TestShopifyCreateTypedInputs(t *testing.T) {
	stub := &shopifyStub{t: t, responses: []string{
		`{"data":{"articleCreate":{"article":{"id":"gid://shopify/Article/3"},"userErrors":[]}}}`,
	}}
	if _, _, err := newTestWriter(t).Create(context.Background(), refOf(stub.serve(), ShopifyArticle), map[string]string{
		"title":     "Sizing",
		"published": "true",
		"tags":      "fit, sizing",
		"author":    `{"name":"Ada"}`,
		"image":     `{"url":"https://cdn/x.png","altText":"A shoe"}`,
	}); err != nil {
		t.Fatal(err)
	}
	got := stub.requests[0].Variables["in"]
	want := map[string]any{
		"title":       "Sizing",
		"isPublished": true,
		"tags":        []any{"fit", "sizing"},
		"author":      map[string]any{"name": "Ada"},
		"image":       map[string]any{"url": "https://cdn/x.png", "altText": "A shoe"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("input = %v", got)
	}
}

func TestShopifyTypedInvalidValueSendsNothing(t *testing.T) {
	stub := &shopifyStub{t: t}
	ref := refOf(stub.serve(), ShopifyArticle)
	w := newTestWriter(t)
	if _, err := w.UpdateField(context.Background(), ref, "published", "soon"); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("update: err = %v", err)
	}
	if _, _, err := w.Create(context.Background(), ref, map[string]string{"title": "x", "author": "Ada"}); !errors.Is(err, ErrInvalidValue) {
		t.Errorf("create: err = %v", err)
	}
	if len(stub.requests) != 0 {
		t.Fatalf("sent %d requests", len(stub.requests))
	}
}

func TestShopifyTypedUpdateAndRead(t *testing.T) {
	ctx := context.Background()
	w := newTestWriter(t)

	stub := &shopifyStub{t: t, responses: []string{`{"data":{"articleUpdate":{"userErrors":[]}}}`}}
	if _, err := w.UpdateField(ctx, refOf(stub.serve(), ShopifyArticle), "tags", `["a"]`); err != nil {
		t.Fatal(err)
	}
	if in := stub.requests[0].Variables["in"]; !reflect.DeepEqual(in, map[string]any{"tags": []any{"a"}}) {
		t.Fatalf("input = %v", in)
	}

	stub = &shopifyStub{t: t, responses: []string{
		`{"data":{"article":{"value":{"altText":"old","url":"https://cdn/x.png"}}}}`,
		`{"data":{"article":{"value":null}}}`,
		`{"data":{"article":{"value":false}}}`,
	}}
	ref := refOf(stub.serve(), ShopifyArticle)
	if got, err := w.ReadField(ctx, ref, "image"); err != nil || got != `{"altText":"old","url":"https://cdn/x.png"}` {
		t.Fatalf("image = %q, %v", got, err)
	}
	if q := stub.requests[0].Query; q != "query($id:ID!){article(id:$id){value: image{altText url}}}" {
		t.Fatalf("query = %q", q)
	}
	if got, err := w.ReadField(ctx, ref, "image"); err != nil || got != "" {
		t.Fatalf("no image = %q, %v", got, err)
	}
	if got, err := w.ReadField(ctx, ref, "published"); err != nil || got != "false" {
		t.Fatalf("published = %q, %v", got, err)
	}
}
