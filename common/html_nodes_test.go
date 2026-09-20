package common

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

const htmlNodesDoc = `<html><head><title> Shop </title><style>p{}</style></head><body>
<svg><title>Visa</title></svg><p>Hello <b>big</b> world</p><script>var x</script>
<a href="/a">A</a><a href="https://other.example/b">B</a><a href="%zz">bad</a><a>none</a></body></html>`

func parseHTMLNodesDoc(t *testing.T) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(htmlNodesDoc))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestExtractLinksTitleText(t *testing.T) {
	doc := parseHTMLNodesDoc(t)
	base, _ := url.Parse("https://shop.example/dir/")
	want := []string{"https://shop.example/a", "https://other.example/b"}
	if got := ExtractLinks(base, doc); !reflect.DeepEqual(got, want) {
		t.Errorf("links = %v", got)
	}
	if got := ExtractTitle(doc); got != "Shop" {
		t.Errorf("title = %q", got)
	}
	if got := ExtractText(doc); !strings.Contains(got, "var x") || !strings.Contains(got, "Hello big world") {
		t.Errorf("text = %q", got)
	}
	if got := PlainTextNode(doc); got != "Hello big world ABbadnone" {
		t.Errorf("plain text = %q", got)
	}
}

func TestExtractTitleOnlyInSVG(t *testing.T) {
	doc, _ := html.Parse(strings.NewReader(`<body><svg><title>Visa</title></svg></body>`))
	if got := ExtractTitle(doc); got != "" {
		t.Errorf("title = %q", got)
	}
}

func TestWithScheme(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":         "https://example.com",
		"http://example.com":  "http://example.com",
		"https://example.com": "https://example.com",
	} {
		if got := WithScheme(in); got != want {
			t.Errorf("WithScheme(%q) = %q", in, got)
		}
	}
}

func TestResolveURL(t *testing.T) {
	lookup := func(_ context.Context, host string) ([]string, error) {
		switch host {
		case "apex.example", "www.only-www.example":
			return []string{"192.0.2.1"}, nil
		}
		return nil, errors.New("no such host")
	}
	ctx := context.Background()
	if got, www, err := resolveURL(ctx, "https://apex.example/p", lookup); err != nil || www || got != "https://apex.example/p" {
		t.Errorf("apex: %q %v %v", got, www, err)
	}
	if got, www, err := resolveURL(ctx, "https://only-www.example:8443/p?q=1", lookup); err != nil || !www || got != "https://www.only-www.example:8443/p?q=1" {
		t.Errorf("www fallback: %q %v %v", got, www, err)
	}
	for _, raw := range []string{"https://dead.example", "https://www.dead.example"} {
		if _, _, err := resolveURL(ctx, raw, lookup); !errors.Is(err, ErrHostUnresolvable) {
			t.Errorf("%s: err = %v", raw, err)
		}
	}
	if _, _, err := resolveURL(ctx, "dead.example", lookup); err == nil || errors.Is(err, ErrHostUnresolvable) {
		t.Errorf("schemeless: err = %v, want a no-host error", err)
	}
}
