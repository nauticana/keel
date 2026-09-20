package common

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// ExtractLinks returns every <a href> under n resolved against base, in
// document order; unparseable hrefs are skipped.
func ExtractLinks(base *url.URL, n *html.Node) []string {
	var links []string
	if n.Type == html.ElementNode && n.DataAtom == atom.A {
		for _, a := range n.Attr {
			if a.Key != "href" {
				continue
			}
			if link, err := base.Parse(a.Val); err == nil {
				links = append(links, link.String())
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		links = append(links, ExtractLinks(base, c)...)
	}
	return links
}

// ExtractText concatenates every text node under n verbatim, script and style
// content included; PlainTextNode is the visible-text form.
func ExtractText(n *html.Node) string {
	var sb strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			sb.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return sb.String()
}

// ExtractTitle returns the document's first <title>, skipping <svg> subtrees
// whose <title> elements label icons.
func ExtractTitle(n *html.Node) string {
	if n.Type == html.ElementNode {
		switch n.DataAtom {
		case atom.Svg:
			return ""
		case atom.Title:
			if n.FirstChild != nil {
				return strings.TrimSpace(n.FirstChild.Data)
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if t := ExtractTitle(c); t != "" {
			return t
		}
	}
	return ""
}
