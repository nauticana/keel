package common

import (
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

var plainTextSkipped = map[atom.Atom]bool{
	atom.Script: true, atom.Style: true, atom.Noscript: true, atom.Template: true,
	atom.Title: true, // document and svg titles are not rendered in the page
}

// Elements that do not break a word: "<b>wo</b>rd" stays "word".
var plainTextInline = map[atom.Atom]bool{
	atom.A: true, atom.Abbr: true, atom.B: true, atom.Bdi: true, atom.Bdo: true,
	atom.Cite: true, atom.Code: true, atom.Del: true, atom.Dfn: true, atom.Em: true,
	atom.Font: true, atom.I: true, atom.Ins: true, atom.Kbd: true, atom.Label: true,
	atom.Mark: true, atom.Q: true, atom.S: true, atom.Samp: true, atom.Small: true,
	atom.Span: true, atom.Strong: true, atom.Sub: true, atom.Sup: true, atom.Time: true,
	atom.Tt: true, atom.U: true, atom.Var: true,
}

// PlainText returns the visible text of an HTML document or fragment: script,
// style, noscript, template and title content dropped, entities decoded, whitespace
// collapsed, and a space wherever a non-inline element separated two words.
func PlainText(markup string) string {
	doc, err := html.Parse(strings.NewReader(markup))
	if err != nil {
		return strings.Join(strings.Fields(markup), " ")
	}
	return PlainTextNode(doc)
}

// PlainTextNode is PlainText for an already-parsed subtree.
func PlainTextNode(n *html.Node) string {
	var sb strings.Builder
	writePlainText(&sb, n)
	return strings.Join(strings.Fields(sb.String()), " ")
}

func writePlainText(sb *strings.Builder, n *html.Node) {
	switch n.Type {
	case html.TextNode:
		sb.WriteString(n.Data)
		return
	case html.CommentNode, html.DoctypeNode:
		return
	case html.ElementNode:
		if plainTextSkipped[n.DataAtom] {
			return
		}
	}
	breaksWord := n.Type == html.ElementNode && !plainTextInline[n.DataAtom]
	if breaksWord {
		sb.WriteByte(' ')
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		writePlainText(sb, c)
	}
	if breaksWord {
		sb.WriteByte(' ')
	}
}
