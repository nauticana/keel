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
	return strings.Join(PlainTextLines(n), " ")
}

// PlainTextLines is the visible text of a subtree split at non-inline element
// boundaries: one whitespace-collapsed entry per run, empty runs dropped.
func PlainTextLines(n *html.Node) []string {
	var lines []string
	var run strings.Builder
	flush := func() {
		if line := strings.Join(strings.Fields(run.String()), " "); line != "" {
			lines = append(lines, line)
		}
		run.Reset()
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.TextNode:
			run.WriteString(n.Data)
			return
		case html.CommentNode, html.DoctypeNode:
			return
		case html.ElementNode:
			if plainTextSkipped[n.DataAtom] {
				return
			}
		}
		block := n.Type == html.ElementNode && !plainTextInline[n.DataAtom]
		if block {
			flush()
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
		if block {
			flush()
		}
	}
	walk(n)
	flush()
	return lines
}
