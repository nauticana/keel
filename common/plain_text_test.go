package common

import "testing"

func TestPlainText(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"plain string":        {"just  text\n here", "just text here"},
		"empty":               {"", ""},
		"block boundaries":    {"<p>one</p><p>two</p>", "one two"},
		"line break":          {"one<br>two", "one two"},
		"list and table":      {"<ul><li>a</li><li>b</li></ul><table><tr><td>c</td><td>d</td></tr></table>", "a b c d"},
		"inline keeps word":   {"<b>wo</b>rd and <span>sp</span><em>an</em>", "word and span"},
		"script dropped":      {"a <script>alert('x < y')</script>b", "a b"},
		"style dropped":       {"<style>p{color:red}</style><p>shown</p>", "shown"},
		"noscript dropped":    {"<noscript><p>fallback</p></noscript>kept", "kept"},
		"template dropped":    {"<template><p>hidden</p></template>kept", "kept"},
		"head title dropped":  {"<html><head><title>Tab</title></head><body><p>Hi</p></body></html>", "Hi"},
		"svg title dropped":   {"<p>Pay</p><svg><title>Visa</title><path/></svg>", "Pay"},
		"comment dropped":     {"a<!-- secret -->b", "ab"},
		"entities decoded":    {"Tom &amp; Jerry &lt;3 &#8212; caf&eacute;", "Tom & Jerry <3 — café"},
		"nbsp collapses":      {"a&nbsp;&nbsp;b", "a b"},
		"escaped tag is text": {"&lt;script&gt;x&lt;/script&gt;", "<script>x</script>"},
		"unclosed tags":       {"<div><p>broken <b>markup", "broken markup"},
		"full document":       {"<!doctype html><html><head><style>x{}</style></head><body><h1>Hi</h1>there</body></html>", "Hi there"},
	} {
		if got := PlainText(tc.in); got != tc.want {
			t.Errorf("%s: PlainText(%q) = %q, want %q", name, tc.in, got, tc.want)
		}
	}
}
