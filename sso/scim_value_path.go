package sso

import (
	"encoding/json"
	"regexp"
	"strings"
)

// scimValuePathPattern matches a PATCH path `attr[sub eq "x"]` with an
// optional `.subAttribute`, in any case.
type scimValuePathPattern struct {
	re *regexp.Regexp
}

func scimValuePath(attr, filterAttr string) scimValuePathPattern {
	return scimValuePathPattern{regexp.MustCompile(`(?i)^\s*` + attr + `\s*\[\s*` + filterAttr + `\s+eq\s+("(?:[^"\\]|\\.)*")\s*\]\s*(?:\.\s*([A-Za-z$]+))?\s*$`)}
}

// match returns the compared value and the lower-case sub-attribute.
func (p scimValuePathPattern) match(path string) (string, string, bool) {
	m := p.re.FindStringSubmatch(path)
	if m == nil {
		return "", "", false
	}
	var v string
	if json.Unmarshal([]byte(m[1]), &v) != nil {
		return "", "", false
	}
	return v, strings.ToLower(m[2]), true
}
