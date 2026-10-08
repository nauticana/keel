package sso

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// scimEq matches `attribute eq "value"`, the only filter directories need to
// look a resource up before creating it.
var scimEq = regexp.MustCompile(`(?i)^\s*([A-Za-z][A-Za-z0-9.]*)\s+eq\s+("(?:[^"\\]|\\.)*")\s*$`)

// SCIMFilter is a parsed lookup filter: at most one attribute, matched exactly.
type SCIMFilter struct {
	Attribute string // canonical attribute name; empty = no filter
	Value     string
}

// ParseSCIMFilter accepts an empty filter or `attribute eq "value"` on one of
// allowed, compared without regard to case.
func ParseSCIMFilter(filter string, allowed ...string) (SCIMFilter, error) {
	if strings.TrimSpace(filter) == "" {
		return SCIMFilter{}, nil
	}
	m := scimEq.FindStringSubmatch(filter)
	if m == nil {
		return SCIMFilter{}, ErrSCIMInvalidFilter
	}
	var value string
	if err := json.Unmarshal([]byte(m[2]), &value); err != nil || value == "" || len(value) > 255 {
		return SCIMFilter{}, ErrSCIMInvalidFilter
	}
	for _, a := range allowed {
		if strings.EqualFold(m[1], a) {
			return SCIMFilter{Attribute: a, Value: value}, nil
		}
	}
	return SCIMFilter{}, fmt.Errorf("%w: attribute %q", ErrSCIMInvalidFilter, m[1])
}

// scimMemberPath matches `members[value eq "id"]`.
var scimMemberPath = regexp.MustCompile(`(?i)^\s*members\s*\[\s*value\s+eq\s+("(?:[^"\\]|\\.)*")\s*\]\s*$`)

func memberPathValue(path string) (string, bool) {
	m := scimMemberPath.FindStringSubmatch(path)
	if m == nil {
		return "", false
	}
	var v string
	if json.Unmarshal([]byte(m[1]), &v) != nil || v == "" {
		return "", false
	}
	return v, true
}
