package sso

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	scimFilterMaxLength      = 2048
	scimFilterMaxComparisons = 16
	scimFilterMaxTerms       = 32
	scimFilterMaxValue       = 255
)

// scimComparison is one comparison of a filter. attr is the lower-case
// attribute name; value is lower-cased for attributes that are not caseExact.
type scimComparison struct {
	attr, op, value string
	negate          bool
}

// scimFilter is a filter in disjunctive normal form: a resource matches when
// every comparison of some term holds. No terms matches every resource.
type scimFilter struct {
	terms [][]scimComparison
}

// scimFilterSchema lists a resource's filterable attributes and whether each
// is caseExact; key is its case-insensitive lookup attribute.
type scimFilterSchema struct {
	urn        string
	attributes map[string]bool
	key        string
}

var (
	scimUserFilterSchema  = scimFilterSchema{urn: SchemaUser, key: "username", attributes: map[string]bool{"id": true, "username": false, "externalid": true}}
	scimGroupFilterSchema = scimFilterSchema{urn: SchemaGroup, key: "displayname", attributes: map[string]bool{"id": true, "displayname": false, "externalid": true}}
)

// parseSCIMFilter parses an RFC 7644 §3.4.2.2 filter limited to eq, ne, co,
// sw, ew and pr on the schema's attributes, combined with and, or, not and
// parentheses. Anything else is ErrSCIMInvalidFilter.
func parseSCIMFilter(filter string, schema scimFilterSchema) (scimFilter, error) {
	if strings.TrimSpace(filter) == "" {
		return scimFilter{}, nil
	}
	if len(filter) > scimFilterMaxLength {
		return scimFilter{}, fmt.Errorf("%w: longer than %d characters", ErrSCIMInvalidFilter, scimFilterMaxLength)
	}
	tokens, err := tokenizeSCIMFilter(filter)
	if err != nil {
		return scimFilter{}, err
	}
	p := &scimFilterParser{tokens: tokens, schema: schema}
	node, err := p.or()
	if err != nil {
		return scimFilter{}, err
	}
	if p.pos != len(p.tokens) {
		return scimFilter{}, fmt.Errorf("%w: unexpected %q", ErrSCIMInvalidFilter, p.tokens[p.pos].text)
	}
	terms, err := node.dnf(false)
	if err != nil {
		return scimFilter{}, err
	}
	return scimFilter{terms: terms}, nil
}

// scimFilterArgs are the arguments of the filter fragment of the list
// queries. A single term's equalities on id, the key and externalId also bind
// the index-friendly parameters; the remaining comparisons are passed as
// parallel arrays the query evaluates per term.
func (f scimFilter) args(partnerID int64, schema scimFilterSchema) []any {
	var id int64
	key, ext := "", ""
	rest := f.terms
	if len(f.terms) == 1 {
		var left []scimComparison
		for _, c := range f.terms[0] {
			if c.negate || c.op != "eq" || c.value == "" {
				left = append(left, c)
				continue
			}
			switch {
			case c.attr == "id" && id == 0:
				if v, err := strconv.ParseInt(c.value, 10, 64); err == nil && v > 0 {
					id = v
					continue
				}
			case c.attr == schema.key && key == "":
				key = c.value
				continue
			case c.attr == "externalid" && ext == "":
				ext = c.value
				continue
			}
			left = append(left, c)
		}
		rest = nil
		if len(left) > 0 {
			rest = [][]scimComparison{left}
		}
	}
	var termIdx []int64
	var attrs, ops, values []string
	var negs []bool
	for i, term := range rest {
		for _, c := range term {
			termIdx = append(termIdx, int64(i))
			attrs, ops, values, negs = append(attrs, c.attr), append(ops, c.op), append(values, c.value), append(negs, c.negate)
		}
	}
	return []any{partnerID, id, id, key, key, ext, ext, len(rest), termIdx, attrs, ops, negs, values}
}

type scimFilterToken struct {
	kind byte // '(' ')' 'w' word, 's' string
	text string
}

func tokenizeSCIMFilter(s string) ([]scimFilterToken, error) {
	var out []scimFilterToken
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(' || c == ')':
			out = append(out, scimFilterToken{kind: c, text: string(c)})
			i++
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("%w: unterminated string", ErrSCIMInvalidFilter)
			}
			var v string
			if err := json.Unmarshal([]byte(s[i:j+1]), &v); err != nil {
				return nil, fmt.Errorf("%w: malformed string", ErrSCIMInvalidFilter)
			}
			if len(v) > scimFilterMaxValue {
				return nil, fmt.Errorf("%w: value longer than %d characters", ErrSCIMInvalidFilter, scimFilterMaxValue)
			}
			out = append(out, scimFilterToken{kind: 's', text: v})
			i = j + 1
		case isSCIMWordChar(c):
			j := i
			for j < len(s) && isSCIMWordChar(s[j]) {
				j++
			}
			out = append(out, scimFilterToken{kind: 'w', text: s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("%w: unexpected %q", ErrSCIMInvalidFilter, c)
		}
	}
	return out, nil
}

func isSCIMWordChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(".:_-$", c) >= 0
}

type scimFilterNode struct {
	op          string // and, or, not, cmp
	left, right *scimFilterNode
	cmp         scimComparison
}

type scimFilterParser struct {
	tokens      []scimFilterToken
	pos         int
	comparisons int
	schema      scimFilterSchema
}

func (p *scimFilterParser) keyword(word string) bool {
	if p.pos < len(p.tokens) && p.tokens[p.pos].kind == 'w' && strings.EqualFold(p.tokens[p.pos].text, word) {
		p.pos++
		return true
	}
	return false
}

func (p *scimFilterParser) expect(kind byte) error {
	if p.pos >= len(p.tokens) || p.tokens[p.pos].kind != kind {
		return fmt.Errorf("%w: expected %q", ErrSCIMInvalidFilter, kind)
	}
	p.pos++
	return nil
}

func (p *scimFilterParser) or() (*scimFilterNode, error) {
	left, err := p.and()
	for err == nil && p.keyword("or") {
		var right *scimFilterNode
		if right, err = p.and(); err == nil {
			left = &scimFilterNode{op: "or", left: left, right: right}
		}
	}
	return left, err
}

func (p *scimFilterParser) and() (*scimFilterNode, error) {
	left, err := p.unary()
	for err == nil && p.keyword("and") {
		var right *scimFilterNode
		if right, err = p.unary(); err == nil {
			left = &scimFilterNode{op: "and", left: left, right: right}
		}
	}
	return left, err
}

func (p *scimFilterParser) unary() (*scimFilterNode, error) {
	negate := p.keyword("not")
	if negate || (p.pos < len(p.tokens) && p.tokens[p.pos].kind == '(') {
		if err := p.expect('('); err != nil {
			return nil, err
		}
		inner, err := p.or()
		if err != nil {
			return nil, err
		}
		if err := p.expect(')'); err != nil {
			return nil, err
		}
		if negate {
			return &scimFilterNode{op: "not", left: inner}, nil
		}
		return inner, nil
	}
	return p.comparison()
}

func (p *scimFilterParser) comparison() (*scimFilterNode, error) {
	if p.comparisons++; p.comparisons > scimFilterMaxComparisons {
		return nil, fmt.Errorf("%w: more than %d comparisons", ErrSCIMInvalidFilter, scimFilterMaxComparisons)
	}
	if p.pos+1 >= len(p.tokens) || p.tokens[p.pos].kind != 'w' || p.tokens[p.pos+1].kind != 'w' {
		return nil, fmt.Errorf("%w: expected attribute and operator", ErrSCIMInvalidFilter)
	}
	path, op := p.tokens[p.pos].text, strings.ToLower(p.tokens[p.pos+1].text)
	p.pos += 2
	attr := strings.ToLower(path)
	if prefix := strings.ToLower(p.schema.urn) + ":"; strings.HasPrefix(attr, prefix) {
		attr = attr[len(prefix):]
	}
	caseExact, ok := p.schema.attributes[attr]
	if !ok {
		return nil, fmt.Errorf("%w: attribute %q is not filterable", ErrSCIMInvalidFilter, path)
	}
	c := scimComparison{attr: attr, op: op}
	switch op {
	case "pr":
	case "eq", "ne", "co", "sw", "ew":
		if p.pos >= len(p.tokens) || p.tokens[p.pos].kind != 's' {
			return nil, fmt.Errorf("%w: %s %s needs a string value", ErrSCIMInvalidFilter, path, op)
		}
		c.value = p.tokens[p.pos].text
		if !caseExact {
			c.value = strings.ToLower(c.value)
		}
		p.pos++
	default:
		return nil, fmt.Errorf("%w: operator %q is not supported", ErrSCIMInvalidFilter, op)
	}
	return &scimFilterNode{op: "cmp", cmp: c}, nil
}

// dnf pushes negations to the comparisons and distributes and over or.
func (n *scimFilterNode) dnf(negate bool) ([][]scimComparison, error) {
	switch {
	case n.op == "cmp":
		c := n.cmp
		c.negate = negate
		return [][]scimComparison{{c}}, nil
	case n.op == "not":
		return n.left.dnf(!negate)
	}
	left, err := n.left.dnf(negate)
	if err != nil {
		return nil, err
	}
	right, err := n.right.dnf(negate)
	if err != nil {
		return nil, err
	}
	if (n.op == "or") != negate {
		if len(left)+len(right) > scimFilterMaxTerms {
			return nil, fmt.Errorf("%w: too complex", ErrSCIMInvalidFilter)
		}
		return append(left, right...), nil
	}
	if len(left)*len(right) > scimFilterMaxTerms {
		return nil, fmt.Errorf("%w: too complex", ErrSCIMInvalidFilter)
	}
	out := make([][]scimComparison, 0, len(left)*len(right))
	for _, l := range left {
		for _, r := range right {
			out = append(out, append(append([]scimComparison{}, l...), r...))
		}
	}
	return out, nil
}

// scimMemberPath matches `members[value eq "id"]`.
var scimMemberPath = scimValuePath("members", "value")

func memberPathValue(path string) (string, bool) {
	v, sub, ok := scimMemberPath.match(path)
	return v, ok && sub == "" && v != ""
}
