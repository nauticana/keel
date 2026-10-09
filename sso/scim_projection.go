package sso

import (
	"encoding/json"
	"strings"
)

// SCIMProjection applies the attributes and excludedAttributes parameters
// (RFC 7644 §3.4.2.5). Names are case-insensitive, may carry the resource's
// schema URN and may name a sub-attribute (name.givenName, emails.value).
// id and schemas are always returned. Names of other schemas select nothing,
// since keel returns no extension attributes.
type SCIMProjection struct {
	include, exclude map[string]map[string]bool // attribute -> sub-attributes; nil means the whole attribute
}

// NewSCIMProjection parses the comma-separated parameters for a resource of schemaURN.
func NewSCIMProjection(schemaURN, attributes, excludedAttributes string) SCIMProjection {
	parse := func(list string) map[string]map[string]bool {
		if strings.TrimSpace(list) == "" {
			return nil
		}
		out := map[string]map[string]bool{}
		prefix := strings.ToLower(schemaURN) + ":"
		for _, name := range strings.Split(list, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if strings.HasPrefix(name, prefix) {
				name = name[len(prefix):]
			} else if strings.HasPrefix(name, "urn:") {
				continue
			}
			attr, sub, hasSub := strings.Cut(name, ".")
			if attr == "" {
				continue
			}
			subs, seen := out[attr]
			switch {
			case !hasSub:
				out[attr] = nil
			case !seen:
				out[attr] = map[string]bool{sub: true}
			case subs != nil:
				subs[sub] = true
			}
		}
		return out
	}
	return SCIMProjection{include: parse(attributes), exclude: parse(excludedAttributes)}
}

// Includes reports whether the response carries some of the attribute.
func (p SCIMProjection) Includes(attr string) bool {
	attr = strings.ToLower(attr)
	if attr == "id" || attr == "schemas" {
		return true
	}
	if p.include != nil {
		if _, ok := p.include[attr]; !ok {
			return false
		}
	}
	subs, excluded := p.exclude[attr]
	return !excluded || subs != nil
}

// Apply returns the projected resource, or the resource itself when no
// parameter was given.
func (p SCIMProjection) Apply(resource any) (any, error) {
	if p.include == nil && p.exclude == nil {
		return resource, nil
	}
	raw, err := json.Marshal(resource)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	for key, value := range out {
		attr := strings.ToLower(key)
		if attr == "id" || attr == "schemas" {
			continue
		}
		if p.include != nil {
			subs, ok := p.include[attr]
			if !ok {
				delete(out, key)
				continue
			}
			if subs != nil {
				value = projectSubAttributes(value, subs, true)
			}
		}
		if subs, ok := p.exclude[attr]; ok {
			if subs == nil {
				delete(out, key)
				continue
			}
			value = projectSubAttributes(value, subs, false)
		}
		if value == nil {
			delete(out, key)
		} else {
			out[key] = value
		}
	}
	return out, nil
}

// projectSubAttributes keeps (or drops) the named sub-attributes of a complex
// value or of each element of a multi-valued one; an emptied value is nil.
func projectSubAttributes(value any, subs map[string]bool, keep bool) any {
	switch v := value.(type) {
	case map[string]any:
		for key := range v {
			if subs[strings.ToLower(key)] != keep {
				delete(v, key)
			}
		}
		if len(v) == 0 {
			return nil
		}
		return v
	case []any:
		out := v[:0]
		for _, item := range v {
			if item = projectSubAttributes(item, subs, keep); item != nil {
				out = append(out, item)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	if keep {
		return nil
	}
	return value
}
