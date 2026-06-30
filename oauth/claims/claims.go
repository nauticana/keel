// Package claims extracts a keel Principal and individual values from a decoded
// JWT claim set — the logic shared between the local-AS validator
// (authserver.LocalValidator) and the JWKS resource-server validator
// (resource.JWTValidator).
package claims

import (
	"fmt"
	"strings"

	"github.com/nauticana/keel/port"
)

// Principal builds a keel Principal from decoded JWT claims; a sub is required.
func Principal(m map[string]any) (*port.Principal, error) {
	sub, _ := m["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("oauth: token missing sub claim")
	}
	iss, _ := m["iss"].(string)
	return &port.Principal{
		Subject:  sub,
		Issuer:   iss,
		Audience: Audience(m["aud"]),
		Scopes:   Scopes(m),
		Claims:   m,
	}, nil
}

// Scopes reads OAuth scopes from the space-delimited `scope` string (RFC 8693) or
// the `scp` claim, which Entra emits as a space-delimited string and some IdPs as
// an array.
func Scopes(m map[string]any) []string {
	if s, ok := m["scope"].(string); ok && s != "" {
		return strings.Fields(s)
	}
	switch v := m["scp"].(type) {
	case string:
		if v != "" {
			return strings.Fields(v)
		}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Audience reads the `aud` claim, which may arrive as a string or an array.
func Audience(raw any) []string {
	switch a := raw.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, v := range a {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Int64 reads an integer JWT claim that may arrive as int64 (freshly built) or
// float64 (round-tripped through JSON).
func Int64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}

// PartnerID reads partner_id from a decoded JWT claim set (tolerating
// int64-vs-float64 from JSON). The bool reports whether a usable (non-zero) id
// was present, so callers can tell "no tenant" from "tenant 0".
func PartnerID(m map[string]any) (int64, bool) {
	if m == nil {
		return 0, false
	}
	id := Int64(m["partner_id"])
	return id, id != 0
}
