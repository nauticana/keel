package client

import (
	"fmt"
	"strings"
)

// ParamExtraScopes is an AuthURL param naming scopes to request on top of the
// provider's configured set — incremental consent, so a feature needing a wider
// grant re-asks for it without re-running onboarding. Space- or comma-separated;
// the raw parameter is not stored in OAuth state.
const ParamExtraScopes = "extra_scopes"

const stateRequestedScopesKey = "_requested_scopes"

// ParseScopes splits a granted-scope string on either separator providers use
// (space per RFC 6749, comma on Shopify), preserving order and dropping repeats.
func ParseScopes(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(fields))
	seen := make(map[string]bool, len(fields))
	for _, f := range fields {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// JoinScopes renders scopes in the space-separated form stored on a connection.
func JoinScopes(scopes []string) string { return strings.Join(scopes, " ") }

// MissingScopes returns the required scopes absent from granted, in the order
// required lists them — what a re-consent must ask for.
func MissingScopes(granted, required []string) []string {
	have := make(map[string]bool, len(granted))
	for _, s := range granted {
		have[s] = true
	}
	var missing []string
	for _, s := range required {
		if s != "" && !have[s] {
			missing = append(missing, s)
		}
	}
	return missing
}

// mergeScopes appends the caller's extra scopes to the configured ones.
func mergeScopes(configured []string, extra string) []string {
	if extra == "" {
		return configured
	}
	return ParseScopes(JoinScopes(configured) + " " + extra)
}

// MissingScopeError is a grant narrower than the connection requires: the
// consent was partial or tampered with, and re-consent must ask for Missing.
type MissingScopeError struct {
	Provider string
	Missing  []string
}

func (e *MissingScopeError) Error() string {
	return fmt.Sprintf("%s did not grant required scope(s): %s", e.Provider, JoinScopes(e.Missing))
}

// stateExtras keeps the requested set so Callback can apply RFC 6749's rule
// that an omitted scope means the provider granted exactly that set.
func stateExtras(params map[string]string, requested []string) map[string]string {
	out := make(map[string]string, len(params)+1)
	for k, v := range params {
		if k != ParamExtraScopes {
			out[k] = v
		}
	}
	out[stateRequestedScopesKey] = JoinScopes(requested)
	return out
}
