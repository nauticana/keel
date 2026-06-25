package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// oauthRandToken returns a 256-bit random token as hex (codes, refresh tokens,
// client ids/secrets). A crypto/rand failure is surfaced — never return a
// predictable token.
func oauthRandToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// oauthHash is the sha256 hex of s — what we persist for codes, refresh tokens,
// and client secrets so the raw value never sits at rest.
func oauthHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func oauthStr(v any) string       { s, _ := v.(string); return s }
func oauthInt64(v any) int64      { n, _ := v.(int64); return n }
func joinSpace(s []string) string { return strings.Join(s, " ") }

// claimInt64 reads an integer JWT claim that may arrive as int64 (freshly built)
// or float64 (round-tripped through JSON).
func claimInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}

// PartnerFromClaims reads partner_id from a decoded JWT claim set (tolerating
// int64-vs-float64 from JSON). The bool reports whether a usable (non-zero) id
// was present, so callers can tell "no tenant" from "tenant 0".
func PartnerFromClaims(claims map[string]any) (int64, bool) {
	if claims == nil {
		return 0, false
	}
	id := claimInt64(claims["partner_id"])
	return id, id != 0
}

func splitSpace(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Fields(s)
}
