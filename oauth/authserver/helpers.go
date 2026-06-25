package authserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// randToken returns a 256-bit random token as hex (codes, refresh tokens, client
// ids/secrets). A crypto/rand failure is surfaced — never return a predictable
// token.
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashToken is the sha256 hex of s — what we persist for codes, refresh tokens,
// and client secrets so the raw value never sits at rest.
func hashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func joinSpace(s []string) string { return strings.Join(s, " ") }

func splitSpace(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Fields(s)
}
