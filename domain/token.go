package domain

import (
	"crypto/subtle"
	"strings"

	"github.com/nauticana/keel/common"
)

// tokenMatches compares a presented token with the stored SHA-256 in constant time.
func tokenMatches(token, tokenHash string) bool {
	token = strings.TrimSpace(token)
	return token != "" && tokenHash != "" &&
		subtle.ConstantTimeCompare([]byte(common.Sha256Hex(token)), []byte(tokenHash)) == 1
}

// CoveredBy reports whether the normalized host name is parent or a subdomain of it.
func CoveredBy(name, parent string) bool {
	parent = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(parent)), ".")
	return parent != "" && (name == parent || strings.HasSuffix(name, "."+parent))
}
