package common

import (
	"regexp"
	"strings"
	"unicode"
)

type redactionRule struct {
	pattern *regexp.Regexp
	mask    string
}

// credentialRules mask secrets; contactRules mask personal contact data.
// RedactForStorage applies both before operator-visible text reaches a row.
var (
	credentialRules = []redactionRule{
		{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`), "[redacted-key]"},
		{regexp.MustCompile(`(?i)\b(?:sk|rk)-[a-z0-9][a-z0-9-]{14,}`), "[redacted-key]"},
		{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{20,}`), "[redacted-key]"},
		{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), "[redacted-key]"},
		{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+`), "[redacted-token]"},
		{regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]{16,}`), "bearer [redacted]"},
		{regexp.MustCompile(`\benc:v1:[A-Za-z0-9+/=]{8,}`), "[redacted-secret]"},
		{regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+@`), "${1}[redacted]@"},
		{regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[_-]?key|authorization|client[_-]?secret)\s*[=:]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`), "${1}[redacted]"},
		{regexp.MustCompile(`(?i)((?:authorization)\s*[=:]\s*)(?:[a-z][a-z0-9_-]*\s+)?[^"\\\s,;]+`), "${1}[redacted]"},
		{regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[_-]?key|authorization|client[_-]?secret)\s*[=:]\s*)[^"\\\s,;]+`), "${1}[redacted]"},
	}
	contactRules = []redactionRule{
		{regexp.MustCompile(`\b[0-9A-Za-z._%+-]+@[0-9A-Za-z.-]+\.[A-Za-z]{2,}\b`), "[redacted-email]"},
		{regexp.MustCompile(`\b(?:\d{4}[ -]){3}\d{4}\b`), "[redacted-number]"},
		{regexp.MustCompile(`\+?\b\d{10,15}\b`), "[redacted-number]"},
	}
	opaqueRun = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)
)

// RedactForStorage applies the write-time redaction policy to one text value.
func RedactForStorage(text string) string {
	for _, rules := range [][]redactionRule{credentialRules, contactRules} {
		for _, rule := range rules {
			text = rule.pattern.ReplaceAllString(text, rule.mask)
		}
	}
	return text
}

// LooksLikeCredential reports whether text holds a credential RedactForStorage
// masks, or a run of 32 or more key characters mixing upper case, lower case
// and digits. Email addresses and phone numbers are not credentials.
func LooksLikeCredential(text string) bool {
	for _, rule := range credentialRules {
		if rule.pattern.MatchString(text) {
			return true
		}
	}
	for _, run := range opaqueRun.FindAllString(text, -1) {
		if strings.ContainsFunc(run, unicode.IsUpper) && strings.ContainsFunc(run, unicode.IsLower) && strings.ContainsFunc(run, unicode.IsDigit) {
			return true
		}
	}
	return false
}
