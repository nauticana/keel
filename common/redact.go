package common

import "regexp"

// redactionRules is the write-time redaction policy for durable operator-visible
// text (error texts, event details, request summaries): mask credentials and
// personal contact data before they reach a row, so retention policy is the
// only lifetime such values ever have.
var redactionRules = []struct {
	pattern *regexp.Regexp
	mask    string
}{
	{regexp.MustCompile(`(?i)\b(?:sk|rk)-[a-z0-9][a-z0-9-]{14,}`), "[redacted-key]"},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{20,}`), "[redacted-key]"},
	{regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]{16,}`), "bearer [redacted]"},
	{regexp.MustCompile(`\benc:v1:[A-Za-z0-9+/=]{8,}`), "[redacted-secret]"},
	{regexp.MustCompile(`\b[0-9A-Za-z._%+-]+@[0-9A-Za-z.-]+\.[A-Za-z]{2,}\b`), "[redacted-email]"},
	{regexp.MustCompile(`\b(?:\d{4}[ -]){3}\d{4}\b`), "[redacted-number]"},
	{regexp.MustCompile(`\+?\b\d{10,15}\b`), "[redacted-number]"},
}

// RedactForStorage applies the write-time redaction policy to one text value.
func RedactForStorage(text string) string {
	for _, rule := range redactionRules {
		text = rule.pattern.ReplaceAllString(text, rule.mask)
	}
	return text
}
