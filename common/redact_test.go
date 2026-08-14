package common

import (
	"strings"
	"testing"
)

func TestRedactForStorageMasksSensitiveClasses(t *testing.T) {
	cases := []struct {
		name, in, gone string
	}{
		{"anthropic key", "provider rejected key sk-ant-api03-abcdef1234567890", "sk-ant"},
		{"google key", "invalid key AIzaSyD4x9AbCdEfGhIjKlMnOpQrStUvWx", "AIza"},
		{"bearer token", "auth failed: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig", "eyJhbGci"},
		{"envelope ciphertext", "bad credential enc:v1:QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "QWxhZGRpbj"},
		{"email", "reply to john.doe@example.com failed", "john.doe@example.com"},
		{"formatted card", "card 4111 1111 1111 1111 declined", "4111 1111"},
		{"phone", "call +14085551212 for support", "14085551212"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactForStorage(tc.in)
			if strings.Contains(got, tc.gone) {
				t.Fatalf("RedactForStorage(%q) = %q; still contains %q", tc.in, got, tc.gone)
			}
			if !strings.Contains(got, "[redacted") && !strings.Contains(got, "bearer [redacted]") {
				t.Fatalf("RedactForStorage(%q) = %q; no mask inserted", tc.in, got)
			}
		})
	}
}

func TestRedactForStorageKeepsOrdinaryText(t *testing.T) {
	for _, in := range []string{
		"partner 42 agent type BL: no active published release",
		"score keyword 'louvered pergola' draft 17",
		"generate content (task \"Draft blog: pergola care\"): model timeout after 30s",
		"turn completed at 2026-08-13 12:00:00",
	} {
		if got := RedactForStorage(in); got != in {
			t.Fatalf("RedactForStorage(%q) = %q; ordinary text must pass through", in, got)
		}
	}
}
