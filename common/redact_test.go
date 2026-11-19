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
		{"password assignment", `password=hunter2`, "hunter2"},
		{"api key assignment", `api_key: abc123`, "abc123"},
		{"token assignment", `token=xyz`, "xyz"},
		{"quoted credential assignment", `client_secret="two words"`, "two words"},
		{"authorization assignment", `Authorization: Bearer short-token`, "short-token"},
		{"basic authorization assignment", `Authorization: Basic dXNlcjpwYXNz`, "dXNlcjpwYXNz"},
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

func TestLooksLikeCredential(t *testing.T) {
	for _, in := range []string{
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
		"AKIAIOSFODNN7EXAMPLE",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJl",
		"postgres://app:s3cret@db.internal:5432/app",
		"sk-ant-api03-abcdef1234567890",
		"password=hunter2",
		"x9Kq2LmN8pR4tV7wY1zA3bC5dE6fG0hJ",
		"sk_live_abcdefghijklmn", "rk_live_51Habcdefgh", "sk_test_abcdefghij",
		"xoxb-123456789012-abcdefghij", "ghp_abcdefghijklmnopqrstuvwxyz",
		"github_pat_11ABCDEFG_abcdefghijklmno", "glpat-abcdefghijklmnopqrst",
		"ya29.a0AfH6SMBabcdefghijklmnop",
	} {
		if !LooksLikeCredential(in) {
			t.Errorf("LooksLikeCredential(%q) = false", in)
		}
	}
	for _, in := range []string{
		"jwt_secret", "db_password_name", "ops@example.com", "+14085551212",
		"https://vault.example.com/v1/secret", "postgres://db.internal:5432/app",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"0b5e8f9c-3d2a-4f6b-9c1e-7a8d2f4b6c0e",
		"sk-telecom-gateway-west.example.com", "sk-engineering-portal", "rk-prod-cluster-node1",
	} {
		if LooksLikeCredential(in) {
			t.Errorf("LooksLikeCredential(%q) = true", in)
		}
	}
}

func TestRedactForStorageMasksURLPassword(t *testing.T) {
	if got := RedactForStorage("dial postgres://app:s3cret@db:5432"); strings.Contains(got, "s3cret") || !strings.Contains(got, "postgres://app:") {
		t.Fatalf("got %q", got)
	}
}

func TestRedactForStorageMasksWholeKey(t *testing.T) {
	for _, in := range []string{
		"failed with sk-ant-api03-abcdef1234567890. Retrying",
		"key sk-proj-ab12_cd34_ef56_gh78 refused",
		"token ghp_abcdefghijklmnopqrstuvwxyz, sk_live_abcdefghijklmn",
	} {
		got := RedactForStorage(in)
		for _, leak := range []string{"abcdef", "cd34", "gh78"} {
			if strings.Contains(got, leak) {
				t.Errorf("RedactForStorage(%q) = %q", in, got)
			}
		}
	}
	if in := "host sk-telecom-gateway-west.example.com is down"; RedactForStorage(in) != in {
		t.Errorf("a host name was masked: %q", RedactForStorage(in))
	}
}
