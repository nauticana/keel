package config

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrint_ListsSourcesAndMasksSensitiveValues(t *testing.T) {
	rows := ConfigRows{
		"same_as_default":          {Value: "300", Default: "300", Source: "node"},
		"session_timeout":          {Value: "600", Default: "300", Source: "shared"},
		"apns_key_secret":          {Value: "apns_key", Default: "apns_key", Source: "default"},
		"smtp_password":            {Value: "hunter2", Default: "", Source: "node"},
		"oauth_signing_key_secret": {Value: "oauth_key", Default: "oauth_key", Source: "default"},
	}
	var out bytes.Buffer
	if err := Print(&out, rows); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{
		"flags:\n", "config:\n",
		"same_as_default=300 (node, default 300)",
		"session_timeout=600 (shared, default 300)",
		"apns_key_secret=*** (default)",
		"smtp_password=*** (node)",
		"oauth_signing_key_secret=*** (default)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "hunter2") || strings.Contains(text, "oauth_key") {
		t.Fatal("sensitive value printed")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	for key, want := range map[string]bool{
		"db_password": true, "aws_credentials": true, "api_secret": true, "private_key": true,
		"secret_mode": false, "nats_creds_secret": true, "oauth_access_token_ttl": false, "db_user": false,
	} {
		if isSensitiveKey(key) != want {
			t.Errorf("%s: want %v", key, want)
		}
	}
}
