package secret

import (
	"context"
	"testing"
)

func TestSecretProviderForSettings(t *testing.T) {
	ctx := context.Background()
	p, err := NewSecretProviderFor(ctx, Settings{Mode: "local", Keystore: "/x/keys.json"})
	if local, ok := p.(*SecretProviderLocal); err != nil || !ok || local.Filename != "/x/keys.json" {
		t.Fatalf("local = %#v, %v", p, err)
	}
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent")
	if _, err := NewSecretProviderFor(ctx, Settings{Mode: "aws"}); err != nil {
		t.Fatalf("aws with no region must not fail: %v", err)
	}
	for _, s := range []Settings{{Mode: "vault"}, {Mode: "gsm"}, {Mode: "azure"}} {
		if _, err := NewSecretProviderFor(ctx, s); err == nil {
			t.Fatalf("%s with no location must fail", s.Mode)
		}
	}
}
