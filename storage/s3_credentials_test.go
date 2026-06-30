package storage

import (
	"context"
	"errors"
	"testing"
)

type fakeSecrets struct {
	vals map[string]string
	err  error
}

func (f fakeSecrets) GetSecret(_ context.Context, path string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.vals[path], nil
}

func TestLoadS3Config_InjectedStaticCredentials(t *testing.T) {
	cfg, err := loadS3Config(context.Background(), &storageOptions{secrets: fakeSecrets{vals: map[string]string{
		secretS3AccessKeyID:     "AKIAEXAMPLE",
		secretS3SecretAccessKey: "shhh-secret",
	}}})
	if err != nil {
		t.Fatalf("loadS3Config: %v", err)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve credentials: %v", err)
	}
	if creds.AccessKeyID != "AKIAEXAMPLE" || creds.SecretAccessKey != "shhh-secret" {
		t.Fatalf("credentials not injected from keystore: %+v", creds)
	}
}

func TestLoadS3Config_EmptySecretsFailLoud(t *testing.T) {
	_, err := loadS3Config(context.Background(), &storageOptions{secrets: fakeSecrets{vals: map[string]string{}}})
	if err == nil {
		t.Fatal("expected a hard error when injected credentials are empty (no silent env fall-through)")
	}
}

func TestLoadS3Config_SecretProviderErrorPropagates(t *testing.T) {
	_, err := loadS3Config(context.Background(), &storageOptions{secrets: fakeSecrets{err: errors.New("keystore unreachable")}})
	if err == nil {
		t.Fatal("expected the secret-provider error to propagate, not be swallowed")
	}
}
