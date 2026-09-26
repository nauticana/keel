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

func TestS3CredentialSecret(t *testing.T) {
	spec := Spec{CredentialSecret: "s3_docs"}
	value, err := spec.credential(context.Background(), fakeSecrets{vals: map[string]string{
		"s3_docs": `{"access_key_id": "AKIAEXAMPLE", "secret_access_key": "shhh-secret"}`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseS3Credentials(value)
	if err != nil || c.AccessKeyID != "AKIAEXAMPLE" || c.SecretAccessKey != "shhh-secret" {
		t.Fatalf("credentials: %+v %v", c, err)
	}
	if _, err := parseS3Credentials(`{"access_key_id": "only"}`); err == nil {
		t.Fatal("a half credential must be refused")
	}
}

func TestCredentialSecretFailsLoud(t *testing.T) {
	ctx := context.Background()
	if _, err := (Spec{CredentialSecret: "x"}).credential(ctx, fakeSecrets{vals: map[string]string{}}); err == nil {
		t.Fatal("expected a hard error when the secret is empty (no silent fall-through)")
	}
	if _, err := (Spec{CredentialSecret: "x"}).credential(ctx, fakeSecrets{err: errors.New("keystore unreachable")}); err == nil {
		t.Fatal("expected the secret-provider error to propagate")
	}
	if _, err := (Spec{CredentialSecret: "x"}).credential(ctx, nil); err == nil {
		t.Fatal("a secret name without a provider must fail")
	}
	if v, err := (Spec{}).credential(ctx, nil); err != nil || v != "" {
		t.Fatalf("no secret name means ambient chain: %q %v", v, err)
	}
}
