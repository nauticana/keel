package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nauticana/keel/secret"
)

// Spec describes one bucket and how to reach it. CredentialSecret names a
// keystore secret whose value is provider-specific; empty means the
// provider's ambient credential chain.
//
//	s3    {"access_key_id": "…", "secret_access_key": "…", "session_token": "…"?}
//	gcs   the service-account JSON
//	azure the storage account key; the account name comes from AccountURL
//	file  none
type Spec struct {
	Mode             string // s3, gcs, azure or file
	Bucket           string // container for azure, root folder for file
	Project          string // GCS project that owns the bucket; CreateBucket only
	Region           string // S3 region or GCS location; empty defers to the provider
	Endpoint         string // S3-compatible endpoint (R2, MinIO); path-style addressing when set
	AccountURL       string // Azure Blob service endpoint
	PublicBaseURL    string // public-read base for PublicURL on s3
	CredentialSecret string
}

type s3Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

func (s Spec) credential(ctx context.Context, secrets secret.SecretProvider) (string, error) {
	if s.CredentialSecret == "" {
		return "", nil
	}
	if secrets == nil {
		return "", fmt.Errorf("storage: credential secret %q needs a secret provider", s.CredentialSecret)
	}
	value, err := secrets.GetSecret(ctx, s.CredentialSecret)
	if err != nil {
		return "", fmt.Errorf("storage: reading secret %q: %w", s.CredentialSecret, err)
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("storage: secret %q is empty", s.CredentialSecret)
	}
	return value, nil
}

func parseS3Credentials(value string) (s3Credentials, error) {
	var c s3Credentials
	if err := json.Unmarshal([]byte(value), &c); err != nil {
		return c, fmt.Errorf("storage s3: credential secret is not JSON: %w", err)
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return c, fmt.Errorf("storage s3: credential secret needs access_key_id and secret_access_key")
	}
	return c, nil
}
