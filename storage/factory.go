package storage

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/secret"
)

// storageOptions collects the optional knobs passed to New.
type storageOptions struct {
	secrets secret.SecretProvider
}

// Option configures a storage backend at construction.
type Option func(*storageOptions)

// WithSecretProvider sources S3 credentials from the keystore ("s3_access_key_id"
// + "s3_secret_access_key") instead of the AWS SDK's ambient chain. Missing/empty
// secrets are a hard error (no silent fall-through). Omit it to keep the ambient
// chain (e.g. an IAM role).
func WithSecretProvider(sp secret.SecretProvider) Option {
	return func(o *storageOptions) { o.secrets = sp }
}

// NewFromConfig builds the storage_mode backend from the standard flags
// ((nil, nil) when disabled), keeping callers provider-agnostic. s3/R2 honors
// s3_credential_mode (chain = ambient AWS chain/IAM, secret = keystore); gcs and
// azure use their own ambient auth.
func NewFromConfig(ctx context.Context, secrets secret.SecretProvider) (ObjectStorage, error) {
	mode := strings.TrimSpace(common.Config().StorageMode)
	if mode == "" {
		return nil, nil
	}
	var opts []Option
	if mode == "s3" { // credential mode is S3-only; gcs/azure use their own ambient auth
		switch common.Config().S3CredentialMode {
		case "secret":
			if secrets == nil {
				return nil, fmt.Errorf("s3_credential_mode=secret requires a secret provider, got nil")
			}
			opts = append(opts, WithSecretProvider(secrets))
		case "chain":
			// ambient AWS credential chain / IAM role
		default:
			return nil, fmt.Errorf("invalid s3_credential_mode %q (want chain or secret)", common.Config().S3CredentialMode)
		}
	}
	return New(ctx, mode, opts...)
}

// New constructs the ObjectStorage backend named by mode, mirroring the
// secret.NewSecretProvider factory pattern. Pass common.Config().StorageMode (the
// storage_mode flag) as mode.
//
//	s3    — AWS S3, or any S3-compatible provider via s3_endpoint
//	        (Cloudflare R2 = s3 + s3_endpoint + path-style). Credentials
//	        resolve through the AWS SDK's own chain, or from the keystore when
//	        WithSecretProvider is passed.
//	gcs   — Google Cloud Storage; auth via Application Default Credentials.
//	azure — Azure Blob Storage; requires storage_account_url; auth via
//	        azidentity.DefaultAzureCredential.
//
// An empty mode is treated as a configuration error: callers that want
// storage to be optional should check common.Config().StorageMode == "" themselves
// and skip wiring (AbstractWorker.Run does exactly this) rather than relying on
// a nil backend.
func New(ctx context.Context, mode string, opts ...Option) (ObjectStorage, error) {
	o := &storageOptions{}
	for _, opt := range opts {
		opt(o)
	}
	switch mode {
	case "s3":
		return newStorageS3(ctx, o)
	case "gcs":
		return NewStorageGCS(ctx)
	case "azure":
		accountURL := strings.TrimSpace(common.Config().StorageAccountURL)
		if accountURL == "" {
			return nil, fmt.Errorf("storage: storage_account_url is required when storage_mode=azure")
		}
		return NewStorageAzure(accountURL)
	default:
		return nil, fmt.Errorf("unknown storage_mode: %q", mode)
	}
}
