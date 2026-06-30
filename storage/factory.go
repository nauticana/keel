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

// New constructs the ObjectStorage backend named by mode, mirroring the
// secret.NewSecretProvider factory pattern. Pass *common.StorageMode (the
// --storage_mode flag) as mode.
//
//	s3    — AWS S3, or any S3-compatible provider via --s3_endpoint
//	        (Cloudflare R2 = s3 + --s3_endpoint + path-style). Credentials
//	        resolve through the AWS SDK's own chain, or from the keystore when
//	        WithSecretProvider is passed.
//	gcs   — Google Cloud Storage; auth via Application Default Credentials.
//	azure — Azure Blob Storage; requires --storage_account_url; auth via
//	        azidentity.DefaultAzureCredential.
//
// An empty mode is treated as a configuration error: callers that want
// storage to be optional should check *common.StorageMode == "" themselves
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
		accountURL := strings.TrimSpace(*common.StorageAccountURL)
		if accountURL == "" {
			return nil, fmt.Errorf("storage: --storage_account_url is required when --storage_mode=azure")
		}
		return NewStorageAzure(accountURL)
	default:
		return nil, fmt.Errorf("unknown storage_mode: %q", mode)
	}
}
