package storage

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/common"
)

// New constructs the ObjectStorage backend named by mode, mirroring the
// secret.NewSecretProvider factory pattern. Pass *common.StorageMode (the
// --storage_mode flag) as mode.
//
//	s3    — AWS S3, or any S3-compatible provider via --s3_endpoint
//	        (Cloudflare R2 = s3 + --s3_endpoint + path-style). Credentials
//	        resolve through the AWS SDK's own chain.
//	gcs   — Google Cloud Storage; auth via Application Default Credentials.
//	azure — Azure Blob Storage; requires --storage_account_url; auth via
//	        azidentity.DefaultAzureCredential.
//
// An empty mode is treated as a configuration error: callers that want
// storage to be optional should check *common.StorageMode == "" themselves
// and skip wiring (AbstractWorker.Run does exactly this) rather than relying on
// a nil backend.
func New(ctx context.Context, mode string) (ObjectStorage, error) {
	switch mode {
	case "s3":
		return NewStorageS3()
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
