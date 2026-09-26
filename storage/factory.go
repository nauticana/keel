package storage

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/secret"
)

// NewFromConfig builds the storage_mode backend for bucket from the standard
// flags ((nil, nil) when disabled), keeping callers provider-agnostic.
func NewFromConfig(ctx context.Context, secrets secret.SecretProvider, bucket string) (ObjectStorage, error) {
	c := config.Config()
	mode := strings.TrimSpace(c.StorageMode)
	if mode == "" {
		return nil, nil
	}
	return New(ctx, Spec{
		Mode:             mode,
		Bucket:           bucket,
		Endpoint:         c.S3Endpoint,
		AccountURL:       c.StorageAccountURL,
		PublicBaseURL:    c.StoragePublicBaseURL,
		CredentialSecret: c.StorageCredentialSecret,
	}, secrets)
}

// New constructs the ObjectStorage backend the spec names, bound to its
// bucket. The bucket must already exist (ErrBucketNotFound otherwise); New
// never creates one, CreateBucket does.
//
//	s3    — AWS S3, or any S3-compatible provider via Endpoint (Cloudflare R2
//	        = s3 + Endpoint + path-style).
//	gcs   — Google Cloud Storage.
//	azure — Azure Blob Storage; requires AccountURL. Bucket is the container.
//	file  — local file system; Bucket is the root folder.
func New(ctx context.Context, spec Spec, secrets secret.SecretProvider) (ObjectStorage, error) {
	if strings.TrimSpace(spec.Bucket) == "" {
		return nil, fmt.Errorf("storage: a bucket is required for storage_mode=%s", spec.Mode)
	}
	switch spec.Mode {
	case "s3":
		return NewStorageS3(ctx, spec, secrets)
	case "gcs":
		return NewStorageGCS(ctx, spec, secrets)
	case "azure":
		return NewStorageAzure(ctx, spec, secrets)
	case "file":
		return NewStorageFile(spec)
	default:
		return nil, fmt.Errorf("unknown storage_mode: %q", spec.Mode)
	}
}

// CreateBucket creates the bucket the spec names; an administrative call kept
// apart from New. Creating one that exists is not an error.
func CreateBucket(ctx context.Context, spec Spec, secrets secret.SecretProvider) error {
	switch spec.Mode {
	case "s3":
		return createBucketS3(ctx, spec, secrets)
	case "gcs":
		return createBucketGCS(ctx, spec, secrets)
	case "azure":
		return createBucketAzure(ctx, spec, secrets)
	case "file":
		return createBucketFile(spec)
	default:
		return fmt.Errorf("unknown storage_mode: %q", spec.Mode)
	}
}
