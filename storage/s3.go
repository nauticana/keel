package storage

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nauticana/keel/common"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Keystore secret names for injected S3 credentials (see WithSecretProvider).
const (
	secretS3AccessKeyID     = "s3_access_key_id"
	secretS3SecretAccessKey = "s3_secret_access_key"
)

// S3-compatible endpoint overrides. Set s3_endpoint to point the client at a
// non-AWS provider (Cloudflare R2, MinIO, Wasabi, Backblaze B2):
//
//	s3_endpoint=https://<account>.r2.cloudflarestorage.com   # Cloudflare R2
//	AWS_REGION=auto                                            # R2 doesn't use regions
//	AWS_ACCESS_KEY_ID=<r2 access key>                          # via SDK credential chain
//	AWS_SECRET_ACCESS_KEY=<r2 secret>
//
// Leave s3_endpoint empty to use the AWS S3 default endpoint resolution.
// (Credentials still resolve via the AWS SDK's own chain — that is the SDK's
// concern, not a keel knob; only keel's own switches go through flags.)

// s3MultipartThreshold is the body size at which UploadObject switches from a
// single PutObject (which silently rejects bodies > 5 GiB) to multipart.
const s3MultipartThreshold = 5 * 1024 * 1024

type StorageS3 struct {
	client        *s3.Client
	presignClient *s3.PresignClient
	uploader      *transfermanager.Client

	// publicBaseURL is the public-read base for PublicURL, from
	// storage_public_base_url (an R2 custom domain or *.r2.dev host).
	// Empty disables PublicURL (returns ""). Trailing slash trimmed.
	publicBaseURL string
}

// NewStorageS3 builds the S3 backend using the AWS SDK's ambient credential
// chain. Prefer storage.New(ctx, "s3", storage.WithSecretProvider(sp)) to source
// credentials from the keystore instead.
func NewStorageS3() (*StorageS3, error) {
	return newStorageS3(context.Background(), &storageOptions{})
}

func newStorageS3(ctx context.Context, o *storageOptions) (*StorageS3, error) {
	cfg, err := loadS3Config(ctx, o)
	if err != nil {
		return nil, err
	}
	opts := []func(*s3.Options){}
	if endpoint := strings.TrimSpace(common.Config().S3Endpoint); endpoint != "" {
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			// R2 and most non-AWS providers require path-style addressing
			// because they don't vend virtual-hosted subdomain certificates.
			o.UsePathStyle = true
		})
	}
	client := s3.NewFromConfig(cfg, opts...)
	uploader := transfermanager.New(client, func(o *transfermanager.Options) {
		o.MultipartUploadThreshold = s3MultipartThreshold
	})
	return &StorageS3{
		client:        client,
		presignClient: s3.NewPresignClient(client),
		uploader:      uploader,
		publicBaseURL: strings.TrimRight(strings.TrimSpace(common.Config().StoragePublicBaseURL), "/"),
	}, nil
}

// loadS3Config builds the AWS config. With a secret provider (WithSecretProvider)
// it injects static credentials from the keystore and fails loudly if they are
// missing or empty; without one it falls back to the AWS SDK's ambient chain.
func loadS3Config(ctx context.Context, o *storageOptions) (aws.Config, error) {
	if o != nil && o.secrets != nil {
		id, err := o.secrets.GetSecret(ctx, secretS3AccessKeyID)
		if err != nil {
			return aws.Config{}, fmt.Errorf("storage s3: reading secret %q: %w", secretS3AccessKeyID, err)
		}
		key, err := o.secrets.GetSecret(ctx, secretS3SecretAccessKey)
		if err != nil {
			return aws.Config{}, fmt.Errorf("storage s3: reading secret %q: %w", secretS3SecretAccessKey, err)
		}
		if strings.TrimSpace(id) == "" || strings.TrimSpace(key) == "" {
			return aws.Config{}, fmt.Errorf("storage s3: credential injection requested but %q/%q are empty in the keystore", secretS3AccessKeyID, secretS3SecretAccessKey)
		}
		return config.LoadDefaultConfig(ctx,
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(id, key, "")))
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return aws.Config{}, fmt.Errorf("storage s3: load AWS config: %w", err)
	}
	return cfg, nil
}

// PublicURL returns <storage_public_base_url>/<key>. The bucket arg is
// ignored: the public base domain (R2 custom domain or *.r2.dev) already
// maps to a single bucket, matching how downstream projects serve media.
// Returns "" when storage_public_base_url is unset, so callers can treat
// an empty result as "no public URL configured".
func (s *StorageS3) PublicURL(bucket, key string) string {
	if s.publicBaseURL == "" {
		return ""
	}
	return s.publicBaseURL + "/" + strings.TrimLeft(key, "/")
}

// Upload writes reader to the named (bucket, key) via the transfer manager, so
// bodies over s3MultipartThreshold use multipart instead of failing.
func (s *StorageS3) Upload(ctx context.Context, bucket, key string, reader io.Reader, contentType string) error {
	_, err := s.uploader.UploadObject(ctx, &transfermanager.UploadObjectInput{
		Bucket:      &bucket,
		Key:         &key,
		Body:        reader,
		ContentType: &contentType,
	})
	if err != nil {
		return fmt.Errorf("s3: failed to upload %s/%s: %w", bucket, key, err)
	}
	return nil
}

func (s *StorageS3) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		return nil, fmt.Errorf("s3: failed to download %s/%s: %w", bucket, key, err)
	}
	return result.Body, nil
}

func (s *StorageS3) Delete(ctx context.Context, bucket, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		return fmt.Errorf("s3: failed to delete %s/%s: %w", bucket, key, err)
	}
	return nil
}

func (s *StorageS3) GetSignedURL(ctx context.Context, bucket, key string, expirySeconds int) (string, error) {
	result, err := s.presignClient.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key}, s3.WithPresignExpires(time.Duration(expirySeconds)*time.Second))
	if err != nil {
		return "", fmt.Errorf("s3: failed to sign URL for %s/%s: %w", bucket, key, err)
	}
	return result.URL, nil
}

var _ ObjectStorage = (*StorageS3)(nil)
