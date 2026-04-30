package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3-compatible endpoint overrides. Set S3_ENDPOINT to point the client at a
// non-AWS provider (Cloudflare R2, MinIO, Wasabi, Backblaze B2):
//
//	S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com   # Cloudflare R2
//	AWS_REGION=auto                                          # R2 doesn't use regions
//	AWS_ACCESS_KEY_ID=<r2 access key>
//	AWS_SECRET_ACCESS_KEY=<r2 secret>
//
// Leave S3_ENDPOINT unset to use the AWS S3 default endpoint resolution.
const envS3Endpoint = "S3_ENDPOINT"

// s3MultipartThreshold is the body size at which Upload switches from
// a single PutObject to the SDK's multipart Uploader. A single
// PutObject silently rejects bodies > 5 GiB, so callers expecting to
// upload large objects need the multipart path. Setting the threshold
// at 5 MiB matches AWS's recommended cut-over for most workloads.
const s3MultipartThreshold = 5 * 1024 * 1024

type StorageS3 struct {
	client        *s3.Client
	presignClient *s3.PresignClient
	uploader      *manager.Uploader
}

func NewStorageS3() (*StorageS3, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	opts := []func(*s3.Options){}
	if endpoint := os.Getenv(envS3Endpoint); endpoint != "" {
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			// R2 and most non-AWS providers require path-style addressing
			// because they don't vend virtual-hosted subdomain certificates.
			o.UsePathStyle = true
		})
	}
	client := s3.NewFromConfig(cfg, opts...)
	return &StorageS3{
		client:        client,
		presignClient: s3.NewPresignClient(client),
		uploader:      manager.NewUploader(client),
	}, nil
}

// Upload writes reader to the named (bucket, key). Always routes via
// the multipart Uploader (P1-29) so bodies larger than 5 GiB succeed
// — the previous single PutObject path would silently fail on those.
// For small bodies the Uploader still issues one PutObject request,
// so the perf cost on the common-case path is negligible.
func (s *StorageS3) Upload(ctx context.Context, bucket, key string, reader io.Reader, contentType string) error {
	_, err := s.uploader.Upload(ctx, &s3.PutObjectInput{
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
