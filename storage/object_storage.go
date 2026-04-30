package storage

import (
	"context"
	"io"
)

type ObjectStorage interface {
	Upload(ctx context.Context, bucket, key string, reader io.Reader, contentType string) error
	Download(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, bucket, key string) error
	GetSignedURL(ctx context.Context, bucket, key string, expirySeconds int) (string, error)
}
