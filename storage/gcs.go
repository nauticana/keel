package storage

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"cloud.google.com/go/storage"
)

// StorageGCS is the Google Cloud Storage adapter.
//
// Signed-URL caveat (P1-30): SignedURL requires the runtime to
// produce an RSA private key OR have iam.serviceAccountTokenCreator
// permission on its own service account so the SDK can call
// IAM SignBlob to sign the URL on its behalf. On GKE / Cloud Run /
// Compute Engine with the default service account this works only if
// the SA has been granted SAC on itself; without that the SignedURL
// call fails with a generic "private key is required" error. The
// GetSignedURL method below documents the requirement and surfaces
// a clearer error when the underlying SDK cannot sign.
type StorageGCS struct {
	client *storage.Client
}

func NewStorageGCS(ctx context.Context) (*StorageGCS, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}
	return &StorageGCS{client: client}, nil
}

// Close releases the GCS client. Idempotent.
func (s *StorageGCS) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

func (s *StorageGCS) Upload(ctx context.Context, bucket, key string, reader io.Reader, contentType string) error {
	w := s.client.Bucket(bucket).Object(key).NewWriter(ctx)
	w.ContentType = contentType
	if _, err := io.Copy(w, reader); err != nil {
		_ = w.Close()
		return fmt.Errorf("gcs: failed to upload %s/%s: %w", bucket, key, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("gcs: failed to finalize upload %s/%s: %w", bucket, key, err)
	}
	return nil
}

func (s *StorageGCS) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	r, err := s.client.Bucket(bucket).Object(key).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcs: failed to download %s/%s: %w", bucket, key, err)
	}
	return r, nil
}

func (s *StorageGCS) Delete(ctx context.Context, bucket, key string) error {
	if err := s.client.Bucket(bucket).Object(key).Delete(ctx); err != nil {
		return fmt.Errorf("gcs: failed to delete %s/%s: %w", bucket, key, err)
	}
	return nil
}

// GetSignedURL returns a V4-signed URL valid for expirySeconds. The
// runtime needs either a private key in the credentials JSON OR
// iam.serviceAccountTokenCreator on its own service account so the
// SDK can call IAM SignBlob.
func (s *StorageGCS) GetSignedURL(ctx context.Context, bucket, key string, expirySeconds int) (string, error) {
	url, err := s.client.Bucket(bucket).SignedURL(key, &storage.SignedURLOptions{
		Method:  http.MethodGet,
		Expires: time.Now().Add(time.Duration(expirySeconds) * time.Second),
		Scheme:  storage.SigningSchemeV4,
	})
	if err != nil {
		return "", fmt.Errorf("gcs: sign URL for %s/%s (runtime needs IAM SignBlob permission or a private key): %w", bucket, key, err)
	}
	return url, nil
}
