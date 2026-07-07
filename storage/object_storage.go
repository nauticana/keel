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

	// PublicURL returns the stable, non-expiring URL at which an object is
	// served when the bucket is publicly readable. Unlike GetSignedURL it
	// performs no signing and makes no API call — it is pure string
	// construction, safe to call on hot paths and to persist in a DB row.
	//
	//   - GCS  → https://storage.googleapis.com/<bucket>/<key>
	//   - S3/R2→ <storage_public_base_url>/<key> (the public base domain —
	//            an R2 custom domain or *.r2.dev host — already maps to the
	//            bucket, so the bucket arg is not part of the path). Returns
	//            "" when storage_public_base_url is unset.
	//   - Azure→ <account-url>/<bucket>/<key>
	//
	// The returned URL is only reachable if the bucket/object is actually
	// configured for public read; PublicURL does not grant that access.
	PublicURL(bucket, key string) string
}
