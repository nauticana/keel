package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// MaxSignedURLSeconds is the providers' ceiling: S3 and GCS V4 signatures and
// Azure user delegation keys last at most 7 days.
const MaxSignedURLSeconds = 7 * 24 * 60 * 60

// signedURLExpiry validates expirySeconds and returns it as a duration.
func signedURLExpiry(expirySeconds int) (time.Duration, error) {
	if expirySeconds < 1 || expirySeconds > MaxSignedURLSeconds {
		return 0, fmt.Errorf("%w: %d seconds", ErrInvalidExpiry, expirySeconds)
	}
	return time.Duration(expirySeconds) * time.Second, nil
}

var (
	ErrNotFound           = errors.New("storage: object not found")
	ErrExists             = errors.New("storage: object already exists")
	ErrPreconditionFailed = errors.New("storage: object changed since it was read")
	ErrBucketNotFound     = errors.New("storage: bucket not found")
	ErrUnsupported        = errors.New("storage: operation not supported by this backend")
	ErrEmptyPrefix        = errors.New("storage: refusing to delete under an empty prefix")
	ErrInvalidKey         = errors.New("storage: invalid object key")
	ErrInvalidExpiry      = errors.New("storage: signed URL expiry must be 1 second to 7 days")
)

// ObjectStorage is one bucket (container, or root folder for the file backend).
// Keys are provider-neutral "/"-separated paths. Missing objects wrap
// ErrNotFound. An app that writes several buckets holds one instance per bucket.
type ObjectStorage interface {
	Bucket() string
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, data io.Reader, contentType string, attributes map[string]string) error
	// PutObjectIfAbsent writes only when no object is at key, wrapping
	// ErrExists otherwise; the check and the write are one provider call.
	PutObjectIfAbsent(ctx context.Context, key string, data io.Reader, contentType string, attributes map[string]string) error
	DeleteObject(ctx context.Context, key string) error
	// ListObjects returns up to limit keys that start with prefix; 0 means all.
	ListObjects(ctx context.Context, prefix string, limit int) ([]string, error)
	// ListPrefixes returns the names between prefix and the next "/" (the
	// immediate child folders), without the prefix and without a trailing "/".
	ListPrefixes(ctx context.Context, prefix string, limit int) ([]string, error)
	// SetObjectAttributes replaces all attributes of the object, wrapping
	// ErrPreconditionFailed when the object changed while it was being updated.
	SetObjectAttributes(ctx context.Context, key string, attributes map[string]string) error
	GetObjectAttributes(ctx context.Context, key string) (map[string]string, error)
	GetObjectAndAttributes(ctx context.Context, key string) (*Component, error)
	// GetSignedURL refuses an expiry outside 1..MaxSignedURLSeconds with ErrInvalidExpiry.
	GetSignedURL(ctx context.Context, key string, expirySeconds int) (string, error)

	// PublicURL returns the stable, non-expiring URL at which an object is
	// served when the bucket is publicly readable. It makes no API call and
	// grants no access.
	//
	//   - GCS      → https://storage.googleapis.com/<bucket>/<key>
	//   - S3/R2    → <PublicBaseURL>/<key> ("" when unset)
	//   - Azure    → <AccountURL>/<container>/<key>
	//   - file     → always ""
	PublicURL(key string) string
}
