package storage

import (
	"context"
	"errors"
	"io"
)

var (
	ErrNotFound           = errors.New("storage: object not found")
	ErrExists             = errors.New("storage: object already exists")
	ErrPreconditionFailed = errors.New("storage: object changed since it was read")
	ErrBucketNotFound     = errors.New("storage: bucket not found")
	ErrUnsupported        = errors.New("storage: operation not supported by this backend")
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
