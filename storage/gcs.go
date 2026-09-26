package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nauticana/keel/secret"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// StorageGCS is the Google Cloud Storage adapter.
//
// Signed-URL caveat: SignedURL requires the runtime to hold an RSA private key
// (a service-account JSON credential) OR iam.serviceAccountTokenCreator on its
// own service account so the SDK can call IAM SignBlob. On GKE / Cloud Run /
// Compute Engine with the default service account this works only if the SA
// has been granted that role on itself.
type StorageGCS struct {
	client *storage.Client
	bucket *storage.BucketHandle
	name   string
}

func NewStorageGCS(ctx context.Context, spec Spec, secrets secret.SecretProvider) (*StorageGCS, error) {
	client, err := newGCSClient(ctx, spec, secrets)
	if err != nil {
		return nil, err
	}
	bucket := client.Bucket(spec.Bucket)
	if err := probeGCSBucket(ctx, bucket); err != nil {
		client.Close()
		return nil, gcsErr("bucket", spec.Bucket, err)
	}
	return &StorageGCS{client: client, bucket: bucket, name: spec.Bucket}, nil
}

// probeGCSBucket verifies the bucket with an object listing, which needs only
// storage.objects.list (roles/storage.objectViewer); bucket.Attrs would need
// storage.buckets.get, which object-only service accounts lack.
func probeGCSBucket(ctx context.Context, bucket *storage.BucketHandle) error {
	query := &storage.Query{}
	if err := query.SetAttrSelection([]string{"Name"}); err != nil {
		return err
	}
	_, err := bucket.Objects(ctx, query).Next()
	if errors.Is(err, iterator.Done) {
		return nil
	}
	if gcsCode(err) == http.StatusNotFound {
		return storage.ErrBucketNotExist
	}
	return err
}

func newGCSClient(ctx context.Context, spec Spec, secrets secret.SecretProvider) (*storage.Client, error) {
	value, err := spec.credential(ctx, secrets)
	if err != nil {
		return nil, err
	}
	var opts []option.ClientOption
	if value != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(value)))
	}
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}
	return client, nil
}

func createBucketGCS(ctx context.Context, spec Spec, secrets secret.SecretProvider) error {
	if spec.Project == "" {
		return fmt.Errorf("gcs: create bucket %s: Spec.Project is required", spec.Bucket)
	}
	client, err := newGCSClient(ctx, spec, secrets)
	if err != nil {
		return err
	}
	defer client.Close()
	err = client.Bucket(spec.Bucket).Create(ctx, spec.Project, &storage.BucketAttrs{Location: spec.Region})
	if err != nil && gcsCode(err) != http.StatusConflict {
		return fmt.Errorf("gcs: create bucket %s: %w", spec.Bucket, err)
	}
	return nil
}

func (s *StorageGCS) Bucket() string { return s.name }

// PublicURL returns https://storage.googleapis.com/<bucket>/<key>. Keys are
// emitted as-is (object names may contain "/"); a leading "/" is trimmed.
func (s *StorageGCS) PublicURL(key string) string {
	return "https://storage.googleapis.com/" + s.name + "/" + strings.TrimLeft(key, "/")
}

// Close releases the GCS client. Idempotent.
func (s *StorageGCS) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

func gcsCode(err error) int {
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return 0
}

func gcsErr(op, key string, err error) error {
	switch {
	case errors.Is(err, storage.ErrObjectNotExist):
		return fmt.Errorf("gcs: %s %s: %w", op, key, ErrNotFound)
	case errors.Is(err, storage.ErrBucketNotExist):
		return fmt.Errorf("gcs: %s %s: %w", op, key, ErrBucketNotFound)
	}
	return fmt.Errorf("gcs: %s %s: %w", op, key, err)
}

func (s *StorageGCS) write(ctx context.Context, obj *storage.ObjectHandle, data io.Reader, contentType string, attributes map[string]string) error {
	// Close commits whatever was written; only a cancelled context aborts.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := obj.NewWriter(ctx)
	w.ContentType = contentType
	w.Metadata = attributes
	if _, err := io.Copy(w, data); err != nil {
		cancel()
		_ = w.Close()
		return err
	}
	return w.Close()
}

func (s *StorageGCS) PutObject(ctx context.Context, key string, data io.Reader, contentType string, attributes map[string]string) error {
	if err := s.write(ctx, s.bucket.Object(key), data, contentType, attributes); err != nil {
		return gcsErr("put", key, err)
	}
	return nil
}

func (s *StorageGCS) PutObjectIfAbsent(ctx context.Context, key string, data io.Reader, contentType string, attributes map[string]string) error {
	err := s.write(ctx, s.bucket.Object(key).If(storage.Conditions{DoesNotExist: true}), data, contentType, attributes)
	if err != nil && gcsCode(err) == http.StatusPreconditionFailed {
		return fmt.Errorf("gcs: put %s: %w", key, ErrExists)
	}
	if err != nil {
		return gcsErr("put", key, err)
	}
	return nil
}

func (s *StorageGCS) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	r, err := s.bucket.Object(key).NewReader(ctx)
	if err != nil {
		return nil, gcsErr("get", key, err)
	}
	return r, nil
}

// GetObjectAndAttributes pins the read to the generation whose attributes it
// returned, so content and attributes always belong to the same write.
func (s *StorageGCS) GetObjectAndAttributes(ctx context.Context, key string) (*Component, error) {
	attrs, err := s.bucket.Object(key).Attrs(ctx)
	if err != nil {
		return nil, gcsErr("attrs", key, err)
	}
	r, err := s.bucket.Object(key).Generation(attrs.Generation).NewReader(ctx)
	if err != nil {
		return nil, gcsErr("get", key, err)
	}
	defer r.Close()
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, gcsErr("read", key, err)
	}
	return NewComponent(content, nonNil(attrs.Metadata)), nil
}

func (s *StorageGCS) DeleteObject(ctx context.Context, key string) error {
	if err := s.bucket.Object(key).Delete(ctx); err != nil {
		return gcsErr("delete", key, err)
	}
	return nil
}

func (s *StorageGCS) ListObjects(ctx context.Context, prefix string, limit int) ([]string, error) {
	return s.list(ctx, &storage.Query{Prefix: prefix}, limit, func(a *storage.ObjectAttrs) string { return a.Name })
}

func (s *StorageGCS) ListPrefixes(ctx context.Context, prefix string, limit int) ([]string, error) {
	return s.list(ctx, &storage.Query{Prefix: prefix, Delimiter: "/"}, limit, func(a *storage.ObjectAttrs) string {
		if a.Prefix == "" {
			return ""
		}
		return childName(prefix, a.Prefix)
	})
}

func (s *StorageGCS) list(ctx context.Context, query *storage.Query, limit int, name func(*storage.ObjectAttrs) string) ([]string, error) {
	if err := query.SetAttrSelection([]string{"Name"}); err != nil {
		return nil, gcsErr("list", query.Prefix, err)
	}
	var names []string
	it := s.bucket.Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return names, nil
		}
		if err != nil {
			return nil, gcsErr("list", query.Prefix, err)
		}
		if n := name(attrs); n != "" {
			names = append(names, n)
			if limit > 0 && len(names) == limit {
				return names, nil
			}
		}
	}
}

// SetObjectAttributes rewrites the object onto itself, conditional on the
// generation read just before: a metadata Update is a merge-patch and would
// keep keys absent from attributes.
func (s *StorageGCS) SetObjectAttributes(ctx context.Context, key string, attributes map[string]string) error {
	obj := s.bucket.Object(key)
	src, err := obj.Attrs(ctx)
	if err != nil {
		return gcsErr("attrs", key, err)
	}
	copier := obj.If(storage.Conditions{GenerationMatch: src.Generation}).CopierFrom(obj.Generation(src.Generation))
	copier.ContentType = src.ContentType
	copier.ContentEncoding = src.ContentEncoding
	copier.ContentLanguage = src.ContentLanguage
	copier.ContentDisposition = src.ContentDisposition
	copier.CacheControl = src.CacheControl
	copier.Metadata = attributes
	_, err = copier.Run(ctx)
	if err != nil && gcsCode(err) == http.StatusPreconditionFailed {
		return fmt.Errorf("gcs: set attributes %s: %w", key, ErrPreconditionFailed)
	}
	if err != nil {
		return gcsErr("set attributes", key, err)
	}
	return nil
}

func (s *StorageGCS) GetObjectAttributes(ctx context.Context, key string) (map[string]string, error) {
	attrs, err := s.bucket.Object(key).Attrs(ctx)
	if err != nil {
		return nil, gcsErr("attrs", key, err)
	}
	return nonNil(attrs.Metadata), nil
}

// GetSignedURL returns a V4-signed URL valid for expirySeconds. The runtime
// needs either a private key in the credentials JSON OR
// iam.serviceAccountTokenCreator on its own service account (IAM SignBlob).
func (s *StorageGCS) GetSignedURL(ctx context.Context, key string, expirySeconds int) (string, error) {
	url, err := s.bucket.SignedURL(key, &storage.SignedURLOptions{
		Method:  http.MethodGet,
		Expires: time.Now().Add(time.Duration(expirySeconds) * time.Second),
		Scheme:  storage.SigningSchemeV4,
	})
	if err != nil {
		return "", fmt.Errorf("gcs: sign URL for %s (runtime needs IAM SignBlob permission or a private key): %w", key, err)
	}
	return url, nil
}

var _ ObjectStorage = (*StorageGCS)(nil)
