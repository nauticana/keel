package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/nauticana/keel/secret"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// s3MultipartThreshold is the body size at which UploadObject switches from a
// single PutObject (which silently rejects bodies > 5 GiB) to multipart.
const s3MultipartThreshold = 5 * 1024 * 1024

type StorageS3 struct {
	client        *s3.Client
	presignClient *s3.PresignClient
	uploader      *transfermanager.Client
	bucket        string
	publicBaseURL string
}

// NewStorageS3 builds the S3 backend. Credentials come from spec.CredentialSecret
// or, when it is empty, the AWS SDK's ambient chain. Set spec.Endpoint for a
// non-AWS provider (R2, MinIO, Wasabi); it switches to path-style addressing
// because those providers don't vend virtual-hosted subdomain certificates.
func NewStorageS3(ctx context.Context, spec Spec, secrets secret.SecretProvider) (*StorageS3, error) {
	client, err := newS3Client(ctx, spec, secrets)
	if err != nil {
		return nil, err
	}
	if _, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &spec.Bucket}); err != nil {
		return nil, s3Err("head bucket", spec.Bucket, err)
	}
	uploader := transfermanager.New(client, func(o *transfermanager.Options) {
		o.MultipartUploadThreshold = s3MultipartThreshold
	})
	return &StorageS3{
		client:        client,
		presignClient: s3.NewPresignClient(client),
		uploader:      uploader,
		bucket:        spec.Bucket,
		publicBaseURL: strings.TrimRight(strings.TrimSpace(spec.PublicBaseURL), "/"),
	}, nil
}

func newS3Client(ctx context.Context, spec Spec, secrets secret.SecretProvider) (*s3.Client, error) {
	value, err := spec.credential(ctx, secrets)
	if err != nil {
		return nil, err
	}
	var loadOpts []func(*awsconfig.LoadOptions) error
	if value != "" {
		c, err := parseS3Credentials(value)
		if err != nil {
			return nil, err
		}
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)))
	}
	if region := strings.TrimSpace(spec.Region); region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("storage s3: load AWS config: %w", err)
	}
	var opts []func(*s3.Options)
	if endpoint := strings.TrimSpace(spec.Endpoint); endpoint != "" {
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = true
		})
	}
	return s3.NewFromConfig(cfg, opts...), nil
}

func createBucketS3(ctx context.Context, spec Spec, secrets secret.SecretProvider) error {
	client, err := newS3Client(ctx, spec, secrets)
	if err != nil {
		return err
	}
	input := &s3.CreateBucketInput{Bucket: &spec.Bucket}
	// us-east-1 is the API default and rejects an explicit constraint.
	if region := strings.TrimSpace(spec.Region); region != "" && region != "us-east-1" {
		input.CreateBucketConfiguration = &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(region),
		}
	}
	_, err = client.CreateBucket(ctx, input)
	var owned *types.BucketAlreadyOwnedByYou
	if err != nil && !errors.As(err, &owned) {
		return fmt.Errorf("s3: create bucket %s: %w", spec.Bucket, err)
	}
	return nil
}

func (s *StorageS3) Bucket() string { return s.bucket }

// PublicURL returns <PublicBaseURL>/<key>; the public base domain (R2 custom
// domain or *.r2.dev) already maps to the bucket. Returns "" when unset.
func (s *StorageS3) PublicURL(key string) string {
	if s.publicBaseURL == "" {
		return ""
	}
	return s.publicBaseURL + "/" + strings.TrimLeft(key, "/")
}

func s3Code(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

func s3Err(op, key string, err error) error {
	switch s3Code(err) {
	case "NoSuchKey", "NotFound":
		return fmt.Errorf("s3: %s %s: %w", op, key, ErrNotFound)
	case "NoSuchBucket":
		return fmt.Errorf("s3: %s %s: %w", op, key, ErrBucketNotFound)
	}
	return fmt.Errorf("s3: %s %s: %w", op, key, err)
}

func (s *StorageS3) put(ctx context.Context, key string, data io.Reader, contentType string, attributes map[string]string, ifNoneMatch *string) error {
	_, err := s.uploader.UploadObject(ctx, &transfermanager.UploadObjectInput{
		Bucket:      &s.bucket,
		Key:         &key,
		Body:        data,
		ContentType: &contentType,
		Metadata:    attributes,
		IfNoneMatch: ifNoneMatch,
	})
	return err
}

// PutObject writes data via the transfer manager, so bodies over
// s3MultipartThreshold use multipart instead of failing.
func (s *StorageS3) PutObject(ctx context.Context, key string, data io.Reader, contentType string, attributes map[string]string) error {
	if err := s.put(ctx, key, data, contentType, attributes, nil); err != nil {
		return s3Err("put", key, err)
	}
	return nil
}

func (s *StorageS3) PutObjectIfAbsent(ctx context.Context, key string, data io.Reader, contentType string, attributes map[string]string) error {
	err := s.put(ctx, key, data, contentType, attributes, aws.String("*"))
	if err != nil && s3Code(err) == "PreconditionFailed" {
		return fmt.Errorf("s3: put %s: %w", key, ErrExists)
	}
	if err != nil {
		return s3Err("put", key, err)
	}
	return nil
}

func (s *StorageS3) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return nil, s3Err("get", key, err)
	}
	return result.Body, nil
}

func (s *StorageS3) GetObjectAndAttributes(ctx context.Context, key string) (*Component, error) {
	result, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return nil, s3Err("get", key, err)
	}
	defer result.Body.Close()
	content, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, s3Err("read", key, err)
	}
	return NewComponent(content, nonNil(result.Metadata)), nil
}

func (s *StorageS3) DeleteObject(ctx context.Context, key string) error {
	if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key}); err != nil {
		return s3Err("delete", key, err)
	}
	return nil
}

func (s *StorageS3) ListObjects(ctx context.Context, prefix string, limit int) ([]string, error) {
	var keys []string
	input := &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix}
	if limit > 0 {
		input.MaxKeys = aws.Int32(int32(min(limit, 1000)))
	}
	paginator := s3.NewListObjectsV2Paginator(s.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, s3Err("list", prefix, err)
		}
		for _, obj := range page.Contents {
			keys = append(keys, *obj.Key)
			if limit > 0 && len(keys) == limit {
				return keys, nil
			}
		}
	}
	return keys, nil
}

func (s *StorageS3) ListPrefixes(ctx context.Context, prefix string, limit int) ([]string, error) {
	var names []string
	input := &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix, Delimiter: aws.String("/")}
	if limit > 0 {
		input.MaxKeys = aws.Int32(int32(min(limit, 1000)))
	}
	paginator := s3.NewListObjectsV2Paginator(s.client, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, s3Err("list", prefix, err)
		}
		for _, p := range page.CommonPrefixes {
			names = append(names, childName(prefix, *p.Prefix))
			if limit > 0 && len(names) == limit {
				return names, nil
			}
		}
	}
	return names, nil
}

// SetObjectAttributes copies the object onto itself, the only way S3 replaces
// metadata. The copy restates the HTTP headers, which S3 would otherwise reset,
// and is conditional on the ETag read just before.
func (s *StorageS3) SetObjectAttributes(ctx context.Context, key string, attributes map[string]string) error {
	head, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return s3Err("head", key, err)
	}
	source := url.PathEscape(s.bucket) + "/" + escapeKeyPath(key)
	_, err = s.client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:             &s.bucket,
		Key:                &key,
		CopySource:         &source,
		CopySourceIfMatch:  head.ETag,
		Metadata:           attributes,
		MetadataDirective:  types.MetadataDirectiveReplace,
		ContentType:        head.ContentType,
		CacheControl:       head.CacheControl,
		ContentDisposition: head.ContentDisposition,
		ContentEncoding:    head.ContentEncoding,
		ContentLanguage:    head.ContentLanguage,
	})
	if err != nil && s3Code(err) == "PreconditionFailed" {
		return fmt.Errorf("s3: set attributes %s: %w", key, ErrPreconditionFailed)
	}
	if err != nil {
		return s3Err("set attributes", key, err)
	}
	return nil
}

func (s *StorageS3) GetObjectAttributes(ctx context.Context, key string) (map[string]string, error) {
	head, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return nil, s3Err("head", key, err)
	}
	return nonNil(head.Metadata), nil
}

func (s *StorageS3) GetSignedURL(ctx context.Context, key string, expirySeconds int) (string, error) {
	result, err := s.presignClient.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key}, s3.WithPresignExpires(time.Duration(expirySeconds)*time.Second))
	if err != nil {
		return "", s3Err("sign URL", key, err)
	}
	return result.URL, nil
}

func escapeKeyPath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// childName reduces a provider common prefix ("<prefix>name/") to "name".
func childName(prefix, common string) string {
	return strings.TrimSuffix(strings.TrimPrefix(common, prefix), "/")
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

var _ ObjectStorage = (*StorageS3)(nil)
