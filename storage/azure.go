package storage

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	azservice "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

type StorageAzure struct {
	client *azblob.Client
	url    string
}

func NewStorageAzure(accountURL string) (*StorageAzure, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}
	client, err := azblob.NewClient(accountURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure blob client: %w", err)
	}
	return &StorageAzure{client: client, url: accountURL}, nil
}

func (s *StorageAzure) Upload(ctx context.Context, bucket, key string, reader io.Reader, contentType string) error {
	_, err := s.client.UploadStream(ctx, bucket, key, reader, &azblob.UploadStreamOptions{
		HTTPHeaders: &blob.HTTPHeaders{BlobContentType: &contentType},
	})
	if err != nil {
		return fmt.Errorf("azure: failed to upload %s/%s: %w", bucket, key, err)
	}
	return nil
}

func (s *StorageAzure) Download(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	resp, err := s.client.DownloadStream(ctx, bucket, key, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: failed to download %s/%s: %w", bucket, key, err)
	}
	return resp.Body, nil
}

func (s *StorageAzure) Delete(ctx context.Context, bucket, key string) error {
	_, err := s.client.DeleteBlob(ctx, bucket, key, nil)
	if err != nil {
		return fmt.Errorf("azure: failed to delete %s/%s: %w", bucket, key, err)
	}
	return nil
}

func (s *StorageAzure) GetSignedURL(ctx context.Context, bucket, key string, expirySeconds int) (string, error) {
	now := time.Now().UTC()
	expiry := now.Add(time.Duration(expirySeconds) * time.Second)

	udc, err := s.client.ServiceClient().GetUserDelegationCredential(ctx, azservice.KeyInfo{
		Start:  to(now.Format(sas.TimeFormat)),
		Expiry: to(expiry.Format(sas.TimeFormat)),
	}, nil)
	if err != nil {
		return "", fmt.Errorf("azure: failed to get delegation credential for %s/%s: %w", bucket, key, err)
	}

	sasQuery, err := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPS,
		StartTime:     now,
		ExpiryTime:    expiry,
		Permissions:   (&sas.BlobPermissions{Read: true}).String(),
		ContainerName: bucket,
		BlobName:      key,
	}.SignWithUserDelegation(udc)
	if err != nil {
		return "", fmt.Errorf("azure: failed to sign URL for %s/%s: %w", bucket, key, err)
	}

	// URL-build the path components instead of string-concatenating.
	// Azure blob keys legitimately contain `+`, `?`, ` `, and Unicode
	// runes; without escaping, the resulting URL is malformed for any
	// of those (P1-31). url.PathEscape preserves `/` so virtual-
	// directory-style keys still resolve.
	base := strings.TrimRight(s.url, "/")
	return fmt.Sprintf("%s/%s/%s?%s",
		base,
		url.PathEscape(bucket),
		url.PathEscape(key),
		sasQuery.Encode()), nil
}

func to[T any](v T) *T { return &v }
