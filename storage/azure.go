package storage

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/nauticana/keel/secret"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	azservice "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

type StorageAzure struct {
	client    *azblob.Client
	container *container.Client
	sharedKey *azblob.SharedKeyCredential // nil with the ambient Entra ID credential
	name      string
	url       string
}

// NewStorageAzure builds the Blob backend for spec.AccountURL. With
// spec.CredentialSecret the secret value is the account key and requests and
// SAS URLs are signed with it; without it azidentity.DefaultAzureCredential
// authenticates and SAS URLs use a user delegation key.
func NewStorageAzure(ctx context.Context, spec Spec, secrets secret.SecretProvider) (*StorageAzure, error) {
	client, sharedKey, err := newAzureClient(ctx, spec, secrets)
	if err != nil {
		return nil, err
	}
	containerClient := client.ServiceClient().NewContainerClient(spec.Bucket)
	if _, err := containerClient.GetProperties(ctx, nil); err != nil {
		return nil, azureErr("container", spec.Bucket, err)
	}
	return &StorageAzure{
		client:    client,
		container: containerClient,
		sharedKey: sharedKey,
		name:      spec.Bucket,
		url:       spec.AccountURL,
	}, nil
}

func newAzureClient(ctx context.Context, spec Spec, secrets secret.SecretProvider) (*azblob.Client, *azblob.SharedKeyCredential, error) {
	accountURL := strings.TrimSpace(spec.AccountURL)
	if accountURL == "" {
		return nil, nil, fmt.Errorf("storage: AccountURL is required when storage_mode=azure")
	}
	value, err := spec.credential(ctx, secrets)
	if err != nil {
		return nil, nil, err
	}
	if value != "" {
		account, err := azureAccountName(accountURL)
		if err != nil {
			return nil, nil, err
		}
		sharedKey, err := azblob.NewSharedKeyCredential(account, strings.TrimSpace(value))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create Azure shared key credential: %w", err)
		}
		client, err := azblob.NewClientWithSharedKeyCredential(accountURL, sharedKey, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create Azure blob client: %w", err)
		}
		return client, sharedKey, nil
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}
	client, err := azblob.NewClient(accountURL, cred, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Azure blob client: %w", err)
	}
	return client, nil, nil
}

// azureAccountName is the first host label of https://<account>.blob.core.windows.net/.
func azureAccountName(accountURL string) (string, error) {
	u, err := url.Parse(accountURL)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("storage azure: invalid AccountURL %q", accountURL)
	}
	name, _, _ := strings.Cut(u.Hostname(), ".")
	return name, nil
}

func createBucketAzure(ctx context.Context, spec Spec, secrets secret.SecretProvider) error {
	client, _, err := newAzureClient(ctx, spec, secrets)
	if err != nil {
		return err
	}
	_, err = client.CreateContainer(ctx, spec.Bucket, nil)
	if err != nil && !bloberror.HasCode(err, bloberror.ContainerAlreadyExists) {
		return fmt.Errorf("azure: create container %s: %w", spec.Bucket, err)
	}
	return nil
}

func (s *StorageAzure) Bucket() string { return s.name }

func azureErr(op, key string, err error) error {
	switch {
	case bloberror.HasCode(err, bloberror.BlobNotFound):
		return fmt.Errorf("azure: %s %s: %w", op, key, ErrNotFound)
	case bloberror.HasCode(err, bloberror.ContainerNotFound):
		return fmt.Errorf("azure: %s %s: %w", op, key, ErrBucketNotFound)
	}
	return fmt.Errorf("azure: %s %s: %w", op, key, err)
}

func toAzureMetadata(attrs map[string]string) map[string]*string {
	if attrs == nil {
		return nil
	}
	result := make(map[string]*string, len(attrs))
	for k, v := range attrs {
		result[k] = &v
	}
	return result
}

// fromAzureMetadata lowercases keys: Azure returns them with the first letter
// upcased.
func fromAzureMetadata(attrs map[string]*string) map[string]string {
	result := make(map[string]string, len(attrs))
	for k, v := range attrs {
		if v != nil {
			result[strings.ToLower(k)] = *v
		}
	}
	return result
}

func (s *StorageAzure) put(ctx context.Context, key string, data io.Reader, contentType string, attributes map[string]string, conditions *blob.AccessConditions) error {
	_, err := s.client.UploadStream(ctx, s.name, key, data, &azblob.UploadStreamOptions{
		HTTPHeaders:      &blob.HTTPHeaders{BlobContentType: &contentType},
		Metadata:         toAzureMetadata(attributes),
		AccessConditions: conditions,
	})
	return err
}

func (s *StorageAzure) PutObject(ctx context.Context, key string, data io.Reader, contentType string, attributes map[string]string) error {
	if err := s.put(ctx, key, data, contentType, attributes, nil); err != nil {
		return azureErr("put", key, err)
	}
	return nil
}

func (s *StorageAzure) PutObjectIfAbsent(ctx context.Context, key string, data io.Reader, contentType string, attributes map[string]string) error {
	err := s.put(ctx, key, data, contentType, attributes, &blob.AccessConditions{
		ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfNoneMatch: to(azcore.ETagAny)},
	})
	if err != nil && bloberror.HasCode(err, bloberror.BlobAlreadyExists, bloberror.ConditionNotMet) {
		return fmt.Errorf("azure: put %s: %w", key, ErrExists)
	}
	if err != nil {
		return azureErr("put", key, err)
	}
	return nil
}

func (s *StorageAzure) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := s.client.DownloadStream(ctx, s.name, key, nil)
	if err != nil {
		return nil, azureErr("get", key, err)
	}
	return resp.Body, nil
}

func (s *StorageAzure) GetObjectAndAttributes(ctx context.Context, key string) (*Component, error) {
	resp, err := s.client.DownloadStream(ctx, s.name, key, nil)
	if err != nil {
		return nil, azureErr("get", key, err)
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, azureErr("read", key, err)
	}
	return NewComponent(content, fromAzureMetadata(resp.Metadata)), nil
}

func (s *StorageAzure) DeleteObject(ctx context.Context, key string) error {
	if _, err := s.client.DeleteBlob(ctx, s.name, key, nil); err != nil {
		return azureErr("delete", key, err)
	}
	return nil
}

func azureMax(limit int) *int32 {
	if limit <= 0 {
		return nil
	}
	return to(int32(min(limit, 5000)))
}

func (s *StorageAzure) ListObjects(ctx context.Context, prefix string, limit int) ([]string, error) {
	var keys []string
	pager := s.client.NewListBlobsFlatPager(s.name, &azblob.ListBlobsFlatOptions{Prefix: &prefix, MaxResults: azureMax(limit)})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, azureErr("list", prefix, err)
		}
		for _, item := range page.Segment.BlobItems {
			keys = append(keys, *item.Name)
			if limit > 0 && len(keys) == limit {
				return keys, nil
			}
		}
	}
	return keys, nil
}

func (s *StorageAzure) ListPrefixes(ctx context.Context, prefix string, limit int) ([]string, error) {
	var names []string
	pager := s.container.NewListBlobsHierarchyPager("/", &container.ListBlobsHierarchyOptions{Prefix: &prefix, MaxResults: azureMax(limit)})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, azureErr("list", prefix, err)
		}
		for _, p := range page.Segment.BlobPrefixes {
			names = append(names, childName(prefix, *p.Name))
			if limit > 0 && len(names) == limit {
				return names, nil
			}
		}
	}
	return names, nil
}

// SetObjectAttributes replaces the metadata, conditional on the ETag read just
// before.
func (s *StorageAzure) SetObjectAttributes(ctx context.Context, key string, attributes map[string]string) error {
	client := s.container.NewBlobClient(key)
	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return azureErr("attributes", key, err)
	}
	_, err = client.SetMetadata(ctx, toAzureMetadata(attributes), &blob.SetMetadataOptions{
		AccessConditions: &blob.AccessConditions{ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: props.ETag}},
	})
	if err != nil && bloberror.HasCode(err, bloberror.ConditionNotMet) {
		return fmt.Errorf("azure: set attributes %s: %w", key, ErrPreconditionFailed)
	}
	if err != nil {
		return azureErr("set attributes", key, err)
	}
	return nil
}

func (s *StorageAzure) GetObjectAttributes(ctx context.Context, key string) (map[string]string, error) {
	props, err := s.container.NewBlobClient(key).GetProperties(ctx, nil)
	if err != nil {
		return nil, azureErr("attributes", key, err)
	}
	return fromAzureMetadata(props.Metadata), nil
}

// PublicURL returns <AccountURL>/<container>/<blob> with each path component
// escaped (blob names may contain "+", "?", " ", Unicode). It makes no API call.
func (s *StorageAzure) PublicURL(key string) string {
	return s.blobURL(key)
}

func (s *StorageAzure) blobURL(key string) string {
	return fmt.Sprintf("%s/%s/%s", strings.TrimRight(s.url, "/"), url.PathEscape(s.name), escapeKeyPath(key))
}

func (s *StorageAzure) GetSignedURL(ctx context.Context, key string, expirySeconds int) (string, error) {
	now := time.Now().UTC()
	expiry := now.Add(time.Duration(expirySeconds) * time.Second)
	values := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPS,
		StartTime:     now,
		ExpiryTime:    expiry,
		Permissions:   (&sas.BlobPermissions{Read: true}).String(),
		ContainerName: s.name,
		BlobName:      key,
	}
	var query sas.QueryParameters
	var err error
	if s.sharedKey != nil {
		query, err = values.SignWithSharedKey(s.sharedKey)
	} else {
		var udc *azservice.UserDelegationCredential
		udc, err = s.client.ServiceClient().GetUserDelegationCredential(ctx, azservice.KeyInfo{
			Start:  to(now.Format(sas.TimeFormat)),
			Expiry: to(expiry.Format(sas.TimeFormat)),
		}, nil)
		if err != nil {
			return "", fmt.Errorf("azure: failed to get delegation credential for %s: %w", key, err)
		}
		query, err = values.SignWithUserDelegation(udc)
	}
	if err != nil {
		return "", fmt.Errorf("azure: failed to sign URL for %s: %w", key, err)
	}
	return s.blobURL(key) + "?" + query.Encode(), nil
}

func to[T any](v T) *T { return &v }

var _ ObjectStorage = (*StorageAzure)(nil)
