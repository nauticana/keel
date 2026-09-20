// Package content reads and edits fields of existing objects on external
// content platforms. It owns the ports, provider selection, typed provider
// errors and provider transports; which logical fields exist, and where each
// lives on a provider, is injected by the app.
package content

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrUnsupportedProvider = errors.New("content: unsupported provider")
	ErrUnsupportedKind     = errors.New("content: unsupported resource kind")
	ErrUnsupportedField    = errors.New("content: unsupported field")
	// ErrResourceNotFound: the provider has no object with that id. Never
	// reported as an empty value, so callers cannot baseline an edit on "".
	ErrResourceNotFound = errors.New("content: resource not found on provider")
	// ErrAccessDenied: the provider refused the credential (401/403) — usually a
	// missing scope that needs re-authorization, not a retry.
	ErrAccessDenied = errors.New("content: provider denied access")
	// ErrThrottled: the provider rate-limited the request; retry later.
	ErrThrottled = errors.New("content: provider throttled the request")
	// ErrRejected: the provider understood the request and refused the change.
	ErrRejected = errors.New("content: provider rejected the request")
)

// ResourceRef addresses one object through one authorized connection.
type ResourceRef struct {
	Endpoint string // provider API base URL
	Token    string
	Kind     string
	ID       string // provider-native id
}

type WriteResult struct {
	Response string // raw provider response, for audit
}

// ResourceWriter edits one field of an existing object; one impl per provider.
type ResourceWriter interface {
	ReadField(ctx context.Context, ref ResourceRef, field string) (string, error)
	UpdateField(ctx context.Context, ref ResourceRef, field, value string) (WriteResult, error)
}

// FieldReader reads a live field through the partner's own connection.
type FieldReader interface {
	ReadField(ctx context.Context, partnerID int64, provider, kind, id, field string) (string, error)
}

// AccessResolver yields a usable token and API endpoint for a partner's active
// connection; connect.CredentialStoreDB implements it.
type AccessResolver interface {
	ResolveAccess(ctx context.Context, partnerID int64, provider string) (token, apiEndpoint string, err error)
}

// Writers is the provider → writer selection, assembled at composition time.
type Writers map[string]ResourceWriter

func (w Writers) For(provider string) (ResourceWriter, error) {
	if writer, ok := w[provider]; ok && writer != nil {
		return writer, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedProvider, provider)
}

// ConnectionFieldReader is the FieldReader over an AccessResolver and Writers.
type ConnectionFieldReader struct {
	access  AccessResolver
	writers Writers
}

var _ FieldReader = (*ConnectionFieldReader)(nil)

func NewConnectionFieldReader(access AccessResolver, writers Writers) (*ConnectionFieldReader, error) {
	if access == nil {
		return nil, errors.New("content: nil access resolver")
	}
	return &ConnectionFieldReader{access: access, writers: writers}, nil
}

func (r *ConnectionFieldReader) ReadField(ctx context.Context, partnerID int64, provider, kind, id, field string) (string, error) {
	writer, err := r.writers.For(provider)
	if err != nil {
		return "", err
	}
	token, endpoint, err := r.access.ResolveAccess(ctx, partnerID, provider)
	if err != nil {
		return "", fmt.Errorf("resolve %s access: %w", provider, err)
	}
	return writer.ReadField(ctx, ResourceRef{Endpoint: endpoint, Token: token, Kind: kind, ID: id}, field)
}
