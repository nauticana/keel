// Package content reads, edits, creates and deletes objects on external content
// platforms, and puts files on them. It owns the ports, provider selection,
// typed provider errors and provider transports; which logical fields exist,
// where each lives on a provider, and which object to create with what content,
// are injected by the app.
package content

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
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
	// ErrUnsupportedOperation: the provider's writer does not implement the
	// operation (creating, deleting, uploading, listing or annotating images,
	// listing redirects) the caller asked for.
	ErrUnsupportedOperation = errors.New("content: operation unsupported by provider")
	// ErrMediaTooLarge: the upload exceeds the uploader's size cap.
	ErrMediaTooLarge = errors.New("content: media exceeds the size cap")
	// ErrInvalidValue: the value cannot be decoded into the field's ValueType;
	// nothing was sent.
	ErrInvalidValue = errors.New("content: value does not fit the field's type")
)

// ValueType is how a field's string value is decoded before it is sent, and
// how a read renders it: a non-string field reads back as JSON text, which
// its own decoder accepts, and null reads as "".
type ValueType int

const (
	ValueString ValueType = iota
	ValueBool             // strconv.ParseBool
	ValueList             // a JSON array of strings, or comma-separated; "" is an empty list
	ValueJSON             // any JSON document; "" is null
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

// ResourceCreator creates an object of ref.Kind from the same logical fields
// UpdateField writes. ref.ID is ignored on the way in; the returned ref carries
// the provider's own id, so the caller can edit or delete what it just made.
type ResourceCreator interface {
	Create(ctx context.Context, ref ResourceRef, fields map[string]string) (ResourceRef, WriteResult, error)
}

// ResourceDeleter removes the object ref addresses.
type ResourceDeleter interface {
	Delete(ctx context.Context, ref ResourceRef) (WriteResult, error)
}

// MediaUploader puts a file on the platform's own CDN and returns the URL to
// write into a field — storage puts bytes in our bucket, which is not what a CMS
// field wants. ref.Kind and ref.ID are unused; the connection is what matters.
type MediaUploader interface {
	Upload(ctx context.Context, ref ResourceRef, name, contentType string, r io.Reader) (url string, result WriteResult, err error)
}

// ResourceImage is one image a resource owns. URL is empty while the provider
// is still processing the file.
type ResourceImage struct {
	ID  string // provider-native id, the handle SetImageAlt takes
	URL string
	Alt string
}

// MediaLister lists the images a resource owns, e.g. a product's gallery.
type MediaLister interface {
	ListImages(ctx context.Context, ref ResourceRef) ([]ResourceImage, error)
}

// MediaAnnotator sets the alt text of one image the resource owns; an image
// that is not the resource's own is ErrResourceNotFound.
type MediaAnnotator interface {
	SetImageAlt(ctx context.Context, ref ResourceRef, imageID, alt string) (WriteResult, error)
}

// Redirect sends requests for Path, e.g. "/pages/old", to Target.
type Redirect struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Target string `json:"target"`
}

// RedirectLister lists the platform's URL redirects; ref.Kind and ref.ID are unused.
type RedirectLister interface {
	ListRedirects(ctx context.Context, ref ResourceRef) ([]Redirect, error)
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

// Creator, Deleter, Uploader, Lister, Annotator and RedirectLister select the provider's writer and report whether
// it carries that capability, so a caller never type-asserts on its own.
func (w Writers) Creator(provider string) (ResourceCreator, error) {
	return capability[ResourceCreator](w, provider, "create")
}

func (w Writers) Deleter(provider string) (ResourceDeleter, error) {
	return capability[ResourceDeleter](w, provider, "delete")
}

func (w Writers) Uploader(provider string) (MediaUploader, error) {
	return capability[MediaUploader](w, provider, "upload")
}

func (w Writers) Lister(provider string) (MediaLister, error) {
	return capability[MediaLister](w, provider, "list images")
}

func (w Writers) Annotator(provider string) (MediaAnnotator, error) {
	return capability[MediaAnnotator](w, provider, "annotate images")
}

func (w Writers) RedirectLister(provider string) (RedirectLister, error) {
	return capability[RedirectLister](w, provider, "list redirects")
}

func capability[T any](w Writers, provider, op string) (T, error) {
	var zero T
	writer, err := w.For(provider)
	if err != nil {
		return zero, err
	}
	able, ok := writer.(T)
	if !ok {
		return zero, fmt.Errorf("%w: %s cannot %s", ErrUnsupportedOperation, provider, op)
	}
	return able, nil
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

func (t ValueType) valid() bool { return t >= ValueString && t <= ValueJSON }

// decode turns a caller's string into the JSON value the field's input takes.
func (t ValueType) decode(value string) (any, error) {
	switch t {
	case ValueString:
		return value, nil
	case ValueBool:
		b, err := strconv.ParseBool(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not a boolean", ErrInvalidValue, value)
		}
		return b, nil
	case ValueList:
		trimmed := strings.TrimSpace(value)
		if strings.HasPrefix(trimmed, "[") {
			var items []string
			if err := json.Unmarshal([]byte(trimmed), &items); err != nil {
				return nil, fmt.Errorf("%w: list: %w", ErrInvalidValue, err)
			}
			return items, nil
		}
		items := []string{}
		for item := range strings.SplitSeq(trimmed, ",") {
			if item = strings.TrimSpace(item); item != "" {
				items = append(items, item)
			}
		}
		return items, nil
	case ValueJSON:
		if strings.TrimSpace(value) == "" {
			return nil, nil
		}
		dec := json.NewDecoder(strings.NewReader(value))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("%w: json: %w", ErrInvalidValue, err)
		}
		if _, err := dec.Token(); err != io.EOF {
			return nil, fmt.Errorf("%w: json: trailing data", ErrInvalidValue)
		}
		return v, nil
	}
	return nil, fmt.Errorf("%w: unknown value type %d", ErrInvalidValue, t)
}

// render is decode's inverse for a value the provider returned.
func (t ValueType) render(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	switch t {
	case ValueString:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", fmt.Errorf("content: field is not a string (map it with a ValueType): %w", err)
		}
		return s, nil
	case ValueBool:
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", fmt.Errorf("content: field is not a boolean: %w", err)
		}
	case ValueList:
		var value []string
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", fmt.Errorf("content: field is not a string list: %w", err)
		}
	case ValueJSON:
	default:
		return "", fmt.Errorf("content: unknown value type %d", t)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return "", err
	}
	return buf.String(), nil
}
