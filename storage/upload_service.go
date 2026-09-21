package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"slices"
	"strings"
)

var (
	ErrContentTypeNotAllowed = errors.New("storage: content type not allowed")
	ErrObjectTooLarge        = errors.New("storage: object exceeds the size limit")
)

// UploadService validates an object before writing it and mints short-lived
// read URLs. The content type is sniffed from the bytes, never taken from the
// client.
type UploadService struct {
	Storage          ObjectStorage
	Bucket           string
	MaxBytes         int64
	ContentTypes     []string // allowed media types, e.g. "image/png"
	SignedURLSeconds int
}

// Upload writes r under key and returns the sniffed media type.
func (s *UploadService) Upload(ctx context.Context, key string, r io.Reader) (string, error) {
	if s.Storage == nil || s.MaxBytes <= 0 || len(s.ContentTypes) == 0 || s.Bucket == "" {
		return "", fmt.Errorf("storage: UploadService needs Storage, Bucket, MaxBytes and ContentTypes")
	}
	head := make([]byte, 512)
	n, err := io.ReadFull(r, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", fmt.Errorf("storage: read upload: %w", err)
	}
	head = head[:n]
	mediaType, _, err := mime.ParseMediaType(http.DetectContentType(head))
	if err != nil || !slices.Contains(s.ContentTypes, mediaType) {
		return "", fmt.Errorf("%w: %s", ErrContentTypeNotAllowed, mediaType)
	}
	body := &cappedReader{r: io.MultiReader(bytes.NewReader(head), r), remaining: s.MaxBytes}
	if err := s.Storage.Upload(ctx, s.Bucket, key, body, mediaType); err != nil {
		// Every backend aborts on a reader error, so nothing was written and an
		// object already at key is intact; deleting here would destroy it.
		if body.exceeded {
			return "", ErrObjectTooLarge
		}
		return "", fmt.Errorf("storage: upload %s: %w", key, err)
	}
	return mediaType, nil
}

func (s *UploadService) SignedURL(ctx context.Context, key string) (string, error) {
	if s.Storage == nil || s.Bucket == "" || s.SignedURLSeconds <= 0 {
		return "", fmt.Errorf("storage: Storage, Bucket and a positive SignedURLSeconds are required")
	}
	return s.Storage.GetSignedURL(ctx, s.Bucket, key, s.SignedURLSeconds)
}

type cappedReader struct {
	r         io.Reader
	remaining int64
	exceeded  bool
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	if c.remaining < 0 {
		c.exceeded = true
		return 0, ErrObjectTooLarge
	}
	return n, err
}

// SanitizeFilename reduces a client filename to a safe key segment.
func SanitizeFilename(name string) string {
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	var b strings.Builder
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
			b.WriteRune(c)
		default:
			b.WriteByte('_')
		}
	}
	clean := strings.TrimLeft(b.String(), ".")
	if clean == "" {
		return "file"
	}
	return clean
}
