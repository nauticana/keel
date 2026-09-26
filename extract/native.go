package extract

import (
	"context"
	"fmt"
	"mime"
)

const (
	mediaPDF      = "application/pdf"
	mediaDOCX     = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	mediaPlain    = "text/plain"
	mediaMarkdown = "text/markdown"
)

// Native extracts text in pure Go: plain text, Markdown, DOCX and PDF text
// layers. MaxBytes caps each decompressed DOCX part and the extracted text,
// since a small compressed upload can expand without bound. Scanned pages
// have no text layer; an OCR provider handles those.
type Native struct {
	MaxBytes int64 // required
}

var _ TextExtractor = Native{}

func (Native) Supports(mediaType string) bool {
	switch baseType(mediaType) {
	case mediaPlain, mediaMarkdown, mediaDOCX, mediaPDF:
		return true
	}
	return false
}

func (n Native) Extract(ctx context.Context, mediaType string, raw []byte) (Extracted, error) {
	if n.MaxBytes <= 0 {
		return Extracted{}, fmt.Errorf("extract: Native.MaxBytes is required")
	}
	if err := ctx.Err(); err != nil {
		return Extracted{}, err
	}
	switch baseType(mediaType) {
	case mediaPlain, mediaMarkdown:
		if int64(len(raw)) > n.MaxBytes {
			return Extracted{}, ErrTooLarge
		}
		return extractPlain(raw, baseType(mediaType) == mediaMarkdown), nil
	case mediaDOCX:
		return extractDOCX(ctx, raw, n.MaxBytes)
	case mediaPDF:
		return extractPDF(ctx, raw, n.MaxBytes)
	}
	return Extracted{}, fmt.Errorf("%w: %s", ErrUnsupportedMediaType, mediaType)
}

func baseType(mediaType string) string {
	base, _, err := mime.ParseMediaType(mediaType)
	if err != nil {
		return mediaType
	}
	return base
}
