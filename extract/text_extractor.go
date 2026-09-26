// Package extract turns document bytes into UTF-8 text with section offsets,
// behind one port so native parsers and OCR providers are interchangeable.
package extract

import (
	"context"
	"errors"
)

var (
	ErrUnsupportedMediaType = errors.New("extract: unsupported media type")
	ErrTooLarge             = errors.New("extract: document exceeds the size limit")
	ErrEncrypted            = errors.New("extract: encrypted PDFs are not extracted")
)

// Section kinds.
const (
	Heading   = "heading"
	Paragraph = "paragraph"
	Table     = "table"
	Page      = "page"
)

// Section is a byte range [Start, End) of Extracted.Text. Page is 1-based
// for page sections; Level is 1-9 for headings. A page section with
// Start == End is a page without a text layer (a scan), for an OCR fallback.
type Section struct {
	Kind  string
	Level int
	Page  int
	Start int
	End   int
}

type Extracted struct {
	Text     string
	Sections []Section
}

// EmptyPages returns the numbers of the pages that have no text layer.
func (e Extracted) EmptyPages() []int {
	var pages []int
	for _, s := range e.Sections {
		if s.Kind == Page && s.Start == s.End {
			pages = append(pages, s.Page)
		}
	}
	return pages
}

type TextExtractor interface {
	Supports(mediaType string) bool
	Extract(ctx context.Context, mediaType string, raw []byte) (Extracted, error)
}
