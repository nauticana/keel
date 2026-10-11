package extract

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// PageRecognizer reads the text of the given 1-based pages of a document,
// keyed by page number. A page it finds no text on may be omitted.
type PageRecognizer interface {
	RecognizePages(ctx context.Context, mediaType string, raw []byte, pages []int) (map[int]string, error)
}

// OCR extracts with Primary and sends only the PDF pages that have no text
// layer to Recognizer, splicing the recognized text into those page sections.
type OCR struct {
	Primary    TextExtractor
	Recognizer PageRecognizer
	MaxBytes   int64 // extract_max_bytes: the extracted text including recognized pages; required
	MaxPages   int   // extract_ocr_max_pages: the most pages recognized per document; zero means 100
}

const ocrMaxPages = 100

var _ TextExtractor = OCR{}

func (o OCR) Supports(mediaType string) bool { return o.Primary.Supports(mediaType) }

func (o OCR) Extract(ctx context.Context, mediaType string, raw []byte) (Extracted, error) {
	if o.Primary == nil || o.Recognizer == nil || o.MaxBytes <= 0 || o.MaxPages < 0 {
		return Extracted{}, errors.New("extract: OCR needs Primary, Recognizer, a positive MaxBytes and a non-negative MaxPages")
	}
	out, err := o.Primary.Extract(ctx, mediaType, raw)
	pages := out.EmptyPages()
	if err != nil || len(pages) == 0 || baseType(mediaType) != mediaPDF {
		return out, err
	}
	limit := o.MaxPages
	if limit == 0 {
		limit = ocrMaxPages
	}
	if len(pages) > limit {
		return Extracted{}, fmt.Errorf("%w: %d pages need OCR, the limit is %d", ErrTooLarge, len(pages), limit)
	}
	recognized, err := o.Recognizer.RecognizePages(ctx, baseType(mediaType), raw, pages)
	if err != nil {
		return Extracted{}, fmt.Errorf("extract: ocr: %w", err)
	}
	return splicePages(out, recognized, o.MaxBytes)
}

// splicePages fills empty page sections with recognized text and shifts every later offset.
func splicePages(in Extracted, recognized map[int]string, maxBytes int64) (Extracted, error) {
	var text strings.Builder
	out := Extracted{Sections: make([]Section, 0, len(in.Sections))}
	cursor := 0
	for _, s := range in.Sections {
		text.WriteString(in.Text[cursor:s.Start])
		start := text.Len()
		if s.Kind == Page && s.Start == s.End {
			text.WriteString(strings.ReplaceAll(validUTF8(recognized[s.Page]), "\f", "\n"))
		} else {
			text.WriteString(in.Text[s.Start:s.End])
		}
		if int64(text.Len()) > maxBytes {
			return Extracted{}, ErrTooLarge
		}
		cursor = s.End
		s.Start, s.End = start, text.Len()
		out.Sections = append(out.Sections, s)
	}
	text.WriteString(in.Text[cursor:])
	out.Text = text.String()
	return out, nil
}
