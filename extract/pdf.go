package extract

import (
	"context"
	"errors"
	"fmt"

	"github.com/carlos7ags/folio/reader"
)

// pageText orders a page's text spans by position, like folio's
// LocationStrategy, but keeps invisible ones (render mode 3): that is how a
// scanned page carries its OCR text layer.
type pageText struct {
	reader.LocationStrategy
}

func (p *pageText) ProcessSpan(span reader.TextSpan) {
	span.Visible = true
	p.LocationStrategy.ProcessSpan(span)
}

// extractPDF reads each page's text layer into one page section; a page
// without one yields an empty section (see Extracted.EmptyPages). maxBytes
// bounds every decoded stream, their total, and the extracted text. Panics
// on malformed input become errors, and ctx is checked between pages.
func extractPDF(ctx context.Context, raw []byte, maxBytes int64) (out Extracted, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = Extracted{}, fmt.Errorf("extract pdf: malformed document: %v", r)
		}
	}()
	doc, err := reader.ParseWithOptions(raw, reader.ReadOptions{MemoryLimits: reader.MemoryLimits{
		MaxStreamSize: maxBytes,
		MaxTotalAlloc: maxBytes,
		MaxXrefSize:   maxBytes,
	}})
	if err != nil {
		return Extracted{}, pdfError(err)
	}
	var text []byte
	for i := 0; i < doc.PageCount(); i++ {
		if err := ctx.Err(); err != nil {
			return Extracted{}, err
		}
		page, err := doc.Page(i)
		if err != nil {
			return Extracted{}, pdfError(fmt.Errorf("page %d: %w", i+1, err))
		}
		content, err := page.ExtractTextWithStrategy(&pageText{})
		if err != nil {
			return Extracted{}, pdfError(fmt.Errorf("page %d: %w", i+1, err))
		}
		start := len(text)
		text = append(text, validUTF8(content)...)
		if int64(len(text)) > maxBytes {
			return Extracted{}, ErrTooLarge
		}
		out.Sections = append(out.Sections, Section{Kind: Page, Page: i + 1, Start: start, End: len(text)})
		text = append(text, '\f')
	}
	out.Text = string(text)
	return out, nil
}

func pdfError(err error) error {
	switch {
	case errors.Is(err, reader.ErrMemoryLimitExceeded):
		return fmt.Errorf("%w: %w", ErrTooLarge, err)
	case errors.Is(err, reader.ErrInvalidPassword), errors.Is(err, reader.ErrUnsupportedEncryption):
		return fmt.Errorf("%w: %w", ErrEncrypted, err)
	}
	return fmt.Errorf("extract pdf: %w", err)
}
