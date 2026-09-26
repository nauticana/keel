package extract

import (
	"context"
	"fmt"

	"github.com/razvandimescu/gopdf/pdf"
)

// extractPDF reads each page's text layer, line by line, into one page
// section; a page without one yields an empty section (see
// Extracted.EmptyPages). The parser decodes streams without a bound, so
// checkPDFStreams measures them first; panics on malformed input become
// errors, and ctx is checked between pages.
func extractPDF(ctx context.Context, raw []byte, maxBytes int64) (out Extracted, err error) {
	if err := checkPDFStreams(ctx, raw, maxBytes); err != nil {
		return Extracted{}, err
	}
	defer func() {
		if r := recover(); r != nil {
			out, err = Extracted{}, fmt.Errorf("extract pdf: malformed document: %v", r)
		}
	}()
	doc, err := pdf.OpenBytes(raw)
	if err != nil {
		return Extracted{}, fmt.Errorf("extract pdf: %w", err)
	}
	var text []byte
	for i := 0; i < doc.NumPages(); i++ {
		if err := ctx.Err(); err != nil {
			return Extracted{}, err
		}
		content, err := doc.Page(i).Text()
		if err != nil {
			return Extracted{}, fmt.Errorf("extract pdf: page %d: %w", i+1, err)
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
