package extract

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

const (
	wordML  = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
	markupC = "http://schemas.openxmlformats.org/markup-compatibility/2006"
)

// extractDOCX reads word/document.xml; see docxWalker for what counts as text
// and docxStyles for how headings are recognised.
func extractDOCX(ctx context.Context, raw []byte, maxBytes int64) (Extracted, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return Extracted{}, fmt.Errorf("extract docx: %w", err)
	}
	styles, err := readStyles(zr, maxBytes)
	if err != nil {
		return Extracted{}, err
	}
	doc, err := openPart(zr, "word/document.xml", maxBytes)
	if err != nil {
		return Extracted{}, err
	}
	if doc == nil {
		return Extracted{}, fmt.Errorf("extract docx: word/document.xml missing")
	}
	defer doc.Close()
	w := newDocxWalker(styles, maxBytes)
	return w.walk(ctx, xml.NewDecoder(doc))
}

// capReader fails a read once more than max bytes were decompressed.
type capReader struct {
	r   io.Reader
	max int64
	n   int64
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if c.n += int64(n); c.n > c.max {
		return 0, ErrTooLarge
	}
	return n, err
}

func openPart(zr *zip.Reader, name string, maxBytes int64) (io.ReadCloser, error) {
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("extract docx: %s: %w", name, err)
		}
		return struct {
			io.Reader
			io.Closer
		}{&capReader{r: rc, max: maxBytes}, rc}, nil
	}
	return nil, nil
}

func attr(el xml.StartElement, local string) string {
	for _, a := range el.Attr {
		if a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

func docxErr(err error) error {
	if errors.Is(err, ErrTooLarge) {
		return ErrTooLarge
	}
	return fmt.Errorf("extract docx: %w", err)
}
