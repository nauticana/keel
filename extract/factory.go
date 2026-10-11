package extract

import (
	"context"
	"fmt"
	"strings"

	"github.com/nauticana/keel/config"
)

// New builds the extractor named by mode: native, or gcp_vision, which is
// native with Cloud Vision OCR for PDF pages that have no text layer.
func New(ctx context.Context, mode string, maxBytes int64, ocrMaxPages int) (TextExtractor, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("extract: extract_max_bytes must be positive")
	}
	native := Native{MaxBytes: maxBytes}
	switch strings.TrimSpace(mode) {
	case "", "native":
		return native, nil
	case "gcp_vision":
		if ocrMaxPages < 0 {
			return nil, fmt.Errorf("extract: extract_ocr_max_pages must not be negative")
		}
		recognizer, err := NewVision(ctx)
		if err != nil {
			return nil, err
		}
		return OCR{Primary: native, Recognizer: recognizer, MaxBytes: maxBytes, MaxPages: ocrMaxPages}, nil
	default:
		return nil, fmt.Errorf("extract: unknown extract_mode %q", mode)
	}
}

// NewFromConfig reads extract_mode, extract_max_bytes and extract_ocr_max_pages.
func NewFromConfig(ctx context.Context) (TextExtractor, error) {
	c := config.Config()
	return New(ctx, c.ExtractMode, c.ExtractMaxBytes, c.ExtractOCRMaxPages)
}
