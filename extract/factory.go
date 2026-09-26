package extract

import (
	"fmt"
	"strings"

	"github.com/nauticana/keel/config"
)

// New builds the extractor named by mode: native.
func New(mode string, maxBytes int64) (TextExtractor, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("extract: extract_max_bytes must be positive")
	}
	switch strings.TrimSpace(mode) {
	case "", "native":
		return Native{MaxBytes: maxBytes}, nil
	default:
		return nil, fmt.Errorf("extract: unknown extract_mode %q", mode)
	}
}

// NewFromConfig reads extract_mode and extract_max_bytes.
func NewFromConfig() (TextExtractor, error) {
	return New(config.Config().ExtractMode, config.Config().ExtractMaxBytes)
}
