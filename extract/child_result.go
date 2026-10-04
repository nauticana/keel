package extract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const childResultVersion = 1

// childResult is the child's stdout: one JSON object and nothing else.
type childResult struct {
	Version int `json:"version"`
	Extracted
}

// resultMax bounds the child's stdout: JSON escaping can grow text sixfold,
// and anything beyond that headroom is not a result of a maxBytes document.
func resultMax(maxBytes int64) int64 { return 8*maxBytes + 64<<10 }

func encodeResult(w io.Writer, e Extracted) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(childResult{Version: childResultVersion, Extracted: e})
}

func decodeResult(raw []byte) (Extracted, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r childResult
	if err := dec.Decode(&r); err != nil {
		return Extracted{}, fmt.Errorf("%w: decode child result: %w", ErrIsolationFailed, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Extracted{}, fmt.Errorf("%w: child result has trailing data", ErrIsolationFailed)
	}
	if r.Version != childResultVersion {
		return Extracted{}, fmt.Errorf("%w: child result version %d, want %d", ErrIsolationFailed, r.Version, childResultVersion)
	}
	for _, s := range r.Sections {
		if !validSection(s, len(r.Text)) {
			return Extracted{}, fmt.Errorf("%w: child result has an invalid section %+v", ErrIsolationFailed, s)
		}
	}
	return r.Extracted, nil
}

func validSection(s Section, textLen int) bool {
	switch s.Kind {
	case Heading, Paragraph, Table, Page:
	default:
		return false
	}
	return s.Level >= 0 && s.Level <= 9 && s.Page >= 0 && s.Start >= 0 && s.Start <= s.End && s.End <= textLen
}
