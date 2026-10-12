package model

import (
	"errors"
	"fmt"
	"strings"
)

// ErrColumnNotFound reports a column name absent from a QueryResult.
var ErrColumnNotFound = errors.New("column not found")

// QueryResult is the column-name-aware return shape of every QueryService.
// Rows is a positional slice (one entry per Columns position).
type QueryResult struct {
	Columns []string
	Rows    [][]any
}

// Indexes resolves column names to row positions once per result, so callers
// index rows directly. Every missing name is reported in one error.
func (qr *QueryResult) Indexes(names ...string) ([]int, error) {
	out := make([]int, len(names))
	var missing []string
	for i, name := range names {
		out[i] = -1
		if qr != nil {
			for j, col := range qr.Columns {
				if col == name {
					out[i] = j
					break
				}
			}
		}
		if out[i] < 0 {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrColumnNotFound, strings.Join(missing, ", "))
	}
	return out, nil
}

// AsMaps projects Rows into []map[string]any keyed by Columns, for JSON-encoding
// an ad-hoc query. Returns an empty slice (not nil) when there are no rows; each
// row is a fresh map.
func (qr *QueryResult) AsMaps() []map[string]any {
	if qr == nil || len(qr.Rows) == 0 {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0, len(qr.Rows))
	for _, row := range qr.Rows {
		m := make(map[string]any, len(qr.Columns))
		for i, col := range qr.Columns {
			if i >= len(row) {
				break
			}
			m[col] = row[i]
		}
		out = append(out, m)
	}
	return out
}
