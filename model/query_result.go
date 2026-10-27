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

// Row returns row i, or ErrRowOutOfRange.
func (qr *QueryResult) Row(i int) (Row, error) {
	if qr == nil || i < 0 || i >= len(qr.Rows) {
		return Row{}, fmt.Errorf("%w: %d", ErrRowOutOfRange, i)
	}
	return Row{columns: qr.Columns, values: qr.Rows[i]}, nil
}

// Col returns the named column of row i converted by Coerce.
func (qr *QueryResult) Col[T any](i int, name string) (T, error) {
	r, err := qr.Row(i)
	if err != nil {
		var zero T
		return zero, err
	}
	return r.Get[T](name)
}

// Scan maps every row through into, stopping at the first error.
func (qr *QueryResult) Scan[T any](into func(Row) (T, error)) ([]T, error) {
	if qr == nil {
		return nil, nil
	}
	out := make([]T, len(qr.Rows))
	for i, values := range qr.Rows {
		var err error
		if out[i], err = into(Row{columns: qr.Columns, values: values}); err != nil {
			return nil, fmt.Errorf("row %d: %w", i, err)
		}
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
