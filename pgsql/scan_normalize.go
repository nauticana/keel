package pgsql

import (
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nauticana/keel/model"
)

// ErrNonFiniteNumeric rejects a NaN or infinite NUMERIC: no caller can use it
// as a number, and passing it on would corrupt arithmetic silently.
var ErrNonFiniteNumeric = errors.New("pgsql: non-finite NUMERIC value")

// scanResult drains rows into a QueryResult with one allocation per row.
func scanResult(rows pgx.Rows) (*model.QueryResult, error) {
	defer rows.Close()
	fieldDescs := rows.FieldDescriptions()
	cols := make([]string, len(fieldDescs))
	for i, fd := range fieldDescs {
		cols[i] = fd.Name
	}
	var results [][]any
	for rows.Next() {
		row, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query iteration: %w", err)
	}
	return &model.QueryResult{Columns: cols, Rows: results}, nil
}

// scanRow decodes the current row and normalizes it in place.
func scanRow(rows pgx.Rows) ([]any, error) {
	row, err := rows.Values()
	if err != nil {
		return nil, fmt.Errorf("failed to scan row: %w", err)
	}
	for i, v := range row {
		if row[i], err = normalizeValue(v); err != nil {
			return nil, fmt.Errorf("column %s: %w", rows.FieldDescriptions()[i].Name, err)
		}
	}
	return row, nil
}

// normalizeValue turns pgx wrapper types into the primitives common.As*
// recognizes: NUMERIC becomes float64, TIME a "HH:MM:SS" string, and a NULL
// wrapper nil.
func normalizeValue(v any) (any, error) {
	switch n := v.(type) {
	case pgtype.Numeric:
		if !n.Valid {
			return nil, nil
		}
		return numericFloat(n)
	case pgtype.Time:
		// time.Time would carry a bogus 0001-01-01 date.
		if !n.Valid {
			return nil, nil
		}
		sec := n.Microseconds / 1_000_000
		return fmt.Sprintf("%02d:%02d:%02d", sec/3600, (sec%3600)/60, sec%60), nil
	}
	return v, nil
}

func numericFloat(n pgtype.Numeric) (any, error) {
	if n.NaN || n.InfinityModifier != pgtype.Finite {
		return nil, ErrNonFiniteNumeric
	}
	f, err := n.Float64Value()
	if err != nil {
		return nil, err
	}
	if math.IsInf(f.Float64, 0) {
		return nil, ErrNonFiniteNumeric
	}
	return f.Float64, nil
}
