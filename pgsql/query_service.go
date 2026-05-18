package pgsql

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

type QueryServicePgsql struct {
	Client      *pgxpool.Pool
	Queries     map[string]string
	IdGenerator port.BigintGenerator
}

func (s *QueryServicePgsql) Query(ctx context.Context, queryName string, args ...any) (*model.QueryResult, error) {
	sql := s.Queries[queryName]
	if sql == "" {
		return nil, fmt.Errorf("query not found: %s", queryName)
	}
	rows, err := s.Client.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to run query: %w", err)
	}
	defer rows.Close()

	fieldDescs := rows.FieldDescriptions()
	cols := make([]string, len(fieldDescs))
	for i, fd := range fieldDescs {
		cols[i] = fd.Name
	}

	var results [][]any
	for rows.Next() {
		columns := make([]any, len(cols))
		columnPointers := make([]any, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}
		if err := rows.Scan(columnPointers...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		row := make([]any, len(cols))
		for i := range cols {
			// normalizeValue strips pgx wrapper types (pgtype.Numeric,
			// pgtype.Date, pgtype.Timestamp[tz]) so callers consuming
			// the row via common.As* helpers get native Go primitives
			// (float64 / time.Time) instead of the -1 sentinel from
			// the unknown-type branch. See scan_normalize.go.
			row[i] = normalizeValue(*columnPointers[i].(*any))
		}
		results = append(results, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("query iteration: %w", err)
	}
	return &model.QueryResult{Columns: cols, Rows: results}, nil
}

func (s *QueryServicePgsql) GenID() int64 {
	return s.IdGenerator.NextID()
}
