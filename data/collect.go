package data

import (
	"context"
	"errors"

	"github.com/nauticana/keel/port"
)

// ErrRowsUnsupported: the QueryService cannot stream typed rows.
var ErrRowsUnsupported = errors.New("data: query service does not implement port.RowQuerier")

// Collect runs a named query and scans each row into a T, reading cells in
// SELECT-list order straight into typed variables. Use it for hot queries;
// QueryResult stays the shape for small and ad-hoc ones.
func Collect[T any](ctx context.Context, qs port.QueryService, queryName string, scan func(port.RowScanner) (T, error), args ...any) ([]T, error) {
	q, ok := qs.(port.RowQuerier)
	if !ok {
		return nil, ErrRowsUnsupported
	}
	var out []T
	err := q.QueryEach(ctx, queryName, func(r port.RowScanner) error {
		v, err := scan(r)
		if err != nil {
			return err
		}
		out = append(out, v)
		return nil
	}, args...)
	if err != nil {
		return nil, err
	}
	return out, nil
}
