package pgsql

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// namedQuery runs a query of a named catalog on a pool or a transaction.
type namedQuery struct {
	conn    pgxQuerier
	queries map[string]string
}

func (q namedQuery) rows(ctx context.Context, name string, args []any) (pgx.Rows, error) {
	sql := q.queries[name]
	if sql == "" {
		return nil, fmt.Errorf("query not found: %s", name)
	}
	rows, err := q.conn.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to run query: %w", err)
	}
	return rows, nil
}

func (q namedQuery) result(ctx context.Context, name string, args []any) (*model.QueryResult, error) {
	rows, err := q.rows(ctx, name, args)
	if err != nil {
		return nil, err
	}
	return scanResult(rows)
}

// each hands every row to scan and always closes the rows.
func (q namedQuery) each(ctx context.Context, name string, scan func(port.RowScanner) error, args []any) error {
	rows, err := q.rows(ctx, name, args)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("query iteration: %w", err)
	}
	return nil
}
