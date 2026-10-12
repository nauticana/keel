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
	return scanResult(rows)
}

func (s *QueryServicePgsql) GenID() int64 {
	return s.IdGenerator.NextID()
}

var _ port.QueryService = (*QueryServicePgsql)(nil)
