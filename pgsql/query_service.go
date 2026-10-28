package pgsql

import (
	"context"

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
	return namedQuery{s.Client, s.Queries}.result(ctx, queryName, args)
}

func (s *QueryServicePgsql) QueryEach(ctx context.Context, queryName string, scan func(port.RowScanner) error, args ...any) error {
	return namedQuery{s.Client, s.Queries}.each(ctx, queryName, scan, args)
}

func (s *QueryServicePgsql) GenID() int64 {
	return s.IdGenerator.NextID()
}

var (
	_ port.QueryService = (*QueryServicePgsql)(nil)
	_ port.RowQuerier   = (*QueryServicePgsql)(nil)
)
