package data

import (
	"context"

	"github.com/nauticana/keel/model"
)

type QueryService interface {
	Query(ctx context.Context, queryName string, args ...any) (*model.QueryResult, error)
	GenID() int64
}

type TxQueryService interface {
	QueryService
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	GenID() int64
}
