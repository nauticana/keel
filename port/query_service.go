package port

import (
	"context"

	"github.com/nauticana/keel/model"
)

type QueryService interface {
	Query(ctx context.Context, queryName string, args ...any) (*model.QueryResult, error)
	GenID() int64
}

// RowScanner reads the current row into typed destinations in SELECT-list order.
type RowScanner interface {
	Scan(dest ...any) error
}

// RowQuerier is an optional QueryService capability for hot queries: it hands
// each row to scan without boxing cells into a QueryResult. A scan error stops
// the iteration and is returned unchanged.
type RowQuerier interface {
	QueryEach(ctx context.Context, queryName string, scan func(RowScanner) error, args ...any) error
}

type TxQueryService interface {
	QueryService
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// TxQueryCatalog is an optional transaction capability that binds another
// named-SQL catalog to the same in-flight transaction. Horizontal services
// use it to compose independently-owned query maps without concatenating
// private maps at every downstream call site. catalogID must be globally
// stable and unique; PostgreSQL uses it to compile placeholders once.
type TxQueryCatalog interface {
	QueryService(catalogID string, queries map[string]string) QueryService
}
