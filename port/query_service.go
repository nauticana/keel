package port

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
}

// TxQueryCatalog is an optional transaction capability that binds another
// named-SQL catalog to the same in-flight transaction. Horizontal services
// use it to compose independently-owned query maps without concatenating
// private maps at every downstream call site. catalogID must be globally
// stable and unique; PostgreSQL uses it to compile placeholders once.
type TxQueryCatalog interface {
	QueryService(catalogID string, queries map[string]string) QueryService
}
