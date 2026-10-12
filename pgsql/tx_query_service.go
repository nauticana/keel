package pgsql

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

var txQueryCatalogs sync.Map

func cachedTransactionQueries(catalogID string, queries map[string]string) map[string]string {
	if catalogID == "" {
		return rewriteQueries(queries)
	}
	if cached, ok := txQueryCatalogs.Load(catalogID); ok {
		return cached.(map[string]string)
	}
	rewritten := rewriteQueries(queries)
	actual, _ := txQueryCatalogs.LoadOrStore(catalogID, rewritten)
	return actual.(map[string]string)
}

type TxQueryServicePgsql struct {
	Tx          pgx.Tx
	Queries     map[string]string
	IdGenerator port.BigintGenerator
}

func (s *TxQueryServicePgsql) Query(ctx context.Context, queryName string, args ...any) (*model.QueryResult, error) {
	sql := s.Queries[queryName]
	if sql == "" {
		return nil, fmt.Errorf("query not found: %s", queryName)
	}
	rows, err := s.Tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to run query: %w", err)
	}
	return scanResult(rows)
}

func (s *TxQueryServicePgsql) Commit(ctx context.Context) error {
	return s.Tx.Commit(ctx)
}

func (s *TxQueryServicePgsql) Rollback(ctx context.Context) error {
	return s.Tx.Rollback(ctx)
}

func (s *TxQueryServicePgsql) GenID() int64 {
	return s.IdGenerator.NextID()
}

// QueryService binds an independently-owned named query catalog to this same
// pgx transaction. It does not begin or commit another transaction.
func (s *TxQueryServicePgsql) QueryService(catalogID string, queries map[string]string) port.QueryService {
	return &TxQueryServicePgsql{
		Tx:          s.Tx,
		Queries:     cachedTransactionQueries(catalogID, queries),
		IdGenerator: s.IdGenerator,
	}
}

var _ port.TxQueryService = (*TxQueryServicePgsql)(nil)
var _ port.TxQueryCatalog = (*TxQueryServicePgsql)(nil)
