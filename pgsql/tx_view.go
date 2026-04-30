package pgsql

import (
	"github.com/jackc/pgx/v5"
	"github.com/nauticana/keel/data"
)

// pgsqlTxView yields tx-bound TableService copies. Lookups go via the
// repository's TableServices map; the returned service shares all
// metadata with the registered one but routes its DB calls through
// the in-flight pgx.Tx instead of the pool.
type pgsqlTxView struct {
	tx   pgx.Tx
	repo *RepositoryPgsql
}

// Table returns a tx-bound TableService for the named table, or nil
// when the repository has no service for that name. Callers handle
// nil as "table not registered" — typically a programming error in
// the caller.
func (v *pgsqlTxView) Table(name string) data.TableService {
	base, ok := v.repo.TableServices[name].(*TableServicePgsql)
	if !ok || base == nil {
		return nil
	}
	return base.WithTx(v.tx)
}
