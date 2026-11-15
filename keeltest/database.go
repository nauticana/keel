// Package keeltest holds fakes of keel's repository for downstream service tests.
package keeltest

import (
	"context"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// Database is a DatabaseRepository answering named queries from Queries,
// transactions from Tx, and grants from Grants keyed "object/action/scope".
// Any other repository method panics on the nil embedded value.
type Database struct {
	port.DatabaseRepository
	Queries *Queries
	Tx      *Queries
	Grants  map[string]bool
	// Checked records every grant asked for, with its principal.
	Checked []string
	As      []model.Principal
}

// NewDatabase returns a database whose callers hold grants ("TABLE/SELECT/foo").
func NewDatabase(grants ...string) *Database {
	d := &Database{Queries: NewQueries(), Tx: NewQueries(), Grants: map[string]bool{}}
	for _, g := range grants {
		d.Grants[g] = true
	}
	return d
}

func (d *Database) GetQueryService(context.Context, map[string]string) port.QueryService {
	return d.Queries
}

func (d *Database) BeginTx(context.Context, map[string]string) (port.TxQueryService, error) {
	return d.Tx, nil
}

// RunInTx commits Tx when fn returns nil and rolls it back otherwise.
func (d *Database) RunInTx(ctx context.Context, fn func(view port.TxView) error) error {
	if err := fn(TxView{Queries: d.Tx}); err != nil {
		_ = d.Tx.Rollback(ctx)
		return err
	}
	return d.Tx.Commit(ctx)
}

func (d *Database) CheckActionPermission(_ context.Context, principal model.Principal, object, action, scope string) (bool, bool) {
	key := object + "/" + action + "/" + scope
	d.Checked = append(d.Checked, key)
	d.As = append(d.As, principal)
	return principal.Valid() && d.Grants[key], false
}

var _ port.DatabaseRepository = (*Database)(nil)
