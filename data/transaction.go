package data

import (
	"context"
	"time"

	"github.com/nauticana/keel/port"
)

// RollbackDetached ends a transaction even when the request context that
// started it has already been cancelled. The bounded background context is
// specifically for cleanup and releasing database locks.
func RollbackDetached(tx port.TxQueryService) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tx.Rollback(ctx)
}

// InTx runs fn in a transaction of db bound to queries and commits when fn
// returns nil; otherwise, or when fn panics, it rolls back.
func InTx(ctx context.Context, db port.DatabaseRepository, queries map[string]string, fn func(tx port.TxQueryService) error) error {
	tx, err := db.BeginTx(ctx, queries)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = RollbackDetached(tx)
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}
