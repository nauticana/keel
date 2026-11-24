package data

import (
	"context"
	"errors"
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
// returns nil; otherwise, or when fn panics, it rolls back. A failed rollback
// joins the returned error.
func InTx(ctx context.Context, db port.DatabaseRepository, queries map[string]string, fn func(tx port.TxQueryService) error) (err error) {
	tx, err := db.BeginTx(ctx, queries)
	if err != nil {
		return err
	}
	// A commit attempt ends the transaction either way, so only fn's failure rolls back.
	committing := false
	defer func() {
		if !committing {
			if rollbackErr := RollbackDetached(tx); rollbackErr != nil {
				err = errors.Join(err, rollbackErr)
			}
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	committing = true
	return tx.Commit(ctx)
}
