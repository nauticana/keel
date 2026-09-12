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
