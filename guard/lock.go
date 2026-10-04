package guard

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nauticana/keel/port"
)

// QueryLock is the named query Lock runs; merge Queries into the catalog given
// to BeginTx for the transaction that checks and writes.
const QueryLock = "guard_xact_lock"

var Queries = map[string]string{
	QueryLock: "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))",
}

var ErrNoLockKey = errors.New("guard: a lock key is required")

// Lock takes a transaction-scoped advisory lock on key, so concurrent callers
// with the same key run their guard check and write one at a time. The lock is
// released when tx commits or rolls back.
func Lock(ctx context.Context, tx port.TxQueryService, key string) error {
	if strings.TrimSpace(key) == "" {
		return ErrNoLockKey
	}
	if _, err := tx.Query(ctx, QueryLock, "guard:"+key); err != nil {
		return fmt.Errorf("guard lock: %w", err)
	}
	return nil
}
