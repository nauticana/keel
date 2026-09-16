package idempotency

import (
	"context"
	"time"

	"github.com/nauticana/keel/model"
	"github.com/nauticana/keel/port"
)

// Every timestamp is CURRENT_TIMESTAMP: the database decides lease expiry, never a worker's clock.
var pgsqlQueries = map[string]string{
	qFind: `SELECT state_code, result FROM idempotency_ledger WHERE ledger_key = ?`,
	qClaim: `INSERT INTO idempotency_ledger (ledger_key, state_code, fence, updated_at) VALUES (?, 'I', ?, CURRENT_TIMESTAMP)
	         ON CONFLICT DO NOTHING RETURNING ledger_key`,
	qReclaim: `UPDATE idempotency_ledger SET fence = ?, updated_at = CURRENT_TIMESTAMP
	           WHERE ledger_key = ? AND state_code = 'I' AND updated_at <= CURRENT_TIMESTAMP - (INTERVAL '1 second' * ?) RETURNING ledger_key`,
	qRenew: `UPDATE idempotency_ledger SET updated_at = CURRENT_TIMESTAMP
	         WHERE ledger_key = ? AND fence = ? AND state_code = 'I' RETURNING ledger_key`,
	qComplete: `UPDATE idempotency_ledger SET state_code = 'C', result = ?, updated_at = CURRENT_TIMESTAMP
	            WHERE ledger_key = ? AND fence = ? AND (state_code IN ('I', 'U') OR (state_code = 'C' AND result = ?)) RETURNING ledger_key`,
	qUnknown: `UPDATE idempotency_ledger SET state_code = 'U', result = NULL, updated_at = CURRENT_TIMESTAMP
	           WHERE ledger_key = ? AND fence = ? AND state_code IN ('I', 'U') RETURNING ledger_key`,
	qRelease: `DELETE FROM idempotency_ledger WHERE ledger_key = ? AND fence = ? AND state_code IN ('I', 'U') RETURNING ledger_key`,
}

type pgsqlLedgerQueries struct{}

var _ ledgerQueryProvider = pgsqlLedgerQueries{}

func (pgsqlLedgerQueries) GetQueries() map[string]string {
	return pgsqlQueries
}

// PgsqlLedger keeps the ledger in the idempotency_ledger table.
type PgsqlLedger struct {
	AbstractDatabaseLedger
}

var _ port.IdempotencyLedger = (*PgsqlLedger)(nil)

// NewPgsqlLedger binds the PostgreSQL implementation to a database repository; lease 0 never takes over a claim.
func NewPgsqlLedger(db port.DatabaseRepository, lease time.Duration) *PgsqlLedger {
	return &PgsqlLedger{AbstractDatabaseLedger: AbstractDatabaseLedger{
		AbstractLedger: AbstractLedger{Lease: lease},
		db:             db,
		queryProvider:  pgsqlLedgerQueries{},
	}}
}

func (l *PgsqlLedger) Begin(ctx context.Context, key string) (model.LedgerEntry, error) {
	return l.begin(ctx, key)
}

func (l *PgsqlLedger) Renew(ctx context.Context, key, fence string) error {
	return l.renew(ctx, key, fence)
}

func (l *PgsqlLedger) Complete(ctx context.Context, key, fence string, result []byte) error {
	return l.complete(ctx, key, fence, result)
}

func (l *PgsqlLedger) MarkUnknown(ctx context.Context, key, fence string) error {
	return l.markUnknown(ctx, key, fence)
}

func (l *PgsqlLedger) Release(ctx context.Context, key, fence string) error {
	return l.release(ctx, key, fence)
}
