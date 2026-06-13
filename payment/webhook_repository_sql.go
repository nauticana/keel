package payment

import (
	"context"
	"fmt"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/data"
)

// Webhook processing status values stored in payment_webhook_log.processing_status.
const (
	StatusReceived  = "R" // logged, not yet processed
	StatusProcessed = "P" // handler returned nil
	StatusFailed    = "F" // handler or verification returned an error
	StatusDuplicate = "D" // idempotency: already seen
	StatusSkipped   = "S" // event-type not in WebhookProcessor.AllowedEventTypes; never reached the handler
)

const (
	qLogWebhook           = "payment_log_webhook"
	qCheckWebhookExists   = "payment_check_webhook_exists"
	qUpdateWebhookStatus  = "payment_update_webhook_status"
	qReclaimFailedWebhook = "payment_reclaim_failed_webhook"
	// qVerifyWebhookIndex asserts the UNIQUE index on
	// payment_webhook_log(provider, event_id) exists. The index is the
	// authoritative race guard for concurrent webhook retries — if a
	// downstream applied the schema without it (partial migration,
	// hand-written DDL), idempotency silently degrades to a
	// log-and-retry-storm. Boot-time invariant check fails fast.
	//
	// Postgres-specific: queries pg_indexes for an index definition
	// containing both column names and the UNIQUE keyword. Substring
	// match is correct because indexdef holds the original CREATE
	// statement verbatim.
	qVerifyWebhookIndex = "payment_verify_webhook_index"
)

// webhookQueries are the SQL statements used by SQLWebhookRepository.
// Split into a var so extensions can override or extend them.
var webhookQueries = map[string]string{
	qLogWebhook: `
INSERT INTO payment_webhook_log
 (id, provider, event_id, event_type, processing_status, raw_payload)
VALUES
 (nextval('payment_webhook_log_seq'), ?, ?, ?, 'R', ?)
RETURNING id
`,
	// Match any prior log for (provider, event_id) regardless of its
	// terminal status. The Process() flow turns an existing 'P' / 'D'
	// row into a Duplicate response, and an existing 'R' row into a
	// Duplicate as well — concurrent retries from the provider must
	// never both reach the handler. The unique index on
	// (provider, event_id) backs this contract at the DB layer.
	qCheckWebhookExists: `
SELECT processing_status
  FROM payment_webhook_log
 WHERE provider = ? AND event_id = ?
 LIMIT 1
`,
	qUpdateWebhookStatus: `
UPDATE payment_webhook_log
   SET processing_status = ?,
       error_message = ?,
       processed_at = CURRENT_TIMESTAMP
 WHERE id = ?
`,
	// Atomically re-claim a previously-failed delivery for reprocessing.
	// The `processing_status = 'F'` predicate is the race guard: among
	// concurrent provider retries, exactly one UPDATE flips F→R and gets
	// the RETURNING id; the rest match no row. Terminal (P/D/S) and
	// in-flight (R) rows are left untouched so a retry never re-runs a
	// handler that already succeeded or is still running.
	qReclaimFailedWebhook: `
UPDATE payment_webhook_log
   SET processing_status = 'R',
       error_message = NULL,
       processed_at = CURRENT_TIMESTAMP
 WHERE provider = ? AND event_id = ? AND processing_status = 'F'
RETURNING id
`,
	qVerifyWebhookIndex: `
SELECT 1
  FROM pg_indexes
 WHERE schemaname = current_schema()
   AND tablename = 'payment_webhook_log'
   AND indexdef ILIKE '%UNIQUE%'
   AND indexdef ILIKE '%provider%'
   AND indexdef ILIKE '%event_id%'
 LIMIT 1
`,
}

// SQLWebhookRepository is the default SQL-backed implementation of
// port.WebhookRepository. It targets the shared `payment_webhook_log`
// table defined in keel's schema.
//
// queryService is built once and cached (v0.4.4 perf): the previous
// implementation called `r.DB.GetQueryService(ctx, webhookQueries)` on
// every webhook delivery, which re-ran the placeholder rewriter
// (literal-aware state machine over the entire query map) per call.
// The result is identical across calls and the underlying
// QueryService holds only a pool reference, so a sync.Once-gated
// build is both safe and free of the per-delivery rewrite cost.
type SQLWebhookRepository struct {
	DB data.DatabaseRepository

	qsOnce sync.Once
	qs     data.QueryService
}

func NewSQLWebhookRepository(db data.DatabaseRepository) *SQLWebhookRepository {
	return &SQLWebhookRepository{DB: db}
}

// queryService returns the cached query service, lazily constructing
// it on first use. Lazy because GetQueryService takes a ctx that's
// only available at call time, not at NewSQLWebhookRepository time —
// but pgxpool's GetQueryService doesn't actually do anything with
// the ctx beyond pass-through, so subsequent calls' ctx is irrelevant
// to the cached instance.
func (r *SQLWebhookRepository) queryService(ctx context.Context) data.QueryService {
	r.qsOnce.Do(func() {
		r.qs = r.DB.GetQueryService(ctx, webhookQueries)
	})
	return r.qs
}

// Log inserts a raw webhook row and returns the generated log ID.
func (r *SQLWebhookRepository) Log(ctx context.Context, provider, eventID, eventType string, rawBody []byte) (int64, error) {
	res, err := r.queryService(ctx).Query(ctx, qLogWebhook, provider, eventID, eventType, string(rawBody))
	if err != nil {
		return 0, fmt.Errorf("log webhook: %w", err)
	}
	if len(res.Rows) == 0 {
		return 0, fmt.Errorf("log webhook: no id returned")
	}
	return common.AsInt64(res.Rows[0][0]), nil
}

// Exists returns true if a webhook for (provider, eventID) has already
// been seen — regardless of terminal status. The processor treats any
// hit as a duplicate so a second concurrent retry of the same event
// never re-enters the domain handler. (The unique index on
// (provider, event_id) is the authoritative race guard; this query is
// the cheap path for the common-case "already seen" branch.)
func (r *SQLWebhookRepository) Exists(ctx context.Context, provider, eventID string) (bool, error) {
	res, err := r.queryService(ctx).Query(ctx, qCheckWebhookExists, provider, eventID)
	if err != nil {
		return false, fmt.Errorf("check webhook exists: %w", err)
	}
	return len(res.Rows) > 0, nil
}

// ReclaimFailed atomically re-claims a StatusFailed delivery for retry.
// ok=false when no failed row matched (absent, terminal, in-flight, or
// claimed by a concurrent retry).
func (r *SQLWebhookRepository) ReclaimFailed(ctx context.Context, provider, eventID string) (int64, bool, error) {
	res, err := r.queryService(ctx).Query(ctx, qReclaimFailedWebhook, provider, eventID)
	if err != nil {
		return 0, false, fmt.Errorf("reclaim failed webhook: %w", err)
	}
	if len(res.Rows) == 0 {
		return 0, false, nil
	}
	return common.AsInt64(res.Rows[0][0]), true, nil
}

// UpdateStatus flips the status + error_message on the log row.
func (r *SQLWebhookRepository) UpdateStatus(ctx context.Context, logID int64, status, message string) error {
	var msg any
	if message != "" {
		msg = message
	}
	_, err := r.queryService(ctx).Query(ctx, qUpdateWebhookStatus, status, msg, logID)
	if err != nil {
		return fmt.Errorf("update webhook status: %w", err)
	}
	return nil
}

// VerifySchema asserts the schema invariants this repository relies on
// — currently the UNIQUE index on (provider, event_id). Call once at
// boot from main.go so a partially-migrated database (e.g. the YAML
// shipped but the index DDL was applied by hand and dropped) fails the
// app at startup with a clear error instead of silently losing
// idempotency under load.
//
// Postgres-only: the query reads pg_indexes. MySQL / SQLite consumers
// should provide their own driver-specific check or skip this call.
func (r *SQLWebhookRepository) VerifySchema(ctx context.Context) error {
	res, err := r.queryService(ctx).Query(ctx, qVerifyWebhookIndex)
	if err != nil {
		return fmt.Errorf("verify webhook log schema: %w", err)
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("payment_webhook_log: missing UNIQUE index on (provider, event_id) — idempotency cannot be enforced without it; apply the index defined in schema/basis/25_payment_webhook_log.yml")
	}
	return nil
}

var (
	_ WebhookRepository = (*SQLWebhookRepository)(nil)
	_ WebhookReclaimer  = (*SQLWebhookRepository)(nil)
)
