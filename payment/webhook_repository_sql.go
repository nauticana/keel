package payment

import (
	"context"
	"fmt"
	"sync"

	"github.com/nauticana/keel/common"
	"github.com/nauticana/keel/config"
	"github.com/nauticana/keel/port"
)

// Webhook processing status values stored in payment_webhook_log.processing_status.
const (
	StatusReceived   = "R" // logged, not yet processed
	StatusProcessed  = "P" // handler returned nil
	StatusFailed     = "F" // parsing, enrichment, handler, or after-hook returned an error
	StatusDuplicate  = "D" // idempotency: already seen
	StatusSkipped    = "S" // event-type not in WebhookProcessor.AllowedEventTypes; never reached the handler
	StatusDeadLetter = "L" // replay failed at MaxAttempts; terminal until an operator intervenes
)

// claimLeaseSeconds (DB clock, last_claimed_at) spaces replay attempts per
// row and bounds how long a crashed claim blocks recovery. Sourced from the
// webhook_claim_lease_seconds config flag; the config load rejects
// non-positive values.
func claimLeaseSeconds() int { return config.Config().WebhookClaimLeaseSeconds }

const (
	qLogWebhook           = "payment_log_webhook"
	qCheckWebhookExists   = "payment_check_webhook_exists"
	qUpdateWebhookStatus  = "payment_update_webhook_status"
	qReclaimFailedWebhook = "payment_reclaim_failed_webhook"
	qClaimFailedWebhook   = "payment_claim_failed_webhook"
	qVerifyWebhookColumns = "payment_verify_webhook_columns"
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
 (id, provider, event_id, event_type, processing_status, request_id, raw_payload)
VALUES
 (nextval('payment_webhook_log_seq'), ?, ?, ?, 'R', ?, ?)
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
RETURNING id
`,
	// Atomically re-claim a failed or abandoned delivery: among concurrent
	// provider retries exactly one UPDATE matches and renews the lease.
	// Terminal rows and R rows within their lease never match; an R row
	// past its lease is a crashed claim and is claimable again.
	qReclaimFailedWebhook: `
UPDATE payment_webhook_log
   SET processing_status = 'R',
       error_message = NULL,
       processed_at = NULL,
       last_claimed_at = CURRENT_TIMESTAMP
 WHERE provider = ? AND event_id = ?
   AND (processing_status = 'F'
        OR (processing_status = 'R'
            AND COALESCE(last_claimed_at, received_at) < CURRENT_TIMESTAMP - make_interval(secs => ?)))
RETURNING id
`,
	// Claim one replayable delivery: a failed row past the lease cooldown,
	// or an abandoned R row past its lease. The cooldown — not the row
	// lock, which ends at commit — is what keeps overlapping sweeps from
	// spending multiple attempts on the same row; the id cursor does the
	// same within one sweep.
	qClaimFailedWebhook: `
WITH candidate AS (
    SELECT id,
           replay_attempts >= ? AS exhausted
      FROM payment_webhook_log
     WHERE provider = ANY(?)
       AND id > ?
       AND (last_claimed_at IS NULL
            OR last_claimed_at < CURRENT_TIMESTAMP - make_interval(secs => ?))
       AND (processing_status = 'F'
            OR (processing_status = 'R'
                AND COALESCE(last_claimed_at, received_at) < CURRENT_TIMESTAMP - make_interval(secs => ?)))
     ORDER BY id
     LIMIT 1
       FOR UPDATE SKIP LOCKED
)
UPDATE payment_webhook_log AS webhook
   SET processing_status = CASE WHEN candidate.exhausted THEN 'L' ELSE 'R' END,
       error_message = CASE
           WHEN candidate.exhausted THEN COALESCE(webhook.error_message, 'replay attempts exhausted')
           ELSE NULL
       END,
       processed_at = CASE WHEN candidate.exhausted THEN CURRENT_TIMESTAMP ELSE NULL END,
       replay_attempts = CASE
           WHEN candidate.exhausted THEN webhook.replay_attempts
           ELSE webhook.replay_attempts + 1
       END,
       last_claimed_at = CURRENT_TIMESTAMP
  FROM candidate
 WHERE webhook.id = candidate.id
RETURNING webhook.id,
          webhook.provider,
          webhook.event_id,
          webhook.event_type,
          webhook.request_id,
          webhook.raw_payload,
          webhook.replay_attempts,
          webhook.processing_status
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
	qVerifyWebhookColumns: `
SELECT column_name
  FROM information_schema.columns
 WHERE table_schema = current_schema()
   AND table_name = 'payment_webhook_log'
   AND column_name IN ('request_id', 'replay_attempts', 'last_claimed_at')
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
	DB port.DatabaseRepository

	qsOnce sync.Once
	qs     port.QueryService
}

func NewSQLWebhookRepository(db port.DatabaseRepository) *SQLWebhookRepository {
	return &SQLWebhookRepository{DB: db}
}

// queryService returns the cached query service, lazily constructing
// it on first use. Lazy because GetQueryService takes a ctx that's
// only available at call time, not at NewSQLWebhookRepository time —
// but pgxpool's GetQueryService doesn't actually do anything with
// the ctx beyond pass-through, so subsequent calls' ctx is irrelevant
// to the cached instance.
func (r *SQLWebhookRepository) queryService(ctx context.Context) port.QueryService {
	r.qsOnce.Do(func() {
		r.qs = r.DB.GetQueryService(ctx, webhookQueries)
	})
	return r.qs
}

// Log inserts a raw webhook row and returns the generated log ID.
func (r *SQLWebhookRepository) Log(ctx context.Context, provider, eventID, eventType, requestID string, rawBody []byte) (int64, error) {
	var correlated any
	if requestID != "" {
		correlated = requestID
	}
	res, err := r.queryService(ctx).Query(ctx, qLogWebhook, provider, eventID, eventType, correlated, string(rawBody))
	if err != nil {
		return 0, fmt.Errorf("log webhook: %w", err)
	}
	if len(res.Rows) == 0 {
		return 0, fmt.Errorf("log webhook: no id returned")
	}
	return common.AsInt64(res.Rows[0][0]), nil
}

// ClaimFailed atomically claims the oldest replayable delivery for one of
// providers with id > afterID. An exhausted row is moved directly to
// StatusDeadLetter; otherwise ReplayAttempts includes the new claim.
func (r *SQLWebhookRepository) ClaimFailed(ctx context.Context, maxAttempts int, afterID int64, providers []string) (*WebhookDelivery, bool, error) {
	if maxAttempts <= 0 {
		return nil, false, fmt.Errorf("claim failed webhook: maxAttempts must be positive")
	}
	if len(providers) == 0 {
		return nil, false, fmt.Errorf("claim failed webhook: providers are required")
	}
	res, err := r.queryService(ctx).Query(ctx, qClaimFailedWebhook,
		maxAttempts, providers, afterID, claimLeaseSeconds(), claimLeaseSeconds())
	if err != nil {
		return nil, false, fmt.Errorf("claim failed webhook: %w", err)
	}
	if len(res.Rows) == 0 {
		return nil, false, nil
	}
	row := res.Rows[0]
	if len(row) < 8 {
		return nil, false, fmt.Errorf("claim failed webhook: got %d columns, want 8", len(row))
	}
	return &WebhookDelivery{
		LogID:          common.AsInt64(row[0]),
		Provider:       common.AsString(row[1]),
		EventID:        common.AsString(row[2]),
		EventType:      common.AsString(row[3]),
		RequestID:      common.AsString(row[4]),
		RawBody:        []byte(common.AsString(row[5])),
		ReplayAttempts: int(common.AsInt64(row[6])),
		DeadLettered:   common.AsString(row[7]) == StatusDeadLetter,
	}, true, nil
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

// ReclaimFailed atomically re-claims a StatusFailed or lease-expired
// StatusReceived delivery for retry. ok=false when no row matched (absent,
// terminal, in-flight within its lease, or claimed by a concurrent retry).
func (r *SQLWebhookRepository) ReclaimFailed(ctx context.Context, provider, eventID string) (int64, bool, error) {
	res, err := r.queryService(ctx).Query(ctx, qReclaimFailedWebhook, provider, eventID, claimLeaseSeconds())
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
	res, err := r.queryService(ctx).Query(ctx, qUpdateWebhookStatus, status, msg, logID)
	if err != nil {
		return fmt.Errorf("update webhook status: %w", err)
	}
	if len(res.Rows) == 0 {
		return fmt.Errorf("update webhook status: row %d not found", logID)
	}
	return nil
}

// VerifySchema asserts the schema invariants this repository relies on: the
// UNIQUE index on (provider, event_id) and the correlation/replay columns. Call once at
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
		return fmt.Errorf("payment_webhook_log: missing UNIQUE index on (provider, event_id) — idempotency cannot be enforced without it; apply the index defined in schema/payment/payment_webhook_log.yml")
	}
	res, err = r.queryService(ctx).Query(ctx, qVerifyWebhookColumns)
	if err != nil {
		return fmt.Errorf("verify webhook replay schema: %w", err)
	}
	found := make(map[string]bool, len(res.Rows))
	for _, row := range res.Rows {
		if len(row) > 0 {
			found[common.AsString(row[0])] = true
		}
	}
	for _, column := range []string{"request_id", "replay_attempts", "last_claimed_at"} {
		if !found[column] {
			return fmt.Errorf("payment_webhook_log: missing %s column — apply the migration in migration_guide.json", column)
		}
	}
	return nil
}

var (
	_ WebhookRepository = (*SQLWebhookRepository)(nil)
	_ WebhookReclaimer  = (*SQLWebhookRepository)(nil)
)
